//! Link-layer handling — `sensor.py:packet_handler()` plus the offset learner from
//! `sensor.py:_guess_dlt_ip_offset()` / `core/fastfilter.py:guess_ip_offset()`.

use std::collections::HashMap;

use crate::settings;

/// DLT values, as `pcap_datalink()` returns them on the platform the sensor runs on. libpcap
/// translates a savefile's LINKTYPE_ value into these when it opens a capture, so a pcap recorded
/// on another OS arrives in the same numbering.
pub const DLT_NULL: i32 = 0;
pub const DLT_EN10MB: i32 = 1;
pub const DLT_PPP: i32 = 9;
pub const DLT_LINUX_SLL: i32 = 113;
// OpenBSD numbers three of these differently (pcap/dlt.h); 12 is raw IP everywhere else and
// loopback there, so the value cannot be decided at runtime.
#[cfg(target_os = "openbsd")]
pub const DLT_RAW: i32 = 14;
#[cfg(not(target_os = "openbsd"))]
pub const DLT_RAW: i32 = 12;
#[cfg(target_os = "openbsd")]
pub const DLT_LOOP: i32 = 12;
#[cfg(not(target_os = "openbsd"))]
pub const DLT_LOOP: i32 = 108;
#[cfg(target_os = "openbsd")]
pub const DLT_ENC: i32 = 13;
#[cfg(not(target_os = "openbsd"))]
pub const DLT_ENC: i32 = 109;
pub const DLT_PPP_SERIAL: i32 = 50;
pub const DLT_PPP_ETHER: i32 = 51;
pub const DLT_C_HDLC: i32 = 104;
pub const DLT_IEEE802_11: i32 = 105;
pub const DLT_PFLOG: i32 = 117;
pub const DLT_PRISM_HEADER: i32 = 119;
pub const DLT_IEEE802_11_RADIO: i32 = 127;
pub const DLT_PPI: i32 = 192;
pub const DLT_IPV4: i32 = 228;
pub const DLT_IPV6: i32 = 229;
pub const DLT_NFLOG: i32 = 239;
pub const DLT_NETANALYZER: i32 = 240;
pub const DLT_LINUX_SLL2: i32 = 276;
/// pf state synchronisation on NetBSD, OpenBSD, DragonFly and macOS. Never IP.
pub const DLT_PFSYNC_BSD: i32 = 18;

#[inline]
fn ip_at(packet: &[u8], off: usize) -> Option<usize> {
    match packet.get(off)? >> 4 {
        4 | 6 => Some(off),
        _ => None,
    }
}

/// A 4-byte address-family header (`DLT_NULL`, `DLT_LOOP`, and the start of `DLT_ENC`).
///
/// The family is in the capturing host's byte order for NULL and in network order for LOOP, and a
/// savefile can come from a machine of either endianness, so both readings are tried. IPv6 is 24
/// (Net/OpenBSD, and what Npcap writes on Windows today), 28 (FreeBSD) or 30 (macOS); 23 is what
/// older Npcap builds wrote. All of them mean IPv6.
fn af_family_offset(packet: &[u8], header: usize) -> Option<usize> {
    let raw: [u8; 4] = packet.get(0..4)?.try_into().ok()?;
    let ok = |family: u32| matches!(family, 2 | 23 | 24 | 28 | 30);
    if ok(u32::from_le_bytes(raw)) || ok(u32::from_be_bytes(raw)) {
        ip_at(packet, header)
    } else {
        None
    }
}

/// `DLT_PFLOG`: the first byte is the header length, which differs between OpenBSD and FreeBSD
/// versions of the struct; the payload starts at that length rounded up to a 4-byte boundary, as
/// tcpdump's print-pflog.c reads it. Anything shorter than the oldest known header is not one.
fn pflog_offset(packet: &[u8]) -> Option<usize> {
    let length = *packet.first()? as usize;
    if length < 45 {
        return None;
    }
    ip_at(packet, (length + 3) & !3)
}

/// `DLT_NFLOG`: a 4-byte header (family 2 or 10), then TLVs running to the end of the packet,
/// length and type in the capturing host's byte order. Type 9 carries the packet itself.
fn nflog_offset(packet: &[u8]) -> Option<usize> {
    if !matches!(*packet.first()?, 2 | 10) {
        return None;
    }
    let mut off = 4usize;
    while off + 4 <= packet.len() {
        let len_le = u16::from_le_bytes([packet[off], packet[off + 1]]) as usize;
        let ty_le = u16::from_le_bytes([packet[off + 2], packet[off + 3]]);
        // a big-endian capture: the same fields read the other way round
        let (len, ty) = if len_le >= 4 && off + len_le <= packet.len() {
            (len_le, ty_le)
        } else {
            (
                u16::from_be_bytes([packet[off], packet[off + 1]]) as usize,
                u16::from_be_bytes([packet[off + 2], packet[off + 3]]),
            )
        };
        if len < 4 || off + len > packet.len() {
            return None;
        }
        if ty & 0x7fff == 9 {
            return ip_at(packet, off + 4);
        }
        off += (len + 3) & !3;
    }
    None
}

/// An 802.11 data frame at `off`, followed by an LLC/SNAP header carrying IPv4 or IPv6.
///
/// The MAC header is 24 bytes, plus 6 for a fourth address (to-DS and from-DS both set), plus 2
/// for QoS data, plus 4 more for an HT control field (QoS with the order bit). Management and
/// control frames carry no IP, null-data subtypes carry nothing, and a protected frame is
/// encrypted, so all of those are dropped rather than misread.
fn ieee80211_offset(packet: &[u8], off: usize) -> Option<usize> {
    let fc0 = *packet.get(off)?;
    let fc1 = *packet.get(off + 1)?;
    if (fc0 >> 2) & 0x3 != 2 || fc1 & 0x40 != 0 {
        return None;
    }
    let subtype = fc0 >> 4;
    if subtype & 0x4 != 0 {
        return None;
    }
    let mut header = 24;
    if fc1 & 0x3 == 0x3 {
        header += 6;
    }
    if subtype & 0x8 != 0 {
        header += 2;
        if fc1 & 0x80 != 0 {
            header += 4;
        }
    }
    let llc = off + header;
    match packet.get(llc..llc + 8)? {
        [0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00] | [0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd] => ip_at(packet, llc + 8),
        _ => None,
    }
}

/// The link types whose header is not a fixed length, or that `DLT_OFFSETS` never described
/// correctly. `Some(result)` when the datalink is one of them; `None` sends it on to the table.
///
/// None of these goes to the offset learner: it locks the first offset two packets agree on,
/// which for a header whose length changes per packet (radiotap, PPI, PFLOG, NFLOG) silently
/// misreads every packet after the lock.
fn special_offset(datalink: i32, packet: &[u8]) -> Option<Option<usize>> {
    Some(match datalink {
        DLT_NULL | DLT_LOOP => af_family_offset(packet, 4),
        // address family (4), SPI (4), flags (4)
        DLT_ENC => af_family_offset(packet, 12),
        DLT_RAW | DLT_IPV4 | DLT_IPV6 => ip_at(packet, 0),
        DLT_PFLOG => pflog_offset(packet),
        DLT_NFLOG => nflog_offset(packet),
        DLT_LINUX_SLL2 => match packet.get(0..2)? {
            [0x08, 0x00] | [0x86, 0xdd] => ip_at(packet, 20),
            _ => None,
        },
        // Cisco HDLC and PPP in HDLC framing: address, control, then the protocol
        DLT_C_HDLC => match packet.get(2..4)? {
            [0x08, 0x00] | [0x86, 0xdd] => ip_at(packet, 4),
            _ => None,
        },
        DLT_PPP_SERIAL => match packet.get(2..4)? {
            [0x00, 0x21] | [0x00, 0x57] => ip_at(packet, 4),
            _ => None,
        },
        // PPPoE without the Ethernet header: 6 bytes of PPPoE, then the PPP protocol
        DLT_PPP_ETHER => match packet.get(6..8)? {
            [0x00, 0x21] | [0x00, 0x57] => ip_at(packet, 8),
            _ => None,
        },
        // a 4-byte pseudo-header in front of an ordinary Ethernet frame
        DLT_NETANALYZER => ip_offset(DLT_EN10MB, packet, 18),
        DLT_IEEE802_11 => ieee80211_offset(packet, 0),
        DLT_IEEE802_11_RADIO => {
            let len = u16::from_le_bytes(packet.get(2..4)?.try_into().ok()?) as usize;
            ieee80211_offset(packet, len)
        }
        DLT_PPI => {
            let len = u16::from_le_bytes(packet.get(2..4)?.try_into().ok()?) as usize;
            match u32::from_le_bytes(packet.get(4..8)?.try_into().ok()?) {
                105 => ieee80211_offset(packet, len),
                1 => ip_offset(DLT_EN10MB, packet, len + 14),
                _ => None,
            }
        }
        // a fixed 144-byte Prism monitor header; its own length field is at bytes 4..8
        DLT_PRISM_HEADER => {
            let len = u32::from_le_bytes(packet.get(4..8)?.try_into().ok()?) as usize;
            ieee80211_offset(packet, if len == 144 { len } else { 144 })
        }
        DLT_PFSYNC_BSD => None,
        _ => return None,
    })
}

/// Resolve where the IP header starts, for a datalink present in `DLT_OFFSETS`.
/// Returns `None` when the frame is not IP (or is too short), which drops the packet
/// exactly as the Python handler does.
pub fn ip_offset(datalink: i32, packet: &[u8], base: usize) -> Option<usize> {
    if datalink == DLT_RAW {
        return Some(base);
    }
    if let Some(result) = special_offset(datalink, packet) {
        return result;
    }
    if datalink == DLT_PPP {
        // (IPv4, IPv6) PPP protocol fields
        let field = packet.get(2..4)?;
        return if field == [0x00, 0x21] || field == [0x00, 0x57] { Some(base) } else { None };
    }
    if base >= 2 {
        let mut offset = base;
        // STACKED tags, not just one. The parser used to skip a single 0x8100 and drop everything
        // else "matching sensor.py", which was a real justification while that sensor existed and
        // is now just a hole: on a carrier or campus SPAN port carrying QinQ, or any 802.1ad
        // S-tagged link, EVERY frame failed the ethertype test and the sensor reported a quiet
        // network. Same shape as the PPPoE gap in #19297 - not a missed detection, a missed link.
        //
        // Three TPIDs are recognised: 0x8100 (802.1Q C-tag), 0x88a8 (802.1ad S-tag) and 0x9100
        // (pre-standard QinQ, still emitted by older kit). MAX_VLAN_TAGS bounds the walk so a
        // crafted frame of nothing but tags cannot make this loop over the whole packet; two is
        // what QinQ uses in practice and the limit leaves room without being unbounded.
        let mut tags = 0;
        while tags < MAX_VLAN_TAGS {
            match packet.get(offset.checked_sub(2)?..offset) {
                Some([0x81, 0x00]) | Some([0x88, 0xa8]) | Some([0x91, 0x00]) => {
                    offset += 4;
                    tags += 1;
                }
                _ => break,
            }
        }
        let ethertype = packet.get(offset.checked_sub(2)?..offset)?;
        if ethertype == [0x08, 0x00] || ethertype == [0x86, 0xdd] {
            return Some(offset);
        }
        // PPPoE session (RFC 2516): a 6-byte PPPoE header, then the 2-byte PPP protocol field,
        // then IP. Common on any link fed by a DSL/fibre CPE, and on a SPAN port mirroring one it
        // is *all* the interesting traffic - a sensor that drops it sees only whatever the capture
        // host itself originates, which is precisely the symptom in issue #19297.
        //
        // Note this needs handling here rather than by `guess()`: the heuristic only runs for an
        // UNKNOWN datalink, and a mirrored Ethernet port is DLT_EN10MB, so the frame was simply
        // dropped with no fallback.
        if ethertype == [0x88, 0x64] {
            let ppp = packet.get(offset + 6..offset + 8)?;
            if ppp == [0x00, 0x21] || ppp == [0x00, 0x57] {
                return Some(offset + 8);
            }
        }
    }
    None
}

/// How many stacked VLAN tags to walk before giving up. QinQ uses two; the limit exists so a
/// frame made entirely of tags cannot turn the walk into a scan of the whole packet.
const MAX_VLAN_TAGS: usize = 4;

/// Common IP protocol numbers used by the offset heuristic
/// (`core/fastfilter.py:_COMMON_IP_PROTO`).
const COMMON_IP_PROTO: [u8; 11] = [1, 2, 6, 17, 47, 50, 51, 58, 89, 103, 132];

/// `core/fastfilter.py:_ip_header_score()` — 2 = length-consistent, 1 = plausible, 0 = no.
fn ip_header_score(b: &[u8], off: usize, n: usize) -> u8 {
    let Some(&first) = b.get(off) else { return 0 };
    let v = first >> 4;
    if v == 4 && off + 20 <= n {
        let ihl = (first & 0x0f) as usize * 4;
        let total = ((b[off + 2] as usize) << 8) | b[off + 3] as usize;
        let proto = b[off + 9];
        if !((20..=60).contains(&ihl) && total >= ihl && COMMON_IP_PROTO.contains(&proto)) {
            return 0;
        }
        let rem = n - off;
        if rem >= total && rem - total <= 64 {
            return 2;
        }
        return if total <= 65535 { 1 } else { 0 };
    }
    if v == 6 && off + 40 <= n {
        let nexthdr = b[off + 6];
        if !COMMON_IP_PROTO.contains(&nexthdr) && !matches!(nexthdr, 0 | 43 | 44 | 60) {
            return 0;
        }
        let payload = ((b[off + 4] as usize) << 8) | b[off + 5] as usize;
        let rem = n - off - 40;
        if payload > 0 && rem >= payload && rem - payload <= 64 {
            return 2;
        }
        return 1;
    }
    0
}

/// `core/fastfilter.py:guess_ip_offset()`
pub fn guess_ip_offset(packet: &[u8], max_off: usize) -> Option<usize> {
    let n = packet.len();
    if n == 0 {
        return None;
    }
    let hi = max_off.min(n - 1);
    let mut weak = None;
    for off in 0..=hi {
        match ip_header_score(packet, off, n) {
            2 => return Some(off),
            1 if weak.is_none() => weak = Some(off),
            _ => {}
        }
    }
    weak
}

/// `sensor.py:_dlt_learn` — per-datalink learner that locks an inferred offset once two
/// packets agree, while still using the provisional guess in the meantime.
#[derive(Default)]
pub struct DltLearner {
    locked: HashMap<i32, Option<usize>>,
    provisional: HashMap<i32, usize>,
}

impl DltLearner {
    pub fn guess(&mut self, datalink: i32, packet: &[u8]) -> Option<usize> {
        match self.locked.get(&datalink) {
            Some(Some(off)) => return Some(*off),
            Some(None) => return None,
            None => {}
        }
        let off = guess_ip_offset(packet, 64)?;
        if self.provisional.get(&datalink) == Some(&off) {
            self.locked.insert(datalink, Some(off));
            crate::cprintln!(
                "[i] datalink {datalink} missing from offset table; inferred IP offset {off} by heuristic"
            );
            return Some(off);
        }
        self.provisional.insert(datalink, off);
        Some(off)
    }

    /// Full `packet_handler` offset resolution, including the unknown-datalink path.
    pub fn resolve(&mut self, datalink: i32, packet: &[u8]) -> Option<usize> {
        if let Some(result) = special_offset(datalink, packet) {
            return result;
        }
        match settings::dlt_offset(datalink) {
            Some(base) => ip_offset(datalink, packet, base),
            None => {
                crate::output::log_error(
                    &format!("Received unexpected datalink ({datalink}); attempting IP-offset heuristic"),
                    true,
                );
                self.guess(datalink, packet)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn eth(ethertype: u16) -> Vec<u8> {
        let mut v = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        v.extend_from_slice(&ethertype.to_be_bytes());
        v
    }

    /// Ethernet -> PPPoE session -> PPP -> payload, as a DSL/fibre uplink carries it.
    pub(crate) fn pppoe(ppp_proto: u16, payload: &[u8], vlan: bool) -> Vec<u8> {
        let mut v = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        if vlan {
            v.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
        }
        v.extend_from_slice(&0x8864u16.to_be_bytes());
        // ver/type, code (0 = session data), session id, payload length
        v.extend_from_slice(&[0x11, 0x00, 0xf5, 0xd7]);
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(&ppp_proto.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    pub(crate) fn min_ipv4() -> Vec<u8> {
        let mut v = vec![0x45, 0, 0, 20, 0x12, 0x34, 0, 0, 64, 17, 0, 0];
        v.extend_from_slice(&[10, 0, 0, 5]);
        v.extend_from_slice(&[8, 8, 8, 8]);
        v
    }

    #[test]
    fn ethernet_ipv4_and_ipv6() {
        let mut p = eth(0x0800);
        p.extend_from_slice(&min_ipv4());
        assert_eq!(ip_offset(DLT_EN10MB, &p, 14), Some(14));

        let mut p6 = eth(0x86dd);
        p6.extend_from_slice(&[0u8; 40]);
        assert_eq!(ip_offset(DLT_EN10MB, &p6, 14), Some(14));

        // ARP must be dropped
        let mut arp = eth(0x0806);
        arp.extend_from_slice(&[0u8; 28]);
        assert_eq!(ip_offset(DLT_EN10MB, &arp, 14), None);
    }

    #[test]
    fn single_vlan_tag_is_skipped() {
        let mut p = vec![0xaa; 12];
        p.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]); // TPID + TCI
        p.extend_from_slice(&[0x08, 0x00]);
        p.extend_from_slice(&min_ipv4());
        assert_eq!(ip_offset(DLT_EN10MB, &p, 14), Some(18));
    }

    /// `tpids` are the stacked tags to write, outermost first.
    fn tagged(tpids: &[[u8; 2]], ethertype: [u8; 2]) -> Vec<u8> {
        let mut p = vec![0xaa; 12];
        for (i, tpid) in tpids.iter().enumerate() {
            p.extend_from_slice(tpid);
            p.extend_from_slice(&[0x00, 0x64 + i as u8]); // TCI
        }
        p.extend_from_slice(&ethertype);
        p.extend_from_slice(&min_ipv4());
        p
    }

    #[test]
    fn qinq_is_parsed_not_dropped() {
        // two 802.1Q tags: the frame every QinQ SPAN port delivers. This used to return None, so a
        // sensor on such a link saw nothing at all and looked like a quiet network.
        let p = tagged(&[[0x81, 0x00], [0x81, 0x00]], [0x08, 0x00]);
        assert_eq!(ip_offset(DLT_EN10MB, &p, 14), Some(22));
    }

    #[test]
    fn the_8021ad_service_tag_is_recognised() {
        // 0x88a8 outer S-tag with a 0x8100 inner C-tag - the standards-conformant provider frame
        let p = tagged(&[[0x88, 0xa8], [0x81, 0x00]], [0x08, 0x00]);
        assert_eq!(ip_offset(DLT_EN10MB, &p, 14), Some(22));
        // and the pre-standard 0x9100 older kit still emits
        let p = tagged(&[[0x91, 0x00]], [0x86, 0xdd]);
        assert_eq!(ip_offset(DLT_EN10MB, &p, 14), Some(18));
    }

    #[test]
    fn a_tagged_frame_that_is_not_ip_is_still_dropped() {
        // the tags must not become a way past the ethertype check
        let mut arp = vec![0xaa; 12];
        arp.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
        arp.extend_from_slice(&[0x81, 0x00, 0x00, 0x65]);
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0u8; 28]);
        assert_eq!(ip_offset(DLT_EN10MB, &arp, 14), None);
    }

    #[test]
    fn a_frame_of_nothing_but_tags_terminates() {
        // MAX_VLAN_TAGS bounds the walk; past it the ethertype test fails and the frame is dropped
        let mut p = vec![0xaa; 12];
        for _ in 0..64 {
            p.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
        }
        p.extend_from_slice(&[0x08, 0x00]);
        p.extend_from_slice(&min_ipv4());
        assert_eq!(ip_offset(DLT_EN10MB, &p, 14), None);
    }

    #[test]
    fn raw_ppp_null_and_sll() {
        assert_eq!(ip_offset(DLT_RAW, &min_ipv4(), 0), Some(0));

        let mut ppp = vec![0xff, 0x03, 0x00, 0x21];
        ppp.extend_from_slice(&min_ipv4());
        assert_eq!(ip_offset(DLT_PPP, &ppp, 4), Some(4));
        let mut bad_ppp = vec![0xff, 0x03, 0x00, 0x99];
        bad_ppp.extend_from_slice(&min_ipv4());
        assert_eq!(ip_offset(DLT_PPP, &bad_ppp, 4), None);

        let mut null = vec![0x02, 0x00, 0x00, 0x00];
        null.extend_from_slice(&min_ipv4());
        assert_eq!(ip_offset(DLT_NULL, &null, 4), Some(4));

        let mut sll = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x06];
        sll.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00]);
        sll.extend_from_slice(&[0x08, 0x00]);
        sll.extend_from_slice(&min_ipv4());
        assert_eq!(ip_offset(DLT_LINUX_SLL, &sll, 16), Some(16));
    }

    #[test]
    fn truncated_frames_never_panic() {
        for n in 0..20 {
            let p = vec![0u8; n];
            let _ = ip_offset(DLT_EN10MB, &p, 14);
            let _ = ip_offset(DLT_PPP, &p, 4);
            let _ = ip_offset(DLT_NULL, &p, 4);
            let _ = ip_offset(DLT_RAW, &p, 0);
            let _ = guess_ip_offset(&p, 64);
        }
    }

    #[test]
    fn learner_locks_after_two_agreeing_packets() {
        // Mirrors the retired Python suite's TestDLTLearner
        let mut p = eth(0x0800);
        let mut ip = min_ipv4();
        ip.extend_from_slice(&[0u8; 8]); // UDP header
        ip[2] = 0;
        ip[3] = 28;
        p.extend_from_slice(&ip);
        let mut learner = DltLearner::default();
        const UNKNOWN: i32 = 9999;
        assert_eq!(learner.guess(UNKNOWN, &p), Some(14));
        assert!(!learner.locked.contains_key(&UNKNOWN));
        assert_eq!(learner.guess(UNKNOWN, &p), Some(14));
        assert_eq!(learner.locked.get(&UNKNOWN), Some(&Some(14)));
        assert_eq!(learner.guess(UNKNOWN, &p), Some(14));
    }

    #[test]
    fn learner_returns_none_for_non_ip() {
        let mut learner = DltLearner::default();
        assert_eq!(learner.guess(8888, &[0u8; 60]), None);
    }
}

#[cfg(test)]
mod pppoe_tests {
    use super::tests::{min_ipv4, pppoe};
    use super::*;

    /// A SPAN port mirroring a DSL/fibre uplink carries PPPoE and nothing else. Dropping it meant
    /// the sensor detected only traffic the capture host itself originated (issue #19297).
    #[test]
    fn ipv4_inside_pppoe_is_found() {
        let frame = pppoe(0x0021, &min_ipv4(), false);
        assert_eq!(ip_offset(DLT_EN10MB, &frame, 14), Some(22));
        assert_eq!(frame[22] >> 4, 4, "the offset must land on the IP version nibble");
    }

    #[test]
    fn ipv6_inside_pppoe_is_found() {
        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 58, 64];
        v6.extend_from_slice(&[0u8; 32]);
        let frame = pppoe(0x0057, &v6, false);
        assert_eq!(ip_offset(DLT_EN10MB, &frame, 14), Some(22));
        assert_eq!(frame[22] >> 4, 6);
    }

    #[test]
    fn a_vlan_tag_in_front_of_pppoe_is_skipped_too() {
        let frame = pppoe(0x0021, &min_ipv4(), true);
        assert_eq!(ip_offset(DLT_EN10MB, &frame, 14), Some(26));
        assert_eq!(frame[26] >> 4, 4);
    }

    #[test]
    fn non_ip_ppp_payloads_are_ignored() {
        // LCP (0xc021), CHAP (0xc223), IPCP (0x8021): control traffic, no IP header behind it.
        for proto in [0xc021u16, 0xc223, 0x8021] {
            let frame = pppoe(proto, &min_ipv4(), false);
            assert_eq!(ip_offset(DLT_EN10MB, &frame, 14), None, "PPP proto {proto:#06x}");
        }
    }

    #[test]
    fn pppoe_discovery_is_not_treated_as_data() {
        // 0x8863 is PADI/PADO/PADR/PADS - session setup, never IP.
        let mut frame = pppoe(0x0021, &min_ipv4(), false);
        frame[12] = 0x88;
        frame[13] = 0x63;
        assert_eq!(ip_offset(DLT_EN10MB, &frame, 14), None);
    }

    #[test]
    fn a_truncated_pppoe_header_does_not_panic() {
        let full = pppoe(0x0021, &min_ipv4(), false);
        for cut in 0..full.len() {
            let _ = ip_offset(DLT_EN10MB, &full[..cut], 14);
        }
    }

    fn v4() -> Vec<u8> {
        let mut v = vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 8, 8, 8, 8];
        v.extend_from_slice(&[0x9c, 0x40, 0, 53, 0, 8, 0, 0]);
        v
    }

    fn v6() -> Vec<u8> {
        let mut v = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v.extend_from_slice(&[0u8; 32]);
        v.extend_from_slice(&[0x9c, 0x40, 0, 53, 0, 8, 0, 0]);
        v
    }

    fn with(header: &[u8], ip: Vec<u8>) -> Vec<u8> {
        let mut v = header.to_vec();
        v.extend(ip);
        v
    }

    fn at(datalink: i32, packet: &[u8]) -> Option<usize> {
        DltLearner::default().resolve(datalink, packet)
    }

    #[test]
    fn null_and_loop_accept_every_ipv6_family_in_both_byte_orders() {
        // IPv4 is 2; IPv6 is 24 (Net/OpenBSD, current Npcap), 28 (FreeBSD), 30 (macOS), 23 (old Npcap)
        for family in [2u32, 23, 24, 28, 30] {
            let ip = if family == 2 { v4() } else { v6() };
            for header in [family.to_le_bytes(), family.to_be_bytes()] {
                assert_eq!(at(DLT_NULL, &with(&header, ip.clone())), Some(4), "NULL family {family}");
                assert_eq!(at(DLT_LOOP, &with(&header, ip.clone())), Some(4), "LOOP family {family}");
            }
        }
        // 35 is what the old check accepted; it is no address family at all
        assert_eq!(at(DLT_NULL, &with(&35u32.to_le_bytes(), v6())), None);
        assert_eq!(at(DLT_NULL, &with(&7u32.to_le_bytes(), v4())), None, "OSI is not IP");
    }

    #[test]
    fn enc_skips_its_spi_and_flags() {
        let mut header = 2u32.to_be_bytes().to_vec();
        header.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1]);
        assert_eq!(at(DLT_ENC, &with(&header, v4())), Some(12));
    }

    #[test]
    fn raw_ip_types_need_an_ip_version() {
        for dlt in [DLT_RAW, DLT_IPV4, DLT_IPV6] {
            assert_eq!(at(dlt, &v4()), Some(0));
            assert_eq!(at(dlt, &v6()), Some(0));
            assert_eq!(at(dlt, &[0x00, 0x01, 0x02]), None);
        }
    }

    #[test]
    fn pflog_reads_its_own_header_length() {
        for length in [61u8, 68, 69, 72] {
            let mut header = vec![0u8; ((length as usize) + 3) & !3];
            header[0] = length;
            let want = header.len();
            assert_eq!(at(DLT_PFLOG, &with(&header, v4())), Some(want), "pflog length {length}");
        }
        let mut short = vec![0u8; 44];
        short[0] = 44;
        assert_eq!(at(DLT_PFLOG, &with(&short, v4())), None, "shorter than any real pfloghdr");
    }

    #[test]
    fn nflog_finds_the_payload_tlv_in_either_byte_order() {
        for le in [true, false] {
            let tlv = |len: u16, ty: u16| -> Vec<u8> {
                let (l, t) =
                    if le { (len.to_le_bytes(), ty.to_le_bytes()) } else { (len.to_be_bytes(), ty.to_be_bytes()) };
                [l, t].concat()
            };
            let mut p = vec![2, 0, 0, 1];
            p.extend(tlv(8, 1));
            p.extend([0u8; 4]);
            // a 6-byte prefix TLV, padded to 8
            p.extend(tlv(6, 10));
            p.extend([b'x', b'\0', 0, 0]);
            let payload_at = p.len() + 4;
            p.extend(tlv(4 + v4().len() as u16, 9));
            p.extend(v4());
            assert_eq!(at(DLT_NFLOG, &p), Some(payload_at), "little-endian TLVs: {le}");
        }
        assert_eq!(at(DLT_NFLOG, &[7, 0, 0, 0]), None, "family must be IPv4 or IPv6");
    }

    #[test]
    fn sll2_cisco_hdlc_ppp_serial_ppp_ether_netanalyzer() {
        let mut sll2 = vec![0x86, 0xdd, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6];
        sll2.extend([0u8; 8]);
        assert_eq!(at(DLT_LINUX_SLL2, &with(&sll2, v6())), Some(20));
        assert_eq!(at(DLT_C_HDLC, &with(&[0x0f, 0x00, 0x08, 0x00], v4())), Some(4));
        assert_eq!(at(DLT_PPP_SERIAL, &with(&[0xff, 0x03, 0x00, 0x57], v6())), Some(4));
        assert_eq!(at(DLT_PPP_ETHER, &with(&[0x11, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x21], v4())), Some(8));
        let mut na = vec![0u8; 4];
        na.extend([0u8; 12]);
        na.extend([0x08, 0x00]);
        assert_eq!(at(DLT_NETANALYZER, &with(&na, v4())), Some(18));
    }

    #[test]
    fn pfsync_is_never_ip() {
        assert_eq!(at(DLT_PFSYNC_BSD, &with(&[0u8; 4], v4())), None);
    }

    /// An 802.11 data frame: frame control, then the rest of a `header`-byte MAC header, then
    /// LLC/SNAP for IPv4.
    fn wifi(fc0: u8, fc1: u8, header: usize) -> Vec<u8> {
        let mut v = vec![fc0, fc1];
        v.extend(vec![0u8; header - 2]);
        v.extend([0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]);
        v.extend(v4());
        v
    }

    #[test]
    fn ieee80211_header_length_follows_the_frame_control() {
        // data, data with 4 addresses, QoS data, QoS with HT control, QoS with 4 addresses
        for (fc0, fc1, header) in
            [(0x08, 0x01, 24), (0x08, 0x03, 30), (0x88, 0x01, 26), (0x88, 0x81, 30), (0x88, 0x03, 32)]
        {
            assert_eq!(at(DLT_IEEE802_11, &wifi(fc0, fc1, header)), Some(header + 8), "fc {fc0:#x} {fc1:#x}");
        }
        assert_eq!(at(DLT_IEEE802_11, &wifi(0x08, 0x41, 24)), None, "protected frames are encrypted");
        assert_eq!(at(DLT_IEEE802_11, &wifi(0x48, 0x01, 24)), None, "null data carries nothing");
        assert_eq!(at(DLT_IEEE802_11, &wifi(0x80, 0x00, 24)), None, "a beacon is not data");
    }

    #[test]
    fn radiotap_length_is_read_per_packet_and_never_locked() {
        let mut learner = DltLearner::default();
        for rt in [8usize, 8, 18, 36, 8, 18] {
            let mut p = vec![0, 0];
            p.extend((rt as u16).to_le_bytes());
            p.extend(vec![0u8; rt - 4]);
            p.extend(wifi(0x08, 0x01, 24));
            // the learner would have locked 40 after the first two and misread the 18-byte ones
            assert_eq!(learner.resolve(DLT_IEEE802_11_RADIO, &p), Some(rt + 32), "radiotap {rt}");
        }
    }

    #[test]
    fn ppi_and_prism_wrap_the_same_frame() {
        let mut ppi = vec![0, 0];
        ppi.extend(32u16.to_le_bytes());
        ppi.extend(105u32.to_le_bytes());
        ppi.extend([0u8; 24]);
        assert_eq!(at(DLT_PPI, &with(&ppi, wifi(0x08, 0x01, 24))), Some(32 + 32));
        let mut prism = vec![0u8; 4];
        prism.extend(144u32.to_le_bytes());
        prism.extend([0u8; 136]);
        assert_eq!(at(DLT_PRISM_HEADER, &with(&prism, wifi(0x08, 0x01, 24))), Some(144 + 32));
    }

    #[test]
    fn variable_and_new_link_types_never_panic_on_truncation() {
        let samples: Vec<(i32, Vec<u8>)> = vec![
            (DLT_NULL, with(&24u32.to_le_bytes(), v6())),
            (DLT_PFLOG, with(&[64u8; 64], v4())),
            (DLT_IEEE802_11_RADIO, [vec![0, 0, 8, 0, 0, 0, 0, 0], wifi(0x88, 0x83, 32)].concat()),
            (DLT_PPI, [vec![0, 0, 8, 0, 105, 0, 0, 0], wifi(0x08, 0x01, 24)].concat()),
            (DLT_NFLOG, vec![2, 0, 0, 0, 12, 0, 9, 0, 0x45, 0, 0, 0]),
        ];
        for (dlt, full) in samples {
            for cut in 0..full.len() {
                let _ = at(dlt, &full[..cut]);
            }
        }
    }
}
