//! Link-layer handling — `sensor.py:packet_handler()` plus the offset learner from
//! `sensor.py:_guess_dlt_ip_offset()` / `core/fastfilter.py:guess_ip_offset()`.

use std::collections::HashMap;

use crate::settings;

/// Linux DLT values used by the explicit branches in `packet_handler`.
pub const DLT_NULL: i32 = 0;
pub const DLT_EN10MB: i32 = 1;
pub const DLT_PPP: i32 = 9;
pub const DLT_RAW: i32 = 12;
pub const DLT_LINUX_SLL: i32 = 113;

/// Resolve where the IP header starts, for a datalink present in `DLT_OFFSETS`.
/// Returns `None` when the frame is not IP (or is too short), which drops the packet
/// exactly as the Python handler does.
pub fn ip_offset(datalink: i32, packet: &[u8], base: usize) -> Option<usize> {
    if datalink == DLT_RAW {
        return Some(base);
    }
    if datalink == DLT_PPP {
        // (IPv4, IPv6) PPP protocol fields
        let field = packet.get(2..4)?;
        return if field == [0x00, 0x21] || field == [0x00, 0x57] { Some(base) } else { None };
    }
    if datalink == DLT_NULL {
        let field = packet.get(0..4)?;
        return if field == [0x02, 0x00, 0x00, 0x00] || field == [0x23, 0x00, 0x00, 0x00] { Some(base) } else { None };
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
}
