//! Finding the inner packet inside an encapsulated one.
//!
//! A SPAN feed at a datacentre or corporate border is usually an overlay. The addresses in the
//! outer header are tunnel endpoints - the operator's own infrastructure - and every host that
//! actually matters is inside. Matching only the outer header means no inner IP, no port, no DNS
//! name, no HTTP host and no TLS SNI for any of them, which is not a coverage gap so much as
//! being deployed in the wrong place.
//!
//! What this does NOT do is replace the outer packet with the inner one. The outer header is
//! processed exactly as before and the inner is then processed as well, so nothing that used to
//! match stops matching - a tunnel endpoint that is itself a listed address still fires. The cost
//! is that a tunnelled packet is seen as two connections, which is what it is.
//!
//! Depth is capped. Tunnels nest in real deployments (GRE inside IPsec inside a VXLAN fabric is
//! ordinary), but a packet that claims to nest forever is a way to make the parser work
//! arbitrarily hard for one frame, so the walk stops and the rest is left unparsed.

use crate::packet::dlt;
use crate::packet::IpHeader;

/// IANA's VXLAN port.
const VXLAN_PORT: u16 = 4789;
/// Linux chose 8472 before IANA assigned 4789 and it is still the default in a lot of deployed
/// kit, so a sensor that only knows the standard port is blind on half the fabrics in the field.
const VXLAN_LINUX_PORT: u16 = 8472;
/// GENEVE (RFC 8926).
const GENEVE_PORT: u16 = 6081;

const IPPROTO_IPIP: u8 = 4;
const IPPROTO_IPV6: u8 = 41;
const IPPROTO_GRE: u8 = 47;
const IPPROTO_UDP: u8 = 17;

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
/// Transparent Ethernet Bridging - the payload is a whole Ethernet frame.
const ETH_P_TEB: u16 = 0x6558;
/// ERSPAN type II and type III, as carried over GRE by switch SPAN sessions.
const ETH_P_ERSPAN2: u16 = 0x88be;
const ETH_P_ERSPAN3: u16 = 0x22eb;

/// How many encapsulations to unwrap for one packet.
pub const MAX_TUNNEL_DEPTH: usize = 3;

/// Could a packet with this protocol be carrying another one? Cheap enough to run per packet.
#[inline]
pub fn may_encapsulate(protocol: u8) -> bool {
    matches!(protocol, IPPROTO_IPIP | IPPROTO_IPV6 | IPPROTO_GRE | IPPROTO_UDP)
}

/// Offset of the IP header *inside* the packet at `ip_offset`, or `None` if it is not a tunnel.
///
/// `header` is the already-parsed outer header, so this never re-parses what the caller has.
pub fn inner_ip_offset(packet: &[u8], ip_offset: usize, header: &IpHeader) -> Option<usize> {
    let payload = ip_offset.checked_add(header.header_len)?;

    match header.protocol {
        // IP-in-IP and 6-in-4: the inner header starts immediately.
        IPPROTO_IPIP | IPPROTO_IPV6 => at_ip_header(packet, payload),
        IPPROTO_GRE => gre_inner(packet, payload),
        IPPROTO_UDP => {
            // sport, dport, length, checksum
            let dport = u16::from_be_bytes([*packet.get(payload + 2)?, *packet.get(payload + 3)?]);
            let body = payload.checked_add(8)?;
            match dport {
                VXLAN_PORT | VXLAN_LINUX_PORT => {
                    // 8-byte header, then a complete Ethernet frame
                    at_ethernet(packet, body.checked_add(8)?)
                }
                GENEVE_PORT => geneve_inner(packet, body),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Confirm there really is an IP header at `off` before claiming a tunnel.
///
/// Without this an ordinary UDP packet to 4789 that is NOT VXLAN - a scan of the port, say -
/// would have 16 arbitrary bytes read as addresses and reported as a detection on whatever they
/// happened to spell.
fn at_ip_header(packet: &[u8], off: usize) -> Option<usize> {
    match packet.get(off)? >> 4 {
        4 | 6 => Some(off),
        _ => None,
    }
}

/// An inner Ethernet frame at `off`; `dlt::ip_offset` walks its VLAN tags and PPPoE for us.
fn at_ethernet(packet: &[u8], off: usize) -> Option<usize> {
    let ip = dlt::ip_offset(dlt::DLT_EN10MB, packet, off.checked_add(14)?)?;
    at_ip_header(packet, ip)
}

/// GRE (RFC 2784 + 2890). The optional checksum/key/sequence words make the header variable, and
/// mismeasuring it lands the parse in the middle of the payload.
fn gre_inner(packet: &[u8], off: usize) -> Option<usize> {
    let flags = u16::from_be_bytes([*packet.get(off)?, *packet.get(off + 1)?]);
    let proto = u16::from_be_bytes([*packet.get(off + 2)?, *packet.get(off + 3)?]);

    // Version 1 is PPTP, whose payload is PPP rather than an IP packet; leave it alone.
    if flags & 0x0007 != 0 {
        return None;
    }

    let mut len = 4usize;
    if flags & 0x8000 != 0 {
        len += 4; // checksum + reserved1
    }
    if flags & 0x2000 != 0 {
        len += 4; // key
    }
    if flags & 0x1000 != 0 {
        len += 4; // sequence
    }
    let body = off.checked_add(len)?;

    match proto {
        ETH_P_IPV4 | ETH_P_IPV6 => at_ip_header(packet, body),
        ETH_P_TEB => at_ethernet(packet, body),
        // ERSPAN puts its own fixed header between GRE and the mirrored frame.
        ETH_P_ERSPAN2 => at_ethernet(packet, body.checked_add(8)?),
        ETH_P_ERSPAN3 => at_ethernet(packet, body.checked_add(12)?),
        _ => None,
    }
}

/// GENEVE: an 8-byte base header, then `opt_len` 4-byte words of options, then the payload named
/// by the protocol type. The option length is attacker-influenced, so it is added with a checked
/// add and the result still has to look like a header.
fn geneve_inner(packet: &[u8], off: usize) -> Option<usize> {
    let ver_optlen = *packet.get(off)?;
    if ver_optlen >> 6 != 0 {
        return None; // version != 0
    }
    let opt_bytes = usize::from(ver_optlen & 0x3f) * 4;
    let proto = u16::from_be_bytes([*packet.get(off + 2)?, *packet.get(off + 3)?]);
    let body = off.checked_add(8)?.checked_add(opt_bytes)?;

    match proto {
        ETH_P_IPV4 | ETH_P_IPV6 => at_ip_header(packet, body),
        ETH_P_TEB => at_ethernet(packet, body),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::parse_ip;
    use crate::testkit::{erspan, eth, geneve, gre, ipv4, tcp, udp, vxlan};

    /// Parse the outer header the way `process_packet` does, then ask where the inner one starts.
    fn inner(packet: &[u8]) -> Option<usize> {
        let header = parse_ip(packet).ok()?;
        inner_ip_offset(packet, 0, &header)
    }

    /// The inner header must be found at an offset that really parses as one.
    fn inner_src(packet: &[u8]) -> Option<String> {
        let off = inner(packet)?;
        let h = parse_ip(packet.get(off..)?).ok()?;
        Some(h.src.render().as_str().to_string())
    }

    fn payload() -> Vec<u8> {
        ipv4(6, "10.1.1.5", "10.2.2.2", &tcp(1234, 80, 0x02, b""))
    }

    #[test]
    fn vxlan_on_both_ports_is_unwrapped() {
        let frame = eth(&payload(), 0x0800, None);
        assert_eq!(inner_src(&vxlan("192.0.2.1", "192.0.2.2", 42, &frame)).as_deref(), Some("10.1.1.5"));

        // Linux's pre-IANA 8472 carries just as much real traffic as 4789.
        let mut p = vxlan("192.0.2.1", "192.0.2.2", 42, &frame);
        let udp_off = 20;
        p[udp_off + 2..udp_off + 4].copy_from_slice(&8472u16.to_be_bytes());
        assert_eq!(inner_src(&p).as_deref(), Some("10.1.1.5"), "port 8472 must be unwrapped too");
    }

    #[test]
    fn a_vlan_tag_inside_the_tunnel_is_followed() {
        // an overlay carrying tagged frames is ordinary; dlt::ip_offset does the walking
        let frame = eth(&payload(), 0x0800, Some(100));
        assert_eq!(inner_src(&vxlan("192.0.2.1", "192.0.2.2", 1, &frame)).as_deref(), Some("10.1.1.5"));
    }

    #[test]
    fn geneve_options_shift_the_payload() {
        let frame = eth(&payload(), 0x0800, None);
        for opt_bytes in [0usize, 4, 8, 32] {
            let p = geneve("192.0.2.1", "192.0.2.2", ETH_P_TEB, opt_bytes, &frame);
            assert_eq!(inner_src(&p).as_deref(), Some("10.1.1.5"), "opt_len {opt_bytes} mis-measured");
        }
        // and the bare-IP variant, which has no Ethernet header at all
        let p = geneve("192.0.2.1", "192.0.2.2", ETH_P_IPV4, 8, &payload());
        assert_eq!(inner_src(&p).as_deref(), Some("10.1.1.5"));
    }

    /// The variable-length GRE header is the whole difficulty of GRE.
    #[test]
    fn every_gre_flag_combination_lands_on_the_inner_header() {
        for (csum, key, seq) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, true, true),
        ] {
            let p = gre("192.0.2.1", "192.0.2.2", ETH_P_IPV4, csum, key, seq, &payload());
            assert_eq!(
                inner_src(&p).as_deref(),
                Some("10.1.1.5"),
                "GRE csum={csum} key={key} seq={seq}: header length mismeasured"
            );
        }
    }

    #[test]
    fn gre_transparent_ethernet_and_erspan_are_unwrapped() {
        let frame = eth(&payload(), 0x0800, None);
        let p = gre("192.0.2.1", "192.0.2.2", ETH_P_TEB, false, false, false, &frame);
        assert_eq!(inner_src(&p).as_deref(), Some("10.1.1.5"), "transparent Ethernet bridging");

        assert_eq!(
            inner_src(&erspan("192.0.2.1", "192.0.2.2", false, &frame)).as_deref(),
            Some("10.1.1.5"),
            "ERSPAN II"
        );
        assert_eq!(
            inner_src(&erspan("192.0.2.1", "192.0.2.2", true, &frame)).as_deref(),
            Some("10.1.1.5"),
            "ERSPAN III"
        );
    }

    #[test]
    fn gre_version_1_is_left_alone() {
        // PPTP carries PPP, not IP; reading it as a tunnel walks into the middle of a payload
        let mut p = gre("192.0.2.1", "192.0.2.2", ETH_P_IPV4, false, false, false, &payload());
        p[20] |= 0x00;
        p[21] |= 0x01; // version = 1
        assert_eq!(inner(&p), None);
    }

    #[test]
    fn ip_in_ip_is_unwrapped() {
        assert_eq!(inner_src(&ipv4(4, "192.0.2.1", "192.0.2.2", &payload())).as_deref(), Some("10.1.1.5"));
    }

    /// The check that stops this becoming a source of invented detections.
    #[test]
    fn ordinary_traffic_is_never_mistaken_for_a_tunnel() {
        // A scan of the VXLAN port is a real thing, and its payload is not a VXLAN header. Without
        // the "does this look like an IP header" check, 16 arbitrary bytes would be read as source
        // and destination addresses and reported as a detection on whatever they spelled.
        let junk = vec![0xa5u8; 64];
        assert_eq!(inner(&ipv4(17, "198.51.100.1", "198.51.100.2", &udp(1234, 4789, &junk))), None);
        assert_eq!(inner(&ipv4(17, "198.51.100.1", "198.51.100.2", &udp(1234, 6081, &junk))), None);

        // ordinary TCP and UDP are not tunnels
        assert_eq!(inner(&ipv4(6, "1.2.3.4", "5.6.7.8", &tcp(1, 2, 0x02, b"hello"))), None);
        assert_eq!(inner(&ipv4(17, "1.2.3.4", "5.6.7.8", &udp(1, 53, b"hello"))), None);
        assert!(!may_encapsulate(6), "TCP must not even be considered");
    }

    #[test]
    fn truncated_and_hostile_encapsulations_return_none_not_a_panic() {
        // every prefix of a well-formed tunnel: none may panic
        let full = vxlan("192.0.2.1", "192.0.2.2", 1, &eth(&payload(), 0x0800, None));
        for n in 0..full.len() {
            let _ = inner(&full[..n]);
        }
        let full = gre("192.0.2.1", "192.0.2.2", ETH_P_TEB, true, true, true, &eth(&payload(), 0x0800, None));
        for n in 0..full.len() {
            let _ = inner(&full[..n]);
        }

        // a GENEVE option length claiming far more than the packet holds
        let mut p = geneve("192.0.2.1", "192.0.2.2", ETH_P_IPV4, 0, &payload());
        p[28] = 0x3f; // opt_len = 63 words = 252 bytes
        assert_eq!(inner(&p), None);

        // GRE claiming every optional word on a header that has none of them
        let mut p = ipv4(47, "192.0.2.1", "192.0.2.2", &[0xb0, 0x00, 0x08, 0x00]);
        assert_eq!(inner(&p), None);
        p.truncate(21);
        assert_eq!(inner(&p), None);
    }
}
