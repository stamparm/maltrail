//! Bounds-checked packet header parsing.
//!
//! Every parser here takes a borrowed slice and returns `Option`, so a truncated or
//! hostile packet yields `None` instead of panicking. This mirrors `sensor.py`, where a
//! short header raises `struct.error` and the packet is silently dropped.

pub mod dlt;

use crate::addr::Ip;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpHeader {
    pub version: u8,
    /// `iph_length` in `sensor.py` — offset of the transport header inside `ip_data`.
    pub header_len: usize,
    pub protocol: u8,
    pub src: Ip,
    pub dst: Ip,
}

/// Why a packet was not processed (used only for metrics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drop {
    /// Not IPv4/IPv6 (e.g. a misaligned offset from the DLT heuristic).
    NotIp,
    /// A non-first IPv4 fragment: it carries no transport header.
    Fragment,
    /// Header truncated (Python: `struct.error`).
    Truncated,
}

/// IPv6 extension headers that carry a Next Header field and can be stepped over.
///
/// ESP (50) is deliberately not here: everything after it is encrypted, so there is no transport
/// header to find and the packet is reported as protocol 50. 59 ("no next header") ends a chain by
/// definition and terminates the walk the same way any transport protocol does.
const IPV6_EXT_HOPOPT: u8 = 0;
const IPV6_EXT_ROUTING: u8 = 43;
const IPV6_EXT_FRAGMENT: u8 = 44;
const IPV6_EXT_AH: u8 = 51;
const IPV6_EXT_DSTOPTS: u8 = 60;
const IPV6_EXT_MOBILITY: u8 = 135;
const IPV6_EXT_HIP: u8 = 139;
const IPV6_EXT_SHIM6: u8 = 140;

/// Real traffic carries none or one of these; two is already unusual. The cap exists so that a
/// crafted chain cannot make the parser walk forever - the same reasoning as `MAX_VLAN_TAGS`.
/// Exceeding it is not an error: the walk stops and the packet is reported with the extension
/// header as its protocol, which is exactly what this path did before the chain was walked at
/// all, so the addresses still reach the trail lookup.
const MAX_IPV6_EXT_HEADERS: usize = 8;

/// The IPv6 half of `parse_ip`.
///
/// Split out and `#[inline(never)]` so that `parse_ip` stays the size it was: with the extension
/// walk written inline the function grew past what the inliner would take at its call site, and
/// every IPv4 packet paid for a branch it never executes - udp burst suppression +51%, clean TCP
/// pass-through +29%, bulk TLS +20%. IPv6 pays one call, which is nothing beside the parse.
#[inline(never)]
fn parse_ipv6(ip_data: &[u8]) -> Result<IpHeader, Drop> {
    if ip_data.len() < 40 {
        return Err(Drop::Truncated);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&ip_data[8..24]);
    dst.copy_from_slice(&ip_data[24..40]);
    // Walk the extension-header chain to find the real transport header.
    //
    // This used to take Next Header as the protocol and stop, for parity with sensor.py.
    // That sensor is retired, and the behaviour was an evasion primitive: a packet with a
    // Hop-by-Hop header reports protocol 0, so the transport header is never located and
    // no port, DNS name, HTTP host or TLS SNI is read from it. Eight bytes hid a packet
    // from every payload-derived trail.
    //
    // The walk is reached only when Next Header actually names an extension header, so a plain
    // IPv6 packet pays one comparison chain for it.
    let next = ip_data[6];
    let (protocol, header_len) =
        if is_ipv6_ext_header(next) { walk_ipv6_ext_headers(ip_data, next)? } else { (next, 40) };

    Ok(IpHeader {
        version: 6,
        header_len,
        protocol,
        src: Ip::V6(u128::from_be_bytes(src)),
        dst: Ip::V6(u128::from_be_bytes(dst)),
    })
}

/// Does `next_header` name something the walk can step over?
///
/// Kept tiny and inline so the IPv6 fast path - no extension headers, which is nearly all of it -
/// is one comparison chain and never calls the walker at all.
#[inline]
fn is_ipv6_ext_header(next_header: u8) -> bool {
    matches!(
        next_header,
        IPV6_EXT_HOPOPT
            | IPV6_EXT_ROUTING
            | IPV6_EXT_FRAGMENT
            | IPV6_EXT_AH
            | IPV6_EXT_DSTOPTS
            | IPV6_EXT_MOBILITY
            | IPV6_EXT_HIP
            | IPV6_EXT_SHIM6
    )
}

/// Step over the extension-header chain, returning (transport protocol, transport header offset).
///
/// `#[inline(never)]`: this is cold - real traffic carries no extension headers - and letting it
/// inline into `parse_ip` pushed that function past the threshold for being inlined into the
/// packet path, which cost every IPv4 packet 15-54% on the small-packet benchmarks.
#[inline(never)]
fn walk_ipv6_ext_headers(ip_data: &[u8], first: u8) -> Result<(u8, usize), Drop> {
    let mut protocol = first;
    let mut offset = 40usize;

    for _ in 0..MAX_IPV6_EXT_HEADERS {
        let ext_len = match protocol {
            IPV6_EXT_FRAGMENT => {
                if offset + 4 > ip_data.len() {
                    return Err(Drop::Truncated);
                }
                // A non-first fragment has no transport header behind it. Stop the walk rather
                // than reporting Drop::Fragment as IPv4 does: the addresses are still worth
                // matching against IP trails, and reporting them is what this path already did.
                // Only the first fragment gains payload inspection.
                if u16::from_be_bytes([ip_data[offset + 2], ip_data[offset + 3]]) >> 3 != 0 {
                    break;
                }
                8
            }
            IPV6_EXT_HOPOPT | IPV6_EXT_ROUTING | IPV6_EXT_DSTOPTS | IPV6_EXT_MOBILITY | IPV6_EXT_HIP
            | IPV6_EXT_SHIM6 => {
                if offset + 2 > ip_data.len() {
                    return Err(Drop::Truncated);
                }
                // Hdr Ext Len counts 8-octet units NOT including the first 8.
                (ip_data[offset + 1] as usize + 1) * 8
            }
            IPV6_EXT_AH => {
                if offset + 2 > ip_data.len() {
                    return Err(Drop::Truncated);
                }
                // RFC 4302: 4-octet units, minus 2. The one header here that is not measured in
                // eights, and getting it wrong desynchronises the whole chain.
                (ip_data[offset + 1] as usize + 2) * 4
            }
            _ => break,
        };

        if offset + ext_len > ip_data.len() {
            return Err(Drop::Truncated);
        }
        protocol = ip_data[offset];
        offset += ext_len;
    }

    Ok((protocol, offset))
}

/// Parse the IP header at the start of `ip_data` (`sensor.py:_process_packet`).
pub fn parse_ip(ip_data: &[u8]) -> Result<IpHeader, Drop> {
    let first = *ip_data.first().ok_or(Drop::NotIp)?;
    match first >> 4 {
        4 => {
            if ip_data.len() < 20 {
                return Err(Drop::Truncated);
            }
            // fragment_offset = ip_header[4] & 0x1fff; a non-zero value means this is not
            // the first fragment, so the transport header is absent.
            let frag = u16::from_be_bytes([ip_data[6], ip_data[7]]) & 0x1fff;
            if frag != 0 {
                return Err(Drop::Fragment);
            }
            Ok(IpHeader {
                version: 4,
                header_len: ((first & 0x0f) as usize) << 2,
                protocol: ip_data[9],
                src: Ip::V4(u32::from_be_bytes([ip_data[12], ip_data[13], ip_data[14], ip_data[15]])),
                dst: Ip::V4(u32::from_be_bytes([ip_data[16], ip_data[17], ip_data[18], ip_data[19]])),
            })
        }
        6 => parse_ipv6(ip_data),
        _ => Err(Drop::NotIp),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    /// Data offset in 32-bit words (`doff_reserved >> 4`).
    pub data_offset: u8,
}

/// `struct.unpack("!HHLLBB", ip_data[iph_length:iph_length + 14])`
pub fn parse_tcp(ip_data: &[u8], header_len: usize) -> Option<TcpHeader> {
    let h = ip_data.get(header_len..header_len + 14)?;
    Some(TcpHeader {
        src_port: u16::from_be_bytes([h[0], h[1]]),
        dst_port: u16::from_be_bytes([h[2], h[3]]),
        data_offset: h[12] >> 4,
        flags: h[13],
    })
}

impl TcpHeader {
    /// `h_size = iph_length + (tcph_length << 2)`; the payload is whatever follows, which
    /// may legitimately be empty.
    pub fn payload<'a>(&self, ip_data: &'a [u8], header_len: usize) -> &'a [u8] {
        let h_size = header_len.saturating_add((self.data_offset as usize) << 2);
        ip_data.get(h_size..).unwrap_or(&[])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

/// `_ = ip_data[iph_length:iph_length + 4]; if len(_) < 4: return`
pub fn parse_udp(ip_data: &[u8], header_len: usize) -> Option<UdpHeader> {
    let h = ip_data.get(header_len..header_len + 4)?;
    Some(UdpHeader { src_port: u16::from_be_bytes([h[0], h[1]]), dst_port: u16::from_be_bytes([h[2], h[3]]) })
}

/// UDP payload (`ip_data[iph_length + 8:]`).
pub fn udp_payload(ip_data: &[u8], header_len: usize) -> &[u8] {
    ip_data.get(header_len.saturating_add(8)..).unwrap_or(&[])
}

/// First byte of an ICMP/ICMPv6 header (the type field).
pub fn icmp_type(ip_data: &[u8], header_len: usize) -> Option<u8> {
    ip_data.get(header_len).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{addr_to_int, parse_ipv6};

    fn ipv4(proto: u8, src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x45, 0];
        let total = (20 + payload.len()) as u16;
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0x12, 0x34, 0, 0, 64, proto, 0, 0]);
        v.extend_from_slice(&addr_to_int(src).unwrap().to_be_bytes());
        v.extend_from_slice(&addr_to_int(dst).unwrap().to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn ipv4_basics() {
        let p = ipv4(6, "10.0.0.5", "66.66.66.66", &[0u8; 20]);
        let h = parse_ip(&p).unwrap();
        assert_eq!(h.version, 4);
        assert_eq!(h.header_len, 20);
        assert_eq!(h.protocol, 6);
        assert_eq!(h.src, Ip::V4(addr_to_int("10.0.0.5").unwrap()));
        assert_eq!(h.dst, Ip::V4(addr_to_int("66.66.66.66").unwrap()));
    }

    #[test]
    fn ipv4_options_change_header_length() {
        // IHL=6 -> 24-byte header (the retired Python suite's test_ipv4_with_options_header_length)
        let mut p = ipv4(6, "10.0.0.5", "66.66.66.66", &[0u8; 24]);
        p[0] = 0x46;
        let h = parse_ip(&p).unwrap();
        assert_eq!(h.header_len, 24);
    }

    #[test]
    fn non_first_fragment_is_skipped() {
        let mut p = ipv4(6, "10.0.0.5", "66.66.66.66", &[0u8; 20]);
        p[6] = 0x00;
        p[7] = 0x01;
        assert_eq!(parse_ip(&p), Err(Drop::Fragment));
        // the DF/MF flag bits alone must not be mistaken for an offset
        p[6] = 0x40;
        p[7] = 0x00;
        assert!(parse_ip(&p).is_ok());
    }

    #[test]
    fn ipv6_basics() {
        let mut p = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        p.extend_from_slice(&parse_ipv6("dead::1").unwrap().to_be_bytes());
        p.extend_from_slice(&parse_ipv6("dead::beef").unwrap().to_be_bytes());
        p.extend_from_slice(&[0u8; 20]);
        let h = parse_ip(&p).unwrap();
        assert_eq!(h.version, 6);
        assert_eq!(h.header_len, 40);
        assert_eq!(h.protocol, 6);
        assert_eq!(h.dst, Ip::V6(parse_ipv6("dead::beef").unwrap()));
    }

    /// IPv6 header with `exts` = (type, total bytes) chain, then `proto`.
    fn v6_chain(proto: u8, exts: &[(u8, usize)], tail: usize) -> Vec<u8> {
        let mut chain: Vec<u8> = Vec::new();
        for (i, &(kind, total)) in exts.iter().enumerate() {
            let next = exts.get(i + 1).map(|&(k, _)| k).unwrap_or(proto);
            chain.push(next);
            chain.push(if kind == IPV6_EXT_AH { (total / 4 - 2) as u8 } else { (total / 8 - 1) as u8 });
            chain.resize(chain.len() + total - 2, 0);
        }
        let first = exts.first().map(|&(k, _)| k).unwrap_or(proto);
        let mut p = vec![0x60, 0, 0, 0, 0, 0, first, 64];
        p.extend_from_slice(&[0u8; 32]);
        p.extend_from_slice(&chain);
        p.extend_from_slice(&vec![0u8; tail]);
        p
    }

    #[test]
    fn ipv6_extension_chain_is_walked_to_the_transport_header() {
        // one Hop-by-Hop: protocol must be UDP, not 0, and the transport header must be located
        let h = parse_ip(&v6_chain(17, &[(IPV6_EXT_HOPOPT, 8)], 8)).unwrap();
        assert_eq!(h.protocol, 17, "Next Header alone is not the protocol when a chain follows");
        assert_eq!(h.header_len, 48);

        // a chain of the 8-octet kinds
        let h =
            parse_ip(&v6_chain(6, &[(IPV6_EXT_HOPOPT, 8), (IPV6_EXT_DSTOPTS, 16), (IPV6_EXT_ROUTING, 8)], 20)).unwrap();
        assert_eq!(h.protocol, 6);
        assert_eq!(h.header_len, 40 + 8 + 16 + 8);

        // AH measures in 4-octet units minus 2, so a 12-byte AH must advance 12 and not 8 or 32
        let h = parse_ip(&v6_chain(17, &[(IPV6_EXT_AH, 12)], 8)).unwrap();
        assert_eq!(h.protocol, 17);
        assert_eq!(h.header_len, 52, "AH length is in 4-octet units; eights desynchronise the chain");
    }

    #[test]
    fn ipv6_esp_terminates_the_walk() {
        // everything past ESP is encrypted - there is no transport header to look for
        let h = parse_ip(&v6_chain(50, &[], 16)).unwrap();
        assert_eq!(h.protocol, 50);
        assert_eq!(h.header_len, 40);
    }

    #[test]
    fn ipv6_first_fragment_is_walked_and_a_later_one_still_matches() {
        let mut p = v6_chain(17, &[], 8);
        p[6] = IPV6_EXT_FRAGMENT;
        let mut frag = [17u8, 0, 0, 0, 0, 0, 0, 1];
        // offset 0 -> the transport header IS behind it, so keep walking
        let mut first = p.clone();
        first.splice(40..40, frag.iter().copied());
        let h = parse_ip(&first).unwrap();
        assert_eq!(h.protocol, 17);
        assert_eq!(h.header_len, 48);

        // a non-first fragment has no transport header, but its addresses still reach the trail
        // lookup - reporting Drop::Fragment here would LOSE an IP match this path always made
        frag[2] = 0x01; // fragment offset != 0
        let mut later = p.clone();
        later.splice(40..40, frag.iter().copied());
        let h = parse_ip(&later).unwrap();
        assert_eq!(h.protocol, IPV6_EXT_FRAGMENT);
        assert_eq!(h.dst, Ip::V6(0));
    }

    #[test]
    fn a_crafted_ipv6_chain_cannot_run_the_parser_away() {
        // more headers than the cap: the walk stops and the packet is still reported, exactly as
        // it was before the chain was walked at all, so nothing that used to match stops matching
        let exts: Vec<(u8, usize)> = (0..MAX_IPV6_EXT_HEADERS + 4).map(|_| (IPV6_EXT_DSTOPTS, 8)).collect();
        let h = parse_ip(&v6_chain(17, &exts, 8)).unwrap();
        assert_eq!(h.protocol, IPV6_EXT_DSTOPTS, "the walk stopped at the cap");
        assert!(h.header_len <= 40 + 8 * MAX_IPV6_EXT_HEADERS);
    }

    #[test]
    fn a_chain_that_runs_off_the_end_is_truncated_not_a_panic() {
        let mut p = v6_chain(17, &[(IPV6_EXT_DSTOPTS, 8)], 8);
        p[41] = 200; // claim a 1608-byte header inside a short packet
        assert_eq!(parse_ip(&p), Err(Drop::Truncated));

        let mut p = v6_chain(17, &[(IPV6_EXT_AH, 12)], 8);
        p[41] = 200;
        assert_eq!(parse_ip(&p), Err(Drop::Truncated));

        // a fragment header whose own 4 bytes are not there
        let mut p = vec![0x60, 0, 0, 0, 0, 0, IPV6_EXT_FRAGMENT, 64];
        p.extend_from_slice(&[0u8; 32]);
        p.extend_from_slice(&[17, 0]);
        assert_eq!(parse_ip(&p), Err(Drop::Truncated));
    }

    #[test]
    fn non_ip_and_truncated() {
        assert_eq!(parse_ip(&[0u8; 64]), Err(Drop::NotIp));
        assert_eq!(parse_ip(&[0x30u8; 64]), Err(Drop::NotIp));
        assert_eq!(parse_ip(&[]), Err(Drop::NotIp));
        assert_eq!(parse_ip(&[0x45u8; 19]), Err(Drop::Truncated));
        assert_eq!(parse_ip(&[0x60u8; 39]), Err(Drop::Truncated));
    }

    #[test]
    fn tcp_and_udp_parsing() {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        let p = ipv4(6, "10.0.0.5", "1.2.3.4", &tcp);
        let ipd = &p[..];
        let h = parse_ip(ipd).unwrap();
        let t = parse_tcp(ipd, h.header_len).unwrap();
        assert_eq!((t.src_port, t.dst_port, t.flags, t.data_offset), (50000, 443, 0x02, 5));
        assert!(t.payload(ipd, h.header_len).is_empty());

        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        let mut body = udp.clone();
        body.extend_from_slice(b"payload");
        let p = ipv4(17, "10.0.0.5", "8.8.8.8", &body);
        let h = parse_ip(&p).unwrap();
        let u = parse_udp(&p, h.header_len).unwrap();
        assert_eq!((u.src_port, u.dst_port), (40000, 53));
        assert_eq!(udp_payload(&p, h.header_len), b"payload");
    }

    #[test]
    fn truncated_transport_headers_return_none() {
        let p = ipv4(6, "10.0.0.5", "1.2.3.4", &[0u8; 8]);
        assert!(parse_tcp(&p, 20).is_none());
        let p = ipv4(17, "10.0.0.5", "1.2.3.4", &[0u8; 2]);
        assert!(parse_udp(&p, 20).is_none());
        assert!(udp_payload(&p, 20).is_empty());
        assert!(icmp_type(&p, 99).is_none());
    }

    #[test]
    fn oversized_header_len_is_safe() {
        let p = ipv4(6, "10.0.0.5", "1.2.3.4", &[0u8; 20]);
        let t = TcpHeader { src_port: 1, dst_port: 2, flags: 0, data_offset: 15 };
        assert!(t.payload(&p, usize::MAX - 8).is_empty());
        assert!(t.payload(&p, 1000).is_empty());
    }
}
