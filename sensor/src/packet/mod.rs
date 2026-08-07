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
        6 => {
            if ip_data.len() < 40 {
                return Err(Drop::Truncated);
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&ip_data[8..24]);
            dst.copy_from_slice(&ip_data[24..40]);
            // NOTE: extension headers are deliberately NOT traversed; sensor.py takes the
            // Next Header field as the protocol, so an IPv6 packet with a Hop-by-Hop or
            // Fragment header falls into the generic IPPROTO_LUT branch there too.
            Ok(IpHeader {
                version: 6,
                header_len: 40,
                protocol: ip_data[6],
                src: Ip::V6(u128::from_be_bytes(src)),
                dst: Ip::V6(u128::from_be_bytes(dst)),
            })
        }
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
        // IHL=6 -> 24-byte header (tests/test_sensor.py:test_ipv4_with_options_header_length)
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
