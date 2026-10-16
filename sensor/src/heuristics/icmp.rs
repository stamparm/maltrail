//! ICMP tunneling (icmpsh, ptunnel, ICMP exfiltration) — a NEW heuristic, with no `sensor.py`
//! counterpart.
//!
//! Real ping tools put a fixed, recognisable payload in every echo request: Windows a cycle of
//! `abcdefghijklmnopqrstuvw`, iputils / BSD / macOS a timestamp followed by bytes counting up from
//! their own offset, monitoring tools a run of one byte (usually zeros) or a constant string. A
//! tunnel puts DATA there, so its requests carry a different payload every time. The detector
//! therefore counts, per (source, destination), the DISTINCT payloads that match no known pattern,
//! and reports once that count crosses [`ICMP_TUNNEL_THRESHOLD`] within the scan window. A
//! constant custom payload (Prometheus' blackbox exporter, a vendor probe) is one distinct value
//! however often it repeats, so it never gets there.
//!
//! Many tools lead with a timestamp and follow it with a fill of their own (`ping -p ff`,
//! busybox), so the timestamp alone would make every request "distinct". Distinctness is
//! therefore judged on [`distinct_part`], the payload past its first [`TIMESTAMP_LEN`] bytes, and a
//! payload no longer than that is never counted: it has no room for anything but a timestamp.
//!
//! Only echo requests are seen (the caller filters), so icmpsh is caught on the victim's
//! requests, which carry its command output; ptunnel on the client's.

/// Distinct non-standard payloads one (source, destination) must EXCEED within the window.
pub const ICMP_TUNNEL_THRESHOLD: usize = 10;

/// The longest timestamp a ping tool leads with (a 64-bit `struct timeval`).
pub const TIMESTAMP_LEN: usize = 16;

/// What two requests from one tool must differ in to count as distinct payloads.
pub fn distinct_part(data: &[u8]) -> &[u8] {
    data.get(TIMESTAMP_LEN..).unwrap_or(&[])
}

/// `data` is the echo payload, after the 8-byte ICMP header.
pub fn is_standard_echo_payload(data: &[u8]) -> bool {
    if data.len() <= TIMESTAMP_LEN {
        return true;
    }
    let first = data[0];
    // zeros (fping, nmap, Windows tracert) or any other single repeated byte
    if data.iter().all(|&b| b == first) {
        return true;
    }
    // Windows ping: a, b, ... w, a, b, ...
    if data.iter().enumerate().all(|(i, &b)| b == b'a' + (i % 23) as u8) {
        return true;
    }
    // iputils, BSD and macOS ping: a struct timeval (8 or 16 bytes), then byte i == i.
    [8usize, 16].iter().any(|&skip| data.len() > skip && data[skip..].iter().zip(skip..).all(|(&b, i)| b == i as u8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_ping_payloads_are_standard() {
        assert!(is_standard_echo_payload(b""));
        // room for a timestamp and nothing else
        assert!(is_standard_echo_payload(&[0xd5, 0x20, 0x08, 0x80, 0x01, 0x02, 0x03, 0x04]));
        assert!(is_standard_echo_payload(&[0u8; 56]));
        assert!(is_standard_echo_payload(b"abcdefghijklmnopqrstuvwabcdefghi"));
        // iputils on x86-64: 16-byte timeval, then 0x10 0x11 ... 0x37 (56 bytes in all)
        let mut linux: Vec<u8> = vec![0x5f, 0x2a, 0x7c, 0x66, 0, 0, 0, 0, 0x41, 0x9e, 0x0c, 0, 0, 0, 0, 0];
        linux.extend(16u8..56);
        assert!(is_standard_echo_payload(&linux));
        // macOS / FreeBSD: 8-byte timestamp, then 0x08 ... 0x37
        let mut bsd: Vec<u8> = vec![0x66, 0x7c, 0x2a, 0x5f, 0x00, 0x0c, 0x9e, 0x41];
        bsd.extend(8u8..56);
        assert!(is_standard_echo_payload(&bsd));
    }

    #[test]
    fn tunnel_payloads_are_not() {
        assert!(!is_standard_echo_payload(b"whoami\r\nnt authority\\system\r\n"));
        assert!(!is_standard_echo_payload(&[
            0xd5, 0x20, 0x08, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
        ]));
        // a counting payload that does not start at its own offset is not iputils
        let shifted: Vec<u8> = (1u8..57).collect();
        assert!(!is_standard_echo_payload(&shifted));
    }
}
