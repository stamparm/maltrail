//! ICMP tunneling (icmpsh, ptunnel, ICMP exfiltration).
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

/// Payloads up to this long are checked against the precomputed tables below; a longer one (no
/// ping tool's default comes near it) takes the byte-by-byte path.
const TABLE_LEN: usize = 1536;

/// Windows ping's fill: `abcdefghijklmnopqrstuvw`, repeated.
static WINDOWS_FILL: [u8; TABLE_LEN] = {
    let mut t = [0u8; TABLE_LEN];
    let mut i = 0;
    while i < TABLE_LEN {
        t[i] = b'a' + (i % 23) as u8;
        i += 1;
    }
    t
};

/// iputils / BSD / macOS fill: byte i is i (mod 256).
static COUNTING_FILL: [u8; TABLE_LEN] = {
    let mut t = [0u8; TABLE_LEN];
    let mut i = 0;
    while i < TABLE_LEN {
        t[i] = i as u8;
        i += 1;
    }
    t
};

/// `data` is the echo payload, after the 8-byte ICMP header.
///
/// Each known fill is one slice comparison - a `memcmp` - against a precomputed table. It was up
/// to four byte-by-byte passes, one of them a division per byte, and an ordinary Linux ping only
/// passes the last: 325 of the 1,518 instructions an echo request cost (callgrind, refnet's ICMP).
/// The answers are the same, checked against the byte-by-byte version kept below.
pub fn is_standard_echo_payload(data: &[u8]) -> bool {
    let n = data.len();
    if n <= TIMESTAMP_LEN {
        return true;
    }
    if n > TABLE_LEN {
        return is_standard_echo_payload_bytewise(data);
    }
    // every byte equal to the one before it == a single repeated byte
    data[1..] == data[..n - 1]
        || data == &WINDOWS_FILL[..n]
        // past a 16-byte timestamp; an 8-byte one counts from offset 8, so it passes this too
        || data[16..] == COUNTING_FILL[16..n]
}

/// The byte-by-byte original: for payloads past the tables, and the oracle the tables are tested
/// against.
fn is_standard_echo_payload_bytewise(data: &[u8]) -> bool {
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
    fn the_tables_answer_exactly_as_the_bytewise_check_does() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut checked = 0usize;
        let mut standard = 0usize;
        let mut check = |data: &[u8]| {
            let expected = is_standard_echo_payload_bytewise(data);
            assert_eq!(
                is_standard_echo_payload(data),
                expected,
                "len {} {:?}",
                data.len(),
                &data[..data.len().min(40)]
            );
            checked += 1;
            standard += usize::from(expected);
        };
        // every length from empty to past the tables, for every known fill, then the same fill
        // with one byte changed at a few positions (start, the timestamp edges, middle, end)
        for n in 0..TABLE_LEN + 40 {
            let ts: Vec<u8> = (0..16).map(|_| next() as u8).collect();
            let mut fills: Vec<Vec<u8>> = vec![
                vec![0u8; n],
                vec![0xff; n],
                (0..n).map(|i| b'a' + (i % 23) as u8).collect(),
                (0..n).map(|i| if i < 8 { ts[i] } else { i as u8 }).collect(),
                (0..n).map(|i| if i < 16 { ts[i] } else { i as u8 }).collect(),
                (0..n).map(|i| (i + 1) as u8).collect(), // counting, but not from its own offset
                (0..n).map(|_| next() as u8).collect(),
            ];
            // periodic fills that are NOT a single byte or Windows' 23-cycle: a check that looks
            // at the wrong distance or the wrong period accepts these
            for period in [2usize, 3, 4, 22, 24] {
                fills.push((0..n).map(|i| b'a' + (i % period) as u8).collect());
            }
            for f in fills.clone() {
                for &at in &[0usize, 7, 8, 15, 16, 17, n / 2, n.saturating_sub(1)] {
                    if at < f.len() {
                        let mut g = f.clone();
                        g[at] ^= 1;
                        fills.push(g);
                    }
                }
            }
            for f in &fills {
                check(f);
            }
        }
        // random payloads over a tiny alphabet, so accidental fills turn up too
        for _ in 0..200_000 {
            let n = (next() % 80) as usize;
            let d: Vec<u8> = (0..n).map(|_| [0u8, 0x10, 0x11, b'a', b'b'][(next() % 5) as usize]).collect();
            check(&d);
        }
        // not vacuous: both answers occurred plenty
        assert!(standard > 5_000 && checked - standard > 5_000, "{standard} standard of {checked}");
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
