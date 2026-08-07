//! DNS extraction, byte-for-byte equivalent to the DNS block of
//! `sensor.py:_process_packet()`.
//!
//! Compatibility notes (all deliberate, all matching Python):
//!  * The question-section walk does **not** honour compression pointers: a label length
//!    byte of `0xc0` is taken as a 192-byte label, exactly like Python's loop.
//!  * A truncated question leaves the trailing dot on the name, which then fails
//!    `VALID_DNS_NAME_REGEX` and drops the packet.
//!  * Non-UTF-8 label bytes become U+FFFD (Python's `get_text` uses `errors="replace"`),
//!    which also fails the name regex.

/// The parsed question section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Lower-cased query name without the trailing dot (`query` in Python).
    pub name: String,
    /// Offset of the terminating zero-length label (`offset` in Python).
    pub name_end: usize,
    /// True when the walk ended because the buffer ran out rather than at a zero label.
    pub truncated: bool,
}

/// `qdcount` from the header, or `None` when the datagram is shorter than 7 bytes
/// (`if len(dns_data) > 6`).
pub fn qdcount(dns_data: &[u8]) -> Option<u16> {
    if dns_data.len() <= 6 {
        return None;
    }
    Some(u16::from_be_bytes([dns_data[4], dns_data[5]]))
}

/// Byte 2 of the header (flags high byte).
pub fn flags_high(dns_data: &[u8]) -> Option<u8> {
    dns_data.get(2).copied()
}

/// Byte 3 of the header (flags low byte: RA + rcode).
pub fn flags_low(dns_data: &[u8]) -> Option<u8> {
    dns_data.get(3).copied()
}

/// Decode the question name starting at offset 12.
pub fn question(dns_data: &[u8]) -> Option<Question> {
    let mut offset = 12usize;
    let mut name = String::with_capacity(64);
    let mut truncated = true;
    let mut non_ascii = false;

    while dns_data.len() > offset {
        let length = dns_data[offset] as usize;
        if length == 0 {
            // query = query[:-1] — drop the trailing dot
            name.pop();
            truncated = false;
            break;
        }
        // Python's slice is forgiving: it yields fewer bytes near the end of the buffer.
        let start = offset + 1;
        let end = (offset + length + 1).min(dns_data.len());
        if start <= end {
            let label = &dns_data[start..end];
            // Fast path: append the label lower-cased in place. It used to build a `String` per
            // LABEL through `from_utf8_lossy` and then allocate a second whole `String` for
            // `to_lowercase()` — four or five allocations for every DNS question on the wire.
            //
            // A DNS name that is not pure ASCII cannot pass `VALID_DNS_NAME_REGEX`, so it is
            // dropped before anything observable happens; the slow path is kept anyway so the
            // decoded text is byte-identical to Python's for every input.
            if label.is_ascii() {
                for b in label {
                    name.push(b.to_ascii_lowercase() as char);
                }
            } else {
                non_ascii = true;
                name.push_str(&String::from_utf8_lossy(label));
            }
        }
        name.push('.');
        offset += length + 1;
    }

    // Python applies `str.lower()` to the whole decoded name, which is Unicode-aware; only the
    // non-ASCII case needs it, and only that case pays for it.
    let name = if non_ascii { name.to_lowercase() } else { name };
    Some(Question { name, name_end: offset, truncated })
}

/// `type_, class_ = struct.unpack("!HH", dns_data[offset + 1:offset + 5])`
pub fn question_type_class(dns_data: &[u8], name_end: usize) -> Option<(u16, u16)> {
    let start = name_end.checked_add(1)?;
    // `checked_add` on BOTH ends: `name_end` is caller-supplied, and `start + 4` overflows for a
    // hostile value. Debug builds panicked on it (release wrapped to an empty range and returned
    // None) — a parser whose contract is "never panics on arbitrary input" must not rely on the
    // build profile for that.
    let slice = dns_data.get(start..start.checked_add(4)?)?;
    Some((u16::from_be_bytes([slice[0], slice[1]]), u16::from_be_bytes([slice[2], slice[3]])))
}

/// Walk the answer section looking for the first Type A record and return its 4 RDATA
/// bytes as an IPv4 address, mirroring the Python answer walk (including its tolerance of
/// truncated / malformed sections).
pub fn first_a_record(dns_data: &[u8], name_end: usize) -> Option<u32> {
    let mut cursor = name_end.checked_add(5)?;
    let mut ptr = cursor;

    while cursor < dns_data.len() {
        ptr = cursor;
        // skip this record's NAME
        while ptr < dns_data.len() {
            let lbl_len = dns_data[ptr];
            if lbl_len & 0xc0 != 0 {
                ptr += 2; // compression pointer
                break;
            }
            if lbl_len == 0 {
                ptr += 1;
                break;
            }
            ptr += lbl_len as usize + 1;
        }

        // need Type(2)+Class(2)+TTL(4)+RdLen(2)
        if ptr + 10 > dns_data.len() {
            break;
        }
        if dns_data[ptr] == 0x00 && dns_data[ptr + 1] == 0x01 {
            break; // Type A
        }
        let rd_len = u16::from_be_bytes([dns_data[ptr + 8], dns_data[ptr + 9]]) as usize;
        cursor = ptr + 10 + rd_len;
    }

    // A RDATA = name-end(ptr) + type(2) + class(2) + ttl(4) + rdlen(2)
    let rdata = dns_data.get(ptr.checked_add(10)?..ptr.checked_add(14)?)?;
    Some(u32::from_be_bytes([rdata[0], rdata[1], rdata[2], rdata[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Named, deterministic offset-overflow contract.
    ///
    /// The fuzz suite catches this class, but only by chance of input; these pin the exact boundary
    /// values forever. Both functions take a caller-supplied `name_end` and must return `None`
    /// rather than overflow — a debug build panicked on `start + 4` here, and release wrapped it
    /// into an empty range, which is a correctness property that must not depend on the profile.
    #[test]
    fn hostile_name_end_offsets_never_overflow() {
        let data = [0u8; 64];
        for offset in [usize::MAX, usize::MAX - 1, usize::MAX - 4, usize::MAX - 5, usize::MAX - 6] {
            assert_eq!(question_type_class(&data, offset), None, "question_type_class({offset})");
            assert_eq!(first_a_record(&data, offset), None, "first_a_record({offset})");
        }
        // A sane offset past the end is also None, not a panic.
        assert_eq!(question_type_class(&data, 1_000), None);
        assert_eq!(first_a_record(&data, 1_000), None);
        // ... and a valid offset still works, so the guards did not break the happy path.
        let query =
            super::super::dns::question(&crate::testkit::dns_query("evil.com", 1, 1, 0x0100)).expect("question");
        assert_eq!(query.name, "evil.com");
    }

    fn query_message(name: &str, qtype: u16, qclass: u16, flags: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x1234u16.to_be_bytes());
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&qclass.to_be_bytes());
        v
    }

    #[test]
    fn decodes_a_query() {
        let m = query_message("evil.com", 1, 1, 0x0100);
        assert_eq!(qdcount(&m), Some(1));
        let q = question(&m).unwrap();
        assert_eq!(q.name, "evil.com");
        assert!(!q.truncated);
        assert_eq!(question_type_class(&m, q.name_end), Some((1, 1)));
        assert_eq!(flags_high(&m), Some(0x01));
        // standard query test from sensor.py: flags_high & 0xfa == 0
        assert_eq!(flags_high(&m).unwrap() & 0xfa, 0x00);
    }

    #[test]
    fn lowercases_the_name() {
        let m = query_message("EVIL.CoM", 1, 1, 0x0100);
        assert_eq!(question(&m).unwrap().name, "evil.com");
    }

    #[test]
    fn truncated_question_keeps_trailing_dot() {
        // header claims a question, body cut short -> Python leaves the trailing '.' so the
        // name fails VALID_DNS_NAME_REGEX and the packet is dropped
        let mut m = query_message("evil.com", 1, 1, 0x0100);
        m.truncate(12 + 5); // "\x04evil"
        let q = question(&m).unwrap();
        assert!(q.truncated);
        assert_eq!(q.name, "evil.");
        assert!(question_type_class(&m, q.name_end).is_none());
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0, 1, 2],
            query_message("evil.com", 1, 1, 0x0100)[..12].to_vec(),
            {
                let mut v = query_message("evil.com", 1, 1, 0x0100)[..12].to_vec();
                v.push(0x3f); // label length 63 overruns the buffer
                v.extend_from_slice(b"AAAAA");
                v
            },
            {
                let mut v = query_message("evil.com", 1, 1, 0x0100)[..12].to_vec();
                v.push(0xc0); // taken as a 192-byte label, exactly like Python
                v.push(0x0c);
                v
            },
        ];
        for m in cases {
            let _ = qdcount(&m);
            if let Some(q) = question(&m) {
                let _ = question_type_class(&m, q.name_end);
                let _ = first_a_record(&m, q.name_end);
            }
        }
    }

    #[test]
    fn invalid_utf8_labels_become_replacement_chars() {
        let mut m = query_message("x", 1, 1, 0x0100)[..12].to_vec();
        m.push(2);
        m.extend_from_slice(&[0xff, 0xfe]);
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        let q = question(&m).unwrap();
        assert!(q.name.contains('\u{fffd}'), "{:?}", q.name);
    }

    #[test]
    fn finds_an_a_record_with_an_uncompressed_answer_name() {
        let mut m = query_message("evil.com", 1, 1, 0x8080);
        let name_end = question(&m).unwrap().name_end;
        // answer: uncompressed name, type A, class IN, ttl, rdlen 4, 1.2.3.4
        m.extend_from_slice(b"\x04evil\x03com\x00");
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert_eq!(first_a_record(&m, name_end), Some(0x0102_0304));
    }

    #[test]
    fn finds_an_a_record_after_a_cname_with_a_compression_pointer() {
        let mut m = query_message("evil.com", 1, 1, 0x8080);
        let name_end = question(&m).unwrap().name_end;
        // CNAME record (skipped), then an A record
        m.extend_from_slice(&[0xc0, 0x0c]);
        m.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c]);
        m.extend_from_slice(&[0xc0, 0x0c]);
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 9, 9, 9]);
        assert_eq!(first_a_record(&m, name_end), Some(0x0909_0909));
    }

    #[test]
    fn empty_answer_section_returns_none() {
        // tests/test_sensor.py:test_dns_response_empty_answer_section_no_crash
        let m = query_message("evil.com", 1, 1, 0x8080);
        let name_end = question(&m).unwrap().name_end;
        assert_eq!(first_a_record(&m, name_end), None);
    }
}
