//! TLS server-certificate detection, end to end through the packet path.
//!
//! The indicator is the leaf certificate's SHA-1 fingerprint, which is what certificate feeds
//! publish (abuse.ch SSLBL lists ~10,000). It matters because it is the one identifier that
//! survives a C2 changing address and domain — re-keying costs the operator more than
//! re-registering — so it catches infrastructure that has moved out from under its other trails.

use maltrail_sensor::testkit::{eth, ipv4, tcp, Harness, HarnessOptions};

/// SHA-1 of `der`, lower-case hex — the form the feeds and therefore the trail keys use.
fn sha1_hex(der: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    use std::fmt::Write;
    Sha1::new().chain_update(der).finalize().iter().fold(String::with_capacity(40), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A server flight: TLS record -> Certificate handshake message -> one DER certificate.
fn server_flight(der: &[u8]) -> Vec<u8> {
    let entry = der.len();
    let list = entry + 3;
    let mut msg = Vec::new();
    msg.extend_from_slice(&[(list >> 16) as u8, (list >> 8) as u8, list as u8]);
    msg.extend_from_slice(&[(entry >> 16) as u8, (entry >> 8) as u8, entry as u8]);
    msg.extend_from_slice(der);

    let mut hs = vec![0x0b];
    hs.extend_from_slice(&[(msg.len() >> 16) as u8, (msg.len() >> 8) as u8, msg.len() as u8]);
    hs.extend_from_slice(&msg);

    let mut record = vec![0x16, 0x03, 0x03, (hs.len() >> 8) as u8, hs.len() as u8];
    record.extend_from_slice(&hs);
    record
}

/// A plausible self-signed C2 certificate: one cert, no chain, ~1.1 kB, so the whole flight
/// fits in a single segment. That shape is why this works without stream reassembly.
fn c2_certificate() -> Vec<u8> {
    (0..1100u32).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

fn harness_with(trails: &[(&str, &str, &str)]) -> Harness {
    Harness::with_options(trails, HarnessOptions::quiet())
}

fn feed_server_flight(h: &mut Harness, der: &[u8], src: &str, dst: &str) {
    let packet = eth(&ipv4(6, src, dst, &tcp(443, 51000, 0x18, &server_flight(der))), 0x0800, None);
    h.feed(&packet, 1700000000, 0, 14);
}

#[test]
fn a_listed_certificate_is_detected_by_its_fingerprint() {
    let der = c2_certificate();
    let digest = sha1_hex(&der);
    let mut h = harness_with(&[(digest.as_str(), "asyncrat c2 cert (suspicious)", "(sslbl)")]);

    feed_server_flight(&mut h, &der, "203.0.113.7", "10.0.0.5");
    h.flush();

    let events = h.events();
    assert_eq!(events.len(), 1, "expected one detection, got {events:?}");
    let event = &events[0];
    assert_eq!(event.trail_type, "CERT");
    assert_eq!(event.trail, digest);
    assert!(event.info.contains("c2 cert"), "{}", event.info);
    assert_eq!(event.reference, "(sslbl)");
    // The server is the source of its own certificate, so the event points at the C2.
    assert_eq!(event.src_ip, "203.0.113.7");
}

#[test]
fn an_unlisted_certificate_is_silent() {
    let der = c2_certificate();
    let mut h = harness_with(&[(sha1_hex(b"some other certificate").as_str(), "x (suspicious)", "(sslbl)")]);
    feed_server_flight(&mut h, &der, "203.0.113.7", "10.0.0.5");
    h.flush();
    assert!(h.events().is_empty(), "a certificate that is not listed must not fire");
}

#[test]
fn a_client_hello_never_produces_a_certificate_event() {
    // The ClientHello path and the certificate path share a record type; they must not confuse
    // each other, or every TLS connection would be hashed and looked up for nothing.
    let hello = maltrail_sensor::protocols::tls::build_client_hello("example.com", true);
    let mut h = harness_with(&[(sha1_hex(&hello).as_str(), "wrong (suspicious)", "(sslbl)")]);
    let packet = eth(&ipv4(6, "10.0.0.5", "203.0.113.7", &tcp(51000, 443, 0x18, &hello)), 0x0800, None);
    h.feed(&packet, 1700000000, 0, 14);
    h.flush();
    assert!(h.events().is_empty(), "a ClientHello must not be fingerprinted as a certificate");
}

#[test]
fn the_switch_turns_it_off() {
    let der = c2_certificate();
    let digest = sha1_hex(&der);
    let mut options = HarnessOptions::quiet();
    options.extra.push("CHECK_TLS_CERTIFICATES false".to_string());
    let mut h = Harness::with_options(&[(digest.as_str(), "c2 cert (suspicious)", "(sslbl)")], options);

    feed_server_flight(&mut h, &der, "203.0.113.7", "10.0.0.5");
    h.flush();
    assert!(h.events().is_empty(), "CHECK_TLS_CERTIFICATES false must disable the check");
}

#[test]
fn a_certificate_split_across_segments_is_not_half_matched() {
    // No stream reassembly: a flight that does not fit one segment must produce nothing rather
    // than a fingerprint of the fragment, which would match nothing and look like a clean run.
    let der = c2_certificate();
    let digest = sha1_hex(&der);
    let mut h = harness_with(&[(digest.as_str(), "c2 cert (suspicious)", "(sslbl)")]);

    let flight = server_flight(&der);
    let half = &flight[..flight.len() / 2];
    let packet = eth(&ipv4(6, "203.0.113.7", "10.0.0.5", &tcp(443, 51000, 0x18, half)), 0x0800, None);
    h.feed(&packet, 1700000000, 0, 14);
    h.flush();
    assert!(h.events().is_empty(), "a truncated certificate must not fire");
}
