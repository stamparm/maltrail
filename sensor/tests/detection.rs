//! Detection-path tests, ported case-for-case from the retired Python suite.
//!
//! Each test drives the real `process_packet` / `check_domain` code through the testkit
//! harness and asserts on the events actually written to a log file, so the assertions cover
//! the whole chain (parse -> detect -> format -> write) rather than an internal API.

use maltrail_sensor::testkit::*;

const MALWARE: (&str, &str) = ("malware (dummy)", "ref");

fn trails(entries: &[(&str, &str, &str)]) -> Harness {
    Harness::new(entries)
}

fn dns(name: &str) -> Vec<u8> {
    dns_query(name, 1, 1, 0x0100)
}

// --- _check_domain ---------------------------------------------------------------

#[test]
fn exact_domain_hit() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("evil.com"))), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail_type, "DNS");
    assert_eq!(events[0].trail, "evil.com");
    assert_eq!(events[0].info, "malware (dummy)");
    assert_eq!(events[0].proto, "UDP");
}

#[test]
fn subdomain_hit_marks_parent() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("www.evil.com"))), 1);
    assert_eq!(h.trails(), vec!["(www).evil.com"]);
}

#[test]
fn onion_via_tor2web_gateway() {
    let mut h = trails(&[("badsite.onion", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("badsite.onion.to"))), 1);
    assert_eq!(h.trails(), vec!["badsite.onion(.to)"]);
}

#[test]
fn ip_adress_com_relation() {
    let mut h = trails(&[("evil", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("evil.ip-adress.com"))), 1);
    assert_eq!(h.trails(), vec!["evil(.ip-adress.com)"]);
}

#[test]
fn clean_domain_is_silent() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("good.com"))), 1);
    assert!(h.events().is_empty());
}

#[test]
fn wildcard_regex_trail() {
    let mut h = trails(&[("dga[0-9]+\\.wildcard-test\\.com", MALWARE.0, "(static)")]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("dga4242.wildcard-test.com"))), 1);
    assert_eq!(h.trails(), vec!["dga4242.wildcard-test.com"]);
}

#[test]
fn wildcard_regex_trail_brackets_the_prefix() {
    let mut h = trails(&[("dga[0-9]+\\.wildcard-test\\.com", MALWARE.0, "(static)")]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("x.dga1.wildcard-test.com"))), 1);
    // prefix is bracketed, then ".)" is rewritten to ")."
    assert_eq!(h.trails(), vec!["(x).dga1.wildcard-test.com"]);
}

#[test]
fn ip_literal_query_is_ignored() {
    let mut h = trails(&[("1.2.3.4", MALWARE.0, MALWARE.1)]);
    // a DNS query for a dotted-quad name must not be treated as a domain
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("1.2.3.4"))), 1);
    assert!(h.events().is_empty(), "{:?}", h.events());
}

#[test]
fn infrastructure_names_under_suspicious_parents_are_skipped() {
    // e.g. ns2.nobel.su: an [rd]ns/nf/mx/nic name under a "suspicious" parent is not itself
    // an indicator, and the walk continues to the next parent
    let mut h = trails(&[("nobel.su", "sinkhole test (malware)", "(static)")]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("ns2.nobel.su"))), 1);
    assert!(h.events().is_empty(), "{:?}", h.events());
}

#[test]
fn dynamic_dns_parents_are_skipped_for_bare_and_www() {
    // NOTE: a ".example" name would be dropped by IGNORE_DNS_QUERY_SUFFIXES before it ever
    // reaches the domain check (see dns_queries_with_ignored_suffixes_are_dropped).
    let mut h = trails(&[("noip-dyn.com", "dynamic domain (suspicious)", "(static)")]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("noip-dyn.com"))), 1);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40001, 53, &dns("www.noip-dyn.com"))), 2);
    assert!(h.events().is_empty(), "{:?}", h.events());
    // ... but a real subdomain still fires
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40002, 53, &dns("victim.noip-dyn.com"))), 3);
    assert_eq!(h.trails(), vec!["(victim).noip-dyn.com"]);
}

#[test]
fn dns_queries_with_ignored_suffixes_are_dropped() {
    // IGNORE_DNS_QUERY_SUFFIXES / the ".intranet." guard short-circuit the whole DNS path,
    // before any trail or heuristic check.
    let mut h = trails(&[("evil.example", MALWARE.0, MALWARE.1), ("evil.local", MALWARE.0, MALWARE.1)]);
    for (i, name) in ["evil.example", "evil.local", "1.0.0.127.in-addr.arpa", "x.intranet.corp"].iter().enumerate() {
        h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000 + i as u16, 53, &dns(name))), 1 + i as u64);
    }
    assert!(h.events().is_empty(), "{:?}", h.events());
}

#[test]
fn condensable_events_are_held_until_a_flush() {
    // CONDENSE_ON_INFO_KEYWORDS ("tor exit", "user agent", "port scanning", ...) buffer the
    // event until the condensing flush, exactly like core/log.py. ("attacker" is also a
    // condense keyword, but a SYN to an "attacker" trail is suppressed outright - see
    // attacker_and_off_web_parking_trails_are_suppressed_on_syn.)
    let mut h = trails(&[("66.66.66.66", "tor exit node", "ref")]);
    h.feed_ip(&ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b"")), 1);
    assert!(h.raw_events().is_empty(), "condensable events must not be written immediately");
    h.flush();
    assert_eq!(h.raw_events().len(), 1);
}

#[test]
fn condensing_merges_ports_and_destinations() {
    let mut h = trails(&[("66.66.66.66", "tor exit node", "ref")]);
    for i in 0..3u16 {
        h.feed_ip(&ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000 + i, 443 + i, 0x02, b"")), 1 + i as u64);
    }
    let events = h.events();
    assert_eq!(events.len(), 1, "one condensed record per (src_ip, trail): {events:?}");
    assert_eq!(events[0].src_port, "50000,50001,50002");
    assert_eq!(events[0].dst_port, "443,444,445");
}

// --- TCP / UDP / ICMP ------------------------------------------------------------

#[test]
fn tcp_syn_to_bad_ip() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    h.feed_ip(&ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b"")), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail_type, "IP");
    assert_eq!(events[0].trail, "66.66.66.66");
}

#[test]
fn tcp_syn_ipport_trail() {
    let mut h = trails(&[("66.66.66.66:4444", "c2 (dummy)", "ref")]);
    h.feed_ip(&ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 4444, 0x02, b"")), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail_type, "IPORT");
    assert_eq!(events[0].trail, "66.66.66.66:4444");
}

#[test]
fn attacker_and_off_web_parking_trails_are_suppressed_on_syn() {
    let mut h = trails(&[("66.66.66.66", "known attacker", "ref"), ("77.77.77.77", "parking site", "ref")]);
    h.feed_ip(&ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b"")), 1);
    h.feed_ip(&ipv4(6, "10.0.0.5", "77.77.77.77", &tcp(50001, 8080, 0x02, b"")), 2);
    assert!(h.events().is_empty(), "{:?}", h.events());
    // a parking site on a web port is still reported
    h.feed_ip(&ipv4(6, "10.0.0.5", "77.77.77.77", &tcp(50002, 80, 0x02, b"")), 3);
    assert_eq!(h.trails(), vec!["77.77.77.77"]);
}

#[test]
fn inbound_syn_from_bad_source_excludes_malware_infos() {
    let mut h = trails(&[("9.9.9.1", "malware (dummy)", "ref"), ("9.9.9.2", "botnet c2", "ref")]);
    h.feed_ip(&ipv4(6, "9.9.9.1", "10.0.0.5", &tcp(31337, 50000, 0x02, b"")), 1);
    assert!(h.events().is_empty(), "the src branch drops 'malware' infos: {:?}", h.events());
    h.feed_ip(&ipv4(6, "9.9.9.2", "10.0.0.5", &tcp(31338, 50001, 0x02, b"")), 2);
    assert_eq!(h.trails(), vec!["9.9.9.2"]);
}

#[test]
fn duplicate_syn_bursts_collapse() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    for _ in 0..5 {
        h.feed_ip(&ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b"")), 1);
    }
    assert_eq!(h.events().len(), 1, "identical SYNs in one second must collapse");
}

#[test]
fn udp_non_dns_to_bad_ip() {
    let mut h = trails(&[("66.66.66.66", "suspicious (dummy)", "ref")]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "66.66.66.66", &udp(40000, 1900, &[0u8; 8])), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail, "66.66.66.66");
    assert_eq!(events[0].proto, "UDP");
}

#[test]
fn a_query_with_an_underscore_reaches_the_lookup() {
    // VALID_DNS_NAME_REGEX rejected '_' outright, so the query was thrown away BEFORE the trail
    // lookup. 134 static trails - dynamic-DNS hosts, mostly - could therefore never fire, however
    // exactly they matched. The underscore is legal in a queried name (SRV, _dmarc, DKIM) and
    // sensor/tools/check_trails.py reported the strandings.
    let mut h = trails(&[("dheeraj_gaurav.mooo.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("dheeraj_gaurav.mooo.com"))), 1);
    assert_eq!(h.trails(), vec!["dheeraj_gaurav.mooo.com"], "an underscore name must reach the lookup");
}

#[test]
fn an_underscore_in_the_last_label_is_still_rejected() {
    // The positive control for the widening: the trailing label is a TLD and no real one has an
    // underscore, so it stays out of the last position.
    let mut h = trails(&[("evil.tld_x", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("evil.tld_x"))), 1);
    assert!(h.events().is_empty(), "an underscore in the TLD position must still be rejected");
}

#[test]
fn udp_non_dns_to_malware_ip_is_reported() {
    // Deliberate divergence from the retired Python sensor, sensor.py:880 (listed in docs/COMPATIBILITY.md), which collapsed the dst-side and src-side
    // matches into one `trail` and then applied the src-side "malware" suppression to both -
    // so a datagram TO a known C2 address produced nothing at all. The TCP path never did this:
    // it suppresses "attacker" on the dst side and "malware" only on the src side.
    let mut h = trails(&[("66.66.66.66", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "66.66.66.66", &udp(40000, 4444, &[0u8; 8])), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "UDP to a malware-listed destination must be reported: {events:?}");
    assert_eq!(events[0].trail, "66.66.66.66");
    assert_eq!(events[0].proto, "UDP");
}

#[test]
fn udp_non_dns_from_malware_ip_stays_suppressed() {
    // The positive control for the test above: the src-side "malware" rule is the one that was
    // intended, and it still holds. Backscatter from a listed host is not a detection.
    let mut h = trails(&[("66.66.66.66", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "66.66.66.66", "10.0.0.5", &udp(4444, 40000, &[0u8; 8])), 1);
    assert!(h.events().is_empty(), "UDP FROM a malware-listed source stays suppressed");
}

#[test]
fn udp_non_dns_to_attacker_ip_is_suppressed() {
    // The dst-side rule the TCP path uses, now applied here too.
    let mut h = trails(&[("66.66.66.66", "attacker (dummy)", "ref")]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "66.66.66.66", &udp(40000, 4444, &[0u8; 8])), 1);
    assert!(h.events().is_empty(), "UDP to an attacker-listed destination stays suppressed");
}

#[test]
fn distinct_dns_queries_on_one_socket_are_both_examined() {
    // Deliberate divergence from the retired Python sensor, sensor.py:863 (listed in docs/COMPATIBILITY.md). The burst filter compared only
    // (second, 5-tuple) and ran BEFORE the DNS parser, so a clean query immediately followed by
    // a malicious one on the same resolver socket in the same second was never parsed at all.
    // A stub resolver walking its `search` list does exactly this.
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("good.example"))), 1);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("evil.com"))), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "the second query on a reused socket must still be examined: {events:?}");
    assert_eq!(events[0].trail, "evil.com");
}

#[test]
fn identical_dns_datagrams_still_collapse() {
    // The positive control for the test above: burst suppression is still doing its job. A
    // byte-for-byte repeat (a retransmit) is skipped, which is all the filter was ever for.
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    let packet = ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("evil.com")));
    h.feed_ip(&packet, 1);
    h.feed_ip(&packet, 1);
    assert_eq!(h.events().len(), 1, "identical datagrams in one second must still collapse");
}

#[test]
fn icmp_echo_request_only() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    let echo = [0x08u8, 0x00, 0, 0, 0, 0, 0, 0];
    h.feed_ip(&ipv4(1, "10.0.0.5", "66.66.66.66", &echo), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].proto, "ICMP");
    assert_eq!(events[0].src_port, "-");
    assert_eq!(events[0].dst_port, "-");
    assert_eq!(events[0].trail, "66.66.66.66");

    let reply = [0x00u8, 0x00, 0, 0, 0, 0, 0, 0];
    h.feed_ip(&ipv4(1, "10.0.0.5", "66.66.66.66", &reply), 2);
    assert_eq!(h.events().len(), 1, "echo replies must be ignored");
}

#[test]
fn ipv4_options_shift_the_transport_header() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    let packet = ipv4_opts(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b""), 6, 0);
    h.feed_ip(&packet, 1);
    assert_eq!(h.trails(), vec!["66.66.66.66"]);
}

#[test]
fn non_first_fragment_is_skipped() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    let packet = ipv4_opts(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b""), 5, 0x0001);
    h.feed_ip(&packet, 1);
    assert!(h.events().is_empty());
    assert!(h.errors().is_empty(), "fragment handling must not log an error");
}

#[test]
fn non_ip_offsets_are_dropped_quietly() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    h.feed_ip(&[0u8; 64], 1);
    h.feed_ip(&[0x30u8; 64], 1);
    assert!(h.events().is_empty());
    assert!(h.errors().is_empty());
}

#[test]
fn ipv6_detections() {
    let mut h = trails(&[("dead::beef", "badnet (dummy)", "ref"), ("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&ipv6(6, "dead::1", "dead::beef", &tcp(50000, 443, 0x02, b"")), 1);
    assert_eq!(h.trails(), vec!["dead::beef"]);
    h.feed_ip(&ipv6(17, "dead::1", "dead::2", &udp(40000, 53, &dns("evil.com"))), 2);
    assert_eq!(h.trails(), vec!["dead::beef", "evil.com"]);
}

#[test]
fn ipv6_extension_headers_do_not_hide_the_payload() {
    // An IPv6 packet may carry Hop-by-Hop, Routing or Destination-Options headers between the
    // fixed header and the transport header. Until the chain was walked, Next Header was taken as
    // the protocol, so such a packet reported protocol 0/43/60 - the transport header was never
    // located and NO port, DNS name, HTTP host or TLS SNI was ever read from it. One 8-byte
    // Hop-by-Hop header was enough to hide a packet from every payload-derived trail, which is a
    // detection-evasion primitive rather than a coverage gap.
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);

    h.feed_ip(&ipv6_ext(17, "dead::1", "dead::2", &[(0, 6)], &udp(40000, 53, &dns("evil.com"))), 1);
    assert_eq!(h.trails(), vec!["evil.com"], "a Hop-by-Hop header must not hide the DNS query behind it");

    // a chain, and one of the 4-octet-unit kinds (AH) which measures its length differently
    h.feed_ip(&ipv6_ext(17, "dead::3", "dead::4", &[(0, 6), (60, 6), (43, 14)], &udp(40001, 53, &dns("evil.com"))), 2);
    assert!(h.errors().is_empty(), "{:?}", h.errors());
}

#[test]
fn ipv6_port_trails_survive_an_extension_header() {
    // the same evasion, seen from the trail type: with the transport header unreachable there is
    // no port, so an IP:port trail silently degrades to a plain IP match or to nothing at all
    let mut h = trails(&[("[dead::beef]:443", "c2 (dummy)", "ref")]);
    h.feed_ip(&ipv6_ext(6, "dead::1", "dead::beef", &[(60, 6)], &tcp(50000, 443, 0x02, b"")), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail, "[dead::beef]:443");
}

#[test]
fn tunnelled_traffic_is_not_invisible() {
    // A SPAN feed at a datacentre or corporate border is usually an OVERLAY: the packets on the
    // mirror port are VXLAN/GENEVE/GRE, and the addresses in the outer header are tunnel
    // endpoints - our own infrastructure. Until the payload was decapsulated the sensor matched
    // those outer headers and nothing else, so every host inside the overlay was invisible: no
    // inner IP, no port, no DNS name, no HTTP host, no TLS SNI.
    let inner_dns = ipv4(17, "10.1.1.5", "10.1.1.1", &udp(40000, 53, &dns("evil.com")));
    let frame = eth(&inner_dns, 0x0800, None);

    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&vxlan("192.0.2.1", "192.0.2.2", 42, &frame), 1);
    assert_eq!(h.trails(), vec!["evil.com"], "VXLAN hid the query inside it");

    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&geneve("192.0.2.1", "192.0.2.2", 0x6558, 8, &frame), 1);
    assert_eq!(h.trails(), vec!["evil.com"], "GENEVE (with options) hid the query inside it");

    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&gre("192.0.2.1", "192.0.2.2", 0x0800, false, false, false, &inner_dns), 1);
    assert_eq!(h.trails(), vec!["evil.com"], "GRE hid the query inside it");

    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&erspan("192.0.2.1", "192.0.2.2", false, &frame), 1);
    assert_eq!(h.trails(), vec!["evil.com"], "ERSPAN II hid the mirrored frame inside it");
}

#[test]
fn a_tunnel_does_not_hide_an_inner_ip_or_port_trail() {
    // the same evasion seen from the trail type: with the inner header unreachable, an IP:port
    // trail on a host inside the overlay can never fire
    let inner = ipv4(6, "10.1.1.5", "10.9.9.9", &tcp(50000, 443, 0x02, b""));
    let mut h = trails(&[("10.9.9.9:443", "c2 (dummy)", "ref")]);
    h.feed_ip(&vxlan("192.0.2.1", "192.0.2.2", 7, &eth(&inner, 0x0800, None)), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail, "10.9.9.9:443");
}

#[test]
fn ipv6_addr_port_trail() {
    let mut h = trails(&[("[dead::beef]:443", "c2 (dummy)", "ref")]);
    h.feed_ip(&ipv6(6, "dead::1", "dead::beef", &tcp(50000, 443, 0x02, b"")), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail_type, "IPORT", "an IPv6 IP:port trail must not be typed as IP");
    assert_eq!(events[0].trail, "[dead::beef]:443");
}

#[test]
fn vlan_tagged_frames_are_followed() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    let inner = ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b""));
    let frame = eth(&inner, 0x0800, Some(100));
    h.feed(&frame, 1, 0, 18);
    assert_eq!(h.trails(), vec!["66.66.66.66"]);
}

// --- malformed input -------------------------------------------------------------

#[test]
fn malformed_dns_is_silent_and_logs_nothing() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    let header = |flags: u16, qd: u16, an: u16| {
        let mut v = Vec::new();
        v.extend_from_slice(&0x1234u16.to_be_bytes());
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&qd.to_be_bytes());
        v.extend_from_slice(&an.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    };
    let mut payloads: Vec<Vec<u8>> = vec![
        header(0x0100, 1, 0),
        [header(0x0100, 1, 0), b"\x04evil\x03com".to_vec()].concat(),
        [header(0x0100, 1, 0), vec![0x3f], b"AAAAA".to_vec()].concat(),
        [header(0x0100, 1, 0), vec![0xc0, 0x0c]].concat(),
        [header(0x8080, 1, 1), b"\x04evil\x03com\x00".to_vec(), vec![0, 1, 0, 1]].concat(),
        vec![0x00, 0x01, 0x02],
        vec![],
    ];
    payloads.push(vec![0xffu8; 300]);
    for (i, payload) in payloads.iter().enumerate() {
        h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000 + i as u16, 53, payload)), 1 + i as u64);
    }
    assert!(h.events().is_empty(), "{:?}", h.events());
    assert!(h.errors().is_empty(), "malformed DNS must not reach the error log: {:?}", h.errors());
}

#[test]
fn truncated_packets_never_panic() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    let full = ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
    for n in 0..full.len() {
        h.feed_ip(&full[..n], 1);
    }
    let dnsfull = ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("evil.com")));
    for n in 0..dnsfull.len() {
        h.feed_ip(&dnsfull[..n], 2);
    }
    assert!(h.errors().is_empty(), "{:?}", h.errors());
}

#[test]
fn hostile_byte_patterns_never_panic() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    for pattern in [0x00u8, 0x45, 0x60, 0xff, 0x0a, 0x22] {
        for n in [0usize, 1, 8, 20, 40, 60, 200, 1500, 2000] {
            h.feed_ip(&vec![pattern; n], 1);
        }
    }
    assert!(h.errors().is_empty(), "{:?}", h.errors());
}

// --- HTTP ------------------------------------------------------------------------

fn http_packet(payload: &[u8], dst: &str, sport: u16) -> Vec<u8> {
    ipv4(6, "10.0.0.5", dst, &tcp(sport, 80, 0x18, payload))
}

#[test]
fn http_host_matches_bad_domain() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&http_packet(&http_get("/x", Some("evil.com"), "curl/8"), "66.66.66.66", 50000), 1);
    let dns_events: Vec<_> = h.events().into_iter().filter(|e| e.trail_type == "DNS").collect();
    assert_eq!(dns_events.len(), 1, "{dns_events:?}");
    assert_eq!(dns_events[0].trail, "evil.com");
}

#[test]
fn http_to_bad_dst_ip_annotates_the_host() {
    let mut h = trails(&[("66.66.66.66", "badnet (dummy)", "ref")]);
    h.feed_ip(&http_packet(&http_get("/x", Some("evil.com"), "curl/8"), "66.66.66.66", 50000), 1);
    let ip_events: Vec<_> = h.events().into_iter().filter(|e| e.trail_type == "IP").collect();
    assert_eq!(ip_events.len(), 1, "{ip_events:?}");
    assert_eq!(ip_events[0].trail, "66.66.66.66 (evil.com)");
}

#[test]
fn http_url_path_trail() {
    let mut h = trails(&[("/malicious-login.php", MALWARE.0, "(static)")]);
    h.feed_ip(
        &http_packet(&http_get("/malicious-login.php", Some("victim.example"), "curl/8"), "203.0.113.10", 50000),
        1,
    );
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail_type, "URL");
    assert_eq!(events[0].trail, "(victim.example)/malicious-login.php");
}

#[test]
fn http_host_plus_path_trail() {
    let mut h = trails(&[("evil-url.example/bad/path", MALWARE.0, "(static)")]);
    h.feed_ip(&http_packet(&http_get("/bad/path", Some("evil-url.example"), "curl/8"), "203.0.113.11", 50000), 1);
    assert_eq!(h.trails(), vec!["evil-url.example/bad/path"]);
}

// #19622: an architecture-tagged path under a bare-IP Host is an IoT dropper URL - but only when
// one of OUR hosts fetched it. The guard used to look at the destination alone, so somebody else's
// traffic passing the sensor was filed as our infection, at HIGH severity.
#[test]
fn iot_dropper_fetched_by_our_host_is_reported() {
    let mut h = trails(&[]);
    h.feed_ip(&http_packet(&http_get("/mirai.x86", Some("198.51.100.99"), "curl/8"), "198.51.100.99", 50000), 1);
    let hits: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("iot-malware download")).collect();
    assert_eq!(hits.len(), 1, "our own host fetching a dropper must be reported: {hits:?}");
}

#[test]
fn iot_dropper_between_two_outsiders_is_silent() {
    let mut h = trails(&[]);
    // neither endpoint is ours: an external client fetching from an external server
    let payload = http_get("/mirai.x86", Some("198.51.100.99"), "curl/8");
    h.feed_ip(&ipv4(6, "203.0.113.7", "198.51.100.99", &tcp(50000, 80, 0x18, &payload)), 1);
    let hits: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("iot-malware download")).collect();
    assert!(hits.is_empty(), "somebody else's traffic reported as our infection: {hits:?}");
}

#[test]
fn http_clean_request_is_silent() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    h.feed_ip(&http_packet(&http_get("/", Some("good.example"), "curl/8"), "1.1.1.1", 50000), 1);
    assert!(h.events().is_empty(), "{:?}", h.events());
}

#[test]
fn http_missing_host_header_heuristic() {
    let mut h = Harness::with_options(
        &[],
        HarnessOptions { use_heuristics: true, check_missing_host: true, check_host_domains: true, extra: vec![] },
    );
    h.feed_ip(&http_packet(&http_get("/admin.php", None, "x"), "66.66.66.66", 50001), 1);
    let http_events: Vec<_> = h.events().into_iter().filter(|e| e.trail_type == "HTTP").collect();
    assert_eq!(http_events.len(), 1, "{http_events:?}");
    assert!(http_events[0].info.contains("missing host"), "{http_events:?}");
    assert_eq!(http_events[0].trail, "66.66.66.66/admin.php");
}

#[test]
fn http_suspicious_request_regexes() {
    let cases: [(&str, &str, &str); 5] = [
        ("/items.php?id=1%20UNION%20ALL%20SELECT%20a,b%20FROM%20users", "sqli.example", "potential sql injection"),
        ("/download?file=../../../../etc/passwd", "trav.example", "potential directory traversal"),
        ("/search?q=<script>alert(1)</script>", "xss.example", "potential xss injection"),
        ("/cgi?cmd=;cat%20/etc/passwd", "rce.example", "potential remote code execution"),
        ("/x?tpl=${7*7}", "ssti.example", "potential ssti injection"),
    ];
    for (i, (path, host, expected)) in cases.iter().enumerate() {
        let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
        h.feed_ip(&http_packet(&http_get(path, Some(host), "curl/8"), "203.0.113.12", 50000 + i as u16), 1);
        let events = h.events();
        assert!(events.iter().any(|e| e.info.contains(expected)), "expected {expected:?} for {path:?}, got {events:?}");
    }
}

#[test]
fn http_direct_download_heuristic() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    h.feed_ip(&http_packet(&http_get("/setup.exe", Some("dl.example"), "curl/8"), "203.0.113.17", 50000), 1);
    let events = h.events();
    assert!(events.iter().any(|e| e.info.contains("direct .exe download")), "{events:?}");
    assert_eq!(events[0].trail, "dl.example(/setup.exe)");
    // Negative control for the test below: with no forwarded-for header the source is the
    // packet's own address and nothing is appended.
    assert_eq!(events[0].src_ip, "10.0.0.5");
}

#[test]
fn http_forwarded_for_is_appended_to_the_source() {
    // A request arriving through a CDN or reverse proxy carries the real client in a
    // forwarded-for header, and the event has to name it or the detection points at the proxy.
    // Any of the three header names, in any case, and the search is over the RAW packet bytes.
    for header in ["X-Forwarded-For", "x-forwarded-for", "True-Client-IP", "CF-Connecting-IP"] {
        let request = format!(
            "GET /setup.exe HTTP/1.1\r\nHost: dl.example\r\n{header}: 198.51.100.9\r\n\
             User-Agent: curl/8\r\nAccept: */*\r\n\r\n"
        );
        let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
        h.feed_ip(&http_packet(request.as_bytes(), "203.0.113.17", 50000), 1);
        let events = h.events();
        assert!(events.iter().any(|e| e.info.contains("direct .exe download")), "{header}: {events:?}");
        assert_eq!(events[0].src_ip, "10.0.0.5,198.51.100.9", "{header}");
    }

    // A header that merely looks similar must not be picked up.
    let request = "GET /setup.exe HTTP/1.1\r\nHost: dl.example\r\nX-Forwarded-Host: 198.51.100.9\r\n\
                   User-Agent: curl/8\r\nAccept: */*\r\n\r\n";
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    h.feed_ip(&http_packet(request.as_bytes(), "203.0.113.17", 50000), 1);
    assert_eq!(h.events()[0].src_ip, "10.0.0.5");
}

#[test]
fn http_suspicious_user_agent() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    h.feed_ip(&http_packet(&http_get("/", Some("ua.example"), "masscan/1.0"), "203.0.113.19", 50000), 1);
    let ua: Vec<_> = h.events().into_iter().filter(|e| e.trail_type == "UA").collect();
    assert_eq!(ua.len(), 1, "{ua:?}");
    assert!(ua[0].info.contains("user agent (suspicious)"));
    assert!(ua[0].trail.contains("masscan"), "{:?}", ua[0].trail);
}

#[test]
fn http_whitelisted_user_agent_is_silent() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    // WHITELIST_UA_REGEX carries "Sophos"; the suspicious pattern must not win
    h.feed_ip(&http_packet(&http_get("/", Some("ua.example"), "Sophos masscan/1.0"), "203.0.113.19", 50000), 1);
    assert!(h.events().iter().all(|e| e.trail_type != "UA"), "{:?}", h.events());
}

#[test]
fn http_post_body_is_scanned() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    let body = "POST /submit HTTP/1.1\r\nHost: postsqli.example\r\n\r\nq=1 UNION ALL SELECT pwd FROM users";
    h.feed_ip(&http_packet(body.as_bytes(), "203.0.113.16", 50000), 1);
    let events = h.events();
    assert!(events.iter().any(|e| e.info.contains("potential sql injection")), "{events:?}");
    assert!(events[0].trail.starts_with("postsqli.example("), "{:?}", events[0].trail);
}

#[test]
fn http_response_heuristics() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    let sinkhole = b"HTTP/1.1 200 OK\r\nServer: sinkhole\r\n\r\n";
    h.feed_ip(&ipv4(6, "203.0.113.20", "10.0.0.5", &tcp(80, 50000, 0x18, sinkhole)), 1);
    let ct = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-sh\r\n\r\n#!/bin/sh";
    h.feed_ip(&ipv4(6, "203.0.113.21", "10.0.0.5", &tcp(80, 50001, 0x18, ct)), 2);
    let title = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><title>Domain Seized</title></html>";
    h.feed_ip(&ipv4(6, "203.0.113.22", "10.0.0.5", &tcp(80, 50002, 0x18, title)), 3);
    let infos: Vec<String> = h.events().into_iter().map(|e| e.info).collect();
    assert!(infos.iter().any(|i| i.contains("sinkhole response")), "{infos:?}");
    assert!(infos.iter().any(|i| i.contains("content type (suspicious)")), "{infos:?}");
    assert!(infos.iter().any(|i| i.contains("seized domain")), "{infos:?}");
}

#[test]
fn http_title_without_closing_tag_is_not_a_trail() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    let body = format!("HTTP/1.1 200 OK\r\n\r\n<title>Domain Seized{}", "A".repeat(500));
    h.feed_ip(&ipv4(6, "203.0.113.23", "10.0.0.5", &tcp(80, 50003, 0x18, body.as_bytes())), 1);
    assert!(h.events().is_empty(), "an unterminated <title> must not become a multi-KB trail");
}

// --- heuristics ------------------------------------------------------------------

#[test]
fn slow_port_scan_is_detected_once_per_window() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..20u16 {
        let packet = eth(&ipv4(6, "203.0.113.9", "198.51.100.7", &tcp(40000 + i, 1000 + i, 0x02, b"")), 0x0800, None);
        h.feed(&packet, i as u64, 0, 14);
    }
    let tick = eth(&ipv4(17, "203.0.113.9", "192.0.2.2", &udp(1, 2, &[0u8; 8])), 0x0800, None);
    h.feed(&tick, 22, 0, 14);
    let scans: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("potential port scanning")).collect();
    assert_eq!(scans.len(), 1, "once per (scanner, target) per window: {scans:?}");
    assert_eq!(scans[0].trail, "203.0.113.9");
}

#[test]
fn stealth_scans_are_detected_and_ack_is_not() {
    for (flags, name, expected) in [(0x00u8, "NULL", 1usize), (0x01, "FIN", 1), (0x29, "XMAS", 1), (0x10, "ACK", 0)] {
        let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
        for i in 0..20u16 {
            let packet =
                eth(&ipv4(6, "203.0.113.9", "198.51.100.7", &tcp(40000 + i, 1000 + i, flags, b"")), 0x0800, None);
            h.feed(&packet, i as u64, 0, 14);
        }
        let tick = eth(&ipv4(17, "203.0.113.9", "192.0.2.2", &udp(1, 2, &[0u8; 8])), 0x0800, None);
        h.feed(&tick, 22, 0, 14);
        let scans = h.events().into_iter().filter(|e| e.info.contains("potential port scanning")).count();
        assert_eq!(scans, expected, "{name} scan");
    }
}

#[test]
fn udp_scan_is_detected_and_benign_udp_is_not() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..20u16 {
        let packet = eth(&ipv4(17, "203.0.113.9", "198.51.100.7", &udp(40000 + i, 1000 + i, &[0u8; 8])), 0x0800, None);
        h.feed(&packet, i as u64, 0, 14);
    }
    let tick = eth(&ipv4(17, "203.0.113.9", "192.0.2.2", &udp(1, 2, &[0u8; 8])), 0x0800, None);
    h.feed(&tick, 25, 0, 14);
    let scans = h.events().into_iter().filter(|e| e.info.contains("potential udp scanning")).count();
    assert_eq!(scans, 1);

    // QUIC-like: one port to many hosts must stay clean
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..40u16 {
        let packet =
            eth(&ipv4(17, "203.0.113.9", &format!("198.51.100.{}", i % 50), &udp(40000, 443, &[0u8; 8])), 0x0800, None);
        h.feed(&packet, 0, i as u32, 14);
    }
    let tick = eth(&ipv4(17, "203.0.113.9", "192.0.2.2", &udp(1, 2, &[0u8; 8])), 0x0800, None);
    h.feed(&tick, 25, 0, 14);
    assert!(h.events().is_empty(), "benign UDP must not false-positive: {:?}", h.events());
}

#[test]
fn infection_scan_is_detected() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..40u16 {
        let packet = ipv4(6, "10.0.0.5", &format!("10.9.9.{i}"), &tcp(53000 + i, 445, 0x02, b""));
        h.feed_ip(&packet, 1);
    }
    h.feed_ip(&ipv4(17, "10.0.0.5", "192.0.2.3", &udp(1, 2, b"flush")), 3);
    let events: Vec<_> = h.events().into_iter().filter(|e| e.trail_type == "PORT").collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].trail, "445");
    assert!(events[0].info.contains("potential infection"));
}

#[test]
fn web_scan_suppressed_internally_but_flagged_externally() {
    // internal -> internal must be suppressed
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..14u16 {
        let payload = http_get(&format!("/scan{i}/x"), Some("webscan.example"), "curl/8");
        h.feed_ip(&ipv4(6, "172.21.0.1", "172.21.0.4", &tcp(52000 + i, 80, 0x18, &payload)), 1);
    }
    h.feed_ip(&ipv4(17, "172.21.0.1", "192.0.2.4", &udp(1, 2, b"flush")), 3);
    assert!(
        h.events().iter().all(|e| !e.info.contains("web scanning")),
        "internal<->internal web scan must be suppressed: {:?}",
        h.events()
    );

    // external -> internal must fire
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..14u16 {
        let payload = http_get(&format!("/scan{i}/x"), Some("webscan.example"), "curl/8");
        h.feed_ip(&ipv4(6, "203.0.113.7", "172.21.0.4", &tcp(52000 + i, 80, 0x18, &payload)), 1);
    }
    h.feed_ip(&ipv4(17, "203.0.113.7", "192.0.2.4", &udp(1, 2, b"flush")), 3);
    let events: Vec<_> = h.events().into_iter().filter(|e| e.trail_type == "PATH").collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].dst_ip, "172.21.0.4");
    assert_eq!(events[0].trail, "*");
}

#[test]
fn disabled_heuristics_mute_only_the_named_one() {
    let mut h = Harness::with_options(
        &[],
        HarnessOptions {
            use_heuristics: true,
            check_host_domains: true,
            check_missing_host: false,
            extra: vec!["DISABLED_HEURISTICS port_scanning, dns_exhaustion".to_string()],
        },
    );
    for i in 0..20u16 {
        let packet = ipv4(6, "203.0.113.9", "198.51.100.7", &tcp(40000 + i, 1000 + i, 0x02, b""));
        h.feed_ip(&packet, i as u64);
    }
    h.feed_ip(&ipv4(17, "203.0.113.9", "192.0.2.2", &udp(1, 2, &[0u8; 8])), 25);
    assert!(h.events().iter().all(|e| !e.info.contains("port scanning")), "{:?}", h.events());
}

#[test]
fn long_domain_heuristic() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    let long = "a".repeat(30);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns(&format!("{long}.example.org")))), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(events[0].info.contains("long domain"));
    assert_eq!(events[0].trail, format!("({long}).example.org"));
}

#[test]
fn dns_exhaustion_fires_once_over_threshold() {
    let mut h = Harness::with_options(
        &[],
        HarnessOptions { use_heuristics: true, check_host_domains: true, check_missing_host: false, extra: vec![] },
    );
    // DNS_EXHAUSTION_THRESHOLD is 1000, so drive it with 1002 distinct subdomains
    for i in 0..1002u32 {
        let name = format!("s{i}.tunnel-test.com");
        h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns(&name))), 1 + i as u64 % 30);
    }
    let events: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("dns exhaustion")).collect();
    assert_eq!(events.len(), 1, "exactly one exhaustion alert: {}", events.len());
    assert!(events[0].trail.ends_with(".tunnel-test.com"), "{:?}", events[0].trail);
}

#[test]
fn nxdomain_flood_and_dga_labels() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    let nx = |name: &str| dns_query(name, 1, 1, 0x8083);
    for i in 0..25u16 {
        h.feed_ip(
            &ipv4(17, "8.8.8.8", "203.0.113.5", &udp(53, 40000 + i, &nx(&format!("nx{i}.dgaparent.com")))),
            1 + i as u64,
        );
    }
    let events: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("excessive no such domain")).collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(events[0].trail.ends_with(").dgaparent.com"), "{:?}", events[0].trail);

    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    h.feed_ip(&ipv4(17, "8.8.8.8", "203.0.113.5", &udp(53, 40001, &nx("xkqwzlvbnmfghjd.com"))), 1);
    h.feed_ip(&ipv4(17, "8.8.8.8", "203.0.113.5", &udp(53, 40002, &nx("google.com"))), 2);
    let events: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("no such domain (suspicious)")).collect();
    assert_eq!(events.len(), 1, "only the DGA-looking label trips: {events:?}");
    assert_eq!(events[0].trail, "(xkqwzlvbnmfghjd).com");
}

#[test]
fn dns_response_sinkhole_and_parking() {
    let mut h = Harness::with_options(
        &[
            ("198.51.100.90", "sinkhole testsink (malware)", "(static)"),
            ("198.51.100.91", "parking site (suspicious)", "(static)"),
        ],
        HarnessOptions::heuristics(),
    );
    let response = |name: &str, answer: &str, compressed: bool| {
        let mut out = Vec::new();
        out.extend_from_slice(&0x1337u16.to_be_bytes());
        out.extend_from_slice(&0x8080u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&[0, 1, 0, 1]);
        if compressed {
            out.extend_from_slice(&[0xc0, 0x0c]);
        } else {
            for label in name.split('.') {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
            out.push(0);
        }
        out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        out.extend_from_slice(&maltrail_sensor::addr::addr_to_int(answer).unwrap().to_be_bytes());
        out
    };
    h.feed_ip(&ipv4(17, "8.8.8.8", "10.0.0.5", &udp(53, 50010, &response("sinkholed.com", "198.51.100.90", true))), 1);
    h.feed_ip(&ipv4(17, "8.8.8.8", "10.0.0.5", &udp(53, 50011, &response("parked.com", "198.51.100.91", false))), 2);
    let infos: Vec<String> = h.events().into_iter().map(|e| e.info).collect();
    assert!(infos.iter().any(|i| i.contains("sinkholed by testsink")), "{infos:?}");
    assert!(infos.iter().any(|i| i.contains("parked site")), "{infos:?}");
}

#[test]
fn log_throttling_collapses_repeats_within_a_bucket() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    // Same second, distinct source ports -> the burst filter does not apply, but the
    // (ip, trail) throttle does.
    for i in 0..10u16 {
        h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000 + i, 53, &dns("evil.com"))), 5);
    }
    let events = h.events();
    assert_eq!(events.len(), 2, "first event opens the bucket, the second registers it: {events:?}");
}

// --- SNI ------------------------------------------------------------------------

#[test]
fn tls_sni_is_checked_when_enabled() {
    let mut h = Harness::with_options(
        &[("tls-evil.example", MALWARE.0, "(static)")],
        HarnessOptions {
            use_heuristics: true,
            check_host_domains: true,
            check_missing_host: false,
            extra: vec!["USE_FAST_PREFILTER true".to_string(), "FAST_FLOW_CUTOFF 4".to_string()],
        },
    );
    let hello = maltrail_sensor::protocols::tls::build_client_hello("tls-evil.example", true);
    h.feed_ip(&ipv4(6, "10.0.0.5", "203.0.113.30", &tcp(50400, 443, 0x18, &hello)), 1);
    assert_eq!(h.trails(), vec!["tls-evil.example"]);
}

#[test]
fn tls_sni_is_ignored_when_disabled() {
    let mut h = Harness::with_options(&[("tls-evil.example", MALWARE.0, "(static)")], HarnessOptions::heuristics());
    let hello = maltrail_sensor::protocols::tls::build_client_hello("tls-evil.example", true);
    h.feed_ip(&ipv4(6, "10.0.0.5", "203.0.113.30", &tcp(50400, 443, 0x18, &hello)), 1);
    assert!(h.events().is_empty(), "SNI extraction is opt-in: {:?}", h.events());
}

// --- TLS client fingerprints (JA3 / JA4) ----------------------------------------
//
// The digests below are the JA3/JA4 of `build_client_hello("evil.com")`, cross-checked against
// `core/tls_intel.py:parse_client_hello()` (see the vector test in protocols/tls.rs).

#[test]
fn a_listed_ja3_client_fingerprint_fires() {
    let mut h = trails(&[("1e7c622032b0cb79401b0f7be3793a1a", "malware", "abuse.ch")]);
    let hello = maltrail_sensor::protocols::tls::build_client_hello("evil.com", true);
    h.feed_ip(&ipv4(6, "10.0.0.5", "203.0.113.30", &tcp(50400, 443, 0x18, &hello)), 1);
    assert_eq!(h.trails(), vec!["1e7c622032b0cb79401b0f7be3793a1a"]);
    assert_eq!(h.events()[0].trail_type, "JA3");
    assert_eq!(h.events()[0].info, "malware");
}

#[test]
fn a_ja4_trail_matches_when_no_ja3_is_listed() {
    let mut h = trails(&[("t12d010100_0f2cb44170f4_d2e2adf7177b", "potential malware site", "(custom)")]);
    let hello = maltrail_sensor::protocols::tls::build_client_hello("evil.com", true);
    h.feed_ip(&ipv4(6, "10.0.0.5", "203.0.113.30", &tcp(50401, 443, 0x18, &hello)), 1);
    assert_eq!(h.trails(), vec!["t12d010100_0f2cb44170f4_d2e2adf7177b"]);
    assert_eq!(h.events()[0].trail_type, "JA4");
}

#[test]
fn an_unlisted_client_fingerprint_is_silent() {
    // The same hello against a trail set that lists neither hash: no event, and the SNI of the
    // very same hello is what carries the detection instead (or nothing does).
    let mut h = trails(&[("unrelated.example", MALWARE.0, MALWARE.1)]);
    let hello = maltrail_sensor::protocols::tls::build_client_hello("clean.example.org", true);
    h.feed_ip(&ipv4(6, "10.0.0.5", "203.0.113.30", &tcp(50402, 443, 0x18, &hello)), 1);
    assert!(h.events().is_empty(), "{:?}", h.events());
}

/// The result-cache counters must actually reach the metrics registry.
///
/// They were incremented on the packet path and then hard-coded to zero in `MetricsSlot::snapshot`,
/// so `maltrail_cache_hits_total` / `_misses_total` exported 0 forever — a metric that is always
/// zero is worse than no metric, because it reads as "no cache pressure".
#[test]
fn result_cache_counters_are_published() {
    let mut h = trails(&[("evil.com", MALWARE.0, MALWARE.1)]);
    // Three sightings of one clean domain. With the doorkeeper admission filter the first is a
    // miss that only records a fingerprint, the second is a miss that ADMITS it to the cache, and
    // the third hits — so two misses then a hit is the correct sequence, not miss-then-hit.
    for i in 0..3 {
        h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000 + i, 53, &dns("cache-probe.example.org"))), 1 + i as u64);
    }
    let m = h.state.metrics;
    assert!(m.cache_misses > 0, "a fresh domain must record a cache miss (got {})", m.cache_misses);
    assert!(m.cache_hits > 0, "a repeated domain must record a cache hit (got {})", m.cache_hits);

    // ... and survive the publish/snapshot round trip the metrics endpoint reads through.
    let slot = maltrail_sensor::metrics::MetricsSlot::default();
    slot.publish(&m);
    let round_tripped = slot.snapshot();
    assert_eq!(round_tripped.cache_hits, m.cache_hits, "cache_hits lost in publish/snapshot");
    assert_eq!(round_tripped.cache_misses, m.cache_misses, "cache_misses lost in publish/snapshot");
}

/// Concurrent first write to the daily event log must not lose or corrupt records.
///
/// Every worker owns its own `EventSink`. The log file was previously created with an
/// `exists()`-then-`File::create` sequence, so at a day boundary two workers could both find it
/// missing and the second `File::create` would TRUNCATE what the first had already written. It is
/// now a single atomic `create(true).append(true)` open.
///
/// Barrier-synchronised so the sinks genuinely race on the first write, which is the only moment
/// the bug was reachable.
#[test]
fn concurrent_sinks_racing_the_first_write_lose_nothing() {
    use std::sync::{Arc, Barrier};

    let dir = std::env::temp_dir().join(format!("mt-log-race-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    const SINKS: usize = 32;
    const PER_SINK: usize = 25;
    let barrier = Arc::new(Barrier::new(SINKS));
    let mut handles = Vec::new();
    for worker in 0..SINKS {
        let barrier = barrier.clone();
        let dir = dir.clone();
        handles.push(std::thread::spawn(move || {
            let mut h = Harness::with_log_dir(&dir, &[("evil.com", MALWARE.0, MALWARE.1)]);
            barrier.wait(); // every sink opens the (missing) log at the same instant
            for i in 0..PER_SINK {
                // Distinct source AND destination per event: the throttle keys on (ip, trail) for
                // both endpoints, so a shared resolver address would suppress most of these and the
                // test would measure throttling instead of the write race.
                h.feed_ip(
                    &ipv4(
                        17,
                        &format!("10.0.{worker}.{i}"),
                        &format!("203.0.{worker}.{i}"),
                        &udp(40000 + i as u16, 53, &dns("evil.com")),
                    ),
                    1_700_000_000,
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread");
    }

    let mut lines = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().map(|e| e == "log").unwrap_or(false)
            && path.file_name().map(|n| n != "error.log").unwrap_or(false)
        {
            let text = std::fs::read_to_string(&path).unwrap();
            for line in text.lines() {
                assert!(line.starts_with('"'), "a record was split or interleaved: {line:?}");
                assert!(line.contains("evil.com"), "corrupted record: {line:?}");
                lines += 1;
            }
        }
    }
    // Throttling admits a bounded number per (ip, trail); every source here is distinct, so nothing
    // should be suppressed and nothing may be lost to a truncating create.
    assert_eq!(lines, SINKS * PER_SINK, "records lost or duplicated under a concurrent first write");
    let _ = std::fs::remove_dir_all(&dir);
}

// --- dns tunnelling ---
//
// The bar is a conjunction on purpose. Measured against 4,300 synthetic reputation and blocklist
// queries - antivirus hash lookups, DNSBL, CDN and object-store names - this reported none of them
// and reported the one real tunnel in the same capture exactly once.

fn tunnel_query(h: &mut Harness, host: &str, name: &str, sec: u64) {
    h.feed_ip(&ipv4(17, host, "10.0.0.1", &udp(40000, 53, &dns(name))), sec);
}

/// base32-ish, never repeated - what an encoder emits
fn chunk(i: u64, len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut state = i.wrapping_mul(6364136223846793005).wrapping_add(1);
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push(char::from(b'a' + ((state >> 33) % 26) as u8));
    }
    out
}

#[test]
fn a_sustained_encoded_channel_is_reported_once() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..300u64 {
        tunnel_query(&mut h, "10.0.0.5", &format!("{}.t.exfil-zone.top", chunk(i, 40)), i * 2);
    }
    let tunnels: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("dns tunneling")).collect();
    assert_eq!(tunnels.len(), 1, "one report per (source, zone) per window, not one per packet");
}

#[test]
fn the_same_volume_delivered_as_a_burst_is_not_reported() {
    // a workstation opening a folder full of files hammers its reputation service like this
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..300u64 {
        tunnel_query(&mut h, "10.0.0.5", &format!("{}.t.exfil-zone.top", chunk(i, 40)), 10);
    }
    assert!(h.events().iter().all(|e| !e.info.contains("dns tunneling")), "a burst is not a session");
}

#[test]
fn a_reputation_service_is_never_reported_however_much_it_is_used() {
    // sxl.sophos.com is NOT in data/whitelist.txt - HASH_LABEL_SERVICE_ZONES is what covers it,
    // and this is the case that made the older long_domain heuristic emit one event per lookup
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..600u64 {
        tunnel_query(&mut h, "10.0.0.6", &format!("{}.sxl.sophos.com", chunk(i, 40)), i * 2);
    }
    let noisy: Vec<_> = h.events().into_iter().filter(|e| e.info.contains("suspicious")).collect();
    assert!(noisy.is_empty(), "an antivirus lookup must produce nothing at all: {noisy:?}");
}

#[test]
fn a_blocklist_is_never_reported() {
    let mut h = Harness::with_options(&[], HarnessOptions::heuristics());
    for i in 0..900u64 {
        let name = format!("{}.{}.{}.{}.zen.spamhaus.org", i % 254 + 1, i % 251 + 1, i % 247 + 1, i % 241 + 1);
        tunnel_query(&mut h, "10.0.0.7", &name, i * 2);
    }
    assert!(h.events().iter().all(|e| !e.info.contains("dns tunneling")));
}

#[test]
fn use_heuristics_false_silences_it() {
    // heuristic_enabled() only consults DISABLED_HEURISTICS, so this needs the use_heuristics
    // check too - without it an operator who turned heuristics off still got these events.
    let mut h = Harness::with_options(&[], HarnessOptions::quiet());
    for i in 0..300u64 {
        tunnel_query(&mut h, "10.0.0.5", &format!("{}.t.exfil-zone.top", chunk(i, 40)), i * 2);
    }
    assert!(h.events().iter().all(|e| !e.info.contains("dns tunneling")));
}

#[test]
fn muting_it_silences_it() {
    let mut h = Harness::with_options(
        &[],
        HarnessOptions { extra: vec!["DISABLED_HEURISTICS dns_tunneling".to_string()], ..HarnessOptions::heuristics() },
    );
    for i in 0..300u64 {
        tunnel_query(&mut h, "10.0.0.5", &format!("{}.t.exfil-zone.top", chunk(i, 40)), i * 2);
    }
    assert!(h.events().iter().all(|e| !e.info.contains("dns tunneling")));
}

// --- longest-match precedence: specific trail vs whitelisted ancestor (divergence #3) ---
//
// the retired Python sensor suppresses a name whenever ANY ancestor domain is whitelisted, which made
// every exact trail on a shared platform (`*.googleusercontent.com`, ...) dead on arrival -
// 3,082 real static trails. The Rust sensor lets an exact, more-specific trail fire; see
// docs/COMPATIBILITY.md difference 22 for the full policy.

fn harness_with_user_whitelist(trails: &[(&str, &str, &str)], entries: &[&str]) -> (Harness, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "mt-user-whitelist-{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::write(&path, format!("{}\n", entries.join("\n"))).expect("write user whitelist");
    let h = Harness::with_options(
        trails,
        HarnessOptions { extra: vec![format!("USER_WHITELIST {}", path.display())], ..HarnessOptions::quiet() },
    );
    (h, path)
}

#[test]
fn trail_under_whitelisted_parent_fires() {
    let (mut h, wl) =
        harness_with_user_whitelist(&[("bad.platform.invalid", MALWARE.0, MALWARE.1)], &["platform.invalid"]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns("bad.platform.invalid"))), 1);
    assert_eq!(h.trails(), vec!["bad.platform.invalid"]);
    let _ = std::fs::remove_file(wl);
}

#[test]
fn subdomain_of_trail_under_whitelisted_parent_fires() {
    let (mut h, wl) =
        harness_with_user_whitelist(&[("bad.platform.invalid", MALWARE.0, MALWARE.1)], &["platform.invalid"]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40001, 53, &dns("www.bad.platform.invalid"))), 1);
    assert_eq!(h.trails(), vec!["(www).bad.platform.invalid"]);
    let _ = std::fs::remove_file(wl);
}

#[test]
fn whitelisted_sibling_without_trail_stays_silent() {
    let (mut h, wl) =
        harness_with_user_whitelist(&[("bad.platform.invalid", MALWARE.0, MALWARE.1)], &["platform.invalid"]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40002, 53, &dns("benign.platform.invalid"))), 1);
    // the sibling matches no trail, and the whitelisted parent still keeps the heuristics off
    assert!(h.events().is_empty());
    let _ = std::fs::remove_file(wl);
}

#[test]
fn whitelist_entry_equal_to_trail_still_wins() {
    // a tie goes to the whitelist: the operator explicitly cleared this exact name
    let (mut h, wl) = harness_with_user_whitelist(
        &[("cleared.platform.invalid", MALWARE.0, MALWARE.1)],
        &["cleared.platform.invalid"],
    );
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40003, 53, &dns("cleared.platform.invalid"))), 1);
    assert!(h.events().is_empty());
    let _ = std::fs::remove_file(wl);
}

#[test]
fn wildcard_trail_still_suppressed_by_whitelisted_ancestor() {
    // only EXACT-name trail hits earn the precedence; the wildcard regexset does not
    let (mut h, wl) =
        harness_with_user_whitelist(&[(r"dga[0-9]+\.platform\.test", MALWARE.0, MALWARE.1)], &["platform.invalid"]);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40004, 53, &dns("dga1234.platform.invalid"))), 1);
    assert!(h.events().is_empty());
    let _ = std::fs::remove_file(wl);
}

#[test]
fn http_trail_on_whitelisted_platform_host_fires() {
    let (mut h, wl) =
        harness_with_user_whitelist(&[("cdn.platform.invalid/mal.php", MALWARE.0, MALWARE.1)], &["platform.invalid"]);
    h.feed_ip(&http_packet(&http_get("/mal.php", Some("cdn.platform.invalid"), "curl/8"), "203.0.113.9", 50000), 1);
    let events = h.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(events[0].trail.contains("cdn.platform.invalid"), "{events:?}");
    let _ = std::fs::remove_file(wl);
}

#[test]
fn http_heuristic_under_whitelisted_ancestor_stays_silent() {
    // precedence never re-enables HEURISTICS on a whitelisted platform: benign software
    // downloads from CDN hosts must not turn into "direct .exe download" noise
    let wl = std::env::temp_dir().join(format!("mt-user-whitelist-{}-heur", std::process::id()));
    std::fs::write(&wl, "platform.invalid\n").expect("write user whitelist");
    let mut h = Harness::with_options(
        &[],
        HarnessOptions {
            use_heuristics: true,
            extra: vec![format!("USER_WHITELIST {}", wl.display())],
            ..HarnessOptions::quiet()
        },
    );
    h.feed_ip(
        &http_packet(&http_get("/setup.exe", Some("storage.platform.invalid"), "curl/8"), "203.0.113.9", 50001),
        1,
    );
    assert!(h.events().is_empty(), "{:?}", h.events());
    let _ = std::fs::remove_file(wl);
}

// --- periodic-beaconing heuristic (NEW, no sensor.py counterpart) -------------------

#[test]
fn a_timer_like_connection_pattern_fires_beaconing_once() {
    let mut h = Harness::with_options(&[], HarnessOptions { use_heuristics: true, ..HarnessOptions::quiet() });
    // nine SYNs to one destination, exactly 30 s apart: the eighth gap completes the verdict
    for i in 0..12u64 {
        h.feed_ip(&ipv4(6, "10.0.0.5", "93.184.216.34", &tcp(50000, 443, 0x02, b"")), 1000 + 30 * i);
    }
    let events = h.events();
    assert_eq!(events.len(), 1, "one beacon event, not one per packet {events:?}");
    assert!(events[0].trail.contains("93.184.216.34:443"), "{events:?}");
    assert_eq!(events[0].info, "potential periodic beaconing (suspicious)");
}

#[test]
fn a_whitelisted_destination_stays_silent() {
    // the tuning knob for pollers: whitelist the NTP pool / monitoring endpoint, not the victim
    let path = std::env::temp_dir().join(format!(
        "mt-beacon-whitelist-{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::write(&path, "93.184.216.34\n").expect("write user whitelist");
    let mut h = Harness::with_options(
        &[],
        HarnessOptions {
            use_heuristics: true,
            extra: vec![format!("USER_WHITELIST {}", path.display())],
            ..HarnessOptions::quiet()
        },
    );
    for i in 0..12u64 {
        h.feed_ip(&ipv4(6, "10.0.0.5", "93.184.216.34", &tcp(50000, 443, 0x02, b"")), 1000 + 30 * i);
    }
    assert!(h.events().is_empty(), "{:?}", h.events());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn jittered_and_local_traffic_stay_silent() {
    let mut h = Harness::with_options(&[], HarnessOptions { use_heuristics: true, ..HarnessOptions::quiet() });
    // human-ish jitter around a minute never crosses the CV bound
    let gaps = [52u64, 71, 44, 83, 39, 66, 91, 48, 77, 55];
    let mut sec = 1u64;
    for g in gaps {
        sec += g;
        h.feed_ip(&ipv4(6, "10.0.0.5", "93.184.216.34", &tcp(50000, 443, 0x02, b"")), sec);
    }
    assert!(h.events().is_empty(), "{:?}", h.events());

    // localhost destinations are excluded entirely
    for i in 0..12u64 {
        h.feed_ip(&ipv4(6, "10.0.0.5", "127.0.0.1", &tcp(50001, 8080, 0x02, b"")), 2000 + 30 * i);
    }
    assert!(h.events().is_empty(), "{:?}", h.events());
}

#[test]
fn beaconing_off_with_heuristics_disabled() {
    // quiet() = USE_HEURISTICS false: the default harness posture must produce nothing
    let mut h = Harness::new(&[]);
    for i in 0..12u64 {
        h.feed_ip(&ipv4(6, "10.0.0.5", "93.184.216.35", &tcp(50000, 443, 0x02, b"")), 1000 + 30 * i);
    }
    assert!(h.events().is_empty(), "{:?}", h.events());
}
