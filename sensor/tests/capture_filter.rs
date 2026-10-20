//! The shipped `CAPTURE_FILTER`, compiled by libpcap and run against packets.
//!
//! A packet this filter drops never reaches the sensor, so a wrong clause is a silent miss no
//! other test can see: the replay harness reads pcaps without it. Two such holes shipped -
//! libpcap's `tcp[]` reads IPv4 only, so no IPv6 SYN or TLS handshake was ever captured, and the
//! second segment of a ~2 KB browser ClientHello, which carries the SNI half of the time, was
//! dropped for not starting with a TLS record header.

use maltrail_sensor::testkit::{eth, ipv4, ipv6, repo_root, tcp, udp};

fn shipped_filter() -> String {
    let conf = std::fs::read_to_string(repo_root().join("maltrail.conf")).unwrap();
    let line = conf.lines().find(|l| l.starts_with("CAPTURE_FILTER ")).expect("no CAPTURE_FILTER line");
    line["CAPTURE_FILTER ".len()..].trim().to_string()
}

/// (what, should pass, source port, destination port, TCP flags, payload)
type Case = (&'static str, bool, u16, u16, u8, Vec<u8>);

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;

#[test]
fn shipped_filter_passes_what_detections_need_and_nothing_bulky() {
    let cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let program = cap.compile(&shipped_filter(), true).expect("the shipped filter must compile");

    let hello_start = [&[0x16, 0x03, 0x01, 0x07, 0xd0, 0x01][..], &[0u8; 1400]].concat();
    let record = |kind: u8, len: usize| [&[kind, 0x03, 0x03][..], &vec![0x41; len]].concat();
    let cases: Vec<Case> = vec![
        ("SYN to any port", true, 40000, 22, SYN, vec![]),
        ("ClientHello start", true, 40000, 443, ACK, hello_start.clone()),
        ("server handshake flight", true, 443, 40000, ACK, record(0x16, 900)),
        ("ClientHello continuation", true, 40000, 443, PSH_ACK, vec![0x99; 560]),
        ("HTTP", true, 40000, 80, PSH_ACK, b"GET / HTTP/1.1\r\n\r\n".to_vec()),
        ("SYN-ACK", false, 22, 40000, 0x12, vec![]),
        ("bare ACK", false, 40000, 443, ACK, vec![]),
        ("client application data", false, 40000, 443, PSH_ACK, record(0x17, 300)),
        ("client ChangeCipherSpec", false, 40000, 443, PSH_ACK, record(0x14, 3)),
        ("full-size upload segment", false, 40000, 443, ACK, vec![0x99; 1400]),
        ("server data", false, 443, 40000, ACK, vec![0x99; 1200]),
    ];
    for v6 in [false, true] {
        for (name, expected, sport, dport, flags, payload) in &cases {
            let segment = tcp(*sport, *dport, *flags, payload);
            let frame = if v6 {
                eth(&ipv6(6, "2001:db8::1", "2001:db8::2", &segment), 0x86dd, None)
            } else {
                eth(&ipv4(6, "10.0.0.1", "198.51.100.7", &segment), 0x0800, None)
            };
            let family = if v6 { "IPv6" } else { "IPv4" };
            assert_eq!(program.filter(&frame), *expected, "{family} {name}");
        }
    }

    // QUIC: the long-header handshake passes, short-header data does not.
    let quic = |first: u8| eth(&ipv4(17, "10.0.0.1", "198.51.100.7", &udp(40000, 443, &[first; 1200])), 0x0800, None);
    assert!(program.filter(&quic(0xc3)), "QUIC Initial");
    assert!(!program.filter(&quic(0x43)), "QUIC short header");
}
