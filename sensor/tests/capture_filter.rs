//! The shipped `CAPTURE_FILTER`, compiled by libpcap and run against packets.
//!
//! A packet this filter drops never reaches the sensor, so a wrong clause is a silent miss no
//! other test can see: the replay harness reads pcaps without it. Two such holes shipped -
//! libpcap's `tcp[]` reads IPv4 only, so no IPv6 SYN or TLS handshake was ever captured, and the
//! second segment of a ~2 KB browser ClientHello, which carries the SNI half of the time, was
//! dropped for not starting with a TLS record header.

use maltrail_sensor::testkit::{erspan, eth, gre, ipv4, ipv6, ipv6_ext, repo_root, tcp, udp};

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

/// TLS handshakes and HTTP requests are recognized by how their payload starts, on any port, and
/// DNS over TCP by its port. A BPF load past the end of the packet rejects it outright, so a
/// 4-byte payload test evaluated before `port 53` drops the 2-byte DNS length-prefix segment;
/// the frames here are unpadded, as on `any`.
#[test]
fn shipped_filter_passes_tls_http_and_dns_on_any_port() {
    let filter = shipped_filter();
    let ether = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap().compile(&filter, true).unwrap();
    let sll = pcap::Capture::dead(pcap::Linktype(113)).unwrap().compile(&filter, true).unwrap();
    let cooked = |ethertype: u16, packet: &[u8]| {
        [&[0, 0, 0, 1, 0, 6, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0][..], &ethertype.to_be_bytes(), packet].concat()
    };

    let hello = [&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01][..], &[0u8; 508]].concat();
    let flight = [&[0x16, 0x03, 0x03, 0x04, 0x4c, 0x0b][..], &[0x41; 1100]].concat();
    let dns_query = [&[0x00, 0x1d, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01][..], &[0u8; 23]].concat();
    let cases: Vec<Case> = vec![
        ("ClientHello to 8443", true, 40000, 8443, PSH_ACK, hello.clone()),
        ("ClientHello to 993", true, 40000, 993, PSH_ACK, hello.clone()),
        ("server certificate flight from 6606", true, 6606, 40000, PSH_ACK, flight),
        ("GET to 81", true, 40000, 81, PSH_ACK, b"GET /gate.php HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()),
        ("POST to 5000", true, 40000, 5000, PSH_ACK, b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()),
        ("CONNECT to 49152", true, 40000, 49152, PSH_ACK, b"CONNECT a.b:443 HTTP/1.1\r\n\r\n".to_vec()),
        ("DNS/TCP query", true, 40000, 53, PSH_ACK, dns_query.clone()),
        ("DNS/TCP length prefix alone", true, 40000, 53, PSH_ACK, vec![0x00, 0x1d]),
        ("DNS/TCP response", true, 53, 40000, PSH_ACK, dns_query),
        (
            "application data on 8443",
            false,
            40000,
            8443,
            PSH_ACK,
            [&[0x17, 0x03, 0x03, 0x01, 0x00][..], &[0x99; 256]].concat(),
        ),
        ("random payload to 5000", false, 40000, 5000, PSH_ACK, vec![0x47, 0x45, 0x54, 0x58, 0x99, 0x99]),
        ("upload led by 0x16 on 443", false, 40000, 443, ACK, [&[0x16, 0x77][..], &[0x99; 1398]].concat()),
        ("server data led by 0x16 on 443", false, 443, 40000, ACK, [&[0x16, 0x01][..], &[0x99; 1200]].concat()),
    ];
    for (name, expected, sport, dport, flags, payload) in &cases {
        let segment = tcp(*sport, *dport, *flags, payload);
        let v4 = ipv4(6, "10.0.0.1", "198.51.100.7", &segment);
        let v6 = ipv6(6, "2001:db8::1", "2001:db8::2", &segment);
        assert_eq!(ether.filter(&eth(&v4, 0x0800, None)), *expected, "IPv4 {name}");
        assert_eq!(ether.filter(&eth(&v6, 0x86dd, None)), *expected, "IPv6 {name}");
        assert_eq!(sll.filter(&cooked(0x0800, &v4)), *expected, "SLL IPv4 {name}");
        assert_eq!(sll.filter(&cooked(0x86dd, &v6)), *expected, "SLL IPv6 {name}");
    }
}

/// ECN-setup SYNs (RFC 3168: SYN+ECE+CWR, AccECN adds AE in byte 12) are SYNs.
#[test]
fn shipped_filter_passes_ecn_syns() {
    let cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let program = cap.compile(&shipped_filter(), true).unwrap();
    let mut acc_ecn = tcp(40000, 22, 0xc2, &[]);
    acc_ecn[12] |= 0x01;
    for (name, expected, segment) in [
        ("ECN SYN", true, tcp(40000, 22, 0xc2, &[])),
        ("AccECN SYN", true, acc_ecn),
        ("ECE SYN-ACK", false, tcp(22, 40000, 0x52, &[])),
        ("SYN+RST", false, tcp(40000, 22, 0x06, &[])),
    ] {
        let v4 = eth(&ipv4(6, "10.0.0.1", "198.51.100.7", &segment), 0x0800, None);
        let v6 = eth(&ipv6(6, "2001:db8::1", "2001:db8::2", &segment), 0x86dd, None);
        assert_eq!(program.filter(&v4), expected, "IPv4 {name}");
        assert_eq!(program.filter(&v6), expected, "IPv6 {name}");
    }
}

/// Encapsulations the parser unwraps must reach it: the filter cannot look inside them, so they
/// pass whole. Each inner packet is a bulk TCP segment the bare filter drops, or a DNS query it
/// passes, so only the encapsulation decides.
#[test]
fn shipped_filter_passes_what_the_parser_unwraps() {
    let filter = shipped_filter();
    let cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let program = cap.compile(&filter, true).unwrap();

    let bulk = tcp(443, 40000, ACK, &[0x99; 1200]);
    let dns = udp(40000, 53, &[0u8; 30]);
    let inner4 = ipv4(6, "10.1.1.5", "10.9.9.9", &bulk);
    let inner6 = ipv6(6, "2001:db8::5", "2001:db8::9", &bulk);
    let dns4 = ipv4(17, "10.1.1.5", "10.9.9.9", &dns);
    let mirrored = eth(&inner4, 0x0800, None);
    let ext_bulk = |exts: &[(u8, usize)]| eth(&ipv6_ext(6, "2001:db8::1", "2001:db8::2", exts, &bulk), 0x86dd, None);
    let pppoe = |payload: &[u8], ppp: u16| {
        [&[0x11, 0x00, 0x00, 0x01][..], &((payload.len() + 2) as u16).to_be_bytes(), &ppp.to_be_bytes(), payload]
            .concat()
    };
    let tagged = |outer: u16, frame_tail: &[u8]| {
        let mut f = eth(frame_tail, 0x8100, None);
        f[12..14].copy_from_slice(&outer.to_be_bytes());
        f
    };
    let vlan10 = |ethertype: u16, payload: &[u8]| [&[0x00, 0x0a][..], &ethertype.to_be_bytes(), payload].concat();

    assert!(!program.filter(&mirrored), "control: the bare inner packet is filtered out");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("GRE", eth(&gre("192.0.2.1", "192.0.2.2", 0x0800, false, false, false, &inner4), 0x0800, None)),
        ("GRE key+seq", eth(&gre("192.0.2.1", "192.0.2.2", 0x0800, true, true, true, &inner4), 0x0800, None)),
        ("ERSPAN II", eth(&erspan("192.0.2.1", "192.0.2.2", false, &mirrored), 0x0800, None)),
        ("ERSPAN III", eth(&erspan("192.0.2.1", "192.0.2.2", true, &mirrored), 0x0800, None)),
        (
            "GRE over IPv6",
            eth(&ipv6(47, "2001:db8::1", "2001:db8::2", &[&[0, 0, 0x08, 0][..], &inner4].concat()), 0x86dd, None),
        ),
        ("IP-in-IP", eth(&ipv4(4, "192.0.2.1", "192.0.2.2", &inner4), 0x0800, None)),
        ("6in4", eth(&ipv4(41, "192.0.2.1", "192.0.2.2", &inner6), 0x0800, None)),
        ("4in6", eth(&ipv6(4, "2001:db8::1", "2001:db8::2", &inner4), 0x86dd, None)),
        ("IPv6 hop-by-hop", ext_bulk(&[(0, 6)])),
        ("IPv6 routing", ext_bulk(&[(43, 6)])),
        ("IPv6 destination options", ext_bulk(&[(60, 6)])),
        ("PPPoE session", eth(&pppoe(&dns4, 0x0021), 0x8864, None)),
        ("802.1Q + PPPoE", eth(&vlan10(0x8864, &pppoe(&dns4, 0x0021)), 0x8100, None)),
        ("802.1Q in the frame", eth(&dns4, 0x0800, Some(10))),
        ("QinQ 802.1ad", tagged(0x88a8, &vlan10(0x8100, &vlan10(0x0800, &dns4)))),
        ("QinQ 0x9100", tagged(0x9100, &vlan10(0x8100, &vlan10(0x0800, &dns4)))),
        ("QinQ, outer tag stripped by the kernel", eth(&vlan10(0x0800, &dns4), 0x8100, None)),
        ("MPLS unicast", eth(&[&[0x00, 0x01, 0x01, 0x40][..], &inner4].concat(), 0x8847, None)),
        (
            "MPLS multicast, 2 labels",
            eth(&[&[0x00, 0x01, 0x00, 0x40, 0x00, 0x02, 0x01, 0x40][..], &inner4].concat(), 0x8848, None),
        ),
    ];
    for (name, frame) in &cases {
        assert!(program.filter(frame), "{name}");
    }

    // `any` is LINUX_SLL: the ethertype is at link[14:2], after a 16-byte cooked header.
    let sll = pcap::Capture::dead(pcap::Linktype(113)).unwrap();
    let sll_program = sll.compile(&filter, true).expect("the shipped filter must compile for `any`");
    let cooked = |protocol: u16, payload: &[u8]| {
        [&[0, 0, 0, 1, 0, 6, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0][..], &protocol.to_be_bytes(), payload].concat()
    };
    assert!(!sll_program.filter(&cooked(0x0800, &inner4)), "control: SLL bulk TCP");
    assert!(sll_program.filter(&cooked(0x0800, &dns4)), "control: SLL DNS");
    assert!(sll_program.filter(&cooked(0x8864, &pppoe(&dns4, 0x0021))), "SLL PPPoE");
    assert!(sll_program.filter(&cooked(0x8100, &vlan10(0x0800, &dns4))), "SLL QinQ inner tag");
    assert!(sll_program.filter(&cooked(0x8847, &[&[0x00, 0x01, 0x01, 0x40][..], &inner4].concat())), "SLL MPLS");
    assert!(
        sll_program
            .filter(&cooked(0x0800, &ipv4(47, "192.0.2.1", "192.0.2.2", &[&[0, 0, 0x08, 0][..], &inner4].concat()))),
        "SLL GRE"
    );
}

/// A filter that does not compile stops the capture, so the shipped one must compile for every
/// link type the parser reads (`packet::dlt`). `vlan`, `pppoes` and `ether proto` would not: the
/// first fails for `any` (LINUX_SLL), the others for raw-IP links.
#[test]
fn shipped_filter_compiles_for_every_link_type_the_sensor_reads() {
    let filter = shipped_filter();
    use maltrail_sensor::packet::dlt::*;
    for dlt in [
        DLT_NULL,
        DLT_EN10MB,
        DLT_PPP,
        DLT_LINUX_SLL,
        DLT_LINUX_SLL2,
        DLT_RAW,
        DLT_LOOP,
        DLT_ENC,
        DLT_PPP_SERIAL,
        DLT_PPP_ETHER,
        DLT_C_HDLC,
        DLT_IEEE802_11,
        DLT_PFLOG,
        DLT_PRISM_HEADER,
        DLT_IEEE802_11_RADIO,
        DLT_PPI,
        DLT_IPV4,
        DLT_IPV6,
        DLT_NETANALYZER,
    ] {
        let cap = pcap::Capture::dead(pcap::Linktype(dlt)).unwrap();
        assert!(cap.compile(&filter, true).is_ok(), "the shipped filter does not compile for DLT {dlt}");
    }
}
