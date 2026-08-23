//! Shared test vectors: every expectation in this file was produced by running the actual
//! Python implementation (`sensor/tools/gen_vectors.py`), so these tests compare the
//! Rust port against CPython's real behaviour rather than a hand-written guess.
//!
//! Regenerate with:  python3 sensor/tools/gen_vectors.py

use std::path::PathBuf;

use maltrail_sensor::addr::{self, Ip};
use maltrail_sensor::event::{self, Field};
use maltrail_sensor::heuristics::nxdomain::{consonant_count, label_entropy};
use maltrail_sensor::output;
use maltrail_sensor::protocols::http;
use maltrail_sensor::pyre;
use maltrail_sensor::settings;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("vectors")
}

fn decode(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn load(name: &str) -> Vec<Vec<String>> {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector file {} ({e}); run tools/gen_vectors.py", path.display()));
    text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).map(|l| l.split('\t').map(decode).collect()).collect()
}

fn statics() -> &'static settings::Statics {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    settings::init(root)
}

#[test]
fn safe_value_matches_python() {
    let rows = load("safe_value.tsv");
    assert!(rows.len() >= 20);
    for row in rows {
        assert_eq!(event::safe_value(&row[0]), row[1], "safe_value({:?})", row[0]);
    }
}

#[test]
fn event_lines_match_python() {
    // The generator fixes the timestamp field so only the field layout, quoting and
    // falsy-to-dash handling are compared.
    let rows = load("event_line.tsv");
    assert_eq!(rows.len(), 7);

    let build = |index: usize| -> event::Event {
        // Mirrors the tuples in tools/gen_vectors.py:event_line_vectors()
        let port = |v: &str| -> Field {
            if let Ok(n) = v.parse::<i64>() {
                Field::Int(n)
            } else {
                Field::Text(v.to_string())
            }
        };
        match index {
            0 => event::Event::new(
                1700000000,
                123456,
                "10.0.0.5",
                50000u16,
                "66.66.66.66",
                443u16,
                "TCP",
                "IP",
                "66.66.66.66",
                "malware (test)",
                "(static)",
            ),
            1 => event::Event::new(
                1700000000,
                0,
                "10.0.0.5",
                Field::dash(),
                "66.66.66.66",
                Field::dash(),
                "ICMP",
                "IP",
                "66.66.66.66",
                "badnet",
                "ref",
            ),
            2 => event::Event::new(
                1700000000,
                999999,
                "10.0.0.5",
                0u16,
                "66.66.66.66",
                0u16,
                "UDP",
                "IP",
                "66.66.66.66",
                "x",
                "y",
            ),
            3 => event::Event::new(
                1700000000,
                1,
                "10.0.0.5",
                50000u16,
                "8.8.8.8",
                53u16,
                "UDP",
                "DNS",
                "(www).evil.com",
                "malware (test)",
                "(static)",
            ),
            4 => event::Event::new(
                1700000000,
                1,
                "10.0.0.5,203.0.113.9",
                50000u16,
                "1.2.3.4",
                80u16,
                "TCP",
                "URL",
                "host.example(/a?b=c \"quoted\")",
                "potential sql injection (suspicious)",
                "(heuristic)",
            ),
            5 => event::Event::new(
                1700000000,
                1,
                "10.0.0.5",
                50000u16,
                "1.2.3.4",
                445u16,
                "TCP",
                "PORT",
                Field::Int(445),
                "potential infection",
                "(heuristic)",
            ),
            _ => event::Event::new(
                1700000000,
                1,
                "10.0.0.5",
                port("50000,50001"),
                "1.2.3.4",
                port("80,443"),
                "TCP",
                "IP",
                "1.2.3.4",
                "known attacker",
                "(static)",
            ),
        }
    };

    for (index, row) in rows.iter().enumerate() {
        let e = build(index);
        let localtime = format!("FIXED-TIME.{:06}", e.usec);
        let line = e.render_line("sensor1", &localtime);
        assert_eq!(line.trim_end_matches('\n'), row[1], "event #{index} ({})", row[0]);
    }
}

#[test]
fn cef_escaping_matches_python() {
    for row in load("cef_escape.tsv") {
        let extension = row[1] == "extension";
        assert_eq!(output::cef_escape(&row[0], extension), row[2], "cef_escape({:?}, {extension})", row[0]);
    }
}

#[test]
fn python_repr_matches_cpython() {
    let rows = load("py_repr.tsv");
    let events = [
        event::Event::new(
            1700000000,
            123456,
            "10.0.0.5",
            50000u16,
            "66.66.66.66",
            443u16,
            "TCP",
            "IP",
            "66.66.66.66",
            "malware (test)",
            "(static)",
        ),
        event::Event::new(
            1,
            0,
            "10.0.0.5",
            Field::dash(),
            "1.2.3.4",
            Field::dash(),
            "ICMP",
            "IP",
            "1.2.3.4",
            "it's bad",
            "ref",
        ),
        event::Event::new(1, 0, "10.0.0.5", 1u16, "1.2.3.4", 2u16, "TCP", "PORT", Field::Int(445), "say \"hi\"", "ref"),
        event::Event::new(1, 0, "10.0.0.5", 1u16, "1.2.3.4", 2u16, "TCP", "URL", "a\tb", "tab\there", "ref"),
        event::Event::new(1, 0, "10.0.0.5", 1u16, "1.2.3.4", 2u16, "TCP", "URL", "back\\slash", "a'b\"c", "ref"),
    ];
    assert_eq!(rows.len(), events.len());
    for (row, e) in rows.iter().zip(events.iter()) {
        assert_eq!(e.py_repr(), row[1], "{}", row[0]);
    }
}

#[test]
fn ipv6_rendering_matches_python() {
    for row in load("compress_ipv6.tsv") {
        if let Some(expanded) = row[0].strip_prefix("expanded:") {
            assert_eq!(addr::compress_ipv6(expanded), row[1], "compress_ipv6({expanded:?})");
            continue;
        }
        let bytes: Vec<u8> =
            (0..row[0].len()).step_by(2).map(|i| u8::from_str_radix(&row[0][i..i + 2], 16).unwrap()).collect();
        let mut packed = [0u8; 16];
        packed.copy_from_slice(&bytes);
        assert_eq!(addr::inet_ntoa6(&packed), row[1], "inet_ntoa6({})", row[0]);
    }
}

#[test]
fn addr_port_matches_python() {
    for row in load("addr_port.tsv") {
        let port: u16 = row[1].parse().unwrap();
        let native = addr::parse_canonical_ip(&row[0]).or_else(|| {
            row[0]
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::Ipv6Addr>()
                .ok()
                .map(|v| Ip::V6(u128::from(v)))
        });
        match native {
            // Native rendering must agree for the addresses we can parse.
            Some(ip) if ip.render().as_str() == row[0] => {
                assert_eq!(ip.addr_port(port).as_str(), row[2], "addr_port({:?})", row[0]);
            }
            _ => {
                // Fall back to the text-based helper (hostnames, bracketed input).
                assert_eq!(addr::addr_port_str(&row[0], &row[1]), row[2], "addr_port_str({:?})", row[0]);
            }
        }
    }
}

#[test]
fn parse_host_port_matches_python() {
    for row in load("parse_host_port.tsv") {
        let (host, port) = addr::parse_host_port(&row[0]);
        assert_eq!(host, row[1], "host of {:?}", row[0]);
        let expected = if row[2].is_empty() { None } else { Some(row[2].parse::<u16>().unwrap()) };
        assert_eq!(port, expected, "port of {:?}", row[0]);
    }
}

#[test]
fn unquote_matches_urllib() {
    for row in load("unquote.tsv") {
        assert_eq!(http::unquote(&row[0]), row[1], "unquote({:?})", row[0]);
    }
}

#[test]
fn re_escape_matches_cpython() {
    for row in load("re_escape.tsv") {
        assert_eq!(pyre::escape(&row[0]), row[1], "re.escape({:?})", row[0]);
    }
}

#[test]
fn splitext_matches_posixpath() {
    for row in load("splitext.tsv") {
        let (name, ext) = http::splitext(&row[0]);
        assert_eq!(name, row[1], "name of {:?}", row[0]);
        assert_eq!(ext, row[2], "ext of {:?}", row[0]);
    }
}

#[test]
fn url_trail_checks_match_python() {
    let param_value = pyre::compile(r"(\w+=)[^&=]+");
    for row in load("checks.tsv") {
        let post = if row[1].is_empty() { None } else { Some(row[1].as_str()) };
        let unquoted_post = http::unquote(row[1].as_str());
        let got = http::build_checks(&row[0], post, &unquoted_post, &param_value);
        let expected: Vec<String> = row[2].split('\u{1f}').map(|s| s.to_string()).collect();
        assert_eq!(got, expected, "checks for {:?} / {:?}", row[0], row[1]);
    }
}

#[test]
fn entropy_and_consonants_match_python() {
    for row in load("entropy.tsv") {
        let expected: f64 = row[1].parse().unwrap();
        let got = label_entropy(&row[0]);
        assert!((got - expected).abs() < 1e-9, "entropy({:?}) = {got} != {expected}", row[0]);
        assert_eq!(consonant_count(&row[0]).to_string(), row[2], "consonants({:?})", row[0]);
    }
}

#[test]
fn valid_dns_name_matches_python() {
    let s = statics();
    for row in load("valid_dns_name.tsv") {
        let got = s.valid_dns_name.is_match(&row[0]);
        assert_eq!(got, row[1] == "1", "VALID_DNS_NAME_REGEX on {:?}", row[0]);
    }
}

#[test]
fn suspicious_request_regexes_pick_the_same_description() {
    let s = statics();
    for row in load("suspicious_request.tsv") {
        let mut found = String::new();
        for (desc, re) in &s.suspicious_http_request {
            if re.is_match(&row[0]) {
                found = desc.to_string();
                break;
            }
        }
        assert_eq!(found, row[1], "first match for {:?}", row[0]);
    }
}

#[test]
fn user_agent_classification_matches_python() {
    let s = statics();
    for row in load("suspicious_ua.tsv") {
        assert_eq!(s.whitelist_ua.is_match(&row[0]), row[1] == "1", "WHITELIST_UA_REGEX on {:?}", row[0]);
        let got = s
            .suspicious_ua
            .as_ref()
            .and_then(|re| re.find(&row[0]))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        assert_eq!(got, row[2], "SUSPICIOUS_UA_REGEX on {:?}", row[0]);
    }
}

#[test]
fn sinkhole_regex_matches_python() {
    let s = statics();
    for row in load("sinkhole.tsv") {
        let head: String = row[0].chars().take(2000).collect();
        let got = s.generic_sinkhole.find(&head).map(|m| m.as_str().to_string()).unwrap_or_default();
        assert_eq!(got, row[1], "GENERIC_SINKHOLE_REGEX on {:?}", row[0]);
    }
}

#[test]
fn direct_ip_url_regex_matches_python() {
    let s = statics();
    for row in load("direct_ip_url.tsv") {
        assert_eq!(
            s.suspicious_direct_ip_url.is_match(&row[0]),
            row[1] == "1",
            "SUSPICIOUS_DIRECT_IP_URL_REGEX on {:?}",
            row[0]
        );
    }
}

#[test]
fn wildcard_trail_compile_decisions_match_cpython() {
    // core/common.py:build_trails_regex() drops the wildcard trails CPython cannot compile.
    // The Rust loader must drop exactly the same ones: if Rust rejected a pattern Python
    // accepts, the Rust sensor would silently stop matching a live trail.
    //
    // Real feeds do ship truncated, uncompilable patterns, so "some are rejected" is expected;
    // what matters is that the two engines agree.
    let rows = load("wildcard_trails.tsv");
    assert!(rows.len() >= 10, "expected a meaningful pattern set, got {}", rows.len());

    let mut python_ok_rust_bad = Vec::new();
    let mut python_bad_rust_ok = Vec::new();
    for row in &rows {
        let python_compiles = row[1] == "1";
        let rust_compiles = maltrail_sensor::trails::regexset::can_compile_trail(&row[0]);
        if python_compiles && !rust_compiles {
            python_ok_rust_bad.push(row[0].clone());
        } else if !python_compiles && rust_compiles {
            python_bad_rust_ok.push(row[0].clone());
        }
    }
    assert!(
        python_ok_rust_bad.is_empty(),
        "Rust would LOSE {} trail(s) that CPython accepts: {:?}",
        python_ok_rust_bad.len(),
        python_ok_rust_bad
    );
    assert!(
        python_bad_rust_ok.is_empty(),
        "Rust would ADD {} trail(s) that CPython rejects: {:?}",
        python_bad_rust_ok.len(),
        python_bad_rust_ok
    );
}

#[test]
fn console_colouring_matches_core_colorized() {
    // Every expectation here is the real output of core/colorized.py's ColorizedStream, so the
    // port is compared against CPython rather than against my reading of it - including the
    // quirk where an already-coloured "(malware)" is wrapped again by the generic
    // parenthesis rule.
    let rows = load("colorized.tsv");
    assert!(rows.len() >= 15, "expected a meaningful set of lines, got {}", rows.len());
    for row in rows {
        let got = maltrail_sensor::colorized::colorize_always(&row[0]);
        assert_eq!(got, row[1], "colorize({:?})", row[0]);
    }
}

#[test]
fn client_hello_fingerprints_match_core_tls_intel() {
    // Golden SNI/JA3/JA4 values generated by `core.tls_intel.parse_client_hello` itself
    // (sensor/tools/gen_ja_vectors.py): handcrafted branch-pinning hellos plus seeded
    // mutations/truncations/noise. Empty field = Python produced None (or {}), so the Rust
    // parser must return None too - including the ALPN cases where a cut-short fixed header
    // is survivable but name bytes overrunning the body kill the WHOLE parse.
    let rows = load("client_hellos.tsv");
    assert!(rows.len() >= 200, "expected the full corpus, got {}", rows.len());

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn opt(field: &str) -> Option<&str> {
        if field.is_empty() {
            None
        } else {
            Some(field)
        }
    }

    for row in &rows {
        let (name, data) = (&row[0], unhex(&row[1]));
        let got = maltrail_sensor::protocols::tls::parse_client_hello(&data);
        assert_eq!(row[3].is_empty(), got.is_none(), "{}: parsed-vs-rejected disagreement", name);
        let got = match got {
            Some(ch) => ch,
            None => continue,
        };
        assert_eq!(got.sni.as_deref(), opt(&row[2]), "{}: sni", name);
        assert_eq!(got.ja3, row[3], "{}: ja3", name);
        assert_eq!(got.ja4, row[4], "{}: ja4", name);
    }
}
