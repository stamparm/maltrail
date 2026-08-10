//! `sensor.py:_process_packet()` and `sensor.py:_check_domain()`.
//!
//! This is a line-by-line port. Where the Python code has a quirk that is observable in the
//! emitted events (ordering, bracketing, which guard short-circuits first, a cache that is
//! consulted before a whitelist), the quirk is reproduced and commented rather than
//! "fixed" — see `docs/COMPATIBILITY.md` for the small number of deliberate differences.

use std::borrow::Cow;

use crate::addr::Ip;
use crate::event::{proto as PROTO, trail_type as TRAIL, Event, Field};
use crate::heuristics::dns_exhaustion::Outcome;
use crate::heuristics::nxdomain::{consonant_count, label_entropy, NxAlert};
use crate::heuristics::scan::{InfectionDetail, PathDetail, PortDetail};
use crate::packet::{self, Drop};
use crate::protocols::{dns, http};
use crate::settings;
use crate::state::{FlowStamp, WorkerState};

/// The 5-tuple carried through the detection functions.
#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    pub src: Ip,
    pub src_port: u16,
    pub dst: Ip,
    pub dst_port: u16,
}

#[allow(clippy::too_many_arguments)]
fn emit(
    st: &mut WorkerState,
    sec: u64,
    usec: u32,
    src_ip: &str,
    src_port: Field,
    dst_ip: Field,
    dst_port: Field,
    proto: &str,
    trail_type: &'static str,
    trail: Field,
    info: &str,
    reference: &str,
) {
    let event = Event {
        sec,
        usec,
        src_ip: src_ip.to_string(),
        src_port,
        dst_ip,
        dst_port,
        proto: Field::Text(proto.to_string()),
        trail_type,
        trail,
        info: info.to_string(),
        reference: reference.to_string(),
    };
    st.metrics.events += 1;
    st.sink.log_event(&event, false, false);
}

/// Emit with the standard endpoint fields.
#[allow(clippy::too_many_arguments)]
fn emit_ep(
    st: &mut WorkerState,
    sec: u64,
    usec: u32,
    ep: Endpoints,
    proto: &str,
    trail_type: &'static str,
    trail: Field,
    info: &str,
    reference: &str,
) {
    let src = ep.src.render();
    let dst = ep.dst.render();
    emit(
        st,
        sec,
        usec,
        src.as_str(),
        Field::port(ep.src_port),
        Field::Text(dst.as_str().to_string()),
        Field::port(ep.dst_port),
        proto,
        trail_type,
        trail,
        info,
        reference,
    );
}

// ---------------------------------------------------------------------------
// _check_domain
// ---------------------------------------------------------------------------

/// `sensor.py:_check_domain()`
pub fn check_domain(st: &mut WorkerState, query: &str, sec: u64, usec: u32, ep: Endpoints, proto: &str) {
    check_domain_inner(st, query, sec, usec, ep, proto, None)
}

/// `_check_domain()` with an optional PRECOMPUTED whitelist verdict.
///
/// The DNS path used to walk the whitelist twice per query: once for the registrable domain (the
/// last two or three labels) to gate the exhaustion heuristic, and once for the full name here.
/// Those walks are redundant in the common case, because `_check_domain_member(x)` tests `x` and
/// every parent suffix of `x`, and the suffixes of the domain are a SUBSET of the suffixes of the
/// full name. So `member(full) == false` implies `member(domain) == false` — one walk answers both
/// whenever the answer is "not whitelisted", which is nearly every packet.
#[allow(clippy::too_many_arguments)]
fn check_domain_inner(
    st: &mut WorkerState,
    query: &str,
    sec: u64,
    usec: u32,
    ep: Endpoints,
    proto: &str,
    precomputed_whitelisted: Option<bool>,
) {
    // query = query.lower(); if ':' in query: query = query.split(':', 1)[0]
    //
    // Borrowed unless the name actually needs changing. Real DNS traffic is already lowercase and
    // portless, so this used to allocate a copy of every query for nothing.
    let trimmed = match query.find(':') {
        Some(idx) => &query[..idx],
        None => query,
    };
    let lowered: Cow<'_, str> = if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    };
    let q: &str = lowered.as_ref();

    // if query.replace('.', "").isdigit(): return   (an IP address, not a domain)
    let without_dots = q.bytes().filter(|b| *b != b'.').count();
    if without_dots > 0 && q.bytes().all(|b| b == b'.' || b.is_ascii_digit()) {
        return;
    }

    if st.domain_clean.contains(q) {
        st.metrics.cache_hits += 1;
        return;
    }
    st.metrics.cache_misses += 1;

    let mut result = false;
    let whitelisted = match precomputed_whitelisted {
        Some(v) => v,
        None => st.check_domain_whitelisted(q),
    };
    if settings::is_valid_dns_name(q) && !whitelisted {
        let dots = Dots::of(q);
        let label_count = dots.label_count();
        let first_label = dots.label(q, 0);

        // Reference: https://www.virustotal.com/gui/domain/ip-adress.com/relations
        if q.ends_with(".ip-adress.com") {
            let base = dots.prefix_upto(q, label_count.saturating_sub(2));
            if let Some(info) = st.trails.db().get(base) {
                let (i, r) = (info.info.to_string(), info.reference.to_string());
                result = true;
                let trail = format!("{base}(.ip-adress.com)");
                emit_ep(st, sec, usec, ep, proto, TRAIL::DNS, Field::Text(trail), &i, &r);
            }
        }

        if !result {
            // The parent walk: `for i in range(len(parts)): domain = '.'.join(parts[i:])`.
            // Each of those joins rebuilt a String; a suffix of a dotted name is already a
            // contiguous slice of it, so walk the dot offsets instead.
            let mut start = 0usize;
            loop {
                let domain = &q[start..];
                if let Some(hit) = st.trails.db().get(domain) {
                    let (info, reference) = (hit.info.to_string(), hit.reference.to_string());

                    let is_whole = start == 0;
                    let trail = if is_whole {
                        domain.to_string()
                    } else {
                        // `(prefix).suffix`, where the '.' before the suffix belongs to the suffix
                        format!("({}){}", &q[..start - 1], &q[start - 1..])
                    };

                    // e.g. ns2.nobel.su - an infrastructure name under a "suspicious"/"sinkhole"
                    // parent is not itself an indicator
                    let skip_ns = st.statics.ns_like_prefix.is_match(q)
                        && (info.contains("suspicious") || info.contains("sinkhole"));
                    // e.g. noip.com - the bare domain (or its www) of a dynamic-DNS / free-web
                    // provider is not an indicator
                    let skip_dynamic =
                        (is_whole || first_label == "www") && (info.contains("dynamic") || info.contains("free web"));

                    if !skip_ns && !skip_dynamic {
                        result = true;
                        emit_ep(st, sec, usec, ep, proto, TRAIL::DNS, Field::Text(trail), &info, &reference);
                        break;
                    }
                }
                match memchr::memchr(b'.', &q.as_bytes()[start..]) {
                    Some(rel) => start += rel + 1,
                    None => break,
                }
            }
        }

        if !result
            && st.cfg.use_heuristics
            && st.heuristic_enabled("long_domain")
            && first_label.chars().count() > settings::SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD
            && !first_label.contains('-')
        {
            {
                let trail = if label_count > 2 {
                    format!("({}).{}", dots.prefix_upto(q, label_count - 2), dots.suffix_from(q, label_count - 2))
                } else if label_count == 2 {
                    format!("({}).{}", first_label, dots.last_label(q))
                } else {
                    q.to_string()
                };
                if !trail.is_empty() && !st.statics.whitelist_long_domain.is_match(&trail) {
                    result = true;
                    emit_ep(
                        st,
                        sec,
                        usec,
                        ep,
                        proto,
                        TRAIL::DNS,
                        Field::Text(trail),
                        "long domain (suspicious)",
                        "(heuristic)",
                    );
                }
            }
        }

        if !result && !st.trails.db().regex().is_empty() {
            // The wildcard/regex static-trail fallback.
            let hit = st.trails.db().regex().find(q).map(|h| (h.start, h.end, h.candidate.to_string()));
            if let Some((start, end, candidate)) = hit {
                if let Some(info) = st.trails.db().get(&candidate) {
                    let (i, r) = (info.info.to_string(), info.reference.to_string());
                    result = true;
                    let mut trail = q[start..end].to_string();
                    let prefix = &q[..start];
                    let suffix = &q[end..];
                    if !prefix.is_empty() {
                        trail = format!("({prefix}){trail}");
                    }
                    if !suffix.is_empty() {
                        trail = format!("{trail}({suffix})");
                    }
                    let trail = trail.replace(".)", ").");
                    emit_ep(st, sec, usec, ep, proto, TRAIL::DNS, Field::Text(trail), &i, &r);
                }
            }
        }

        if !result && q.contains(".onion.") {
            // re.sub(r"(\.onion)(\..*)", r"\1($2)", query)
            let trail = st.statics.onion_suffix.replace(q, "$1($2)").to_string();
            let base = trail.split('(').next().unwrap_or("").to_string();
            if let Some(info) = st.trails.db().get(&base) {
                let (i, r) = (info.info.to_string(), info.reference.to_string());
                result = true;
                emit_ep(st, sec, usec, ep, proto, TRAIL::DNS, Field::Text(trail), &i, &r);
            }
        }
    }

    if !result {
        st.domain_clean.insert_if_seen_before(q.to_string(), ());
    }
}

// ---------------------------------------------------------------------------
// _process_packet
// ---------------------------------------------------------------------------

/// `sensor.py:_process_packet()` — processes one raw IP-layer packet.
pub fn process_packet(st: &mut WorkerState, packet_bytes: &[u8], sec: u64, usec: u32, ip_offset: usize) {
    st.last_sec = sec;
    if st.cfg.use_heuristics {
        heuristics_sweep(st, sec, usec);
    }

    let Some(ip_data) = packet_bytes.get(ip_offset..) else {
        st.metrics.packets_ignored += 1;
        return;
    };

    let header = match packet::parse_ip(ip_data) {
        Ok(h) => h,
        Err(Drop::NotIp) => {
            st.metrics.packets_ignored += 1;
            return;
        }
        Err(Drop::Fragment) => {
            st.metrics.packets_fragment += 1;
            return;
        }
        Err(Drop::Truncated) => {
            st.metrics.packets_truncated += 1;
            return;
        }
    };

    st.metrics.packets_processed += 1;

    // Condensed store: both endpoints of every connection, before any protocol dispatch.
    // Same position as `sensor.py`'s `meta.observe_conn()` call — after the IP header is parsed
    // and fragments have been dropped, so it sees exactly the packets Python's does.
    st.meta.observe_conn(header.src, header.dst, sec);

    // TLS/QUIC handshake-head SNI -> _check_domain, the one detection the pcapy-ng fast
    // prefilter adds (core/fastfilter.py:head_sni). Gated on the same switches.
    // Two independent features share the TLS handshake record, so either one is reason enough
    // to look at it: SNI extraction (the prefilter's contribution) and certificate matching.
    if (st.cfg.use_fast_prefilter && st.cfg.fast_flow_cutoff > 0) || st.cfg.check_tls_certificates {
        handshake_sni(st, ip_data, &header, sec, usec);
    }

    match header.protocol {
        6 => tcp(st, packet_bytes, ip_data, &header, sec, usec),
        17 => udp(st, packet_bytes, ip_data, &header, sec, usec),
        other => other_proto(st, ip_data, &header, other, sec, usec),
    }
}

/// `core/fastfilter.py:head_sni()` — pull the SNI out of a TLS ClientHello (TCP) or a QUIC
/// Initial (UDP) and run it through the normal domain check, so malicious domains are
/// surfaced on encrypted traffic.
///
/// NOTE: restricted to IPv4 because `head_sni`'s `_ip_at()` only recognises IPv4 headers.
/// Extending it to IPv6 would detect strictly more, but would also diverge from the Python
/// sensor, so it is left as-is (see docs/COMPATIBILITY.md).
fn handshake_sni(st: &mut WorkerState, ip_data: &[u8], header: &packet::IpHeader, sec: u64, usec: u32) {
    if header.version != 4 {
        return;
    }
    match header.protocol {
        6 => {
            let Some(tcph) = packet::parse_tcp(ip_data, header.header_len) else { return };
            let payload = tcph.payload(ip_data, header.header_len);
            if payload.first() != Some(&0x16) {
                return;
            }
            let ep = Endpoints { src: header.src, src_port: tcph.src_port, dst: header.dst, dst_port: tcph.dst_port };
            // The same record type carries both directions: a ClientHello gives a domain, the
            // server's flight gives a certificate. A packet is one or the other, so the cheaper
            // ClientHello parse runs first and short-circuits.
            if st.cfg.use_fast_prefilter && st.cfg.fast_flow_cutoff > 0 {
                if let Some(sni) = crate::protocols::tls::client_hello_sni(payload) {
                    check_domain(st, &sni, sec, usec, ep, PROTO::TCP);
                    return;
                }
            }
            if st.cfg.check_tls_certificates {
                check_server_certificate(st, payload, sec, usec, ep);
            }
        }
        // QUIC carries no cleartext certificate, so this arm stays the prefilter's alone.
        17 if st.cfg.use_fast_prefilter && st.cfg.fast_flow_cutoff > 0 => {
            let Some(udph) = packet::parse_udp(ip_data, header.header_len) else { return };
            let payload = packet::udp_payload(ip_data, header.header_len);
            if payload.first().map(|b| b & 0x80 == 0).unwrap_or(true) {
                return;
            }
            let Some(sni) = crate::protocols::quic::extract_sni_from_quic_initial(payload) else { return };
            let ep = Endpoints { src: header.src, src_port: udph.src_port, dst: header.dst, dst_port: udph.dst_port };
            check_domain(st, &sni, sec, usec, ep, PROTO::UDP);
        }
        _ => {}
    }
}

/// Match a TLS server certificate against the trail set by its SHA-1 fingerprint.
///
/// Certificate fingerprints are what threat feeds publish for C2 servers (abuse.ch SSLBL lists
/// ~10,000 of them, still growing), and they are the one indicator that survives when a C2 moves
/// address and domain: re-keying costs the operator more than re-registering.
///
/// The fingerprint is looked up in the ordinary trail store, so it inherits updating,
/// whitelisting and atomic reloads with no separate machinery — a 40-character hex string is
/// just another exact-match key.
fn check_server_certificate(st: &mut WorkerState, payload: &[u8], sec: u64, usec: u32, ep: Endpoints) {
    let Some(der) = crate::protocols::tls::server_certificate_der(payload) else { return };
    let digest = sha1_hex(der);
    st.metrics.trail_lookups += 1;
    let Some(hit) = st.trails.db().get(&digest).map(|v| (v.info.to_string(), v.reference.to_string())) else {
        return;
    };
    let (info, reference) = hit;
    emit_ep(st, sec, usec, ep, PROTO::TCP, TRAIL::CERT, Field::Text(digest), &info, &reference);
}

/// Lower-case hex SHA-1, the form certificate feeds publish and therefore the form the trail
/// keys are in.
fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut hex = String::with_capacity(40);
    for byte in out {
        hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        hex.push(char::from_digit((byte & 0xf) as u32, 16).unwrap_or('0'));
    }
    hex
}

/// The per-second heuristics sweep at the top of `_process_packet`.
fn heuristics_sweep(st: &mut WorkerState, sec: u64, usec: u32) {
    let connect_sec = st.connect_sec;
    st.connect_sec = sec;
    if sec <= connect_sec {
        return;
    }

    // --- port scanning ---
    if st.heuristic_enabled("port_scanning") {
        for (src, dst, detail) in st.scan.port_scan_candidates(settings::PORT_SCANNING_THRESHOLD) {
            // NOT locality-suppressed: internal->internal lateral recon is a real detection.
            if st.whitelist.check_whitelisted_ip(src) {
                continue;
            }
            let trail = src.render().as_str().to_string();
            emit_ep(
                st,
                sec,
                usec,
                Endpoints { src, src_port: detail.src_port, dst, dst_port: detail.dst_port },
                PROTO::TCP,
                TRAIL::IP,
                Field::Text(trail),
                "potential port scanning",
                "(heuristic)",
            );
            st.scan.mark_port_alerted(src, dst);
        }
    } else {
        // Python still marks nothing and simply skips logging; the accumulator keeps
        // growing until the window boundary, which is what happens there too.
    }

    // --- infection scanning ---
    if st.heuristic_enabled("infection") {
        let prefix = st.local_prefix();
        for (src, dst_port, detail) in st.scan.infection_candidates(settings::INFECTION_SCANNING_THRESHOLD) {
            if !src.render().as_str().starts_with(&prefix) {
                continue;
            }
            emit_ep(
                st,
                sec,
                usec,
                Endpoints { src, src_port: detail.src_port, dst: detail.dst_ip, dst_port },
                PROTO::TCP,
                TRAIL::PORT,
                Field::Int(dst_port as i64),
                "potential infection",
                "(heuristic)",
            );
            st.scan.mark_infection_alerted(src, dst_port);
        }
    }

    // --- web scanning ---
    if st.heuristic_enabled("web_scanning") {
        for (src, dst, detail) in st.scan.web_scan_candidates(settings::WEB_SCANNING_THRESHOLD) {
            // FP guards: whitelisted sources and internal<->internal traffic (reverse
            // proxies, service meshes, health checks) are not web scanning.
            if st.whitelist.check_whitelisted_ip(src) || (src.is_local() && dst.is_local()) {
                continue;
            }
            emit_ep(
                st,
                detail.sec,
                detail.usec,
                Endpoints { src, src_port: detail.src_port, dst, dst_port: detail.dst_port },
                PROTO::TCP,
                TRAIL::PATH,
                Field::Text("*".to_string()),
                "potential web scanning",
                "(heuristic)",
            );
            st.scan.mark_path_alerted(src, dst);
        }
    }

    // --- UDP scanning ---
    if st.heuristic_enabled("udp_scanning") {
        for (src, dst, detail) in st.scan.udp_scan_candidates(settings::PORT_SCANNING_THRESHOLD) {
            if st.whitelist.check_whitelisted_ip(src) {
                continue;
            }
            let trail = src.render().as_str().to_string();
            emit_ep(
                st,
                sec,
                usec,
                Endpoints { src, src_port: detail.src_port, dst, dst_port: detail.dst_port },
                PROTO::UDP,
                TRAIL::IP,
                Field::Text(trail),
                "potential udp scanning",
                "(heuristic)",
            );
            st.scan.mark_udp_alerted(src, dst);
        }
    }

    // SLIDING WINDOW: state is cleared only at the window boundary, so a scan spread over
    // up to SCAN_WINDOW seconds still accumulates.
    if sec.saturating_sub(st.scan.window_start) >= st.cfg.scan_window {
        st.scan.clear_window(sec);
    }
}

fn tcp(st: &mut WorkerState, packet_bytes: &[u8], ip_data: &[u8], header: &packet::IpHeader, sec: u64, usec: u32) {
    let Some(tcph) = packet::parse_tcp(ip_data, header.header_len) else {
        st.metrics.packets_truncated += 1;
        return;
    };
    let ep = Endpoints { src: header.src, src_port: tcph.src_port, dst: header.dst, dst_port: tcph.dst_port };

    // NOTE: sensor.py runs a plugin-only pre-pass here for flags != 2. Plugins are Python
    // callables and are not supported by this sensor (see docs/COMPATIBILITY.md), so the
    // pre-pass - which never writes an event (skip_write=True) - has no equivalent.

    if tcph.flags == 2 {
        syn(st, ep, sec, usec);
        return;
    }

    if st.cfg.use_heuristics
        && settings::STEALTH_FLAGS.contains(&tcph.flags)
        && !ep.dst.is_localhost()
        && st.heuristic_enabled("port_scanning")
    {
        // NULL (0x00) / bare-FIN (0x01) / XMAS (0x29) are combinations no legitimate stack
        // sends, so they feed the same port-scan accumulator as SYN. ACK/Maimon scans are
        // deliberately excluded (a bare ACK is normal mid-connection traffic).
        st.scan.track_port(
            ep.src,
            ep.dst,
            ep.dst_port,
            PortDetail { sec, usec, src_port: ep.src_port, dst_port: ep.dst_port },
        );
        return;
    }

    let payload = tcph.payload(ip_data, header.header_len);
    // Only HTTP is acted on below, so skip the (costly) full-payload decode for the bulk of
    // line-rate traffic (TLS/443).
    if memchr::memmem::find(payload, b"HTTP/").is_none() {
        return;
    }
    // `from_utf8_lossy` goes through `Utf8Chunks`, which the profile showed at 4.5% of the
    // packet path. `str::from_utf8` uses the optimised validator and borrows; the lossy path is
    // only needed for genuinely invalid UTF-8.
    let tcp_data: Cow<'_, str> = match std::str::from_utf8(payload) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(String::from_utf8_lossy(payload).into_owned()),
    };

    if tcp_data.starts_with("HTTP/") {
        http_response(st, &tcp_data, ep, sec, usec);
    }

    if st.statics.f_sp_http.find(tcp_data.as_bytes()).is_some() {
        http_request(st, packet_bytes, &tcp_data, ep, sec, usec);
    }
}

fn syn(st: &mut WorkerState, ep: Endpoints, sec: u64, usec: u32) {
    let stamp = FlowStamp { sec, src: ep.src, src_port: ep.src_port, dst: ep.dst, dst_port: ep.dst_port };
    let previous = st.last_syn.replace(stamp);
    if previous == Some(stamp) {
        return; // skip bursts
    }

    st.metrics.trail_lookups += 1;
    let dst_hit = st.trails.db().get_ip(ep.dst).map(|v| (v.info.to_string(), v.reference.to_string()));
    let dst_port_hit =
        st.trails.db().get_ip_port(ep.dst, ep.dst_port).map(|v| (v.info.to_string(), v.reference.to_string()));

    if dst_hit.is_some() || dst_port_hit.is_some() {
        let previous_logged = st.last_logged_syn.replace(stamp);
        if previous_logged != Some(stamp) {
            // IPORT iff the matched key is the addr_port form (not the bare IP).
            let (trail, info, reference, trail_type) = match dst_port_hit {
                Some((info, reference)) => {
                    (ep.dst.addr_port(ep.dst_port).as_str().to_string(), info, reference, TRAIL::IPORT)
                }
                None => {
                    let (info, reference) = dst_hit.expect("one of the two matched");
                    (ep.dst.render().as_str().to_string(), info, reference, TRAIL::IP)
                }
            };
            let parking_off_web = info.contains("parking site") && !matches!(ep.dst_port, 80 | 443);
            if !info.contains("attacker") && !parking_off_web {
                emit_ep(st, sec, usec, ep, PROTO::TCP, trail_type, Field::Text(trail), &info, &reference);
            }
        }
    } else if !ep.dst.is_localhost() {
        let src_hit = st.trails.db().get_ip(ep.src).map(|v| (v.info.to_string(), v.reference.to_string()));
        let src_port_hit =
            st.trails.db().get_ip_port(ep.src, ep.src_port).map(|v| (v.info.to_string(), v.reference.to_string()));
        if src_hit.is_some() || src_port_hit.is_some() {
            let previous_logged = st.last_logged_syn.replace(stamp);
            if previous_logged != Some(stamp) {
                let (trail, info, reference, trail_type) = match src_port_hit {
                    Some((info, reference)) => {
                        (ep.src.addr_port(ep.src_port).as_str().to_string(), info, reference, TRAIL::IPORT)
                    }
                    None => {
                        let (info, reference) = src_hit.expect("one of the two matched");
                        (ep.src.render().as_str().to_string(), info, reference, TRAIL::IP)
                    }
                };
                if !info.contains("malware") {
                    emit_ep(st, sec, usec, ep, PROTO::TCP, trail_type, Field::Text(trail), &info, &reference);
                }
            }
        }
    }

    if st.cfg.use_heuristics && !ep.dst.is_localhost() {
        st.scan.track_port(
            ep.src,
            ep.dst,
            ep.dst_port,
            PortDetail { sec, usec, src_port: ep.src_port, dst_port: ep.dst_port },
        );
        if settings::POTENTIAL_INFECTION_PORTS.contains(&ep.dst_port) {
            st.scan.track_infection(
                ep.src,
                ep.dst_port,
                ep.dst,
                InfectionDetail { sec, usec, src_port: ep.src_port, dst_ip: ep.dst },
            );
        }
    }
}

/// The `tcp_data.startswith("HTTP/")` branch: sinkhole banner, seized-domain title and
/// suspicious content types.
fn http_response(st: &mut WorkerState, tcp_data: &str, ep: Endpoints, sec: u64, usec: u32) {
    // re.search(GENERIC_SINKHOLE_REGEX, tcp_data[:2000]) - a CHARACTER slice in Python
    let head: String = tcp_data.chars().take(2000).collect();
    if let Some(m) = st.statics.generic_sinkhole.find(&head) {
        let trail = m.as_str().to_string();
        emit_ep(
            st,
            sec,
            usec,
            ep,
            PROTO::TCP,
            TRAIL::HTTP,
            Field::Text(trail),
            "sinkhole response (malware)",
            "(heuristic)",
        );
    } else if let Some(index) = tcp_data.find("<title>") {
        // Only extract when the closing tag is in the captured bytes; otherwise Python's
        // find() == -1 would grab most of the body as a bogus multi-KB trail.
        let start = index + "<title>".len();
        if let Some(rel_end) = tcp_data[start..].find("</title>") {
            let title = &tcp_data[start..start + rel_end];
            if st.statics.seized_domain.is_match(title) {
                let trail = title.to_string();
                emit_ep(
                    st,
                    sec,
                    usec,
                    ep,
                    PROTO::TCP,
                    TRAIL::HTTP,
                    Field::Text(trail),
                    "seized domain (suspicious)",
                    "(heuristic)",
                );
            }
        }
    }

    if let Some(value) =
        http::header_value_with(tcp_data, &st.statics.f_content_type, "\r\nContent-Type:".len(), &st.statics.f_crlf)
    {
        let content_type = value.trim().to_lowercase();
        if !content_type.is_empty() && st.statics.suspicious_content_types.contains(content_type.as_str()) {
            emit_ep(
                st,
                sec,
                usec,
                ep,
                PROTO::TCP,
                TRAIL::HTTP,
                Field::Text(content_type),
                "content type (suspicious)",
                "(heuristic)",
            );
        }
    }
}

/// The HTTP request branch of `_process_packet`.
/// Apply `SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS`, borrowing when nothing needs encoding.
fn force_encode(value: &str) -> Cow<'_, str> {
    if !settings::SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS.iter().any(|(ch, _)| value.contains(*ch)) {
        return Cow::Borrowed(value);
    }
    let mut out = value.to_string();
    for (ch, replacement) in settings::SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS {
        out = out.replace(ch, replacement);
    }
    Cow::Owned(out)
}

fn http_request(st: &mut WorkerState, packet_bytes: &[u8], tcp_data: &str, ep: Endpoints, sec: u64, usec: u32) {
    let Some(line) = http::request_line(tcp_data, &st.statics.f_crlf, &st.statics.f_sp_http) else { return };
    let method = line.method;
    // Borrowed unless the request actually needs rewriting. A plain `GET /x HTTP/1.1` with a
    // lower-case Host used to allocate a copy of the method, the path, the destination address
    // and the host before doing any work.
    let mut path: Cow<'_, str> = if line.path.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(line.path.to_lowercase())
    } else {
        Cow::Borrowed(line.path)
    };

    let dst_addr = ep.dst.render();
    let dst_rendered: &str = dst_addr.as_str();
    let mut host: Cow<'_, str> = Cow::Borrowed(dst_rendered);

    match http::header_value_with(tcp_data, &st.statics.f_host, "\r\nHost:".len(), &st.statics.f_crlf) {
        Some(raw_host) => {
            let trimmed = raw_host.trim();
            let trimmed = trimmed.strip_suffix(":80").unwrap_or(trimmed);
            host = if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
                Cow::Owned(trimmed.to_lowercase())
            } else {
                Cow::Borrowed(trimmed)
            };

            let first_is_alpha = host.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false);
            let dst_trail = st.trails.db().get_ip(ep.dst).map(|v| (v.info.to_string(), v.reference.to_string()));

            if let (false, true, Some((info, reference))) = (host.is_empty(), first_is_alpha, dst_trail) {
                let host_only = host.split(':').next().unwrap_or("");
                let trail = format!("{dst_rendered} ({host_only})");
                emit_ep(st, sec, usec, ep, PROTO::TCP, TRAIL::IP, Field::Text(trail), &info, &reference);
            } else if st.statics.dotted_host.is_match(&host)
                && st.statics.suspicious_direct_ip_url.is_match(&format!("{host}{path}"))
            {
                let prefix = st.local_prefix();
                if !dst_rendered.starts_with(&prefix) {
                    let trail = format!("({host}){path}");
                    emit_ep(
                        st,
                        sec,
                        usec,
                        ep,
                        PROTO::TCP,
                        TRAIL::HTTP,
                        Field::Text(trail),
                        "potential iot-malware download (suspicious)",
                        "(heuristic)",
                    );
                    return;
                }
            } else if st.cfg.check_host_domains {
                let host_copy = host.to_string();
                check_domain(st, &host_copy, sec, usec, ep, PROTO::TCP);
            }
        }
        None => {
            if st.cfg.use_heuristics && st.cfg.check_missing_host {
                let trail = format!("{host}{path}");
                emit_ep(
                    st,
                    sec,
                    usec,
                    ep,
                    PROTO::TCP,
                    TRAIL::HTTP,
                    Field::Text(trail),
                    "missing host header (suspicious)",
                    "(heuristic)",
                );
            }
        }
    }

    // Borrowed: copying the whole request body on every HTTP packet is pure overhead.
    let post_data: Option<&str> = st.statics.f_crlf2.find(tcp_data.as_bytes()).map(|i| &tcp_data[i + 4..]);

    let mut url: Option<String> = None;
    if st.cfg.use_heuristics && path.starts_with('/') {
        let segment = path.split('/').nth(1).unwrap_or("");
        st.scan.track_path(
            ep.src,
            ep.dst,
            segment,
            PathDetail { sec, usec, src_port: ep.src_port, dst_port: ep.dst_port },
        );
    } else if st.cfg.use_heuristics
        && ep.dst_port == 80
        && path.starts_with("http://")
        && st.statics.proxy_probe_pre_condition.is_match(path.as_ref())
        && !{
            let probe_host = path.split('/').nth(2).unwrap_or("").to_string();
            st.check_domain_whitelisted(&probe_host)
        }
    {
        // trail = re.sub(r"(http://[^/]+/)(.+)", r"\g<1>(\g<2>)", path) then the host is
        // stripped of its port and trailing dots.
        let staged = st.statics.proxy_probe_path.replace(&path, "$1($2)").to_string();
        let trail = st
            .statics
            .proxy_probe_host
            .replace(&staged, |caps: &regex::Captures| {
                let host = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let cleaned = host.split(':').next().unwrap_or("").trim_end_matches('.');
                format!("{}{}", caps.get(1).map(|m| m.as_str()).unwrap_or(""), cleaned)
            })
            .to_string();
        emit_ep(
            st,
            sec,
            usec,
            ep,
            PROTO::TCP,
            TRAIL::HTTP,
            Field::Text(trail),
            "potential proxy probe (suspicious)",
            "(heuristic)",
        );
        return;
    } else if path.contains("://") {
        let unquoted_path = http::unquote(&path);
        // NOTE: to prevent malware-domain FPs caused by outside scanners
        if !st.statics.code_execution.is_match(unquoted_path.as_ref()) {
            let mut candidate = path.split_once("://").map(|(_, rest)| rest).unwrap_or("").to_string();
            if !candidate.contains('/') {
                candidate.push('/');
            }
            let (h, rest) = candidate.split_once('/').unwrap_or((candidate.as_str(), ""));
            let mut h = h.to_string();
            if h.ends_with(":80") {
                h.truncate(h.len() - 3);
            }
            path = Cow::Owned(format!("/{rest}"));
            host = Cow::Owned(h);
            url = Some(candidate.clone());
            let proxy_domain = host.split(':').next().unwrap_or("").to_string();
            check_domain(st, &proxy_domain, sec, usec, ep, PROTO::TCP);
        }
    } else if method == "CONNECT" {
        if let Some((h, rest)) = path.clone().split_once('/') {
            host = Cow::Owned(h.to_string());
            path = Cow::Owned(format!("/{rest}"));
        } else {
            host = Cow::Owned(path.to_string());
            path = Cow::Borrowed("/");
        }
        if let Some(stripped) = host.strip_suffix(":80") {
            host = Cow::Owned(stripped.to_string());
        }
        url = Some(format!("{host}{path}"));
        let proxy_domain = host.split(':').next().unwrap_or("").to_string();
        check_domain(st, &proxy_domain, sec, usec, ep, PROTO::TCP);
    }

    // `url` is only read when a trail actually matches, so it is not built up front any more.
    let prebuilt_url = url;

    if st.cfg.use_heuristics {
        if let Some(raw_ua) =
            http::header_value_with(tcp_data, &st.statics.f_user_agent, "\r\nUser-Agent:".len(), &st.statics.f_crlf)
        {
            let user_agent = http::unquote(raw_ua).trim().to_string();
            if !user_agent.is_empty() {
                let cached = st.user_agent.get(&user_agent).cloned();
                let result = match cached {
                    Some(v) => {
                        st.metrics.cache_hits += 1;
                        v
                    }
                    None => {
                        st.metrics.cache_misses += 1;
                        let computed = classify_user_agent(st, &user_agent);
                        st.user_agent.insert(user_agent.clone(), computed.clone());
                        computed
                    }
                };
                if let Some(trail) = result {
                    emit_ep(
                        st,
                        sec,
                        usec,
                        ep,
                        PROTO::TCP,
                        TRAIL::UA,
                        Field::Text(trail),
                        "user agent (suspicious)",
                        "(heuristic)",
                    );
                }
            }
        }
    }

    let host_for_whitelist = host.clone();
    if st.check_domain_whitelisted(&host_for_whitelist) {
        return;
    }

    if path.contains("//") {
        path = Cow::Owned(path.replace("//", "/"));
    }
    let unquoted_path = http::unquote_cow(&path);
    let unquoted_post_data = http::unquote_cow(post_data.unwrap_or(""));

    let checks = http::build_checks(&path, post_data, &unquoted_post_data, &st.statics.param_value);

    // One reusable buffer instead of `format!` per (check, prefix) pair - `build_checks` returns
    // up to six candidates and each was tried with and without the host prefix.
    let mut candidate = String::with_capacity(host.len() + 96);
    for check in checks.iter().filter(|c| !c.is_empty()) {
        for prefix in ["", host.as_ref()] {
            candidate.clear();
            candidate.push_str(prefix);
            candidate.push_str(check);
            let Some(hit) = st.trails.db().get(&candidate) else { continue };
            let (info, reference) = (hit.info.to_string(), hit.reference.to_string());

            if !path.contains('?') && candidate.contains('?') && post_data.is_some() {
                let body = post_data.unwrap_or("").trim().to_string();
                let trail = format!("{host}({path} \\({method} {body}\\))");
                emit_ep(st, sec, usec, ep, PROTO::TCP, TRAIL::HTTP, Field::Text(trail), &info, &reference);
            } else {
                // parts = url.split(check); every non-empty part is bracketed
                let url = match &prebuilt_url {
                    Some(u) => Cow::Borrowed(u.as_str()),
                    None => Cow::Owned(format!("{host}{path}")),
                };
                let trail = bracket_around(&url, &candidate);
                emit_ep(st, sec, usec, ep, PROTO::TCP, TRAIL::URL, Field::Text(trail), &info, &reference);
            }
            return;
        }
    }

    // `format!("{host}/")` allocated on every request; the candidate buffer is already sized.
    candidate.clear();
    candidate.push_str(&host);
    candidate.push('/');
    if st.trails.db().get(&candidate).is_some() {
        let hit = st.trails.db().get(&candidate).expect("just probed");
        let (info, reference) = (hit.info.to_string(), hit.reference.to_string());
        emit_ep(st, sec, usec, ep, PROTO::TCP, TRAIL::URL, Field::Text(candidate.clone()), &info, &reference);
        return;
    }

    if !st.cfg.use_heuristics {
        return;
    }

    // Forwarded-for headers are searched in the RAW packet bytes, case-insensitively.
    let mut src_ip_field = ep.src.render().as_str().to_string();
    if let Some(caps) = st.statics.forwarded_for.captures(packet_bytes) {
        if let Some(m) = caps.get(2) {
            let forwarded = String::from_utf8_lossy(m.as_bytes()).to_string();
            src_ip_field = format!("{src_ip_field},{forwarded}");
        }
    }

    // `SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS` rewriting allocated once per character in the
    // table, whether or not the character occurred. Check first; ordinary paths contain none.
    let encoded_path = force_encode(&path);
    let encoded_post = post_data.map(force_encode);

    let unquoted_lower: Cow<'_, str> = if unquoted_path.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(unquoted_path.to_lowercase())
    } else {
        Cow::Borrowed(unquoted_path.as_ref())
    };
    if !st.statics.whitelist_request_paths.is_match(unquoted_lower.as_ref()) {
        if st.statics.pre_condition.is_match(unquoted_path.as_ref()) {
            let found = match st.path_findings.get(unquoted_path.as_ref()).cloned() {
                Some(v) => {
                    st.metrics.cache_hits += 1;
                    v
                }
                None => {
                    st.metrics.cache_misses += 1;
                    let mut found = String::new();
                    for (desc, re) in &st.statics.suspicious_http_request {
                        if re.is_match(unquoted_path.as_ref()) {
                            found = desc.to_string();
                            break;
                        }
                    }
                    st.path_findings.insert(unquoted_path.to_string(), found.clone());
                    found
                }
            };
            // Python: `if found and not ("data leakage" in found and is_local(dst_ip))`
            let local_data_leakage = found.contains("data leakage") && ep.dst.is_local();
            if !found.is_empty() && !local_data_leakage {
                let trail = format!("{host}({encoded_path})");
                let info = format!("{found} (suspicious)");
                emit(
                    st,
                    sec,
                    usec,
                    &src_ip_field,
                    Field::port(ep.src_port),
                    Field::Text(dst_rendered.to_string()),
                    Field::port(ep.dst_port),
                    PROTO::TCP,
                    TRAIL::URL,
                    Field::Text(trail),
                    &info,
                    "(heuristic)",
                );
                return;
            }
        }

        if st.statics.pre_condition.is_match(unquoted_post_data.as_ref()) {
            let found = match st.post_findings.get(unquoted_post_data.as_ref()).cloned() {
                Some(v) => {
                    st.metrics.cache_hits += 1;
                    v
                }
                None => {
                    st.metrics.cache_misses += 1;
                    let mut found = String::new();
                    for (desc, re) in &st.statics.suspicious_http_request {
                        if re.is_match(unquoted_post_data.as_ref()) {
                            found = desc.to_string();
                            break;
                        }
                    }
                    st.post_findings.insert(unquoted_post_data.to_string(), found.clone());
                    found
                }
            };
            if !found.is_empty() {
                let body = encoded_post.as_deref().unwrap_or("").trim().to_string();
                let trail = format!("{host}({encoded_path} \\({method} {body}\\))");
                let info = format!("{found} (suspicious)");
                emit(
                    st,
                    sec,
                    usec,
                    &src_ip_field,
                    Field::port(ep.src_port),
                    Field::Text(dst_rendered.to_string()),
                    Field::port(ep.dst_port),
                    PROTO::TCP,
                    TRAIL::HTTP,
                    Field::Text(trail),
                    &info,
                    "(heuristic)",
                );
                return;
            }
        }
    }

    if encoded_path.contains('.') {
        let url: Cow<'_, str> = match &prebuilt_url {
            Some(u) => Cow::Borrowed(u.as_str()),
            None => Cow::Owned(format!("{host}{path}")),
        };
        let parts = http::urlparse_path_query(&url);
        let lowered_path = encoded_path.to_lowercase();
        let filename = parts.path.rsplit('/').next().unwrap_or("");
        let (name, extension) = http::splitext(filename);
        let trail = format!("{host}({lowered_path})");

        if st.statics.suspicious_download_extensions.contains(extension)
            && !ep.dst.is_local()
            && !st.statics.whitelist_direct_download.is_match(&lowered_path)
            && !parts.query.contains('=')
            && name.chars().count() < 10
        {
            let info = format!("direct {extension} download (suspicious)");
            emit(
                st,
                sec,
                usec,
                &src_ip_field,
                Field::port(ep.src_port),
                Field::Text(dst_rendered.to_string()),
                Field::port(ep.dst_port),
                PROTO::TCP,
                TRAIL::URL,
                Field::Text(trail),
                &info,
                "(heuristic)",
            );
        } else {
            let mut hit = None;
            for (desc, re) in &st.statics.suspicious_http_path {
                if re.is_match(filename) {
                    hit = Some(desc.to_string());
                    break;
                }
            }
            if let Some(desc) = hit {
                let info = format!("{desc} (suspicious)");
                emit(
                    st,
                    sec,
                    usec,
                    &src_ip_field,
                    Field::port(ep.src_port),
                    Field::Text(dst_rendered.to_string()),
                    Field::port(ep.dst_port),
                    PROTO::TCP,
                    TRAIL::URL,
                    Field::Text(trail),
                    &info,
                    "(heuristic)",
                );
            }
        }
    }
}

/// `parts = url.split(check); check.join("(%s)" % p if p else p for p in parts)`
fn bracket_around(url: &str, check: &str) -> String {
    let parts: Vec<&str> = url.split(check).collect();
    let mut out = String::with_capacity(url.len() + 4);
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push_str(check);
        }
        if part.is_empty() {
            continue;
        }
        out.push('(');
        out.push_str(part);
        out.push(')');
    }
    out
}

/// The user-agent classifier (`SUSPICIOUS_UA_REGEX` / `WHITELIST_UA_REGEX` block).
fn classify_user_agent(st: &WorkerState, user_agent: &str) -> Option<String> {
    if st.statics.whitelist_ua.is_match(user_agent) {
        return None;
    }
    let re = st.statics.suspicious_ua.as_ref()?;
    let m = re.find(user_agent)?;
    if m.as_str().is_empty() {
        return None;
    }
    let matched = m.as_str();

    // def _(value): return value.rstrip('\\').replace('(', "\\(").replace(')', "\\)")
    let esc = |value: &str| value.trim_end_matches('\\').replace('(', "\\(").replace(')', "\\)");

    let parts: Vec<&str> = user_agent.splitn(2, matched).collect();
    if parts.len() > 1 && !parts[0].is_empty() && !parts[parts.len() - 1].is_empty() {
        return Some(format!("{} ({})", esc(matched), esc(user_agent)));
    }
    // _(match).join(("(%s)" if part else "%s") % _(part) for part in parts)
    let rendered: Vec<String> =
        parts.iter().map(|part| if part.is_empty() { esc(part) } else { format!("({})", esc(part)) }).collect();
    Some(rendered.join(&esc(matched)))
}

fn udp(st: &mut WorkerState, packet_bytes: &[u8], ip_data: &[u8], header: &packet::IpHeader, sec: u64, usec: u32) {
    let Some(udph) = packet::parse_udp(ip_data, header.header_len) else {
        st.metrics.packets_truncated += 1;
        return;
    };
    let ep = Endpoints { src: header.src, src_port: udph.src_port, dst: header.dst, dst_port: udph.dst_port };

    let stamp = FlowStamp { sec, src: ep.src, src_port: ep.src_port, dst: ep.dst, dst_port: ep.dst_port };
    let previous = st.last_udp.replace(stamp);
    if previous == Some(stamp) {
        return; // skip bursts
    }

    if ep.src_port != 53 && ep.dst_port != 53 {
        st.metrics.trail_lookups += 1;
        let hit =
            st.trails.db().get_ip(ep.dst).map(|v| (ep.dst, v.info.to_string(), v.reference.to_string())).or_else(
                || st.trails.db().get_ip(ep.src).map(|v| (ep.src, v.info.to_string(), v.reference.to_string())),
            );

        if let Some((trail_ip, info, reference)) = hit {
            let previous_logged = st.last_logged_udp.replace(stamp);
            if previous_logged != Some(stamp) && !info.contains("malware") {
                let trail = trail_ip.render().as_str().to_string();
                emit_ep(st, sec, usec, ep, PROTO::UDP, TRAIL::IP, Field::Text(trail), &info, &reference);
            }
        }

        // UDP scan coverage (nmap -sU): one source hitting many distinct UDP ports on one
        // host. Benign UDP rarely fans many ports at one host.
        if st.cfg.use_heuristics && !ep.dst.is_localhost() {
            st.scan.track_udp(
                ep.src,
                ep.dst,
                ep.dst_port,
                PortDetail { sec, usec, src_port: ep.src_port, dst_port: ep.dst_port },
            );
        }
        return;
    }

    dns_packet(st, packet_bytes, ip_data, header, ep, sec, usec);
}

/// Label separator offsets of a dotted name, so suffixes and prefixes can be BORROWED from the
/// name instead of rebuilt with `join(".")`.
///
/// Only the tail offsets are recorded, because that is all the DNS query path indexes; the scan
/// is a single backward pass and the struct is a few words on the stack.
struct Dots {
    /// byte offset of the first '.' (if any)
    first: Option<usize>,
    /// byte offsets of the last three '.', nearest last
    tail: [Option<usize>; 3],
    count: usize,
    len: usize,
}

impl Dots {
    fn of(name: &str) -> Dots {
        let b = name.as_bytes();
        let mut d = Dots { first: None, tail: [None; 3], count: 0, len: b.len() };
        for (i, c) in b.iter().enumerate() {
            if *c == b'.' {
                if d.first.is_none() {
                    d.first = Some(i);
                }
                d.tail[2] = d.tail[1];
                d.tail[1] = d.tail[0];
                d.tail[0] = Some(i);
                d.count += 1;
            }
        }
        d
    }

    /// `len(query.split('.'))`
    #[inline]
    fn label_count(&self) -> usize {
        self.count + 1
    }

    /// `parts[-1]`
    #[inline]
    fn last_label<'a>(&self, name: &'a str) -> &'a str {
        match self.tail[0] {
            Some(i) => &name[i + 1..],
            None => name,
        }
    }

    /// `parts[index]` — only label 0 and the last three are addressable, which is all the
    /// query path needs.
    #[inline]
    fn label<'a>(&self, name: &'a str, index: usize) -> &'a str {
        let count = self.label_count();
        if index == 0 {
            return match self.first {
                Some(i) => &name[..i],
                None => name,
            };
        }
        let from_end = count - 1 - index;
        match from_end {
            0 => self.last_label(name),
            1 | 2 => {
                let start = self.tail[from_end].map(|i| i + 1).unwrap_or(0);
                let end = self.tail[from_end - 1].unwrap_or(self.len);
                &name[start..end]
            }
            _ => "",
        }
    }

    /// `parts[index..].join(".")` — begins just after the dot that precedes label `index`, which
    /// is the `count - index`-th dot counted from the end.
    #[inline]
    fn suffix_from<'a>(&self, name: &'a str, index: usize) -> &'a str {
        if index == 0 {
            return name;
        }
        match self.count.checked_sub(index) {
            Some(t) if t < self.tail.len() => match self.tail[t] {
                Some(i) => &name[i + 1..],
                None => name,
            },
            // `index` beyond the recorded tail (or past the last label): the query path never
            // asks for those, and an empty slice is the safe answer.
            _ => "",
        }
    }

    /// `parts[..index].join(".")` — ends at that same dot.
    #[inline]
    fn prefix_upto<'a>(&self, name: &'a str, index: usize) -> &'a str {
        if index == 0 {
            return "";
        }
        if index >= self.label_count() {
            return name;
        }
        match self.count.checked_sub(index) {
            Some(t) if t < self.tail.len() => match self.tail[t] {
                Some(i) => &name[..i],
                None => "",
            },
            _ => "",
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dns_packet(
    st: &mut WorkerState,
    _packet_bytes: &[u8],
    ip_data: &[u8],
    header: &packet::IpHeader,
    ep: Endpoints,
    sec: u64,
    usec: u32,
) {
    let dns_data = packet::udp_payload(ip_data, header.header_len);
    let Some(qd) = dns::qdcount(dns_data) else { return };
    if qd == 0 {
        return;
    }
    let Some(question) = dns::question(dns_data) else { return };
    let query = question.name;

    // `query.split('.')` used to build a Vec here, and every `parts[k..].join(".")` below
    // rebuilt a String. Both are unnecessary: the labels are contiguous inside `query`, so a
    // suffix of them IS a substring of it. `Dots` records the last few separator offsets in one
    // backward scan and hands out borrowed slices - no Vec, no join, no allocation, for the
    // shape that dominates DNS traffic.
    let dots = Dots::of(&query);
    if query.is_empty()
        || !settings::is_valid_dns_name(&query)
        || query.contains(".intranet.")
        || st.statics.ignore_dns_query_suffixes.contains(dots.last_label(&query))
    {
        return;
    }

    // Condensed store: the queried name, recorded after the same validity/ignore filter Python
    // applies and before the standard-query check, so a response-only capture still contributes.
    st.meta.observe_dns(&query, sec);

    let label_count = dots.label_count();
    // The whitelist verdict for the FULL query name, computed once for this packet. `query` is
    // already lower-case and contains no ':' (a DNS name that did would fail
    // `is_valid_dns_name`), so this is exactly what `check_domain` would compute for it.
    let wl_query = st.check_domain_whitelisted(&query);

    let Some(flags_high) = dns::flags_high(dns_data) else { return };
    let Some(flags_low) = dns::flags_low(dns_data) else { return };

    if flags_high & 0xfa == 0x00 {
        // standard query (recursive or not)
        let Some((type_, class_)) = dns::question_type_class(dns_data, question.name_end) else { return };

        if label_count > 2 {
            let domain = if label_count > 3 && dots.label(&query, label_count - 2).len() <= 3 {
                dots.suffix_from(&query, label_count - 3)
            } else {
                dots.suffix_from(&query, label_count - 2)
            };

            // One walk, reused. `wl_query` covers the domain's suffixes too, so when it is false
            // the domain cannot be whitelisted either and the second walk is skipped entirely.
            let wl_domain = if wl_query { st.check_domain_whitelisted(domain) } else { false };
            if !wl_domain {
                st.dns_exhaustion.maybe_hourly_reset(sec);

                // Dashed-quad first labels (e.g. 1-2-3-4.dyn.example) are not tracked.
                if !settings::is_dashed_quad(dots.label(&query, 0)) {
                    let subdomain_part = dots.prefix_upto(&query, label_count - 2);
                    match st.dns_exhaustion.observe(domain, subdomain_part, sec, settings::DNS_EXHAUSTION_THRESHOLD) {
                        Outcome::Continue => {}
                        Outcome::Alert => {
                            let trail = format!(
                                "({}).{}",
                                dots.prefix_upto(&query, label_count - 2),
                                dots.suffix_from(&query, label_count - 2)
                            );
                            // generic DNSBL check
                            if !st.statics.bl_word.is_match(&trail)
                                && !st.dns_exhaustion.has_local_lookup(domain)
                                && st.heuristic_enabled("dns_exhaustion")
                            {
                                emit_ep(
                                    st,
                                    sec,
                                    usec,
                                    ep,
                                    PROTO::UDP,
                                    TRAIL::DNS,
                                    Field::Text(trail),
                                    "potential dns exhaustion (suspicious)",
                                    "(heuristic)",
                                );
                                st.dns_exhaustion.mark_exhausted(domain);
                            }
                            return;
                        }
                        Outcome::Suppress => return,
                    }
                }
            }
        }

        // Reference: http://en.wikipedia.org/wiki/List_of_DNS_record_types
        if !matches!(type_, 12 | 28) && class_ == 1 {
            st.metrics.trail_lookups += 1;
            // The rendered destination is only needed on a hit; rendering it up front cost a
            // String allocation on every clean DNS query, which is nearly all of them.
            if let Some(hit) = st.trails.db().get_ip_port(ep.dst, ep.dst_port) {
                let (info, reference) = (hit.info.to_string(), hit.reference.to_string());
                let trail = format!("{} ({query})", ep.dst.render().as_str());
                emit_ep(st, sec, usec, ep, PROTO::UDP, TRAIL::IPORT, Field::Text(trail), &info, &reference);
            } else if let Some(hit) = st.trails.db().get_ip(ep.dst) {
                let (info, reference) = (hit.info.to_string(), hit.reference.to_string());
                let trail = format!("{} ({query})", ep.dst.render().as_str());
                emit_ep(st, sec, usec, ep, PROTO::UDP, TRAIL::IP, Field::Text(trail), &info, &reference);
            } else if let Some(hit) = st.trails.db().get_ip(ep.src) {
                let (info, reference) = (hit.info.to_string(), hit.reference.to_string());
                let trail = ep.src.render().as_str().to_string();
                emit_ep(st, sec, usec, ep, PROTO::UDP, TRAIL::IP, Field::Text(trail), &info, &reference);
            }

            check_domain_inner(st, &query, sec, usec, ep, PROTO::UDP, Some(wl_query));
        }
        return;
    }

    if !st.cfg.use_heuristics {
        return;
    }

    if flags_high & 0x80 == 0 {
        return; // not a response
    }

    // From here on this is a DNS RESPONSE - a small fraction of DNS traffic, and the branches
    // below index labels from both ends, so the plain Vec stays. The hot QUERY path above never
    // builds it.
    let parts: Vec<&str> = query.split('.').collect();

    if flags_low == 0x80 {
        // recursion available, no error -> look for a sinkholed / parked A record
        if let Some(answer) = dns::first_a_record(dns_data, question.name_end) {
            let answer_ip = Ip::V4(answer);
            let hit = st.trails.db().get_ip(answer_ip).map(|v| (v.info.to_string(), v.reference.to_string()));
            if let Some((info, _reference)) = hit {
                if !st.check_domain_whitelisted(&query) {
                    let trail =
                        format!("({}).{}", parts[..parts.len() - 1].join("."), parts[parts.len() - 1..].join("."));
                    if info.contains("sinkhole") {
                        // e.g. kitro.pl, devomchart.com, jebena.ananikolic.su, vuvet.cn
                        let by = info.split(' ').nth(1).unwrap_or("");
                        let text = format!("sinkholed by {by} (malware)");
                        emit_ep(st, sec, usec, ep, PROTO::UDP, TRAIL::DNS, Field::Text(trail), &text, "(heuristic)");
                    } else if info.contains("parking") {
                        emit_ep(
                            st,
                            sec,
                            usec,
                            ep,
                            PROTO::UDP,
                            TRAIL::DNS,
                            Field::Text(trail),
                            "parked site (suspicious)",
                            "(heuristic)",
                        );
                    }
                }
            }
        }
        return;
    }

    if flags_low != 0x83 {
        return;
    }

    // --- recursion available, no such name (NXDOMAIN) ---
    let parent = parts[parts.len().saturating_sub(2)..].join(".");
    if st.dns_exhaustion.is_exhausted(&parent)
        || st.check_domain_whitelisted(&query)
        || st.trails.db().contains_domain_member(&query)
    {
        return;
    }
    if parts[parts.len() - 1].bytes().all(|b| b.is_ascii_digit()) && !parts[parts.len() - 1].is_empty() {
        return;
    }
    // generic check for DNSBL IP lookups
    let dnsbl_lookup = parts.len() > 4
        && parts[..4].iter().all(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().map(|v| v < 256).unwrap_or(false)
        });

    if !dnsbl_lookup {
        if !ep.dst.is_local() {
            st.nxdomain.maybe_prune(sec);

            let wildcard = if query.matches('.').count() > 1 {
                Some(format!("*.{}", parts[parts.len() - 2..].join(".")))
            } else {
                None
            };
            let keys: Vec<String> = std::iter::once(query.clone()).chain(wildcard).collect();

            for key in keys {
                match st.nxdomain.observe(&key, &query, sec) {
                    None => {}
                    Some(NxAlert::Wildcard { trail, .. }) => {
                        if !st.statics.local_subdomain_lookups.is_match(&trail) {
                            emit_ep(
                                st,
                                sec,
                                usec,
                                ep,
                                PROTO::UDP,
                                TRAIL::DNS,
                                Field::Text(trail),
                                "excessive no such domain (suspicious)",
                                "(heuristic)",
                            );
                        }
                        break;
                    }
                    Some(NxAlert::Exact { trail }) => {
                        emit_ep(
                            st,
                            sec,
                            usec,
                            ep,
                            PROTO::UDP,
                            TRAIL::DNS,
                            Field::Text(trail),
                            "excessive no such domain (suspicious)",
                            "(heuristic)",
                        );
                        break;
                    }
                }
            }
        }

        if parts.len() == 2 && !parts[0].is_empty() && !parts[0].contains('-') {
            let part = parts[0].to_string();
            let trail = format!("({}).{}", parts[0], parts[1]);

            let result = match st.dga_findings.get(&part).cloned() {
                Some(v) => {
                    st.metrics.cache_hits += 1;
                    v
                }
                None => {
                    st.metrics.cache_misses += 1;
                    // Reference: https://github.com/exp0se/dga_detector
                    let mut verdict = None;
                    if label_entropy(&part) > settings::SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD {
                        verdict = Some("entropy threshold no such domain (suspicious)".to_string());
                    }
                    if verdict.is_none() && consonant_count(&part) > settings::SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD {
                        verdict = Some("consonant threshold no such domain (suspicious)".to_string());
                    }
                    st.dga_findings.insert(part.clone(), verdict.clone());
                    verdict
                }
            };

            if let Some(info) = result {
                emit_ep(st, sec, usec, ep, PROTO::UDP, TRAIL::DNS, Field::Text(trail), &info, "(heuristic)");
            }
        }
    }
}

/// The `elif protocol in IPPROTO_LUT` branch (ICMP and friends).
fn other_proto(st: &mut WorkerState, ip_data: &[u8], header: &packet::IpHeader, protocol: u8, sec: u64, usec: u32) {
    let Some(label) = settings::ipproto_label(protocol) else {
        st.metrics.packets_ignored += 1;
        return;
    };

    if protocol == 1 {
        // ICMP: only echo requests
        if dns_or_icmp_type(ip_data, header.header_len) != Some(0x08) {
            return;
        }
    } else if protocol == 58 {
        // ICMPv6: only echo requests
        if dns_or_icmp_type(ip_data, header.header_len) != Some(0x80) {
            return;
        }
    }

    st.metrics.trail_lookups += 1;
    let hit =
        st.trails.db().get_ip(header.dst).map(|v| (header.dst, v.info.to_string(), v.reference.to_string())).or_else(
            || st.trails.db().get_ip(header.src).map(|v| (header.src, v.info.to_string(), v.reference.to_string())),
        );

    if let Some((trail_ip, info, reference)) = hit {
        let src = header.src.render();
        let dst = header.dst.render();
        let trail = trail_ip.render().as_str().to_string();
        emit(
            st,
            sec,
            usec,
            src.as_str(),
            Field::dash(),
            Field::Text(dst.as_str().to_string()),
            Field::dash(),
            label,
            TRAIL::IP,
            Field::Text(trail),
            &info,
            &reference,
        );
    }
}

fn dns_or_icmp_type(ip_data: &[u8], header_len: usize) -> Option<u8> {
    packet::icmp_type(ip_data, header_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Dots` replaces `query.split('.')` plus `join(".")` on the DNS query path. It must agree
    /// with that exactly, for every index the path uses, on every shape of name — this is index
    /// arithmetic, which is precisely where an optimisation quietly changes behaviour.
    #[test]
    fn dots_agrees_with_split_and_join() {
        let names = [
            "evil.com",
            "a.b.com",
            "a.b.c.com",
            "deep.a.b.c.d.example.com",
            "nodot",
            "",
            ".",
            "..",
            "a..b",
            ".leading.com",
            "trailing.com.",
            "1-2-3-4.dyn.example.org",
            "x.y.z",
        ];
        for name in names {
            let parts: Vec<&str> = name.split('.').collect();
            let dots = Dots::of(name);
            assert_eq!(dots.label_count(), parts.len(), "label_count for {name:?}");
            assert_eq!(dots.last_label(name), parts[parts.len() - 1], "last_label for {name:?}");
            assert_eq!(dots.label(name, 0), parts[0], "label(0) for {name:?}");

            // the query path indexes the last three labels and the matching suffixes/prefixes
            for back in 1..=3usize {
                if parts.len() < back + 1 {
                    continue;
                }
                let index = parts.len() - back;
                assert_eq!(dots.label(name, index), parts[index], "label({index}) for {name:?}");
                assert_eq!(dots.suffix_from(name, index), parts[index..].join("."), "suffix_from({index}) {name:?}");
                assert_eq!(dots.prefix_upto(name, index), parts[..index].join("."), "prefix_upto({index}) {name:?}");
            }
        }
    }

    #[test]
    fn bracketing_matches_python_join() {
        assert_eq!(bracket_around("evil.com/bad.php", "/bad.php"), "(evil.com)/bad.php");
        assert_eq!(bracket_around("/bad.php", "/bad.php"), "/bad.php");
        assert_eq!(bracket_around("a/bad.php?x", "/bad.php"), "(a)/bad.php(?x)");
    }
}
