//! Event emission — daily log file, `LOG_SERVER` datagrams, CEF/syslog, Logstash JSON,
//! condensing and log throttling. A direct port of `core/log.py`.
//!
//! The Python server parses these lines, so the formats are a compatibility surface rather than an
//! implementation detail. CEF escaping is asserted byte-for-byte against `core/log.py` by
//! `tests/vectors.rs`, over fixtures `tools/gen_vectors.py` generates from it; the rest is covered
//! by this module's own tests. (This used to claim every rendering was pinned in a
//! `tests/serialization.rs` - a file that does not exist and never did.)

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::addr::parse_host_port;
use crate::event::{local_date_string, local_time_string, syslog_time_string, Event, Field};
use crate::ignore::IgnoreRules;
use crate::settings;
use crate::whitelist::Whitelist;

/// Immutable, shared output configuration.
/// `MTS1 <32 hex chars> <payload>` - the authenticated framing for a LOG_SERVER datagram.
///
/// The listener on the other end is otherwise open by protocol design: anything that can reach the
/// port can append to the log an operator reasons from. This is the sending half of closing that;
/// `core/log.py:mts_open` is the receiving half and the two are pinned together by generated
/// vectors, because a MAC that disagrees across the two implementations fails as silent data loss -
/// the server simply drops every event this sensor sends, and nothing says why.
///
/// HMAC-SHA256 truncated to 128 bits (RFC 2104 section 5), hex-encoded so the datagram stays
/// greppable text like everything else on this path.
pub fn mts_sign(secret: &str, payload: &[u8]) -> Vec<u8> {
    use hmac::{Mac, SimpleHmac};
    let mut mac =
        SimpleHmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(payload);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(5 + 32 + 1 + payload.len());
    out.extend_from_slice(b"MTS1 ");
    for byte in &tag[..16] {
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0x0f) as usize]);
    }
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod mts_tests {
    use super::mts_sign;

    /// Vectors computed by core/log.py's mts_sign. A MAC that disagrees between the two
    /// implementations does not error anywhere - the server just drops every event this sensor
    /// sends, and the operator sees a sensor that looks healthy and a log that stays empty. That
    /// failure mode is why these are pinned rather than left to a round-trip test on one side.
    #[test]
    fn macs_match_the_python_sender() {
        let cases: &[(&str, &[u8], &str)] = &[
            (
                "s3cr3t",
                b"1767261603 \"2026-01-01 10:00:03.123456\" box 10.0.0.8 6666 5.5.5.5 80 TCP IP 5.5.5.5 \"malware (test)\" (static)\n",
                "157a86bdbdf4940dccfd73668f1e74e3",
            ),
            ("k", b"", "8bb990c40a7d61cb97597a942125025b"),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                b"short",
                "c67f8c6d0fec3da7b0fd48be37f06a9d",
            ),
            // a key longer than SHA-256's block is hashed first by HMAC; a payload that is not
            // ASCII must be signed as the bytes it is, not as text
            ("čž secret", "unicode payload čž\n".as_bytes(), "2b576daf9cbbebe124c8320c8a19fedb"),
        ];

        for (secret, payload, expected_mac) in cases {
            let out = mts_sign(secret, payload);
            assert!(out.starts_with(b"MTS1 "), "frame prefix missing");
            let mac = std::str::from_utf8(&out[5..37]).expect("hex is ascii");
            assert_eq!(mac, *expected_mac, "MAC disagrees with core/log.py for secret {secret:?}");
            assert_eq!(&out[37..38], b" ", "one space between MAC and payload");
            assert_eq!(&out[38..], *payload, "payload must be carried byte-for-byte");
        }
    }
}

pub struct OutputConfig {
    pub sensor_name: String,
    pub log_dir: PathBuf,
    pub trails_file: PathBuf,
    pub disable_local_log_storage: bool,
    /// `LOCAL_LOG_FORMAT json`: write the event log as one JSON object per line.
    pub local_log_json: bool,
    pub console: bool,
    pub log_server: Option<String>,
    /// `LOG_SERVER_SECRET`: shared secret authenticating every LOG_SERVER datagram. `None` sends
    /// them unsigned, which is what every deployment did before this existed.
    pub log_server_secret: Option<String>,
    /// Every endpoint named by `SYSLOG_SERVER` / `LOGSTASH_SERVER`. One option may name several,
    /// so a sensor can feed redundant collectors; empty means the sink is off.
    pub syslog_server: Vec<String>,
    pub logstash_server: Vec<String>,
    pub severity_regex: Option<fancy_regex::Regex>,
    /// Event-log throttling (see `crate::throttle` for why this is a redesign rather than a
    /// port). `legacy_divisor` is set from the ACTUAL worker count, since sensor.py's
    /// PROCESS_COUNT is its worker count.
    pub throttle: crate::throttle::ThrottleConfig,
    pub hostname: String,
    pub ignore: IgnoreRules,
    pub whitelist: Arc<Whitelist>,
    pub show_debug: bool,
}

impl OutputConfig {
    /// `core/log.py:log_event()` console fallback condition.
    fn console_output(&self) -> bool {
        (self.disable_local_log_storage && self.log_server.is_none() && self.syslog_server.is_empty()) || self.console
    }
}

/// Per-worker event sink. Owns its own file handle, throttle window, condense buffer and
/// datagram sockets, so the emit path never contends with another worker.
pub struct EventSink {
    cfg: Arc<OutputConfig>,
    log_path: Option<PathBuf>,
    log_file: Option<File>,
    condensed: HashMap<(String, String), Vec<Event>>,
    throttle: crate::throttle::Throttle,
    last_condense_flush: Instant,
    /// Resolved remote-logging endpoints. Only SUCCESSFUL resolutions are cached here; a failure
    /// records a retry deadline in `endpoint_retry` instead, so a transient DNS outage cannot
    /// silence the sink for the lifetime of the process.
    endpoints: HashMap<String, SocketAddr>,
    endpoint_retry: HashMap<String, Instant>,
    sock4: Option<UdpSocket>,
    sock6: Option<UdpSocket>,
    signature_id: Option<(String, Instant)>,
    pub events: u64,
    /// Events that PASSED the throttle and were handed to the sinks. Deliberately not called
    /// `events_written`: a name that says "written" while counting attempts reads as proof that the
    /// events reached disk, which is exactly the claim an operator must not be given for free.
    /// Failures are counted separately in `log_write_errors`.
    pub events_written: u64,
    /// Local event-log open/write failures. Non-zero means detections were produced and LOST.
    pub log_write_errors: u64,
    /// Remote-sink (LOG_SERVER / SYSLOG_SERVER / LOGSTASH_SERVER) delivery failures: an endpoint
    /// that would not resolve, a socket that would not bind, or a datagram that would not send.
    /// With DISABLE_LOCAL_LOG_STORAGE these are detections LOST, and nothing else reports them.
    pub remote_log_errors: u64,
    pub events_ignored: u64,
    pub events_throttled: u64,
    pub events_condensed: u64,
    /// Condense groups refused at `MAX_CONDENSED_KEYS`; those events were written unaggregated.
    pub condense_saturations: u64,
}

/// Total events emitted across all workers (metrics only; never read on the hot path).
pub static EVENTS_TOTAL: AtomicU64 = AtomicU64::new(0);

impl EventSink {
    pub fn new(cfg: Arc<OutputConfig>) -> EventSink {
        let throttle = crate::throttle::Throttle::new(cfg.throttle);
        EventSink {
            cfg,
            log_path: None,
            log_file: None,
            condensed: HashMap::new(),
            throttle,
            last_condense_flush: Instant::now(),
            endpoints: HashMap::new(),
            endpoint_retry: HashMap::new(),
            sock4: None,
            sock6: None,
            signature_id: None,
            events: 0,
            events_written: 0,
            log_write_errors: 0,
            remote_log_errors: 0,
            events_ignored: 0,
            events_throttled: 0,
            events_condensed: 0,
            condense_saturations: 0,
        }
    }

    /// `core/log.py:log_event()`. `skip_write` mirrors the plugin-only pre-pass and
    /// `skip_condensing` the re-entry from the condense flush.
    pub fn log_event(&mut self, event: &Event, skip_write: bool, skip_condensing: bool) {
        self.events += 1;
        EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);

        if self.cfg.ignore.ignore_event(event) {
            self.events_ignored += 1;
            if self.cfg.show_debug {
                crate::cprintln!(
                    "[i] ignore_event src_ip={}, src_port={}, dst_ip={}, dst_port={}",
                    event.src_ip,
                    event.src_port.as_plain(),
                    event.dst_ip.as_plain(),
                    event.dst_port.as_plain()
                );
            }
            return;
        }

        // DNS requests/responses can't be whitelisted based on src_ip/dst_ip.
        let whitelisted = self.cfg.whitelist.check_whitelisted(&event.src_ip)
            || self.cfg.whitelist.check_whitelisted(&event.dst_ip.as_plain());
        if whitelisted && event.trail_type != crate::event::trail_type::DNS {
            return;
        }

        if skip_write {
            return;
        }

        if !skip_condensing && self.cfg.condense_on_info(&event.info) {
            let key = (event.src_ip.clone(), event.trail.as_plain());
            // Each BUCKET was capped, but the number of KEYS was not: the map only shrinks on
            // the flush period, so between flushes an attacker choosing source addresses and
            // trails could add keys without limit, each costing two Strings plus a Vec.
            //
            // At the cap, fall through to the normal throttled write instead of condensing.
            // Dropping the event is not an option — this is a detection — and evicting an
            // existing bucket would discard already-collected evidence. The event still gets
            // written; it simply is not aggregated with its siblings.
            if self.condensed.len() >= settings::MAX_CONDENSED_KEYS && !self.condensed.contains_key(&key) {
                self.condense_saturations += 1;
            } else {
                let bucket = self.condensed.entry(key).or_default();
                if bucket.len() < settings::MAX_CONDENSED_EVENTS {
                    bucket.push(event.clone());
                }
                self.events_condensed += 1;
                return;
            }
        }

        // Event-log throttling. See `crate::throttle`: a small burst is written verbatim, the
        // rest of the window is held and comes out as one aggregated line, so a flood is bounded
        // WITHOUT losing the fact that it happened.
        let (decision, due) = self.throttle.admit(event);
        for summary in due {
            self.write_line(&summary);
        }
        if decision == crate::throttle::Decision::Suppress {
            self.events_throttled += 1;
            return;
        }

        self.write_line(event);
    }

    /// Render and emit one event line to every configured sink.
    fn write_line(&mut self, event: &Event) {
        let localtime = local_time_string(event.sec, event.usec);
        let line = event.render_line(&self.cfg.sensor_name, localtime.as_str());

        if !self.cfg.disable_local_log_storage {
            // LOCAL_LOG_FORMAT json writes the same object LOGSTASH_SERVER sends, plus "time" -
            // without which the file would lose the microseconds every text line records. Only
            // the FILE changes; every other sink below keeps its own format.
            if self.cfg.local_log_json {
                let severity = self.severity_for(&event.info);
                let json = local_json_line(event, severity, &self.cfg.sensor_name, localtime.as_str());
                self.write_event_log(event.sec, &json);
            } else {
                self.write_event_log(event.sec, &line);
            }
        }

        if let Some(endpoint) = self.cfg.log_server.clone() {
            let payload = format!("{} {}", event.sec, line);
            match self.cfg.log_server_secret.as_deref() {
                Some(secret) => {
                    let framed = mts_sign(secret, payload.as_bytes());
                    self.send_datagram(&endpoint, &framed);
                }
                None => self.send_datagram(&endpoint, payload.as_bytes()),
            }
        }

        if !self.cfg.syslog_server.is_empty() || !self.cfg.logstash_server.is_empty() {
            let severity = self.severity_for(&event.info);
            // Rendered once and sent to each collector, rather than re-rendered per endpoint.
            if !self.cfg.syslog_server.is_empty() {
                let payload = self.cef_line(event, severity);
                for endpoint in self.cfg.syslog_server.clone() {
                    self.send_datagram(&endpoint, payload.as_bytes());
                }
            }
            if !self.cfg.logstash_server.is_empty() {
                let payload = logstash_line(event, severity, &self.cfg.hostname);
                for endpoint in self.cfg.logstash_server.clone() {
                    self.send_datagram(&endpoint, payload.as_bytes());
                }
            }
        }

        if self.cfg.console_output() {
            // core/log.py writes the event to stderr, and core/colorized.py wraps stderr too,
            // so the console stream is coloured exactly like the Python sensor's.
            let painted = crate::colorized::colorize(&line);
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(painted.as_bytes());
            let _ = stderr.flush();
        }

        self.events_written += 1;
    }

    fn write_event_log(&mut self, sec: u64, line: &str) {
        let date = local_date_string(sec);
        let path = self.cfg.log_dir.join(format!("{}.log", date.as_str()));
        if self.log_path.as_deref() != Some(path.as_path()) {
            // ONE atomic open. The previous exists()-then-File::create() sequence was a race
            // between workers: each has its own sink, so two could both find the file missing at a
            // day boundary and the second `File::create` would TRUNCATE events the first had
            // already written. `create(true).append(true)` with the mode set in the same call
            // cannot truncate, and gives Python's 0644 on creation without a second syscall.
            match OpenOptions::new().append(true).create(true).mode(0o644).open(&path) {
                Ok(f) => {
                    self.log_file = Some(f);
                    self.log_path = Some(path);
                }
                Err(e) => {
                    self.log_write_errors += 1;
                    log_error(&format!("unable to open event log '{}' ({e})", path.display()), true);
                    return;
                }
            }
        }
        if let Some(file) = self.log_file.as_mut() {
            // ONE write(2) per event, deliberately — not `write_all`.
            //
            // The guarantee that matters with several workers appending to one file is that each
            // event line lands whole: O_APPEND makes the kernel pick the append offset and perform
            // the copy atomically *per system call*, so one call per line means workers interleave
            // whole records. `write_all` loops on a short write, which would split a line across
            // two calls and let another worker's line land in the middle of it.
            //
            // (An earlier comment here justified this with PIPE_BUF. That was wrong: PIPE_BUF
            // bounds atomic writes to PIPES, not regular files. The property being relied on is
            // O_APPEND's atomic offset-plus-write, which has no such size bound in practice but is
            // also not unlimited — hence treating a short write as an error rather than looping.)
            match file.write(line.as_bytes()) {
                Ok(n) if n == line.len() => {}
                Ok(n) => {
                    self.log_write_errors += 1;
                    log_error(
                        &format!(
                            "short write to the event log ({n} of {} bytes); the record may be truncated",
                            line.len()
                        ),
                        true,
                    )
                }
                Err(e) => {
                    self.log_write_errors += 1;
                    log_error(&format!("unable to write event log ({e})"), true)
                }
            }
        }
    }

    fn severity_for(&self, info: &str) -> Severity {
        let Some(re) = &self.cfg.severity_regex else {
            return Severity::Medium;
        };
        match re.captures(info) {
            Ok(Some(caps)) => {
                for name in ["low", "medium", "high"] {
                    if caps.name(name).is_some() {
                        return match name {
                            "low" => Severity::Low,
                            "high" => Severity::High,
                            _ => Severity::Medium,
                        };
                    }
                }
                Severity::Medium
            }
            _ => Severity::Medium,
        }
    }

    /// `core/log.py:_trails_signature_id()` — the trails file's ctime date, refreshed at
    /// most every 5 minutes.
    fn trails_signature_id(&mut self) -> String {
        let stale = match &self.signature_id {
            None => true,
            Some((_, at)) => at.elapsed().as_secs() >= 300,
        };
        if stale {
            let value = trails_ctime_date(&self.cfg.trails_file);
            self.signature_id = Some((value, Instant::now()));
        }
        self.signature_id.as_ref().map(|(v, _)| v.clone()).unwrap_or_default()
    }

    fn cef_line(&mut self, event: &Event, severity: Severity) -> String {
        let signature_id = self.trails_signature_id();
        let extension = format!(
            "src={} spt={} dst={} dpt={} trail={} ref={}",
            event.src_ip,
            event.src_port.as_plain(),
            event.dst_ip.as_plain(),
            event.dst_port.as_plain(),
            cef_escape(&event.trail.as_plain(), true),
            cef_escape(&event.reference, true)
        );
        format!(
            "{syslog_time} {host} CEF:0|{vendor}|{product}|{version}|{signature_id}|{name}|{severity}|{extension}",
            syslog_time = syslog_time_string(event.sec),
            host = self.cfg.hostname,
            vendor = settings::NAME,
            product = "sensor",
            version = settings::VERSION,
            signature_id = signature_id,
            name = cef_escape(&event.info, false),
            severity = severity.cef_value(),
            extension = extension
        )
    }

    /// How long a failed endpoint resolution is remembered before it is tried again.
    ///
    /// Not zero: `resolve_endpoint` calls getaddrinfo, which blocks, and retrying it per event
    /// would put a DNS round-trip on the detection path. Not infinite either, which is what
    /// caching the failure used to mean.
    const ENDPOINT_RETRY_INTERVAL: Duration = Duration::from_secs(30);

    /// Address for `endpoint`, resolving it if it is not already known good.
    ///
    /// Python never had this problem: `_endpoint_address` keeps a hostname as `(host, port)` and
    /// lets `sendto` resolve it on every send, so a DNS blip costs one event. The Rust port
    /// resolved up front and cached the `None`, so the FIRST event during a DNS outage disabled
    /// the endpoint until the process restarted - and with DISABLE_LOCAL_LOG_STORAGE that is
    /// every subsequent detection, silently.
    fn endpoint_addr(&mut self, endpoint: &str) -> Option<SocketAddr> {
        if let Some(addr) = self.endpoints.get(endpoint) {
            return Some(*addr);
        }
        let now = Instant::now();
        if let Some(deadline) = self.endpoint_retry.get(endpoint) {
            if now < *deadline {
                return None;
            }
        }
        match resolve_endpoint(endpoint) {
            Some(addr) => {
                self.endpoints.insert(endpoint.to_string(), addr);
                self.endpoint_retry.remove(endpoint);
                Some(addr)
            }
            None => {
                log_error(&format!("unable to resolve remote logging endpoint '{endpoint}'"), true);
                self.endpoint_retry.insert(endpoint.to_string(), now + Self::ENDPOINT_RETRY_INTERVAL);
                None
            }
        }
    }

    fn send_datagram(&mut self, endpoint: &str, data: &[u8]) {
        let Some(addr) = self.endpoint_addr(endpoint) else {
            self.remote_log_errors += 1;
            return;
        };

        let is_v6 = addr.is_ipv6();
        let bind: &str = if is_v6 { "[::]:0" } else { "0.0.0.0:0" };
        let sock = if is_v6 { &mut self.sock6 } else { &mut self.sock4 };
        if sock.is_none() {
            *sock = UdpSocket::bind(bind).ok();
        }
        let Some(s) = sock.as_ref() else {
            // A socket that will not bind used to be swallowed by `.ok()` and an early return.
            log_error(&format!("unable to open a remote logging socket for '{endpoint}'"), true);
            self.remote_log_errors += 1;
            return;
        };
        if s.send_to(data, addr).is_err() {
            // Drop and recreate the socket once, exactly like `_send_datagram`.
            let fresh = UdpSocket::bind(bind).ok();
            let retried = match &fresh {
                Some(f) => f.send_to(data, addr).is_ok(),
                None => false,
            };
            if is_v6 {
                self.sock6 = fresh;
            } else {
                self.sock4 = fresh;
            }
            if !retried {
                // The second failure used to be discarded outright, so a remote-only deployment
                // could lose every event while `events_written` kept climbing.
                log_error(&format!("unable to send to remote logging endpoint '{endpoint}'"), true);
                self.remote_log_errors += 1;
            }
        }
    }

    /// `core/log.py:flush_condensed_events()`
    pub fn flush_condensed(&mut self) {
        if self.condensed.is_empty() {
            self.last_condense_flush = Instant::now();
            return;
        }
        let snapshot: Vec<Vec<Event>> = self.condensed.drain().map(|(_, v)| v).collect();
        self.last_condense_flush = Instant::now();

        for events in snapshot {
            if let Some(merged) = merge_events(&events) {
                self.log_event(&merged, false, true);
            }
        }
    }

    /// Flush the condense buffer if the Python flush period has elapsed. Called from the
    /// worker loop on a coarse counter, so the hot path pays nothing per packet.
    pub fn maybe_flush_condensed(&mut self) {
        if self.condensed.is_empty() {
            return;
        }
        if self.last_condense_flush.elapsed().as_secs() >= settings::CONDENSED_EVENTS_FLUSH_PERIOD {
            self.flush_condensed();
        }
    }

    /// Emit throttle summaries whose window has closed. `now` is the sensor's current second
    /// (packet clock while replaying, wall clock while live), so a burst that simply STOPS is
    /// still reported instead of sitting in the buffer until shutdown.
    pub fn flush_throttled(&mut self, now: u64) {
        for summary in self.throttle.flush_due(now) {
            self.write_line(&summary);
        }
    }

    /// Emit every held summary, window or no window (shutdown).
    pub fn flush_throttled_all(&mut self) {
        for summary in self.throttle.flush_all() {
            self.write_line(&summary);
        }
    }

    /// Events held back by the throttle, and summary lines emitted for them.
    /// Distinct condense groups currently buffered (bounded by `MAX_CONDENSED_KEYS`).
    pub fn condensed_len(&self) -> usize {
        self.condensed.len()
    }

    pub fn throttle_stats(&self) -> (u64, u64, usize, u64) {
        (self.throttle.suppressed, self.throttle.summaries, self.throttle.tracked_keys(), self.throttle.evicted)
    }
}

/// Collapse several events for one `(src_ip, trail)` into a single event, the way
/// `core/log.py:flush_condensed_events()` does: fields that differ across the group become a
/// comma-joined, sorted list IN PLACE. The line keeps its eleven columns, so nothing downstream
/// (the Maltrail server, `fail2ban`, a SIEM) needs to know that aggregation happened.
///
/// Returns `None` for an empty group.
pub fn merge_events(events: &[Event]) -> Option<Event> {
    let first = events.first()?;
    let mut merged = first.clone();
    let mut sets: [std::collections::BTreeSet<Field>; 4] = Default::default();
    let mut condensed = false;

    for current in events.iter().skip(1) {
        for (j, set) in sets.iter_mut().enumerate() {
            let (cur, base) = match j {
                0 => (&current.src_port, &merged.src_port),
                1 => (&current.dst_ip, &merged.dst_ip),
                2 => (&current.dst_port, &merged.dst_port),
                _ => (&current.proto, &merged.proto),
            };
            if cur != base {
                condensed = true;
                if set.is_empty() {
                    set.insert(base.clone());
                }
                set.insert(cur.clone());
            }
        }
    }

    if condensed {
        for (j, set) in sets.iter().enumerate() {
            if set.is_empty() {
                continue;
            }
            // ','.join(str(_) for _ in sorted(set))
            // NOTE: Python raises TypeError when a set mixes int and str (e.g. an ICMP '-' port
            // beside a numeric one) and loses the whole flush; the Field ordering used here is
            // total, so the record is emitted instead.
            let joined = set.iter().map(|f| f.as_plain()).collect::<Vec<_>>().join(",");
            let field = Field::Text(joined);
            match j {
                0 => merged.src_port = field,
                1 => merged.dst_ip = field,
                2 => merged.dst_port = field,
                _ => merged.proto = field,
            }
        }
    }
    Some(merged)
}

impl OutputConfig {
    fn condense_on_info(&self, info: &str) -> bool {
        settings::statics().condense_on_info.is_match(info)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    fn cef_value(self) -> u8 {
        match self {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
        }
    }
}

/// `core/log.py:_cef_escape()`
pub fn cef_escape(value: &str, extension: bool) -> String {
    let mut out = value.replace('\\', "\\\\");
    out = if extension { out.replace('=', "\\=") } else { out.replace('|', "\\|") };
    out.replace(['\r', '\n'], " ")
}

/// `json.dumps(OrderedDict(...))` with CPython's default separators and `ensure_ascii`.
/// The on-disk form: `logstash_line()` plus `time`, which carries the microseconds.
///
/// Byte-identical to `core/log.py:event_json(..., localtime)`, pinned by `tests/vectors.rs`.
pub fn local_json_line(event: &Event, severity: Severity, sensor: &str, localtime: &str) -> String {
    json_event(event, severity, sensor, Some(localtime))
}

pub fn logstash_line(event: &Event, severity: Severity, hostname: &str) -> String {
    json_event(event, severity, hostname, None)
}

fn json_event(event: &Event, severity: Severity, sensor: &str, localtime: Option<&str>) -> String {
    let mut out = String::with_capacity(256);
    out.push('{');
    json_kv_raw(&mut out, "timestamp", &event.sec.to_string(), true);
    if let Some(localtime) = localtime {
        json_kv_str(&mut out, "time", localtime, false);
    }
    json_kv_str(&mut out, "sensor", sensor, false);
    json_kv_str(&mut out, "severity", severity.label(), false);
    json_kv_str(&mut out, "src_ip", &event.src_ip, false);
    json_kv_field(&mut out, "src_port", &event.src_port);
    json_kv_field(&mut out, "dst_ip", &event.dst_ip);
    json_kv_field(&mut out, "dst_port", &event.dst_port);
    json_kv_field(&mut out, "proto", &event.proto);
    json_kv_str(&mut out, "type", event.trail_type, false);
    json_kv_field(&mut out, "trail", &event.trail);
    json_kv_str(&mut out, "info", &event.info, false);
    json_kv_str(&mut out, "reference", &event.reference, false);
    out.push('}');
    out
}

fn json_kv_raw(out: &mut String, key: &str, raw: &str, first: bool) {
    if !first {
        out.push_str(", ");
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\": ");
    out.push_str(raw);
}

fn json_kv_str(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push_str(", ");
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\": ");
    json_escape(out, value);
}

fn json_kv_field(out: &mut String, key: &str, field: &Field) {
    out.push_str(", \"");
    out.push_str(key);
    out.push_str("\": ");
    match field {
        Field::Int(i) => out.push_str(&i.to_string()),
        Field::Text(s) => json_escape(out, s),
    }
}

fn json_escape(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x80 => out.push(c),
            // ensure_ascii=True: non-ASCII is escaped, with surrogate pairs above BMP
            c => {
                let cp = c as u32;
                if cp <= 0xffff {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let v = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)));
                }
            }
        }
    }
    out.push('"');
}

fn trails_ctime_date(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    let sec = match std::fs::metadata(path) {
        Ok(md) => md.ctime() as u64,
        Err(_) => SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    };
    local_date_string(sec).as_str().to_string()
}

fn resolve_endpoint(endpoint: &str) -> Option<SocketAddr> {
    let (host, port) = parse_host_port(endpoint);
    let port = port?;
    if host.is_empty() {
        return None;
    }
    // Strip a scope-id suffix ("fe80::1%eno1"), which ToSocketAddrs cannot parse.
    let host = host.split('%').next().unwrap_or(&host);
    (host, port).to_socket_addrs().ok()?.next()
}

// --- error log -------------------------------------------------------------------

struct ErrorLog {
    file: Option<File>,
    seen: std::collections::HashSet<String>,
    show_debug: bool,
}

static ERROR_LOG: OnceLock<Mutex<ErrorLog>> = OnceLock::new();

/// `core/log.py:get_error_log_handle()` — must run before workers start.
/// Free bytes available to an unprivileged process on the filesystem holding `path`.
///
/// Maltrail is an IDS: its event logs are evidence, and the sensor deliberately never deletes
/// them. That makes a full disk a real operating condition rather than a hypothetical, and a
/// full disk is the worst kind of sensor failure — appends start failing, detections are lost,
/// and the only outward sign is that alerts stopped, which looks exactly like a quiet network.
///
/// So the free space is measured and exported, and the operator is expected to alert on it
/// LONG before it matters. `f_bavail`, not `f_bfree`: the root-reserved blocks are not available
/// to the `maltrail` user the shipped unit runs as.
pub fn free_bytes(path: &Path) -> Option<u64> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: `c_path` is a valid NUL-terminated string and `st` is a correctly sized,
    // zero-initialised statvfs that the call fills in.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    // f_frsize is the fragment size the block counts are expressed in. The casts are u64->u64
    // on the 64-bit targets we ship, but statvfs uses c_ulong: they are load-bearing for anyone
    // building from source on a 32-bit platform.
    #[allow(clippy::unnecessary_cast)]
    (st.f_frsize as u64).checked_mul(st.f_bavail as u64)
}

pub fn init_error_log(log_dir: &Path, show_debug: bool) {
    let path = log_dir.join("error.log");
    if !path.exists() {
        if let Ok(f) = File::create(&path) {
            drop(f);
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
        }
    }
    let file = OpenOptions::new().append(true).create(true).open(&path).ok();
    let _ = ERROR_LOG.set(Mutex::new(ErrorLog { file, seen: Default::default(), show_debug }));
}

/// `core/log.py:log_error()`
pub fn log_error(msg: &str, single: bool) {
    let Some(lock) = ERROR_LOG.get() else {
        crate::ceprintln!("[!] {msg}");
        return;
    };
    let Ok(mut state) = lock.lock() else { return };
    if single && !state.seen.insert(msg.to_string()) {
        return;
    }
    if state.show_debug {
        crate::ceprintln!("[!] {msg}");
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let stamp = local_time_string(now, 0);
    let stamp = &stamp.as_str()[..19]; // TIME_FORMAT has no microseconds
    if let Some(file) = state.file.as_mut() {
        let _ = file.write_all(format!("{stamp} {msg}\n").as_bytes());
    }
}

/// `core/log.py:create_log_directory()`
pub fn create_log_directory(log_dir: &Path) -> std::io::Result<()> {
    if !log_dir.is_dir() {
        std::fs::create_dir_all(log_dir)?;
        let _ = std::fs::set_permissions(log_dir, std::fs::Permissions::from_mode(0o755));
    }
    crate::cprintln!("[i] using '{}' for log storage", log_dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{proto, trail_type};

    fn sample() -> Event {
        Event::new(
            1700000000,
            123456,
            "10.0.0.5",
            50000u16,
            "66.66.66.66",
            443u16,
            proto::TCP,
            trail_type::IP,
            "66.66.66.66",
            "malware (test)",
            "(static)",
        )
    }

    #[test]
    fn cef_escaping() {
        assert_eq!(cef_escape("a|b", false), "a\\|b");
        assert_eq!(cef_escape("a=b", true), "a\\=b");
        assert_eq!(cef_escape("a\\b", false), "a\\\\b");
        assert_eq!(cef_escape("a\nb", false), "a b");
        // header escaping leaves '=' alone, extension escaping leaves '|' alone
        assert_eq!(cef_escape("a=b", false), "a=b");
        assert_eq!(cef_escape("a|b", true), "a|b");
    }

    #[test]
    fn logstash_field_order_and_types() {
        let line = logstash_line(&sample(), Severity::Medium, "box");
        assert_eq!(
            line,
            r#"{"timestamp": 1700000000, "sensor": "box", "severity": "medium", "src_ip": "10.0.0.5", "src_port": 50000, "dst_ip": "66.66.66.66", "dst_port": 443, "proto": "TCP", "type": "IP", "trail": "66.66.66.66", "info": "malware (test)", "reference": "(static)"}"#
        );
    }

    #[test]
    fn logstash_escapes_non_ascii_like_python() {
        let mut e = sample();
        e.info = "naïve \"quote\"".into();
        let line = logstash_line(&e, Severity::High, "box");
        assert!(line.contains(r#""info": "na\u00efve \"quote\"""#), "{line}");
    }

    #[test]
    fn endpoint_resolution() {
        assert_eq!(resolve_endpoint("127.0.0.1:8337"), Some("127.0.0.1:8337".parse().unwrap()));
        assert_eq!(resolve_endpoint("[::1]:514"), Some("[::1]:514".parse().unwrap()));
        assert_eq!(resolve_endpoint("127.0.0.1"), None);
    }
}
