//! Event emission — daily log file, `LOG_SERVER` datagrams, CEF/syslog, Logstash JSON,
//! condensing and log throttling. A direct port of `core/log.py`.
//!
//! Every rendering here is asserted byte-for-byte against the Python sensor in
//! `tests/serialization.rs`, because the existing Python server parses these lines.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addr::parse_host_port;
use crate::event::{local_date_string, local_time_string, syslog_time_string, Event, Field};
use crate::ignore::IgnoreRules;
use crate::settings;
use crate::whitelist::Whitelist;

/// Immutable, shared output configuration.
pub struct OutputConfig {
    pub sensor_name: String,
    pub log_dir: PathBuf,
    pub trails_file: PathBuf,
    pub disable_local_log_storage: bool,
    pub console: bool,
    pub log_server: Option<String>,
    pub syslog_server: Option<String>,
    pub logstash_server: Option<String>,
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
        (self.disable_local_log_storage && self.log_server.is_none() && self.syslog_server.is_none()) || self.console
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
    endpoints: HashMap<String, Option<SocketAddr>>,
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
    pub events_ignored: u64,
    pub events_throttled: u64,
    pub events_condensed: u64,
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
            sock4: None,
            sock6: None,
            signature_id: None,
            events: 0,
            events_written: 0,
            log_write_errors: 0,
            events_ignored: 0,
            events_throttled: 0,
            events_condensed: 0,
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
            let bucket = self.condensed.entry(key).or_default();
            if bucket.len() < settings::MAX_CONDENSED_EVENTS {
                bucket.push(event.clone());
            }
            self.events_condensed += 1;
            return;
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
            self.write_event_log(event.sec, &line);
        }

        if let Some(endpoint) = self.cfg.log_server.clone() {
            let payload = format!("{} {}", event.sec, line);
            self.send_datagram(&endpoint, payload.as_bytes());
        }

        if self.cfg.syslog_server.is_some() || self.cfg.logstash_server.is_some() {
            let severity = self.severity_for(&event.info);
            if let Some(endpoint) = self.cfg.syslog_server.clone() {
                let payload = self.cef_line(event, severity);
                self.send_datagram(&endpoint, payload.as_bytes());
            }
            if let Some(endpoint) = self.cfg.logstash_server.clone() {
                let payload = logstash_line(event, severity, &self.cfg.hostname);
                self.send_datagram(&endpoint, payload.as_bytes());
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

    fn send_datagram(&mut self, endpoint: &str, data: &[u8]) {
        let resolved = match self.endpoints.get(endpoint) {
            Some(v) => *v,
            None => {
                let v = resolve_endpoint(endpoint);
                if v.is_none() {
                    log_error(&format!("unable to resolve remote logging endpoint '{endpoint}'"), true);
                }
                self.endpoints.insert(endpoint.to_string(), v);
                v
            }
        };
        let Some(addr) = resolved else { return };

        let is_v6 = addr.is_ipv6();
        let sock = if is_v6 { &mut self.sock6 } else { &mut self.sock4 };
        if sock.is_none() {
            let bind: &str = if is_v6 { "[::]:0" } else { "0.0.0.0:0" };
            *sock = UdpSocket::bind(bind).ok();
        }
        let Some(s) = sock.as_ref() else { return };
        if s.send_to(data, addr).is_err() {
            // Drop and recreate the socket once, exactly like `_send_datagram`.
            let bind: &str = if is_v6 { "[::]:0" } else { "0.0.0.0:0" };
            let fresh = UdpSocket::bind(bind).ok();
            if let Some(f) = &fresh {
                let _ = f.send_to(data, addr);
            }
            if is_v6 {
                self.sock6 = fresh;
            } else {
                self.sock4 = fresh;
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
    pub fn throttle_stats(&self) -> (u64, u64, usize) {
        (self.throttle.suppressed, self.throttle.summaries, self.throttle.tracked_keys())
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
pub fn logstash_line(event: &Event, severity: Severity, hostname: &str) -> String {
    let mut out = String::with_capacity(256);
    out.push('{');
    json_kv_raw(&mut out, "timestamp", &event.sec.to_string(), true);
    json_kv_str(&mut out, "sensor", hostname, false);
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
