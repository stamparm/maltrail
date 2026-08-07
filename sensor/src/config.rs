//! `maltrail.conf` reader — a faithful port of `core/settings.py:read_config()`.
//!
//! The existing configuration file is the only configuration source; every option the
//! Python sensor honours is honoured here with the same name, type coercion and
//! validation. A handful of *new* capture-tuning options exist (all optional, all with
//! conservative defaults) because the Rust sensor talks to libpcap directly instead of
//! going through the Python mmap ring — they are listed in `docs/COMPATIBILITY.md`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::addr::parse_host_port;
use crate::settings;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<String>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// `core/settings.py:BLOCK_LENGTH` — retained because `CAPTURE_BUFFER` is rounded down to
/// a whole number of ring blocks and operators compare the logged value with Python's.
pub const BLOCK_LENGTH: u64 = 1 + 2 + 4 + 4 + 4 + settings::SNAP_LEN as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutMode {
    Hash,
    Lb,
    Cpu,
    Rollover,
    Random,
    Qm,
}

impl FanoutMode {
    /// Values from `linux/if_packet.h`.
    pub fn kernel_value(self) -> u32 {
        match self {
            FanoutMode::Hash => 0,
            FanoutMode::Lb => 1,
            FanoutMode::Cpu => 2,
            FanoutMode::Rollover => 3,
            FanoutMode::Random => 4,
            FanoutMode::Qm => 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            FanoutMode::Hash => "hash",
            FanoutMode::Lb => "lb",
            FanoutMode::Cpu => "cpu",
            FanoutMode::Rollover => "rollover",
            FanoutMode::Random => "random",
            FanoutMode::Qm => "qm",
        }
    }

    fn parse(value: &str) -> Option<FanoutMode> {
        match value.trim().to_ascii_lowercase().as_str() {
            "hash" | "" => Some(FanoutMode::Hash),
            "lb" | "roundrobin" | "round-robin" => Some(FanoutMode::Lb),
            "cpu" => Some(FanoutMode::Cpu),
            "rollover" => Some(FanoutMode::Rollover),
            "random" => Some(FanoutMode::Random),
            "qm" => Some(FanoutMode::Qm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSource {
    /// Use the pcap record timestamp (what live capture and Python 2 do).
    Pcap,
    /// Substitute wall-clock time, reproducing the Python 3 `pcapy-ng` workaround in
    /// `sensor.py:packet_handler` (needed for strict offline parity runs).
    Wallclock,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub raw: HashMap<String, Value>,
    pub config_file: PathBuf,
    pub root: PathBuf,

    // --- CLI ---
    pub pcap_files: Vec<PathBuf>,
    pub console: bool,
    pub quiet: bool,
    pub offline: bool,
    pub debug: bool,

    // --- sensor options (core/settings.py names) ---
    pub monitor_interface: String,
    pub capture_filter: String,
    pub capture_buffer: u64,
    pub log_dir: PathBuf,
    pub trails_file: PathBuf,
    pub sensor_name: String,
    pub process_count: u32,
    pub update_period: u64,
    pub use_heuristics: bool,
    pub disabled_heuristics: Vec<String>,
    pub scan_window: u64,
    pub check_missing_host: bool,
    pub check_host_domains: bool,
    pub disable_local_log_storage: bool,
    pub disable_check_sudo: bool,
    pub show_debug: bool,
    pub log_server: String,
    pub syslog_server: String,
    pub logstash_server: String,
    pub remote_severity_regex: String,
    pub ignore_events_regex: String,
    pub user_whitelist: Option<PathBuf>,
    pub user_ignorelist: Option<PathBuf>,
    pub use_condensed_storage: bool,
    /// New: opt out of the startup/periodic trail refresh (for hosts where trails.csv is managed
    /// externally, e.g. pushed by the Maltrail server). Default OFF, i.e. the sensor refreshes
    /// trails exactly like sensor.py does.
    pub disable_trail_updates: bool,
    /// New: repair feed-mangled wildcard-trail patterns instead of dropping them the way
    /// `build_trails_regex()` does. ON by default (it recovers real trails that Maltrail's own
    /// trail generation mangles); set false for byte-exact wildcard parity with `sensor.py`.
    pub repair_truncated_trails: bool,
    /// New: start even when the trail set is empty. OFF by default — a sensor with zero trails
    /// starts cleanly, reports itself healthy and detects nothing, which is the worst failure an
    /// IDS has. Turn on only where an empty set is genuinely expected (heuristics-only sensors,
    /// or a first boot whose trails arrive out of band).
    pub allow_empty_trails: bool,
    /// New: smallest fraction of the current trail count a RELOAD may produce and still be
    /// accepted (0.5 = "reject anything that loses more than half the trails"). Guards against a
    /// truncated or half-written trails.csv silently replacing a good store. 0 disables the check.
    pub trail_reload_min_ratio: f64,
    /// New: event-log throttling. See `crate::throttle` — the shipped default replaces
    /// `core/log.py`'s `sec // PROCESS_COUNT` bucket with burst-then-summarize.
    pub event_throttle_mode: crate::throttle::ThrottleMode,
    pub event_throttle_window: u64,
    pub event_throttle_burst: u32,
    pub event_throttle_max_keys: usize,
    /// New: size of the per-worker domain result caches (default `MAX_CACHE_ENTRIES`, 1000).
    ///
    /// These are PURE caches — the size changes only how often a verdict is recomputed, never the
    /// verdict — so raising it is behaviour-neutral. It is also, measurably, a bad idea under the
    /// workload that motivated it: on a 1M-query DGA flood, 1000 entries cost 1,554 ns/query,
    /// 4,096 cost 1,704 ns and 16,384 cost 2,004 ns. A flood misses at any size, and a bigger
    /// cache just makes each miss touch a colder structure. Kept configurable for hosts whose
    /// working set genuinely fits; the default stays where Python put it.
    pub domain_cache_entries: usize,

    // --- fast-path / fanout options shared with the Python sensor ---
    pub capture_fanout: u32,
    pub use_fast_prefilter: bool,
    pub fast_flow_cutoff: u32,

    // --- Rust-sensor capture tuning (new; see docs/COMPATIBILITY.md) ---
    pub capture_workers: u32,
    pub capture_buffer_size: u64,
    pub capture_snaplen: usize,
    pub capture_timeout_ms: i32,
    pub capture_immediate: bool,
    pub capture_fanout_mode: FanoutMode,
    pub capture_fanout_defrag: bool,
    pub capture_fanout_group: Option<u16>,
    pub offline_timestamps: TimestampSource,
    pub metrics_interval: u64,
    /// New: `host:port` for the Prometheus metrics endpoint. Empty = disabled. Bind loopback
    /// unless you mean to expose traffic volumes and detection counts to the network.
    pub stats_address: String,
}

fn cpu_count() -> u32 {
    std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1)
}

fn expanduser(value: &str) -> String {
    if let Some(rest) = value.strip_prefix('~') {
        if rest.is_empty() || rest.starts_with('/') {
            if let Ok(home) = std::env::var("HOME") {
                return format!("{home}{rest}");
            }
        }
    }
    value.to_string()
}

/// Lexical `os.path.realpath(os.path.join(base, path))`. Deliberately does not touch the
/// filesystem: Python's `realpath` also succeeds for a `LOG_DIR` that does not exist yet.
fn normalize_path(base: &Path, value: &str) -> PathBuf {
    let expanded = expanduser(value);
    let joined = if Path::new(&expanded).is_absolute() { PathBuf::from(&expanded) } else { base.join(&expanded) };
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut is_abs = false;
    for comp in joined.components() {
        match comp {
            std::path::Component::RootDir => {
                is_abs = true;
                out.clear();
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(p) => out.push(p.to_os_string()),
            std::path::Component::Prefix(p) => out.push(p.as_os_str().to_os_string()),
        }
    }
    let mut result = PathBuf::new();
    if is_abs {
        result.push("/");
    }
    for part in out {
        result.push(part);
    }
    result
}

/// Values from `core/settings.py` that `$VAR` references in the config file may resolve to.
fn settings_global(name: &str, root: &Path) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    Some(match name {
        "NAME" => settings::NAME.to_string(),
        "VERSION" => settings::VERSION.to_string(),
        "HOMEPAGE" => settings::HOMEPAGE.to_string(),
        "ROOT_DIR" => root.display().to_string(),
        "HTML_DIR" => root.join("html").display().to_string(),
        "SYSTEM_LOG_DIR" => "/var/log".to_string(),
        "HOSTNAME" => hostname(),
        "USERS_DIR" => format!("{home}/.maltrail"),
        "DEFAULT_TRAILS_FILE" => format!("{home}/.maltrail/trails.csv"),
        "IPCAT_CSV_FILE" => format!("{home}/.maltrail/ipcat.csv"),
        "TIME_FORMAT" => settings::TIME_FORMAT.to_string(),
        "SNAP_LEN" => settings::SNAP_LEN.to_string(),
        "HTTP_DEFAULT_PORT" => "8338".to_string(),
        "CPU_CORES" => cpu_count().to_string(),
        "PLATFORM" => "posix".to_string(),
        _ => return None,
    })
}

pub fn hostname() -> String {
    // gethostname(2); matches socket.gethostname() used for SENSOR_NAME / CEF host.
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a valid, writable 256-byte buffer and we pass its true length;
    // gethostname NUL-terminates on success (truncation is tolerated below).
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len() - 1) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

macro_rules! bail {
    ($($arg:tt)*) => { return Err(ConfigError(format!($($arg)*))) };
}

/// Parse the raw key/value/array structure. Mirrors `read_config()` line handling
/// exactly, including its quirks (comment stripping before quoting, a value-less option
/// becoming an empty array, `strip("'\"")` on values).
pub fn parse_raw(content: &str, root: &Path) -> Result<HashMap<String, Value>, ConfigError> {
    let mut out: HashMap<String, Value> = HashMap::new();
    let mut array: Option<String> = None;

    for raw_line in content.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        // re.sub(r"\s*#.*", "", line)
        let line = match line.find('#') {
            Some(idx) => {
                let mut cut = idx;
                while cut > 0 && line.as_bytes()[cut - 1].is_ascii_whitespace() {
                    cut -= 1;
                }
                &line[..cut]
            }
            None => line,
        };
        if line.trim().is_empty() {
            continue;
        }

        if !line.contains(' ') {
            if line.bytes().any(|c| !(c.is_ascii_alphanumeric() || c == b'_')) {
                if array.as_deref() == Some("USERS") {
                    bail!("invalid USERS entry '{line}'\n[?] (hint: add whitespace at start of line)");
                }
                bail!("invalid configuration (line: '{line}')");
            }
            let name = line.to_ascii_uppercase();
            out.insert(name.clone(), Value::Array(Vec::new()));
            array = Some(name);
            continue;
        }

        if let Some(arr) = array.clone() {
            if line.starts_with(' ') {
                let entry = line.trim().to_string();
                if let Some(Value::Array(items)) = out.get_mut(&arr) {
                    if arr == "IP_ALIASES" {
                        // expand_range() on the address part (server-side option; kept for
                        // configuration-file compatibility only)
                        items.push(entry);
                    } else {
                        items.push(entry);
                    }
                }
                continue;
            }
        }
        array = None;

        let (name, value) = match line.trim().split_once(' ') {
            Some((n, v)) => (n, v),
            None => (line.trim(), ""),
        };
        let name = name.trim().to_ascii_uppercase();
        let value = value.trim_matches(|c| c == '\'' || c == '"').trim().to_string();

        // MALTRAIL_<NAME> environment override
        let value = match std::env::var(format!("MALTRAIL_{name}")) {
            Ok(env) if !env.is_empty() => env,
            _ => value,
        };

        const BOOL_PREFIXES: [&str; 6] = ["USE_", "SET_", "CHECK_", "ENABLE_", "SHOW_", "DISABLE_"];
        if BOOL_PREFIXES.iter().any(|p| name.starts_with(p)) {
            let lower = value.to_ascii_lowercase();
            if !value.is_empty() && !matches!(lower.as_str(), "0" | "1" | "false" | "true") {
                crate::cprintln!(
                    "[!] configuration switch '{name}' expects a boolean (0/1/true/false), got '{value}' (treated as false)"
                );
            }
            out.insert(name, Value::Bool(matches!(lower.as_str(), "1" | "true")));
        } else if !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()) {
            out.insert(name, Value::Int(value.parse::<i64>().unwrap_or(0)));
        } else {
            let mut expanded = value.clone();
            // re.finditer(r"\$([A-Z0-9_]+)", value)
            let mut replacements: Vec<(String, String)> = Vec::new();
            let bytes = expanded.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'$' {
                    let start = i + 1;
                    let mut end = start;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_uppercase() || bytes[end].is_ascii_digit() || bytes[end] == b'_')
                    {
                        end += 1;
                    }
                    if end > start {
                        let var = &expanded[start..end];
                        let whole = format!("${var}");
                        let sub = settings_global(var, root)
                            .or_else(|| std::env::var(var).ok())
                            .unwrap_or_else(|| whole.clone());
                        replacements.push((whole, sub));
                        i = end;
                        continue;
                    }
                }
                i += 1;
            }
            for (from, to) in replacements {
                expanded = expanded.replace(&from, &to);
            }
            if name.ends_with("_DIR") {
                expanded = normalize_path(root, &expanded).display().to_string();
            }
            out.insert(name, Value::Str(expanded));
        }
    }

    Ok(out)
}

fn get_bool(raw: &HashMap<String, Value>, key: &str) -> bool {
    matches!(raw.get(key), Some(Value::Bool(true)))
}

fn get_bool_opt(raw: &HashMap<String, Value>, key: &str) -> Option<bool> {
    match raw.get(key) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn get_str(raw: &HashMap<String, Value>, key: &str) -> String {
    match raw.get(key) {
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Int(i)) => i.to_string(),
        Some(Value::Bool(b)) => (if *b { "True" } else { "False" }).to_string(),
        _ => String::new(),
    }
}

fn get_u64(raw: &HashMap<String, Value>, key: &str) -> Option<u64> {
    match raw.get(key) {
        Some(Value::Int(i)) if *i >= 0 => Some(*i as u64),
        Some(Value::Str(s)) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => s.parse().ok(),
        _ => None,
    }
}

/// `core/settings.py` CAPTURE_BUFFER coercion: plain bytes, `<n>kB|MB|GB`, or `<n>%` of
/// total physical memory.
pub fn parse_byte_size(value: &str) -> Result<u64, ConfigError> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()) {
        return value.parse::<u64>().map_err(|e| ConfigError(e.to_string()));
    }
    let lower = value.to_ascii_lowercase();
    if let Some(idx) = lower.find(|c: char| c.is_ascii_alphabetic() || c == '%') {
        let (num, unit) = (&lower[..idx], lower[idx..].trim());
        let num: u64 = num.trim().parse().map_err(|_| ConfigError(format!("invalid size '{value}'")))?;
        return match unit {
            "kb" | "k" => Ok(num * 1024),
            "mb" | "m" => Ok(num * 1024 * 1024),
            "gb" | "g" => Ok(num * 1024 * 1024 * 1024),
            "%" => {
                let total = total_physmem().ok_or_else(|| {
                    ConfigError("unable to determine total physical memory. Please use absolute value".into())
                })?;
                Ok(total * num / 100)
            }
            _ => Err(ConfigError(format!("invalid size '{value}'"))),
        };
    }
    Err(ConfigError(format!("invalid size '{value}'")))
}

/// `core/settings.py:_get_total_physmem()` (Linux branch).
pub fn total_physmem() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// `sensor.py:_fanout_count()` — identical parsing.
pub fn fanout_count(value: Option<&Value>) -> u32 {
    let text = match value {
        None => return 0,
        Some(Value::Int(i)) => i.to_string(),
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Bool(b)) => (if *b { "true" } else { "false" }).to_string(),
        Some(Value::Array(_)) => return 0,
    };
    if text.is_empty() {
        return 0;
    }
    let n = match text.trim().parse::<i64>() {
        Ok(n) => n,
        Err(_) => {
            if matches!(text.trim().to_ascii_lowercase().as_str(), "true" | "auto" | "yes" | "on") {
                cpu_count() as i64
            } else {
                0
            }
        }
    };
    if n > 1 {
        n as u32
    } else {
        0
    }
}

/// `sensor.py:_cfg_bool()` — for switches without a boolean-implying prefix.
pub fn cfg_bool(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(b)) => *b,
        Some(Value::Int(i)) => *i == 1,
        Some(Value::Str(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        _ => false,
    }
}

impl Config {
    pub fn load(config_file: &Path) -> Result<Config, ConfigError> {
        if !config_file.is_file() {
            bail!("missing configuration file '{}'", config_file.display());
        }
        crate::cprintln!("[i] using configuration file '{}'", config_file.display());
        let content = std::fs::read_to_string(config_file)
            .map_err(|e| ConfigError(format!("unable to read configuration file '{}' ({e})", config_file.display())))?;

        let root = settings::resolve_root(config_file);
        let raw = parse_raw(&content, &root)?;

        for option in ["MONITOR_INTERFACE", "CAPTURE_BUFFER", "LOG_DIR"] {
            if !raw.contains_key(option) {
                bail!("missing mandatory option '{option}' in configuration file '{}'", config_file.display());
            }
        }

        let capture_buffer_raw = get_str(&raw, "CAPTURE_BUFFER");
        let capture_buffer = if capture_buffer_raw.is_empty() {
            0
        } else {
            let bytes = parse_byte_size(&capture_buffer_raw).map_err(|e| {
                ConfigError(format!("invalid configuration value for 'CAPTURE_BUFFER' ('{capture_buffer_raw}'): {e}"))
            })?;
            bytes / BLOCK_LENGTH * BLOCK_LENGTH
        };

        let log_server = get_str(&raw, "LOG_SERVER");
        if !log_server.is_empty() && !log_server.contains(':') {
            bail!("invalid configuration value for 'LOG_SERVER' ('{log_server}')");
        }
        let syslog_server = get_str(&raw, "SYSLOG_SERVER");
        if !syslog_server.is_empty() && parse_host_port(&syslog_server).1.is_none() {
            bail!("invalid configuration value for 'SYSLOG_SERVER' ('{syslog_server}')");
        }
        let logstash_server = get_str(&raw, "LOGSTASH_SERVER");
        if !logstash_server.is_empty() && parse_host_port(&logstash_server).1.is_none() {
            bail!("invalid configuration value for 'LOGSTASH_SERVER' ('{logstash_server}')");
        }
        let remote_severity_regex = get_str(&raw, "REMOTE_SEVERITY_REGEX");
        if !remote_severity_regex.is_empty() && crate::pyre::build_fancy(&remote_severity_regex).is_err() {
            bail!("invalid configuration value for 'REMOTE_SEVERITY_REGEX' ('{remote_severity_regex}')");
        }

        let update_period = match get_u64(&raw, "UPDATE_PERIOD") {
            Some(v) => v,
            None => bail!("invalid configuration value for 'UPDATE_PERIOD' ('{}')", get_str(&raw, "UPDATE_PERIOD")),
        };

        let user_whitelist = {
            let v = get_str(&raw, "USER_WHITELIST");
            if v.is_empty() {
                None
            } else if v.contains(',') {
                crate::cprintln!("[x] configuration value 'USER_WHITELIST' has been changed. Please use it to set location of whitelist file");
                None
            } else {
                let p = normalize_path(&root, &v);
                if !p.is_file() {
                    bail!("missing 'USER_WHITELIST' file '{}'", p.display());
                }
                Some(p)
            }
        };
        let user_ignorelist = {
            let v = get_str(&raw, "USER_IGNORELIST");
            if v.is_empty() {
                None
            } else {
                let p = normalize_path(&root, &v);
                if !p.is_file() {
                    bail!("missing 'USER_IGNORELIST' file '{}'", p.display());
                }
                Some(p)
            }
        };

        let trails_file = {
            let v = get_str(&raw, "TRAILS_FILE");
            if v.is_empty() {
                let home = std::env::var("HOME").unwrap_or_default();
                PathBuf::from(format!("{home}/.maltrail/trails.csv"))
            } else {
                normalize_path(&std::env::current_dir().unwrap_or_else(|_| root.clone()), &v)
            }
        };

        let process_count = get_u64(&raw, "PROCESS_COUNT").filter(|v| *v > 0).unwrap_or(cpu_count() as u64) as u32;

        let disabled_heuristics = {
            let raw_value = get_str(&raw, "DISABLED_HEURISTICS");
            raw_value
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let scan_window = get_u64(&raw, "SCAN_WINDOW").unwrap_or(30).clamp(1, 3600);

        let capture_fanout = fanout_count(raw.get("CAPTURE_FANOUT"));
        // One Rust worker == one Python worker process, so the default worker count is
        // PROCESS_COUNT. This is not cosmetic: `core/log.py`'s throttle keeps state PER WORKER
        // ("2 events per (src,trail) per `sec // PROCESS_COUNT` bucket"), so a sensor running
        // fewer workers than PROCESS_COUNT writes proportionally fewer lines for the same
        // traffic. Defaulting to CAPTURE_FANOUT (unset in the shipped maltrail.conf) meant ONE
        // worker against sensor.py's sixteen, and therefore ~1/16 of the log lines for a
        // repeated detection - the same events, throttled 16x harder.
        // sensor.py runs PROCESS_COUNT processes in total (one captures, PROCESS_COUNT-1 process
        // packets); a Rust worker does both, so PROCESS_COUNT workers is the closest equivalent.
        let capture_workers = match get_u64(&raw, "CAPTURE_WORKERS") {
            Some(n) if n > 0 => n as u32,
            _ => match get_str(&raw, "CAPTURE_WORKERS").trim().to_ascii_lowercase().as_str() {
                "auto" | "true" | "yes" | "on" => cpu_count(),
                // CAPTURE_FANOUT counts capture SOCKETS in sensor.py; here a worker owns its
                // socket, so the two knobs collapse into one and the larger wins.
                _ => capture_fanout.max(process_count).max(1),
            },
        };

        let event_throttle_mode = {
            let v = get_str(&raw, "EVENT_THROTTLE_MODE");
            match crate::throttle::ThrottleMode::parse(&v) {
                Some(m) => m,
                None => {
                    return Err(ConfigError(format!(
                        "invalid configuration value for 'EVENT_THROTTLE_MODE' ('{v}'): expected \
                         'summarize', 'legacy' or 'off'"
                    )))
                }
            }
        };

        let capture_buffer_size = {
            let v = get_str(&raw, "CAPTURE_BUFFER_SIZE");
            if v.is_empty() {
                16 * 1024 * 1024
            } else {
                parse_byte_size(&v).map_err(|e| {
                    ConfigError(format!("invalid configuration value for 'CAPTURE_BUFFER_SIZE' ('{v}'): {e}"))
                })?
            }
        };

        let capture_fanout_mode = {
            let v = get_str(&raw, "CAPTURE_FANOUT_MODE");
            match FanoutMode::parse(&v) {
                Some(m) => m,
                None => bail!("invalid configuration value for 'CAPTURE_FANOUT_MODE' ('{v}')"),
            }
        };

        let offline_timestamps = {
            let v = get_str(&raw, "OFFLINE_TIMESTAMPS").to_ascii_lowercase();
            match v.trim() {
                "" | "pcap" => TimestampSource::Pcap,
                "wallclock" | "wall-clock" | "now" => TimestampSource::Wallclock,
                other => bail!("invalid configuration value for 'OFFLINE_TIMESTAMPS' ('{other}')"),
            }
        };

        let sensor_name = {
            let v = get_str(&raw, "SENSOR_NAME");
            if v.is_empty() {
                hostname()
            } else {
                v
            }
        };

        Ok(Config {
            config_file: config_file.to_path_buf(),
            root: root.clone(),

            pcap_files: Vec::new(),
            console: false,
            quiet: false,
            offline: false,
            debug: false,

            monitor_interface: get_str(&raw, "MONITOR_INTERFACE"),
            capture_filter: get_str(&raw, "CAPTURE_FILTER"),
            capture_buffer,
            log_dir: PathBuf::from(get_str(&raw, "LOG_DIR")),
            trails_file,
            sensor_name,
            process_count,
            update_period,
            use_heuristics: get_bool(&raw, "USE_HEURISTICS"),
            disabled_heuristics,
            scan_window,
            check_missing_host: get_bool(&raw, "CHECK_MISSING_HOST"),
            check_host_domains: get_bool(&raw, "CHECK_HOST_DOMAINS"),
            disable_local_log_storage: get_bool(&raw, "DISABLE_LOCAL_LOG_STORAGE"),
            disable_check_sudo: get_bool(&raw, "DISABLE_CHECK_SUDO"),
            show_debug: get_bool(&raw, "SHOW_DEBUG"),
            log_server,
            syslog_server,
            logstash_server,
            remote_severity_regex,
            ignore_events_regex: get_str(&raw, "IGNORE_EVENTS_REGEX"),
            user_whitelist,
            user_ignorelist,
            // absent switch defaults to on, exactly like read_config()
            use_condensed_storage: get_bool_opt(&raw, "USE_CONDENSED_STORAGE").unwrap_or(true),
            disable_trail_updates: get_bool(&raw, "DISABLE_TRAIL_UPDATES"),
            repair_truncated_trails: get_bool_opt(&raw, "REPAIR_TRUNCATED_TRAILS").unwrap_or(true),
            // cfg_bool, NOT get_bool: only names starting with USE_/SET_/CHECK_/ENABLE_/SHOW_/
            // DISABLE_ are coerced to Value::Bool by the parser (core/settings.py's convention),
            // so `get_bool` on any other name silently reads false however it is written.
            allow_empty_trails: cfg_bool(raw.get("ALLOW_EMPTY_TRAILS")),
            trail_reload_min_ratio: get_str(&raw, "TRAIL_RELOAD_MIN_RATIO")
                .parse::<f64>()
                .ok()
                .filter(|v| (0.0..=1.0).contains(v))
                .unwrap_or(0.5),
            event_throttle_mode,
            event_throttle_window: get_u64(&raw, "EVENT_THROTTLE_WINDOW").unwrap_or(60),
            event_throttle_burst: get_u64(&raw, "EVENT_THROTTLE_BURST").unwrap_or(3).min(u32::MAX as u64) as u32,
            event_throttle_max_keys: get_u64(&raw, "EVENT_THROTTLE_MAX_KEYS").unwrap_or(50_000) as usize,
            domain_cache_entries: get_u64(&raw, "DOMAIN_CACHE_ENTRIES")
                .unwrap_or(settings::MAX_CACHE_ENTRIES as u64)
                .max(64) as usize,

            capture_fanout,
            use_fast_prefilter: get_bool(&raw, "USE_FAST_PREFILTER"),
            fast_flow_cutoff: get_u64(&raw, "FAST_FLOW_CUTOFF").unwrap_or(4) as u32,

            capture_workers,
            capture_buffer_size,
            capture_snaplen: get_u64(&raw, "CAPTURE_SNAPLEN").unwrap_or(settings::SNAP_LEN as u64) as usize,
            capture_timeout_ms: get_u64(&raw, "CAPTURE_TIMEOUT").unwrap_or(settings::CAPTURE_TIMEOUT_MS as u64) as i32,
            capture_immediate: cfg_bool(raw.get("CAPTURE_IMMEDIATE")),
            capture_fanout_mode,
            capture_fanout_defrag: cfg_bool(raw.get("CAPTURE_FANOUT_DEFRAG")),
            capture_fanout_group: get_u64(&raw, "CAPTURE_FANOUT_GROUP").map(|v| (v & 0xffff) as u16),
            offline_timestamps,
            stats_address: get_str(&raw, "STATS_ADDRESS"),
            metrics_interval: get_u64(&raw, "METRICS_INTERVAL").unwrap_or(3600),

            raw,
        })
    }

    pub fn is_offline_replay(&self) -> bool {
        !self.pcap_files.is_empty()
    }

    /// `sensor.py:_heuristic_enabled()`
    pub fn heuristic_enabled(&self, name: &str) -> bool {
        !self.disabled_heuristics.iter().any(|d| d == name)
    }

    pub fn monitor_interfaces(&self) -> Vec<String> {
        self.monitor_interface.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    #[test]
    fn parses_scalars_arrays_and_booleans() {
        let content = "\
# a comment
MONITOR_INTERFACE any
PROCESS_COUNT 16
USE_HEURISTICS true
USE_SSL false
CAPTURE_BUFFER 512MB
USERS
    admin:hash:0:
    local:hash:1000:192.168.0.0/16
SENSOR_NAME box   # trailing comment
";
        let raw = parse_raw(content, &root()).unwrap();
        assert_eq!(raw["MONITOR_INTERFACE"], Value::Str("any".into()));
        assert_eq!(raw["PROCESS_COUNT"], Value::Int(16));
        assert_eq!(raw["USE_HEURISTICS"], Value::Bool(true));
        assert_eq!(raw["USE_SSL"], Value::Bool(false));
        assert_eq!(raw["SENSOR_NAME"], Value::Str("box".into()));
        match &raw["USERS"] {
            Value::Array(items) => assert_eq!(items.len(), 2),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn dollar_expansion_and_dir_normalisation() {
        let content = "LOG_DIR $SYSTEM_LOG_DIR/maltrail\nSENSOR_NAME $HOSTNAME\nX_DIR ./sub/../logs\n";
        let raw = parse_raw(content, &root()).unwrap();
        assert_eq!(raw["LOG_DIR"], Value::Str("/var/log/maltrail".into()));
        assert_eq!(raw["SENSOR_NAME"], Value::Str(hostname()));
        assert_eq!(raw["X_DIR"], Value::Str(root().join("logs").display().to_string()));
    }

    #[test]
    fn unknown_dollar_var_is_left_alone() {
        let content = "FOO $NOPE_NOT_SET_ANYWHERE\n";
        let raw = parse_raw(content, &root()).unwrap();
        assert_eq!(raw["FOO"], Value::Str("$NOPE_NOT_SET_ANYWHERE".into()));
    }

    #[test]
    fn byte_sizes() {
        assert_eq!(parse_byte_size("1024").unwrap(), 1024);
        assert_eq!(parse_byte_size("512MB").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_byte_size("2 GB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_byte_size("bogus").is_err());
    }

    #[test]
    fn fanout_count_matches_python_table() {
        let cpu = cpu_count();
        let cases: [(Option<Value>, u32); 10] = [
            (None, 0),
            (Some(Value::Str(String::new())), 0),
            (Some(Value::Int(0)), 0),
            (Some(Value::Int(1)), 0),
            (Some(Value::Int(4)), 4),
            (Some(Value::Int(8)), 8),
            (Some(Value::Str("true".into())), cpu),
            (Some(Value::Str("auto".into())), cpu),
            (Some(Value::Str("false".into())), 0),
            (Some(Value::Str("garbage".into())), 0),
        ];
        for (value, expected) in cases {
            assert_eq!(fanout_count(value.as_ref()), expected, "{value:?}");
        }
    }

    #[test]
    fn real_maltrail_conf_loads() {
        let cfg = Config::load(&root().join("maltrail.conf")).expect("shipped maltrail.conf must load");
        assert_eq!(cfg.monitor_interface, "any");
        assert!(cfg.use_heuristics);
        assert_eq!(cfg.process_count, 16);
        assert_eq!(cfg.update_period, 86400);
        assert!(cfg.capture_buffer > 0);
        assert_eq!(cfg.capture_buffer % BLOCK_LENGTH, 0);
        assert!(cfg.log_dir.ends_with("maltrail"));
        assert!(!cfg.capture_filter.is_empty());
        assert!(!cfg.remote_severity_regex.is_empty());
        assert_eq!(cfg.sensor_name, hostname());
        assert!(cfg.use_condensed_storage);
    }

    #[test]
    fn missing_mandatory_option_is_fatal() {
        let dir = std::env::temp_dir().join("mt-cfg-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.conf");
        std::fs::write(&path, "MONITOR_INTERFACE any\n").unwrap();
        let err = Config::load(&path).unwrap_err();
        assert!(err.0.contains("missing mandatory option"), "{}", err.0);
    }
}
