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

/// Default libpcap ring per capture socket.
///
/// 64 MB, the low end of what sensor/docs/INSTALL.md has always recommended for throughput, and
/// roughly half a second of a saturated gigabit link. The previous 16 MB default contradicted that
/// guidance and is far too small for the links Maltrail is pointed at: measured at ~250k small
/// packets/s it dropped over 90% of offered traffic, taking 63% of injected detections with it.
pub const DEFAULT_CAPTURE_RING: u64 = 64 * 1024 * 1024;

/// Floor for the ring. Below this a gigabit link drops on any ordinary burst, and the setting is
/// not worth having if it can be turned into a self-inflicted blind spot by a typo.
pub const MIN_CAPTURE_RING: u64 = 4 * 1024 * 1024;

/// Ceiling for an EXPLICIT `CAPTURE_BUFFER_SIZE`. High, because an operator naming this option is
/// telling us about their link, not guessing - a 40 Gbit tap with one worker can justify it.
pub const MAX_CAPTURE_RING: u64 = 1024 * 1024 * 1024;

/// Ceiling when the ring is INFERRED from `CAPTURE_BUFFER` rather than asked for.
///
/// `CAPTURE_BUFFER` ships as `10%` of physical memory and meant something else entirely on the
/// Python sensor (a userspace ring shared between processes). Reading it as a libpcap ring is a
/// reasonable inference - it is what maltrail.conf has always claimed - but it is still an
/// inference, so it gets the conservative end of the range docs/INSTALL.md recommends. On a 64 GB
/// host that is 256 MB per worker instead of 6.4 GB of locked kernel memory times the worker
/// count. An operator who genuinely wants more says CAPTURE_BUFFER_SIZE and gets it.
pub const MAX_INFERRED_CAPTURE_RING: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutMode {
    Hash,
    Lb,
    Cpu,
    Rollover,
    Random,
    Qm,
    /// `PACKET_FANOUT_CBPF` carrying the source-hash program from `capture::srcfanout`.
    ///
    /// Every packet a host sends reaches one worker, which is what the per-source scan heuristics
    /// were written for. `Hash` splits by flow and scatters them: measured over the corpus, 66% of
    /// single-worker heuristic alerts survive at 8 workers under `Hash` and 100% under this.
    Source,
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
            FanoutMode::Source => 6, // PACKET_FANOUT_CBPF
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
            FanoutMode::Source => "source",
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
            "source" | "src" => Some(FanoutMode::Source),
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
    /// `LOCAL_LOG_FORMAT json` writes the event log as one JSON object per line.
    pub local_log_json: bool,
    pub disable_check_sudo: bool,
    pub show_debug: bool,
    pub log_server: String,
    pub log_server_secret: String,
    pub syslog_server: String,
    pub logstash_server: String,
    pub remote_severity_regex: String,
    pub ignore_events_regex: String,
    pub user_whitelist: Option<PathBuf>,
    pub user_ignorelist: Option<PathBuf>,
    pub use_condensed_storage: bool,
    /// Match TLS server certificates against the trail set by SHA-1 fingerprint. New in this
    /// sensor (`sensor.py` extracts certificates for reporting but never matches them), so
    /// `docs/COMPATIBILITY.md` turns it off to keep the differential comparison honest.
    pub check_tls_certificates: bool,
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
    /// Human-readable record of every out-of-range option that was forced into bounds at load.
    /// Reported by `-T`; empty on a sane configuration.
    pub clamps: Vec<String>,
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

/// `os.path.expanduser("~")`'s notion of home.
///
/// Python reads HOME on POSIX and USERPROFILE on Windows, where HOME is normally unset - so a
/// sensor that only looked at HOME resolved `$USERS_DIR` to `/.maltrail` on Windows while the
/// server it shares that path with resolved it to the real profile directory.
fn home_dir() -> String {
    #[cfg(not(windows))]
    {
        std::env::var("HOME").unwrap_or_default()
    }
    #[cfg(windows)]
    {
        // The order os.path.expanduser() uses.
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return profile;
        }
        match (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
            (Ok(drive), Ok(path)) => format!("{drive}{path}"),
            _ => std::env::var("HOME").unwrap_or_default(),
        }
    }
}

fn expanduser(value: &str) -> String {
    if let Some(rest) = value.strip_prefix('~') {
        // A bare '~' or '~/...'. Windows accepts a backslash there too, which is the separator a
        // config file written on Windows would naturally use.
        let separated = rest.starts_with('/') || (cfg!(windows) && rest.starts_with('\\'));
        if rest.is_empty() || separated {
            let home = home_dir();
            if !home.is_empty() {
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
    let mut prefix: Option<std::ffi::OsString> = None;
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
            // A drive letter or UNC share, and NOT a path element. Holding it in `out` lost it:
            // `RootDir` arrives immediately after and clears the accumulator, so on Windows
            // 'Z:\tmp\logs' normalised to '\tmp\logs' - a path that resolves against whichever
            // volume the process happens to be on. A LOG_DIR on D: would have been written to C:
            // with nothing saying so. Unix never produces this component, so nothing changes there.
            std::path::Component::Prefix(p) => {
                prefix = Some(p.as_os_str().to_os_string());
                out.clear();
            }
        }
    }
    let mut head = std::ffi::OsString::new();
    if let Some(p) = prefix {
        head.push(&p);
    }
    if is_abs {
        head.push(std::path::MAIN_SEPARATOR_STR);
    }
    let mut result = PathBuf::from(head);
    for part in out {
        result.push(part);
    }
    result
}

/// Values from `core/settings.py` that `$VAR` references in the config file may resolve to.
fn settings_global(name: &str, root: &Path) -> Option<String> {
    let home = home_dir();
    Some(match name {
        "NAME" => settings::NAME.to_string(),
        "VERSION" => settings::VERSION.to_string(),
        "HOMEPAGE" => settings::HOMEPAGE.to_string(),
        "ROOT_DIR" => root.display().to_string(),
        "HTML_DIR" => root.join("html").display().to_string(),
        // core/settings.py:114 - `"/var/log" if not IS_WIN else "C:\\Windows\\Logs"`. The sensor
        // hardcoded the POSIX half, so on Windows the shipped `LOG_DIR $SYSTEM_LOG_DIR/maltrail`
        // put the sensor's events in `\var\log\maltrail` on whatever the current drive was, while
        // the server read `C:\Windows\Logs\maltrail`. Two halves of one deployment writing to and
        // reading from different directories, with nothing reporting a problem.
        "SYSTEM_LOG_DIR" => if cfg!(windows) { "C:\\Windows\\Logs" } else { "/var/log" }.to_string(),
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

/// The host's own name, for `SENSOR_NAME` and the CEF host field.
///
/// Windows keeps this in the environment rather than behind `gethostname(2)` - the libc crate does
/// not expose winsock's copy - and `COMPUTERNAME` is the same name `socket.gethostname()` reports
/// there.
#[cfg(windows)]
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

#[cfg(not(windows))]
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
/// Option names present in the parsed config that no parser recognises (`KNOWN_CONFIG_OPTIONS`
/// covers every name read by `core/`, `server.py`, `sensor.py` and this sensor). Sorted, so the
/// warning order is stable across runs.
fn unknown_keys(raw: &HashMap<String, Value>) -> Vec<String> {
    let mut out: Vec<String> =
        raw.keys().filter(|name| !settings::KNOWN_CONFIG_OPTIONS.contains(&name.as_str())).cloned().collect();
    out.sort();
    out
}

/// Names in `DISABLED_HEURISTICS` that no heuristic answers to. Sorted, for a stable warning.
///
/// Same failure as `unknown_keys()` one level down: a typo'd VALUE parses fine and is ignored, so
/// the heuristic an operator meant to silence keeps firing while the file looks correct. It is
/// easy to get wrong - the shipped config listed six of the eight accepted names for a while.
fn unknown_heuristics(disabled: &[String]) -> Vec<String> {
    let mut out: Vec<String> =
        disabled.iter().filter(|name| !crate::heuristics::HEURISTIC_NAMES.contains(&name.as_str())).cloned().collect();
    out.sort();
    out.dedup();
    out
}

pub fn parse_raw(content: &str, root: &Path) -> Result<HashMap<String, Value>, ConfigError> {
    let mut out: HashMap<String, Value> = HashMap::new();
    let mut array: Option<String> = None;

    // A UTF-8 BOM is invisible and fatal. Notepad writes one whenever it saves as UTF-8, and so
    // does Windows PowerShell's `Set-Content -Encoding UTF8`, so an operator who opens
    // maltrail.conf on Windows, changes nothing and saves gets a file the sensor refuses with
    //
    //     [!] invalid configuration (line: '')
    //
    // naming a line that looks empty. The bytes are content, not configuration; drop them.
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);

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
                    // IP_ALIASES is a server-side option, parsed here only so the sensor does
                    // not reject a shared configuration file. Its address part is not expanded.
                    items.push(entry);
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

/// `core/settings.py:_get_total_physmem()`.
///
/// The shipped `maltrail.conf` says `CAPTURE_BUFFER 10%`, so a platform where this returns None
/// cannot start with the default configuration at all - the sensor refuses with "unable to
/// determine total physical memory". That is exactly what happened on FreeBSD and macOS, where
/// there is no /proc: the binary ran, `--version` answered, and `-T` failed on the config file the
/// installer had just written.
#[cfg(target_os = "linux")]
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

/// The BSDs and macOS answer the same question through sysctl. `hw.memsize` is a 64-bit byte count
/// on Darwin; FreeBSD's `hw.physmem` is `unsigned long`, which is also 64-bit on every target that
/// matters here, and `hw.realmem` is the fallback on the ones that do not carry `hw.physmem`.
/// OpenBSD has no `sysctlbyname` at all - it is a FreeBSD/NetBSD/macOS convenience, and OpenBSD
/// only offers the numeric MIB form of `sysctl`. The sensor did not compile there at all until
/// this branch existed:
///
/// ```text
/// error[E0425]: cannot find function `sysctlbyname` in crate `libc`
/// ```
///
/// `sysconf` rather than the numeric MIB: the libc crate does not export `HW_PHYSMEM64` for
/// OpenBSD either, and hardcoding the number would trade a compile error for a silently wrong
/// figure if it were ever wrong. `_SC_PHYS_PAGES` x `_SC_PAGESIZE` says exactly what it means.
#[cfg(target_os = "openbsd")]
pub fn total_physmem() -> Option<u64> {
    // SAFETY: sysconf reads a static system property and touches no memory of ours. It returns
    // -1 for a name the system does not know, which is what the checks below are for.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_size <= 0 {
        return None;
    }
    (pages as u64).checked_mul(page_size as u64)
}

#[cfg(all(not(target_os = "linux"), not(target_os = "openbsd"), not(windows)))]
pub fn total_physmem() -> Option<u64> {
    for name in ["hw.memsize\0", "hw.physmem\0", "hw.realmem\0"] {
        let mut value: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: `name` is NUL-terminated, `value` is a live u64 and `len` describes it. sysctlbyname
        // writes at most `len` bytes and reports what it wrote.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr() as *const libc::c_char,
                &mut value as *mut u64 as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 && value > 0 {
            return Some(value);
        }
    }
    None
}

/// Windows has neither /proc/meminfo nor sysctl, and `CAPTURE_BUFFER 10%` - the shipped default -
/// cannot be resolved without an answer here, so a None would refuse to start on the default
/// config. GlobalMemoryStatusEx is the equivalent; it lives in kernel32, which every Windows
/// target links already, so it costs no dependency.
#[cfg(windows)]
pub fn total_physmem() -> Option<u64> {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }
    extern "system" {
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }

    // SAFETY: `status` is a correctly sized, zero-initialised MEMORYSTATUSEX whose `dwLength` is
    // set to its own size, which is the call's only precondition.
    let mut status: MemoryStatusEx = unsafe { std::mem::zeroed() };
    status.length = std::mem::size_of::<MemoryStatusEx>() as u32;
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) } != 0;
    if ok && status.total_phys > 0 {
        Some(status.total_phys)
    } else {
        None
    }
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

/// The endpoints named by a remote-logging option: one, or several separated by commas,
/// semicolons or whitespace. `core/log.py:_endpoints()` splits the same way.
pub fn split_endpoints(value: &str) -> Vec<&str> {
    value.split([',', ';', ' ', '\t', '\n', '\r']).map(str::trim).filter(|s| !s.is_empty()).collect()
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

        for name in unknown_keys(&raw) {
            // A typo'd name parses fine and is then ignored - the feature it was meant to
            // configure just stays off while the file looks correct. Warn rather than fail: an
            // older config meeting a newer sensor (or the reverse) must keep working.
            crate::cprintln!(
                "[!] unknown configuration option '{}' in configuration file '{}' (typo? see 'maltrail.conf' for the accepted names)",
                name,
                config_file.display()
            );
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
        // Either option may name SEVERAL endpoints, so a sensor can feed redundant SIEM
        // collectors (issue #15164). Every one of them is validated: a typo in the second target
        // is exactly as fatal as one in the first, and silently forwarding to one of two
        // configured collectors is the kind of half-working that goes unnoticed for months.
        // Shared secret authenticating LOG_SERVER datagrams. Empty means the previous behaviour:
        // the events go out unsigned and the listener accepts anything that reaches it.
        let log_server_secret = get_str(&raw, "LOG_SERVER_SECRET");

        let syslog_server = get_str(&raw, "SYSLOG_SERVER");
        for endpoint in split_endpoints(&syslog_server) {
            if parse_host_port(endpoint).1.is_none() {
                bail!("invalid configuration value for 'SYSLOG_SERVER' ('{endpoint}')");
            }
        }
        let logstash_server = get_str(&raw, "LOGSTASH_SERVER");
        for endpoint in split_endpoints(&logstash_server) {
            if parse_host_port(endpoint).1.is_none() {
                bail!("invalid configuration value for 'LOGSTASH_SERVER' ('{endpoint}')");
            }
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

        let disabled_heuristics: Vec<String> = {
            let raw_value = get_str(&raw, "DISABLED_HEURISTICS");
            raw_value
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };

        for name in unknown_heuristics(&disabled_heuristics) {
            crate::cprintln!(
                "[!] unknown heuristic '{}' in 'DISABLED_HEURISTICS' (it is not muted; accepted names: {})",
                name,
                crate::heuristics::HEURISTIC_NAMES.join(", ")
            );
        }

        let scan_window = get_u64(&raw, "SCAN_WINDOW").unwrap_or(30).clamp(1, 3600);

        let capture_fanout = fanout_count(raw.get("CAPTURE_FANOUT"));
        // ONE worker by default, deliberately, and NOT derived from PROCESS_COUNT.
        //
        // This used to default to `max(CAPTURE_FANOUT, PROCESS_COUNT)`, i.e. 16 with the shipped
        // maltrail.conf, on the reasoning that one Rust worker == one Python worker process. That
        // reasoning was about log VOLUME: `core/log.py`'s throttle keeps state per worker, so
        // running fewer workers than PROCESS_COUNT wrote proportionally fewer lines for the same
        // traffic. It only ever applied to `EVENT_THROTTLE_MODE legacy`; the default `summarize`
        // mode aggregates suppressed events instead of discarding them, so nothing goes missing.
        //
        // What the old default cost is measured, not assumed. `PACKET_FANOUT_HASH` distributes by
        // FLOW while the scan heuristics count by SOURCE, so a scan is split across workers and
        // each one sees a fraction of it: `tests/multi_worker_parity.rs` finds 91% of the
        // one-worker heuristic alerts surviving at 2 workers, 86% at 4 and 65% at 8. The shipped
        // 16 was past the end of that curve, so every stock install ran degraded heuristics to buy
        // throughput it almost certainly did not need - one worker costs ~865 ns/packet, roughly
        // 1.1M packets/s.
        //
        // Exact trail detection is IDENTICAL at every worker count (same test, asserted in both
        // directions), so this trades nothing for IOC matching. Operators who really do saturate a
        // link set CAPTURE_WORKERS explicitly and take the documented dilution knowingly.
        let capture_workers = match get_u64(&raw, "CAPTURE_WORKERS") {
            Some(n) if n > 0 => n as u32,
            _ => match get_str(&raw, "CAPTURE_WORKERS").trim().to_ascii_lowercase().as_str() {
                "auto" | "true" | "yes" | "on" => cpu_count(),
                // CAPTURE_FANOUT counts capture SOCKETS in sensor.py; here a worker owns its
                // socket, so the two knobs collapse into one. An operator who set CAPTURE_FANOUT
                // asked for fanout explicitly and still gets it; PROCESS_COUNT does not opt in.
                _ => capture_fanout.max(1),
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

        // The libpcap ring, and the single thing standing between a traffic burst and a missed
        // detection. A dropped packet is never seen by any of the detection logic, so this is the
        // one setting whose being wrong cannot be compensated for anywhere else.
        //
        // It used to default to 16 MB regardless of what the operator asked for, while
        // `CAPTURE_BUFFER` - which IS mandatory, ships as `10%`, and is what everybody sets when
        // they want a bigger buffer - never reached libpcap at all. sensor/docs/INSTALL.md already
        // told people to run 64-256 MB. Measured on loopback at ~250k small packets/s, a 16 MB
        // ring dropped over 90% of the offered traffic and 63% of injected detections went with
        // it, so this was not theoretical.
        //
        // Now: CAPTURE_BUFFER_SIZE if given, else CAPTURE_BUFFER (which is what maltrail.conf has
        // always claimed), else DEFAULT_CAPTURE_RING. Clamped either way - `CAPTURE_BUFFER 10%`
        // is 6.4 GB on a 64 GB host, and that much LOCKED kernel memory per worker is its own
        // outage. The clamp is reported, not silent.
        let capture_buffer_size = {
            let v = get_str(&raw, "CAPTURE_BUFFER_SIZE");
            if !v.is_empty() {
                parse_byte_size(&v).map_err(|e| {
                    ConfigError(format!("invalid configuration value for 'CAPTURE_BUFFER_SIZE' ('{v}'): {e}"))
                })?
            } else if capture_buffer > 0 {
                capture_buffer.clamp(DEFAULT_CAPTURE_RING, MAX_INFERRED_CAPTURE_RING)
            } else {
                DEFAULT_CAPTURE_RING
            }
        };

        // LOCAL_LOG_FORMAT: an unknown value is refused rather than silently treated as "text",
        // because the whole point of setting it is that something downstream is expecting the
        // other format.
        let local_log_json = {
            let v = get_str(&raw, "LOCAL_LOG_FORMAT");
            match v.trim().to_ascii_lowercase().as_str() {
                "" | "text" | "plain" => false,
                "json" | "ndjson" => true,
                other => {
                    bail!("invalid configuration value for 'LOCAL_LOG_FORMAT' ('{other}'), expected 'text' or 'json'")
                }
            }
        };

        let capture_fanout_mode = {
            let v = get_str(&raw, "CAPTURE_FANOUT_MODE");
            if v.trim().is_empty() {
                // Unset. A single worker never forms a fanout group, so the mode is moot there.
                // Above one it decides whether the scan heuristics survive being split at all -
                // flow hashing costs 34% of them at 8 workers - so the default is the mode that
                // does not quietly trade detections for throughput. An operator who wants the old
                // behaviour asks for it by name.
                if capture_workers > 1 {
                    FanoutMode::Source
                } else {
                    FanoutMode::Hash
                }
            } else {
                match FanoutMode::parse(&v) {
                    Some(m) => m,
                    None => bail!("invalid configuration value for 'CAPTURE_FANOUT_MODE' ('{v}')"),
                }
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

        let mut cfg = Config {
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
            local_log_json,
            disable_check_sudo: get_bool(&raw, "DISABLE_CHECK_SUDO"),
            show_debug: get_bool(&raw, "SHOW_DEBUG"),
            log_server,
            log_server_secret,
            syslog_server,
            logstash_server,
            remote_severity_regex,
            ignore_events_regex: get_str(&raw, "IGNORE_EVENTS_REGEX"),
            user_whitelist,
            user_ignorelist,
            // absent switch defaults to on, exactly like read_config()
            use_condensed_storage: get_bool_opt(&raw, "USE_CONDENSED_STORAGE").unwrap_or(true),
            // CHECK_ prefix, so read_config() already coerces it to a bool; default on.
            check_tls_certificates: get_bool_opt(&raw, "CHECK_TLS_CERTIFICATES").unwrap_or(true),
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
            event_throttle_max_keys: get_u64(&raw, "EVENT_THROTTLE_MAX_KEYS").unwrap_or(50_000).min(usize::MAX as u64)
                as usize,
            domain_cache_entries: get_u64(&raw, "DOMAIN_CACHE_ENTRIES")
                .unwrap_or(settings::MAX_CACHE_ENTRIES as u64)
                .max(64) as usize,

            capture_fanout,
            use_fast_prefilter: get_bool(&raw, "USE_FAST_PREFILTER"),
            fast_flow_cutoff: get_u64(&raw, "FAST_FLOW_CUTOFF").unwrap_or(4) as u32,

            capture_workers,
            capture_buffer_size,
            // SATURATING, not `as`: a wrapping cast turns an absurd value into a plausible one
            // (and can make a timeout negative, i.e. "block forever"), which then looks like a
            // deliberate setting instead of a typo. clamp_ranges() reports whatever survives.
            capture_snaplen: get_u64(&raw, "CAPTURE_SNAPLEN")
                .unwrap_or(settings::SNAP_LEN as u64)
                .min(usize::MAX as u64) as usize,
            capture_timeout_ms: get_u64(&raw, "CAPTURE_TIMEOUT")
                .unwrap_or(settings::CAPTURE_TIMEOUT_MS as u64)
                .min(i32::MAX as u64) as i32,
            capture_immediate: cfg_bool(raw.get("CAPTURE_IMMEDIATE")),
            capture_fanout_mode,
            capture_fanout_defrag: cfg_bool(raw.get("CAPTURE_FANOUT_DEFRAG")),
            capture_fanout_group: get_u64(&raw, "CAPTURE_FANOUT_GROUP").map(|v| (v & 0xffff) as u16),
            offline_timestamps,
            stats_address: get_str(&raw, "STATS_ADDRESS"),
            metrics_interval: get_u64(&raw, "METRICS_INTERVAL").unwrap_or(3600),

            raw,
            clamps: Vec::new(),
        };
        cfg.clamp_ranges();
        Ok(cfg)
    }

    /// Force every numeric option into a range the sensor can actually operate in, recording
    /// what was changed so `-T` can show the operator the EFFECTIVE configuration.
    ///
    /// These were silent before, and each one is a way to run a sensor that looks configured and
    /// detects nothing: a zero snaplen truncates every packet to nothing; a CAPTURE_TIMEOUT that
    /// does not fit in the C `int` libpcap takes narrows — possibly to a negative value, which
    /// means "block forever" — so shutdown never gets noticed; a zero throttle window or key cap
    /// disables the very bounding it exists for.
    ///
    /// Clamping rather than rejecting is deliberate: a sensor that refuses to start over a
    /// mistyped tunable protects nothing. It runs, at a sane value, and says so loudly.
    fn clamp_ranges(&mut self) {
        macro_rules! clamp {
            ($field:expr, $name:literal, $lo:expr, $hi:expr) => {{
                let original = $field;
                let bounded = original.clamp($lo, $hi);
                if bounded != original {
                    self.clamps
                        .push(format!("{} {} is out of range ({}..={}), using {}", $name, original, $lo, $hi, bounded));
                    $field = bounded;
                }
            }};
        }

        // Below the smallest Ethernet+IP+TCP header there is nothing left to parse; above
        // 262144 libpcap itself starts refusing.
        clamp!(self.capture_snaplen, "CAPTURE_SNAPLEN", 68usize, 262_144usize);
        // libpcap takes a C int; the poll() leash must stay positive and bounded, or shutdown
        // is only noticed when a packet happens to arrive.
        clamp!(self.capture_timeout_ms, "CAPTURE_TIMEOUT", 1i32, 60_000i32);
        // One worker minimum; the ceiling is well past any real core count and exists only to
        // stop a typo from trying to spawn millions of threads.
        clamp!(self.capture_workers, "PROCESS_COUNT/CAPTURE_WORKERS", 1u32, 1024u32);
        clamp!(self.event_throttle_window, "EVENT_THROTTLE_WINDOW", 1u64, 86_400u64);
        clamp!(self.event_throttle_burst, "EVENT_THROTTLE_BURST", 1u32, 1_000_000u32);
        clamp!(self.event_throttle_max_keys, "EVENT_THROTTLE_MAX_KEYS", 1usize, 10_000_000usize);
        clamp!(self.domain_cache_entries, "DOMAIN_CACHE_ENTRIES", 64usize, 10_000_000usize);
        // The ring is kernel memory, locked, PER WORKER. The floor is where a gigabit link starts
        // dropping under any real burst; the ceiling is where more ring stops buying latency
        // headroom and starts being an outage of its own on a many-worker host.
        clamp!(self.capture_buffer_size, "CAPTURE_BUFFER_SIZE", MIN_CAPTURE_RING, MAX_CAPTURE_RING);
    }

    /// Estimated resident cost of the capture rings — the number an operator actually needs
    /// before setting `CAPTURE_WORKERS` on a 32-core box.
    ///
    /// Sized from `CAPTURE_BUFFER_SIZE`, because that is the value handed to libpcap
    /// (`capture::open`), NOT from `CAPTURE_BUFFER`. Reporting the latter meant `-T` answered
    /// "capture ring≈512 MB total" for a sensor whose ring was the 16 MB default — a preflight
    /// check confirming a buffer 64x larger than the one it was about to run with, which is
    /// precisely the reassurance an operator raises this setting to get.
    pub fn estimated_capture_memory_bytes(&self) -> u64 {
        self.capture_buffer_size.saturating_mul(u64::from(self.capture_workers.max(1)))
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
        // Per platform, because $SYSTEM_LOG_DIR is: core/settings.py answers "/var/log" on POSIX
        // and "C:\\Windows\\Logs" on Windows, and this asserting the POSIX answer everywhere is
        // what caught the sensor hardcoding it.
        let expected = if cfg!(windows) { "C:\\Windows\\Logs\\maltrail" } else { "/var/log/maltrail" };
        assert_eq!(raw["LOG_DIR"], Value::Str(expected.into()));
        assert_eq!(raw["SENSOR_NAME"], Value::Str(hostname()));
        // Compared as a PATH, not as a string. normalize_path emits the platform separator, so on
        // Windows the normalised form is '\a\b\logs' while `join` on a POSIX-shaped manifest dir
        // produces '/a/b\logs' - two spellings of the same path that only string equality
        // distinguishes.
        match &raw["X_DIR"] {
            Value::Str(got) => assert_eq!(Path::new(got), root().join("logs").as_path()),
            other => panic!("{other:?}"),
        }
    }

    /// A drive letter is not a path component, and normalize_path used to treat it as one.
    ///
    /// `Component::Prefix` was pushed onto the accumulator and the `Component::RootDir` that
    /// always follows it cleared the accumulator again, so every absolute path in a Windows
    /// config lost its volume: a `LOG_DIR D:\maltrail\logs` became `\maltrail\logs` and resolved
    /// against whichever drive the process was started from. Found by running the sensor's own
    /// test suite for windows-gnu under Wine, which is the only reason it is testable here.
    #[test]
    #[cfg(windows)]
    fn a_windows_absolute_path_keeps_its_drive() {
        let raw = parse_raw("LOG_DIR D:/maltrail/logs\n", &root()).unwrap();
        assert_eq!(raw["LOG_DIR"], Value::Str("D:\\maltrail\\logs".into()));

        // A UNC share is a prefix too, and must survive the same way. The separators it comes
        // back with are whichever ones it was written with - Windows accepts both - so what is
        // asserted is that the server and share are still there, not how they are spelled.
        let unc = parse_raw("LOG_DIR //server/share/maltrail\n", &root()).unwrap();
        match &unc["LOG_DIR"] {
            Value::Str(got) => {
                let head = got.replace('/', "\\");
                assert!(head.starts_with("\\\\server\\share"), "a UNC LOG_DIR lost its share: {got:?}");
                assert!(head.ends_with("\\maltrail"), "a UNC LOG_DIR lost its tail: {got:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// Notepad and Windows PowerShell both write a UTF-8 BOM, and it landed on the first line.
    ///
    /// install.ps1 wrote the configuration with `Set-Content -Encoding UTF8`, which in Windows
    /// PowerShell means "UTF-8 with BOM"; the sensor then refused the file it had just been given
    /// with `invalid configuration (line: '')`, naming a line that renders as empty. The same
    /// happens to any operator who opens maltrail.conf in Notepad and saves it.
    #[test]
    fn a_utf8_bom_is_not_configuration() {
        let raw = parse_raw("\u{feff}USE_HEURISTICS true\nSENSOR_NAME box\n", &root())
            .expect("a leading BOM must not make a valid configuration invalid");
        assert_eq!(raw["USE_HEURISTICS"], Value::Bool(true));
        assert_eq!(raw["SENSOR_NAME"], Value::Str("box".into()));

        // Only at the very start, where an encoder puts it. A BOM in the middle of a file is not
        // a byte-order mark, it is a corrupt line, and it must still be reported.
        assert!(
            parse_raw("USE_HEURISTICS true\n\u{feff}\n", &root()).is_err(),
            "a BOM on a later line is corruption and must not be silently swallowed"
        );
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
        // The shipped config says PROCESS_COUNT 16 and does NOT set CAPTURE_WORKERS. One worker
        // is the answer: deriving the default from PROCESS_COUNT silently ran every stock install
        // with scan heuristics diluted across 16 flow-hashed sockets to buy throughput a single
        // worker already has. Asserted here so it cannot drift back unnoticed.
        assert_eq!(cfg.capture_workers, 1, "the shipped config must default to a single worker");
    }

    #[test]
    fn several_remote_logging_endpoints_are_accepted_and_all_validated() {
        let dir = std::env::temp_dir().join("mt-cfg-endpoints");
        let _ = std::fs::create_dir_all(&dir);
        let base = "MONITOR_INTERFACE any\nCAPTURE_BUFFER 1MB\nLOG_DIR /tmp\nUPDATE_PERIOD 86400\n";
        let write = |name: &str, extra: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("{base}{extra}")).unwrap();
            Config::load(&path)
        };

        // one option, several collectors: comma, semicolon and whitespace all separate
        let cfg = write("multi.conf", "SYSLOG_SERVER 1.2.3.4:514, 5.6.7.8:514\n").expect("must load");
        assert_eq!(split_endpoints(&cfg.syslog_server), vec!["1.2.3.4:514", "5.6.7.8:514"]);
        let cfg = write("mixed.conf", "LOGSTASH_SERVER 1.2.3.4:5000;5.6.7.8:5000 9.9.9.9:5000\n").expect("must load");
        assert_eq!(split_endpoints(&cfg.logstash_server), vec!["1.2.3.4:5000", "5.6.7.8:5000", "9.9.9.9:5000"]);

        // a single endpoint keeps behaving exactly as before
        let cfg = write("one.conf", "SYSLOG_SERVER 1.2.3.4:514\n").expect("must load");
        assert_eq!(split_endpoints(&cfg.syslog_server), vec!["1.2.3.4:514"]);
        assert!(split_endpoints("").is_empty());

        // EVERY endpoint is validated: a typo in the second is as fatal as one in the first,
        // because forwarding to one of two configured collectors is silent half-failure.
        assert!(write("bad2.conf", "SYSLOG_SERVER 1.2.3.4:514, nonsense\n").is_err());
        assert!(write("bad1.conf", "SYSLOG_SERVER nonsense, 1.2.3.4:514\n").is_err());
        assert!(write("badls.conf", "LOGSTASH_SERVER 1.2.3.4:5000, 5.6.7.8\n").is_err());
    }

    #[test]
    fn worker_count_is_opt_in() {
        let dir = std::env::temp_dir().join("mt-cfg-workers");
        let _ = std::fs::create_dir_all(&dir);
        let base = "MONITOR_INTERFACE any\nCAPTURE_BUFFER 1MB\nLOG_DIR /tmp\nUPDATE_PERIOD 86400\n";

        let write = |name: &str, extra: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("{base}{extra}")).unwrap();
            Config::load(&path).expect("config must load")
        };

        // PROCESS_COUNT alone must NOT fan out: it is sensor.py's worker-process count, and
        // honouring it here degraded the scan heuristics of anyone who never touched the setting.
        assert_eq!(write("pc.conf", "PROCESS_COUNT 16\n").capture_workers, 1);
        // Both explicit knobs still work, and still win.
        assert_eq!(write("cw.conf", "CAPTURE_WORKERS 4\n").capture_workers, 4);
        assert_eq!(write("cf.conf", "CAPTURE_FANOUT 8\n").capture_workers, 8);
        assert!(write("auto.conf", "CAPTURE_WORKERS auto\n").capture_workers >= 1);
    }

    #[test]
    fn fanout_defaults_to_source_affinity_only_when_it_matters() {
        let dir = std::env::temp_dir().join("mt-cfg-fanout-default");
        let _ = std::fs::create_dir_all(&dir);
        let base = "MONITOR_INTERFACE any\nCAPTURE_BUFFER 1MB\nLOG_DIR /tmp\nUPDATE_PERIOD 86400\n";
        let write = |name: &str, extra: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("{base}{extra}")).unwrap();
            Config::load(&path).expect("config must load")
        };

        // One worker forms no fanout group at all, so nothing is gained by changing the mode -
        // and leaving it alone keeps the single-worker configuration byte-identical to before.
        assert_eq!(write("one.conf", "").capture_fanout_mode, FanoutMode::Hash);
        assert_eq!(write("cw1.conf", "CAPTURE_WORKERS 1\n").capture_fanout_mode, FanoutMode::Hash);

        // Above one worker the mode decides whether the scan heuristics survive the split, so the
        // default must be the one that does not lose them.
        for (name, extra) in [
            ("cw2.conf", "CAPTURE_WORKERS 2\n"),
            ("cw8.conf", "CAPTURE_WORKERS 8\n"),
            ("cf4.conf", "CAPTURE_FANOUT 4\n"),
        ] {
            let cfg = write(name, extra);
            assert!(cfg.capture_workers > 1, "{name} should have fanned out");
            assert_eq!(cfg.capture_fanout_mode, FanoutMode::Source, "{name} must default to source affinity");
        }

        // An operator who names a mode gets it, including the old behaviour.
        assert_eq!(
            write("hash.conf", "CAPTURE_WORKERS 4\nCAPTURE_FANOUT_MODE hash\n").capture_fanout_mode,
            FanoutMode::Hash
        );
        assert_eq!(
            write("cpu.conf", "CAPTURE_WORKERS 4\nCAPTURE_FANOUT_MODE cpu\n").capture_fanout_mode,
            FanoutMode::Cpu
        );
        assert_eq!(
            write("src1.conf", "CAPTURE_WORKERS 1\nCAPTURE_FANOUT_MODE source\n").capture_fanout_mode,
            FanoutMode::Source
        );
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

    #[test]
    fn typo_options_are_flagged_and_the_shipped_file_is_clean() {
        let content =
            "MONITOR_INTERFACE any\nCAPTURE_BUFFER 1MB\nLOG_DIR /tmp\nUSE_CONDESND_STORAGE true\nUSERS\n admin:x\n";
        let raw = parse_raw(content, Path::new("/")).unwrap();
        assert_eq!(unknown_keys(&raw), vec!["USE_CONDESND_STORAGE".to_string()]);

        // Every name in the shipped maltrail.conf (commented or active) must be known, or every
        // start of the sensor would warn - which is exactly the drift this list exists to catch.
        let conf = crate::testkit::repo_root().join("maltrail.conf");
        let raw = parse_raw(&std::fs::read_to_string(&conf).unwrap(), &crate::settings::resolve_root(&conf)).unwrap();
        assert!(unknown_keys(&raw).is_empty(), "shipped maltrail.conf has unknown options: {:?}", unknown_keys(&raw));
    }

    use crate::heuristics::HEURISTIC_NAMES;

    #[test]
    fn typo_heuristics_are_flagged_and_the_shipped_example_is_clean() {
        // Same failure one level down: a name DISABLED_HEURISTICS does not recognise is accepted
        // in silence, so the heuristic an operator meant to mute keeps firing.
        let disabled: Vec<String> =
            ["port_scanning", "beacon", "dns_tunnelling", "beaconing"].iter().map(|s| s.to_string()).collect();
        assert_eq!(unknown_heuristics(&disabled), vec!["beacon".to_string(), "dns_tunnelling".to_string()]);

        // every accepted name really is accepted
        let all: Vec<String> = HEURISTIC_NAMES.iter().map(|s| s.to_string()).collect();
        assert!(unknown_heuristics(&all).is_empty(), "HEURISTIC_NAMES disagrees with itself");

        // and the worked example in the shipped file must use real names, or an operator who
        // uncomments it silences nothing
        let conf = crate::testkit::repo_root().join("maltrail.conf");
        let text = std::fs::read_to_string(&conf).unwrap();
        let example: Vec<String> = text
            .lines()
            .find(|l| l.starts_with("#DISABLED_HEURISTICS "))
            .map(|l| l.trim_start_matches("#DISABLED_HEURISTICS ").split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
        assert!(!example.is_empty(), "the DISABLED_HEURISTICS example is gone from maltrail.conf");
        assert!(
            unknown_heuristics(&example).is_empty(),
            "maltrail.conf's example mutes {:?}, which no heuristic answers to",
            unknown_heuristics(&example)
        );
    }
}
