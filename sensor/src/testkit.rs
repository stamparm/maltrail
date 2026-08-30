//! In-process test harness: build a worker against a temporary log directory and a
//! fixture trail set, feed it raw packets, read back the events it wrote.
//!
//! Compiled into the library (not behind `cfg(test)`) so integration tests, benches and
//! the fuzz targets can all drive the *real* detection and output path — the same code that
//! runs in production, writing real log lines — instead of a mock.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::config::Config;
use crate::ignore::IgnoreRules;
use crate::output::{EventSink, OutputConfig};
use crate::process;
use crate::settings;
use crate::state::WorkerState;
use crate::trails::{TrailDb, TrailDbBuilder, TrailStore, TrailView};
use crate::whitelist::Whitelist;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// One parsed event log line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedEvent {
    pub time: String,
    pub sensor: String,
    pub src_ip: String,
    pub src_port: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub proto: String,
    pub trail_type: String,
    pub trail: String,
    pub info: String,
    pub reference: String,
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Extra configuration lines appended to the fixture `maltrail.conf`.
#[derive(Default, Clone)]
pub struct HarnessOptions {
    pub use_heuristics: bool,
    pub check_host_domains: bool,
    pub check_missing_host: bool,
    pub extra: Vec<String>,
}

impl HarnessOptions {
    /// Matches the deterministic setup of `the retired Python suite's _SensorTestBase.setUp`.
    pub fn quiet() -> HarnessOptions {
        HarnessOptions { use_heuristics: false, check_host_domains: true, ..Default::default() }
    }

    pub fn heuristics() -> HarnessOptions {
        HarnessOptions { use_heuristics: true, check_host_domains: true, ..Default::default() }
    }
}

pub struct Harness {
    pub dir: PathBuf,
    pub state: WorkerState,
}

impl Harness {
    pub fn new(trails: &[(&str, &str, &str)]) -> Harness {
        Harness::with_options(trails, HarnessOptions::quiet())
    }

    /// A harness whose events go to a CALLER-CHOSEN log directory, so several harnesses can be
    /// pointed at one directory and made to race on the daily log file.
    pub fn with_log_dir(log_dir: &std::path::Path, trails: &[(&str, &str, &str)]) -> Harness {
        Harness::with_options_in(trails, HarnessOptions::quiet(), Some(log_dir))
    }

    pub fn with_options(trails: &[(&str, &str, &str)], options: HarnessOptions) -> Harness {
        Harness::with_options_in(trails, options, None)
    }

    fn with_options_in(
        trails: &[(&str, &str, &str)],
        options: HarnessOptions,
        shared_log_dir: Option<&std::path::Path>,
    ) -> Harness {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("maltrail-harness-{}-{}", std::process::id(), id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create harness dir");
        let log_dir = match shared_log_dir {
            Some(p) => p.to_path_buf(),
            None => dir.join("logs"),
        };
        std::fs::create_dir_all(&log_dir).expect("create log dir");

        let trails_file = dir.join("trails.csv");
        std::fs::write(&trails_file, "").expect("write trails");

        let root = repo_root();
        let config_file = dir.join("harness.conf");
        let mut config_text = format!(
            "MONITOR_INTERFACE any\n\
             CAPTURE_BUFFER 1MB\n\
             PROCESS_COUNT 1\n\
             UPDATE_PERIOD 999999999\n\
             DISABLE_CHECK_SUDO true\n\
             USE_CONDENSED_STORAGE false\n\
             SENSOR_NAME harness\n\
             SCAN_WINDOW 30\n\
             USE_HEURISTICS {}\n\
             CHECK_HOST_DOMAINS {}\n\
             CHECK_MISSING_HOST {}\n\
             LOG_DIR {}\n\
             TRAILS_FILE {}\n",
            options.use_heuristics,
            options.check_host_domains,
            options.check_missing_host,
            log_dir.display(),
            trails_file.display()
        );
        for line in &options.extra {
            config_text.push_str(line);
            config_text.push('\n');
        }
        std::fs::write(&config_file, config_text).expect("write config");

        let mut cfg = Config::load(&config_file).expect("harness config must load");
        cfg.root = root.clone();
        let cfg = Arc::new(cfg);

        settings::init(root.clone());
        crate::output::init_error_log(&log_dir, false);

        // An empty whitelist keeps fixture trails from being filtered out; the shipped
        // whitelist is exercised separately in tests/trails.rs. A test that sets USER_WHITELIST
        // gets it honoured, so the precedence tests can pin real whitelist-vs-trail behaviour.
        let whitelist = Arc::new(match cfg.user_whitelist.clone() {
            Some(p) => Whitelist::load(&root, Some(&p)),
            None => Whitelist::default(),
        });

        let db = build_db(trails);
        let store = Arc::new(TrailStore::new(db));
        let view = TrailView::new(store);

        let output = Arc::new(OutputConfig {
            sensor_name: cfg.sensor_name.clone(),
            log_dir: log_dir.clone(),
            trails_file: cfg.trails_file.clone(),
            disable_local_log_storage: false,
            local_log_json: false,
            console: false,
            log_server: None,
            syslog_server: Vec::new(),
            logstash_server: Vec::new(),
            severity_regex: None,
            // The harness pins LEGACY throttling: its expectations are Python-derived, so the
            // event COUNTS have to be sensor.py's. `divisor: 1` = one worker, PROCESS_COUNT 1.
            throttle: crate::throttle::ThrottleConfig {
                mode: crate::throttle::ThrottleMode::Legacy,
                legacy_divisor: 1,
                ..Default::default()
            },
            hostname: "harness".to_string(),
            ignore: IgnoreRules::default(),
            whitelist: whitelist.clone(),
            show_debug: false,
        });

        let sink = EventSink::new(output);
        let state = WorkerState::new(0, cfg, whitelist, view, sink);
        Harness { dir, state }
    }

    /// Feed one raw packet (`ip_offset` is where the IP header starts).
    pub fn feed(&mut self, packet: &[u8], sec: u64, usec: u32, ip_offset: usize) {
        process::process_packet(&mut self.state, packet, sec, usec, ip_offset);
    }

    /// Feed a packet whose IP header starts at offset 0.
    pub fn feed_ip(&mut self, packet: &[u8], sec: u64) {
        self.feed(packet, sec, 0, 0);
    }

    /// Replay a pcap file through the real capture handle, DLT resolution and packet path
    /// (everything `worker::run` does, minus the thread and the housekeeping timers).
    ///
    /// Returns the number of packets read. `wallclock` selects the Python-3-compatible
    /// timestamp substitution.
    pub fn replay(&mut self, pcap: &std::path::Path, wallclock: bool) -> usize {
        let mut handle = crate::capture::Handle::open_offline(pcap).expect("open pcap");
        let datalink = handle.datalink();
        let snaplen = self.state.cfg.capture_snaplen;
        let mut count = 0usize;
        let mut scratch: Vec<u8> = Vec::new();
        loop {
            match handle.next_packet() {
                Ok(Some(captured)) => {
                    count += 1;
                    let data: &[u8] = if captured.data.len() > snaplen {
                        scratch.clear();
                        scratch.extend_from_slice(&captured.data[..snaplen]);
                        &scratch
                    } else {
                        captured.data
                    };
                    let (sec, usec) = if wallclock {
                        let now =
                            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                        (now.as_secs(), now.subsec_micros())
                    } else {
                        (captured.sec, captured.usec)
                    };
                    if let Some(offset) = self.state.dlt.resolve(datalink, data) {
                        process::process_packet(&mut self.state, data, sec, usec, offset);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        count
    }

    /// Flush any condensed events so they land in the log.
    pub fn flush(&mut self) {
        self.state.sink.flush_condensed();
    }

    pub fn log_dir(&self) -> PathBuf {
        self.dir.join("logs")
    }

    /// All events the sensor has produced, in file order.
    ///
    /// Flushes the condense buffer first: events whose info matches
    /// `CONDENSE_ON_INFO_KEYWORDS` ("port scanning", "user agent", "attacker", ...) are held
    /// back until a flush, exactly like `core/log.py`'s condensing thread, and an offline run
    /// flushes them at exit. Use `raw_events()` to observe the pre-flush state.
    pub fn events(&mut self) -> Vec<LoggedEvent> {
        self.flush();
        self.raw_events()
    }

    /// Events already written to disk, without flushing the condense buffer.
    pub fn raw_events(&self) -> Vec<LoggedEvent> {
        let mut out = Vec::new();
        let dir = self.log_dir();
        let Ok(entries) = std::fs::read_dir(dir) else { return out };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension().map(|e| e == "log").unwrap_or(false)
                    && p.file_name().map(|n| n != "error.log").unwrap_or(false)
            })
            .collect();
        files.sort();
        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else { continue };
            for line in text.lines() {
                if let Some(event) = parse_event_line(line) {
                    out.push(event);
                }
            }
        }
        out
    }

    /// Contents of the error log (a non-empty error log means the sensor hit something it
    /// considered abnormal).
    pub fn errors(&self) -> Vec<String> {
        std::fs::read_to_string(self.log_dir().join("error.log"))
            .map(|text| text.lines().map(|l| l.to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default()
    }

    pub fn trails(&mut self) -> Vec<String> {
        self.events().into_iter().map(|e| e.trail).collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A `WorkerContext` wired to `registry.slots[id]`, for tests that need to drive the real
/// `worker::run` rather than the packet path alone — worker lifecycle, exit classification and
/// the liveness metrics all live in `run`, not in `process_packet`.
///
/// The temporary directory is deliberately leaked (tests are short-lived and the OS reclaims
/// `TMPDIR`); a `Drop` guard would have to outlive the returned context.
pub fn worker_context(registry: &Arc<crate::metrics::Registry>, id: usize) -> crate::worker::WorkerContext {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("maltrail-worker-{}-{}", std::process::id(), counter));
    let log_dir = dir.join("logs");
    std::fs::create_dir_all(&log_dir).expect("create worker log dir");
    let trails_file = dir.join("trails.csv");
    std::fs::write(&trails_file, "").expect("write trails");

    let config_file = dir.join("worker.conf");
    std::fs::write(
        &config_file,
        format!(
            "MONITOR_INTERFACE any\n\
             CAPTURE_BUFFER 1MB\n\
             PROCESS_COUNT 1\n\
             UPDATE_PERIOD 999999999\n\
             DISABLE_CHECK_SUDO true\n\
             USE_CONDENSED_STORAGE false\n\
             USE_HEURISTICS false\n\
             SENSOR_NAME harness\n\
             LOG_DIR {}\n\
             TRAILS_FILE {}\n",
            log_dir.display(),
            trails_file.display()
        ),
    )
    .expect("write worker config");

    let root = repo_root();
    let mut cfg = Config::load(&config_file).expect("worker config must load");
    cfg.root = root.clone();
    settings::init(root);
    crate::output::init_error_log(&log_dir, false);

    crate::worker::WorkerContext {
        id,
        cfg: Arc::new(cfg),
        whitelist: Arc::new(Whitelist::default()),
        store: Arc::new(TrailStore::new(build_db(&[]))),
        output: Arc::new(OutputConfig {
            sensor_name: "harness".to_string(),
            log_dir,
            trails_file,
            disable_local_log_storage: false,
            local_log_json: false,
            console: false,
            log_server: None,
            syslog_server: Vec::new(),
            logstash_server: Vec::new(),
            severity_regex: None,
            throttle: crate::throttle::ThrottleConfig::default(),
            hostname: "harness".to_string(),
            ignore: IgnoreRules::default(),
            whitelist: Arc::new(Whitelist::default()),
            show_debug: false,
        }),
        slot: registry.slots[id].clone(),
        shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

pub fn build_db(trails: &[(&str, &str, &str)]) -> TrailDb {
    let mut builder = TrailDbBuilder::new(trails.len().max(1), 512);
    let mut regex = crate::trails::regexset::TrailRegexBuilder::default();
    for (trail, info, reference) in trails {
        let pair = builder.intern_pair(info, reference);
        regex.offer(trail, reference);
        builder.insert(trail, pair);
    }
    builder.finish(regex.build())
}

/// Split an event log line the way `core/log.py:safe_value()` quoted it.
pub fn parse_event_line(line: &str) -> Option<LoggedEvent> {
    let fields = split_quoted(line);
    if fields.len() != 11 {
        return None;
    }
    Some(LoggedEvent {
        time: fields[0].clone(),
        sensor: fields[1].clone(),
        src_ip: fields[2].clone(),
        src_port: fields[3].clone(),
        dst_ip: fields[4].clone(),
        dst_port: fields[5].clone(),
        proto: fields[6].clone(),
        trail_type: fields[7].clone(),
        trail: fields[8].clone(),
        info: fields[9].clone(),
        reference: fields[10].clone(),
    })
}

pub fn split_quoted(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i];
        if quoted {
            if ch == '"' {
                if bytes.get(i + 1) == Some(&'"') {
                    current.push('"');
                    i += 2;
                    continue;
                }
                quoted = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == ' ' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
        i += 1;
    }
    fields.push(current);
    fields
}

// --- packet builders (mirror tests/_pcapgen.py) -----------------------------------

pub fn eth(payload: &[u8], ethertype: u16, vlan: Option<u16>) -> Vec<u8> {
    let mut out = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    if let Some(vid) = vlan {
        out.extend_from_slice(&[0x81, 0x00]);
        out.extend_from_slice(&vid.to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn ipv4(proto: u8, src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
    ipv4_opts(proto, src, dst, payload, 5, 0)
}

pub fn ipv4_opts(proto: u8, src: &str, dst: &str, payload: &[u8], ihl: u8, frag: u16) -> Vec<u8> {
    let options = vec![0u8; ((ihl as usize).saturating_sub(5)) * 4];
    let total = (ihl as usize * 4 + payload.len()) as u16;
    let mut out = vec![0x40 | (ihl & 0x0f), 0];
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&0x1234u16.to_be_bytes());
    out.extend_from_slice(&frag.to_be_bytes());
    out.push(64);
    out.push(proto);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&crate::addr::addr_to_int(src).expect("src ipv4").to_be_bytes());
    out.extend_from_slice(&crate::addr::addr_to_int(dst).expect("dst ipv4").to_be_bytes());
    out.extend_from_slice(&options);
    out.extend_from_slice(payload);
    out
}

pub fn ipv6(proto: u8, src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.push(proto);
    out.push(64);
    out.extend_from_slice(&crate::addr::parse_ipv6(src).expect("src ipv6").to_be_bytes());
    out.extend_from_slice(&crate::addr::parse_ipv6(dst).expect("dst ipv6").to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// IPv6 carrying a chain of extension headers before `proto`.
///
/// Each `exts` entry is (header type, body length in bytes NOT counting the 2-byte
/// Next-Header/Hdr-Ext-Len prefix). Type 44 (Fragment) is fixed at 8 bytes total and ignores the
/// requested length, which is what makes it usable for the non-first-fragment case.
pub fn ipv6_ext(proto: u8, src: &str, dst: &str, exts: &[(u8, usize)], payload: &[u8]) -> Vec<u8> {
    let mut chain: Vec<u8> = Vec::new();
    for (i, &(kind, body)) in exts.iter().enumerate() {
        // each header names the NEXT one, and the last names the transport protocol
        let next = exts.get(i + 1).map(|&(k, _)| k).unwrap_or(proto);
        if kind == 44 {
            chain.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
            continue;
        }
        // total must be a multiple of 8; hdr_ext_len counts 8-octet units after the first
        let total = (2 + body).div_ceil(8) * 8;
        chain.push(next);
        chain.push((total / 8 - 1) as u8);
        chain.resize(chain.len() + total - 2, 0);
    }

    let first = exts.first().map(|&(k, _)| k).unwrap_or(proto);
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&((chain.len() + payload.len()) as u16).to_be_bytes());
    out.push(first);
    out.push(64);
    out.extend_from_slice(&crate::addr::parse_ipv6(src).expect("src ipv6").to_be_bytes());
    out.extend_from_slice(&crate::addr::parse_ipv6(dst).expect("dst ipv6").to_be_bytes());
    out.extend_from_slice(&chain);
    out.extend_from_slice(payload);
    out
}

pub fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.push(0x50);
    out.push(flags);
    out.extend_from_slice(&65535u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(payload);
    out
}

pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

pub fn dns_query(name: &str, qtype: u16, qclass: u16, flags: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x1234u16.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    out
}

pub fn http_get(path: &str, host: Option<&str>, ua: &str) -> Vec<u8> {
    let mut text = format!("GET {path} HTTP/1.1\r\n");
    if let Some(h) = host {
        text.push_str(&format!("Host: {h}\r\n"));
    }
    text.push_str(&format!("User-Agent: {ua}\r\nAccept: */*\r\n\r\n"));
    text.into_bytes()
}

/// VXLAN (RFC 7348): UDP to 4789, an 8-byte header, then a complete inner Ethernet frame.
pub fn vxlan(src: &str, dst: &str, vni: u32, inner_frame: &[u8]) -> Vec<u8> {
    let mut p = vec![0x08, 0, 0, 0]; // flags: VNI valid
    p.extend_from_slice(&vni.to_be_bytes()[1..]); // 24-bit VNI
    p.push(0);
    p.extend_from_slice(inner_frame);
    ipv4(17, src, dst, &udp(45000, 4789, &p))
}

/// GENEVE (RFC 8926): UDP to 6081, an 8-byte base header plus `opt_bytes` of options, then the
/// payload named by `proto_type` (0x6558 transparent Ethernet, 0x0800 IPv4, 0x86dd IPv6).
pub fn geneve(src: &str, dst: &str, proto_type: u16, opt_bytes: usize, inner: &[u8]) -> Vec<u8> {
    let mut p = vec![((opt_bytes / 4) as u8) & 0x3f, 0]; // ver(2) | opt_len(6), flags
    p.extend_from_slice(&proto_type.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]); // VNI(3) + reserved
    p.resize(8 + opt_bytes, 0);
    p.extend_from_slice(inner);
    ipv4(17, src, dst, &udp(45001, 6081, &p))
}

/// GRE (RFC 2784/2890). The optional checksum/key/sequence words are what make the header a
/// variable length, and getting that length wrong is the whole difficulty of parsing it.
pub fn gre(src: &str, dst: &str, proto_type: u16, checksum: bool, key: bool, seq: bool, inner: &[u8]) -> Vec<u8> {
    let mut flags: u16 = 0;
    if checksum {
        flags |= 0x8000;
    }
    if key {
        flags |= 0x2000;
    }
    if seq {
        flags |= 0x1000;
    }
    let mut p = Vec::new();
    p.extend_from_slice(&flags.to_be_bytes());
    p.extend_from_slice(&proto_type.to_be_bytes());
    if checksum {
        p.extend_from_slice(&[0, 0, 0, 0]); // checksum + reserved1
    }
    if key {
        p.extend_from_slice(&[0, 0, 0, 1]);
    }
    if seq {
        p.extend_from_slice(&[0, 0, 0, 2]);
    }
    p.extend_from_slice(inner);
    ipv4(47, src, dst, &p)
}

/// ERSPAN over GRE: type II (0x88be, 8-byte header) or type III (0x22eb, 12-byte header), then a
/// mirrored Ethernet frame. This is what a switch SPAN session actually puts on the wire.
pub fn erspan(src: &str, dst: &str, type_iii: bool, inner_frame: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; if type_iii { 12 } else { 8 }];
    p[0] = if type_iii { 0x20 } else { 0x10 }; // version nibble
    p.extend_from_slice(inner_frame);
    gre(src, dst, if type_iii { 0x22eb } else { 0x88be }, false, false, false, &p)
}
