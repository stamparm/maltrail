//! `maltrail-sensor` — the Rust sensor entry point.
//!
//! Command-line surface mirrors `sensor.py` (`-c`, `-r`, `-q/--quiet`, `--console`,
//! `--offline`, `--debug`, `--version`), so an existing invocation works unchanged apart
//! from the program name.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use maltrail_sensor::capture::{fanout, CaptureError, Handle};
use maltrail_sensor::colorized;
use maltrail_sensor::config::{Config, TimestampSource};
use maltrail_sensor::ignore::IgnoreRules;
use maltrail_sensor::metrics::Registry;
use maltrail_sensor::output::{self, OutputConfig};
use maltrail_sensor::settings;
use maltrail_sensor::trails::{self, TrailStore};
use maltrail_sensor::trailupdate;
use maltrail_sensor::whitelist::Whitelist;
use maltrail_sensor::worker::{self, WorkerContext};
use maltrail_sensor::{ceprintln, cprintln};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// Set by SIGHUP: reload the trails now instead of waiting for the next poll.
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

struct Args {
    config_file: PathBuf,
    pcap_files: Vec<PathBuf>,
    console: bool,
    quiet: bool,
    offline: bool,
    debug: bool,
    timestamps: Option<TimestampSource>,
    version: bool,
    help: bool,
    test_config: bool,
}

impl Default for Args {
    fn default() -> Args {
        Args {
            config_file: PathBuf::new(),
            pcap_files: Vec::new(),
            console: false,
            quiet: false,
            offline: false,
            debug: false,
            timestamps: None,
            version: false,
            help: false,
            test_config: false,
        }
    }
}

const USAGE: &str = "\
Usage: maltrail-sensor [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -c CONFIG_FILE        configuration file (default: 'maltrail.conf')
  -r PCAP_FILE          pcap file(s) for offline analysis (comma separated, repeatable)
  -q, --quiet           turn off regular output
  --console             print events to console
  --offline             disable (online) trail updates
  --debug               console output and debug messages
  -T, --test-config     validate the configuration, trails, whitelist, log directory and
                        capture filter, then exit (0 = usable, 1 = would not work)
  --timestamps SOURCE   offline timestamp source: 'pcap' (default) or 'wallclock'
                        ('wallclock' reproduces the Python 3 sensor's behaviour, which is
                        what strict offline parity runs need)
";

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut args = Args::default();
    let mut i = 0usize;
    while i < argv.len() {
        let arg = argv[i].clone();
        macro_rules! value_for {
            ($name:expr) => {{
                i += 1;
                match argv.get(i) {
                    Some(v) => v.clone(),
                    None => return Err(format!("{} option requires an argument", $name)),
                }
            }};
        }
        match arg.as_str() {
            "--version" => args.version = true,
            "-h" | "--help" => args.help = true,
            "-q" | "--quiet" => args.quiet = true,
            "--console" => args.console = true,
            "--offline" => args.offline = true,
            "--debug" => args.debug = true,
            "-T" | "--test-config" => args.test_config = true,
            "-c" => args.config_file = PathBuf::from(value_for!("-c")),
            "-r" | "-i" => {
                if arg == "-i" {
                    cprintln!("[x] option '-i' was renamed to '-r'");
                }
                let list = value_for!("-r");
                for part in list.split(',') {
                    if !part.is_empty() {
                        args.pcap_files.push(PathBuf::from(part));
                    }
                }
                // sensor.py also swallows any following existing files after -r/-i
                while let Some(next) = argv.get(i + 1) {
                    if Path::new(next).is_file() {
                        args.pcap_files.push(PathBuf::from(next));
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            "--timestamps" => {
                let value = value_for!("--timestamps");
                args.timestamps = match value.as_str() {
                    "pcap" => Some(TimestampSource::Pcap),
                    "wallclock" => Some(TimestampSource::Wallclock),
                    other => return Err(format!("invalid --timestamps value '{other}'")),
                };
            }
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 1;
    }
    Ok(args)
}

fn main() {
    let code = run();

    // sensor.py ends with os._exit(code), and this uses _exit() for the same reason: a capture
    // worker can be parked inside libpcap's blocking read, holding the lock of the underlying
    // stdio stream. glibc's exit() flushes and closes every FILE stream on the way out, so it
    // would block on that lock and the process would never terminate - even after the shutdown
    // grace period expired and the final metrics were printed. Our own buffers are flushed here,
    // explicitly, because _exit() skips all of that.
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // SAFETY: _exit() terminates the process immediately without running atexit handlers or
    // destructors, which is precisely the intent.
    unsafe { libc::_exit(code) }
}

fn run() -> i32 {
    // Rust ignores SIGPIPE, so writing to a closed pipe raises EPIPE and the default panic
    // handler prints a backtrace — `maltrail-sensor --version | head -1` would panic instead of
    // exiting quietly. Restore the Unix default: die silently when the reader goes away.
    // SAFETY: setting a signal disposition to SIG_DFL has no preconditions.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    // Decide colouring first: core/colorized.py installs its stream wrapper at import time,
    // before anything is printed.
    colorized::init(None);

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            ceprintln!("[!] {e}\n{USAGE}");
            return 1;
        }
    };

    if !args.quiet {
        cprintln!("{} (sensor) #v{} {{{}}}\n", settings::NAME, settings::VERSION, settings::HOMEPAGE);
    }
    if args.version {
        return 0;
    }
    if args.help {
        cprintln!("{USAGE}");
        return 0;
    }

    if !args.quiet {
        cprintln!("[*] starting @ {}\n", now_clock());
    }

    let config_file =
        if args.config_file.as_os_str().is_empty() { default_config_file() } else { args.config_file.clone() };

    let mut cfg = match Config::load(&config_file) {
        Ok(c) => c,
        Err(e) => {
            ceprintln!("[!] {e}");
            return 1;
        }
    };

    cfg.pcap_files = args.pcap_files.clone();
    cfg.console = args.console;
    cfg.quiet = args.quiet;
    cfg.offline = args.offline;
    cfg.debug = args.debug;
    if args.debug {
        cfg.console = true;
        cfg.show_debug = true;
    }
    if let Some(source) = args.timestamps {
        cfg.offline_timestamps = source;
    }

    for path in &cfg.pcap_files {
        // exists(), not is_file(): a FIFO is a perfectly good `-r` source (it lets traffic be
        // streamed in), and sensor.py's os.path.isfile() check rejects those for no good reason.
        if !path.exists() {
            ceprintln!("[!] missing pcap file '{}'", path.display());
            return 1;
        }
    }
    if !cfg.pcap_files.is_empty() && !args.quiet {
        let names: Vec<String> = cfg.pcap_files.iter().map(|p| p.display().to_string()).collect();
        cprintln!("[i] using pcap file(s) '{}'", names.join(","));
    }

    // `-T`: validate everything that can be validated without capturing, then exit. Runs before
    // the privilege check (a configuration test needs no privileges) and before the trail refresh
    // (a test must not mutate the deployment).
    if args.test_config {
        return maltrail_sensor::selftest::run(&cfg);
    }

    // Offline replay reads a file: no privileges are involved, so nothing is demanded. Live
    // capture needs CAP_NET_RAW, which is not the same thing as root. DISABLE_CHECK_SUDO remains
    // the documented escape hatch.
    if !cfg.disable_check_sudo && !cfg.is_offline_replay() && !have_capture_privileges() {
        ceprintln!("[!] no permission to capture packets ('CAP_NET_RAW' is required)");
        ceprintln!(
            "[?] grant it to the binary once, and the sensor never needs root again:\n\
             [?]     sudo setcap cap_net_raw,cap_net_admin=eip {}\n\
             [?] (cap_net_admin is only needed for promiscuous mode and PACKET_FANOUT)\n\
             [?] or run it as root, or set 'DISABLE_CHECK_SUDO true' to skip this check",
            std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "maltrail-sensor".into())
        );
        return 1;
    }

    if let Err(e) = output::create_log_directory(&cfg.log_dir) {
        ceprintln!("[!] unable to create log directory '{}' ({e})", cfg.log_dir.display());
        return 1;
    }
    output::init_error_log(&cfg.log_dir, cfg.show_debug);

    let statics = settings::init(cfg.root.clone());
    let whitelist = Arc::new(Whitelist::load(&cfg.root, cfg.user_whitelist.as_deref()));
    let ignore = IgnoreRules::load(&cfg.root, cfg.user_ignorelist.as_deref(), &cfg.ignore_events_regex);

    if !args.quiet {
        let mut msg = format!("[i] using '{}' for trail storage", cfg.trails_file.display());
        if let Ok(md) = std::fs::metadata(&cfg.trails_file) {
            if let Ok(mtime) = md.modified() {
                msg.push_str(&format!(" (last modification: '{}')", local_stamp(mtime)));
            }
        }
        cprintln!("{msg}");
    }

    // Refresh the trails BEFORE loading them, exactly like sensor.py:init():update_timer().
    // Without this the sensor runs on whatever trails.csv happens to exist and silently misses
    // every IOC added since that file was written.
    refresh_trails(&cfg, args.quiet, true);

    let (db, stats) = match trails::load_with(&cfg.trails_file, &whitelist, load_options(&cfg)) {
        Ok(v) => v,
        Err(e) => {
            ceprintln!("[!] something went wrong during trails file read '{}' ('{e}')", cfg.trails_file.display());
            return 1;
        }
    };
    // Fail closed. A sensor holding zero trails starts cleanly, answers its metrics endpoint,
    // reports itself healthy — and detects nothing. That is strictly worse than not starting,
    // because nobody investigates a sensor that looks fine. Heuristics alone are not a
    // substitute: they find behaviour, not the known-bad indicators that are the whole point.
    if db.is_empty() && !cfg.allow_empty_trails {
        ceprintln!("[!] the trail set is EMPTY ('{}'), so this sensor would detect nothing", cfg.trails_file.display());
        if stats.whitelisted > 0 {
            ceprintln!("[?] {} row(s) were dropped by the whitelist; is it too broad?", stats.whitelisted);
        }
        ceprintln!("[?] check the trail update ran, or set 'ALLOW_EMPTY_TRAILS true' if this is deliberate");
        return 1;
    }
    if !args.quiet {
        cprintln!("[i] {} trails loaded", thousands(stats.loaded as u64));
    }
    let trail_summary = format!(
        "ipv4={} ipv4:port={} ipv6={} wildcard-regex={} whitelisted={} malformed={} memory={:.1} MB",
        thousands(db.ip4_count() as u64),
        thousands(db.ip4_port_count() as u64),
        thousands(db.ip6_count() as u64),
        db.regex().len(),
        thousands(stats.whitelisted as u64),
        stats.malformed,
        db.memory_bytes() as f64 / (1024.0 * 1024.0)
    );
    let skipped_regexes: Vec<String> = db.regex().skipped().to_vec();
    let repaired_regexes: usize = db.regex().repaired().len();
    let trail_count = db.len() as u64;
    let store = Arc::new(TrailStore::new(db));

    let severity_regex = if cfg.remote_severity_regex.is_empty() {
        None
    } else {
        maltrail_sensor::pyre::build_fancy(&cfg.remote_severity_regex).ok()
    };

    let cfg = Arc::new(cfg);

    // --- open capture handles ---------------------------------------------------
    let mut handles: Vec<(Handle, String, Option<u16>)> = Vec::new();
    if cfg.is_offline_replay() {
        for path in &cfg.pcap_files {
            match Handle::open_offline(path) {
                Ok(h) => handles.push((h, path.display().to_string(), None)),
                Err(e) => {
                    ceprintln!("[!] unable to open pcap file '{}' ({e})", path.display());
                    return 1;
                }
            }
        }
    } else {
        let interfaces = cfg.monitor_interfaces();
        if interfaces.is_empty() {
            ceprintln!("[!] no monitoring interface configured ('MONITOR_INTERFACE')");
            return 1;
        }
        let devices: Vec<String> =
            pcap::Device::list().map(|list| list.into_iter().map(|d| d.name).collect()).unwrap_or_default();

        for (index, interface) in interfaces.iter().enumerate() {
            if interface.to_lowercase() != "any" && !devices.is_empty() && !devices.contains(interface) {
                ceprintln!("[!] interface '{interface}' not found");
                ceprintln!("[?] available interfaces: '{}'", devices.join(","));
                return 1;
            }
            let workers = cfg.capture_workers.max(1);
            let group = if workers > 1 || cfg.capture_fanout > 1 {
                Some(cfg.capture_fanout_group.unwrap_or_else(|| fanout::default_group(index)))
            } else {
                None
            };
            if !args.quiet {
                cprintln!("[i] opening interface '{interface}'");
            }
            let mut opened = 0usize;
            for _ in 0..workers {
                match Handle::open_live(&cfg, interface, group) {
                    Ok((h, _info)) => {
                        handles.push((h, interface.clone(), group));
                        opened += 1;
                    }
                    Err(CaptureError::Fanout(e)) if opened == 0 && workers > 1 => {
                        // The kernel refused PACKET_FANOUT for this device. Run a SINGLE worker
                        // instead: falling back to `workers` independent sockets would deliver
                        // every packet to every one of them and multiply detections.
                        ceprintln!("[!] PACKET_FANOUT unavailable on '{interface}' ({e}); falling back to 1 worker");
                        ceprintln!(
                            "[?] a single worker also throttles the event log {workers}x harder than \
                             sensor.py's {workers} processes do (core/log.py keeps the throttle per worker)"
                        );
                        match Handle::open_live(&cfg, interface, None) {
                            Ok((h, _info)) => {
                                handles.push((h, interface.clone(), None));
                                break;
                            }
                            Err(e) => {
                                ceprintln!("[!] unable to open capture on '{interface}': {e}");
                                return 1;
                            }
                        }
                    }
                    Err(e) => {
                        ceprintln!("[!] unable to open capture on '{interface}': {e}");
                        if group.is_some() {
                            ceprintln!(
                                "[?] PACKET_FANOUT was requested ({workers} workers). Refusing to fall back to \
                                 independent sockets, which would deliver every packet to every worker \
                                 (duplicate detections). Set 'CAPTURE_WORKERS 1' to run single-socket."
                            );
                        }
                        return 1;
                    }
                }
            }
        }
    }

    // How many WORKERS will run, which is not the number of handles: an offline replay drives
    // every `-r` file through one worker so their detection state accumulates (see run_all).
    let worker_count = if cfg.is_offline_replay() { 1 } else { handles.len() };

    if handles.is_empty() {
        ceprintln!("[!] no capture source");
        return 1;
    }

    // The log throttle keeps its state PER WORKER, and `core/log.py` divides by PROCESS_COUNT
    // because in sensor.py PROCESS_COUNT *is* the number of workers. Dividing by the actual
    // worker count keeps the aggregate rate identical to sensor.py's whatever the two sensors'
    // worker counts happen to be - a single worker dividing by 16 would write 1/16 of the lines
    // sensor.py writes for the same traffic.
    let output_cfg = Arc::new(OutputConfig {
        sensor_name: cfg.sensor_name.clone(),
        log_dir: cfg.log_dir.clone(),
        trails_file: cfg.trails_file.clone(),
        disable_local_log_storage: cfg.disable_local_log_storage,
        console: cfg.console,
        log_server: non_empty(&cfg.log_server),
        syslog_server: maltrail_sensor::config::split_endpoints(&cfg.syslog_server)
            .iter()
            .map(|s| s.to_string())
            .collect(),
        logstash_server: maltrail_sensor::config::split_endpoints(&cfg.logstash_server)
            .iter()
            .map(|s| s.to_string())
            .collect(),
        severity_regex,
        throttle: maltrail_sensor::throttle::ThrottleConfig {
            mode: cfg.event_throttle_mode,
            window: cfg.event_throttle_window,
            burst: cfg.event_throttle_burst,
            max_keys: cfg.event_throttle_max_keys,
            legacy_divisor: worker_count.max(1) as u32,
        },
        hostname: maltrail_sensor::config::hostname(),
        ignore,
        whitelist: whitelist.clone(),
        show_debug: cfg.show_debug,
    });

    if !args.quiet {
        print_diagnostics(
            &cfg,
            &handles,
            &trail_summary,
            &skipped_regexes,
            repaired_regexes,
            whitelist.as_ref(),
            statics,
        );
    }

    install_signal_handlers();

    let registry = Arc::new(
        Registry::new(worker_count)
            // Free space only means something when this sensor is the one writing the evidence.
            .with_log_dir(if cfg.disable_local_log_storage { None } else { Some(cfg.log_dir.clone()) }),
    );
    registry.trail_count.store(trail_count, Ordering::Relaxed);
    registry.trail_generation.store(store.generation(), Ordering::Relaxed);

    let shutdown = Arc::new(AtomicBool::new(false));

    // --- trail reload thread ---------------------------------------------------
    if !cfg.is_offline_replay() {
        let store_reload = store.clone();
        let cfg_reload = cfg.clone();
        let wl_reload = whitelist.clone();
        let reg_reload = registry.clone();
        let shutdown_reload = shutdown.clone();
        std::thread::Builder::new()
            .name("trail-reload".into())
            .spawn(move || {
                let mut last_mtime = std::fs::metadata(&cfg_reload.trails_file).and_then(|m| m.modified()).ok();
                // Two jobs, mirroring sensor.py's update_timer(): run the trail UPDATE every
                // UPDATE_PERIOD, and notice a trails file refreshed by anyone else (the Maltrail
                // server, a cron job) in between. The mtime poll is cheap, so it runs every
                // minute while the update keeps the configured period.
                // One second, not `UPDATE_PERIOD`: the tick only does a `stat()`, and it bounds how
                // quickly a trails.csv refreshed by anyone else (the server, cron) is picked up.
                // At `UPDATE_PERIOD` that was up to a minute.
                let tick = Duration::from_secs(1);
                let update_period = Duration::from_secs(cfg_reload.update_period.max(1));
                let mut next_update = Instant::now() + update_period;
                loop {
                    std::thread::sleep(tick);
                    if shutdown_reload.load(Ordering::Relaxed) {
                        break;
                    }
                    if Instant::now() >= next_update {
                        next_update = Instant::now() + update_period;
                        refresh_trails(&cfg_reload, cfg_reload.quiet, false);
                        // Same cycle `sensor.py:update_timer()` prunes on. Off the packet path
                        // and a no-op under budget, so it costs a COUNT(*) per period.
                        prune_condensed_store(&cfg_reload);
                    }
                    // SIGHUP forces a reload even when the mtime is unchanged.
                    let forced = RELOAD_REQUESTED.swap(false, Ordering::Relaxed);
                    if forced && !cfg_reload.quiet {
                        cprintln!("[i] SIGHUP: reloading trails");
                    }
                    let mtime = std::fs::metadata(&cfg_reload.trails_file).and_then(|m| m.modified()).ok();
                    if mtime == last_mtime && !forced {
                        continue;
                    }
                    last_mtime = mtime;
                    match trails::load_with(&cfg_reload.trails_file, &wl_reload, load_options(&cfg_reload)) {
                        Ok((db, stats)) => {
                            // A reload that loses most of the trail set is far more likely to be a
                            // half-written or truncated file than a real change, and publishing it
                            // would blind the sensor without any error ever occurring. Keep the
                            // last known-good store: detection continues on slightly stale trails,
                            // which beats continuing on almost none.
                            let current = reg_reload.trail_count.load(Ordering::Relaxed);
                            let incoming = db.len() as u64;
                            let floor = (current as f64 * cfg_reload.trail_reload_min_ratio) as u64;
                            if cfg_reload.trail_reload_min_ratio > 0.0 && current > 0 && incoming < floor {
                                reg_reload.reloads_rejected.fetch_add(1, Ordering::Relaxed);
                                output::log_error(
                                    &format!(
                                        "trail reload REJECTED: {} trails would replace {} (below the \
                                         {:.0}% floor); keeping the current set. If this drop is real, \
                                         restart the sensor or lower 'TRAIL_RELOAD_MIN_RATIO'",
                                        thousands(incoming),
                                        thousands(current),
                                        cfg_reload.trail_reload_min_ratio * 100.0
                                    ),
                                    true,
                                );
                            } else {
                                reg_reload.trail_count.store(incoming, Ordering::Relaxed);
                                store_reload.publish(db);
                                reg_reload.trail_generation.store(store_reload.generation(), Ordering::Relaxed);
                                reg_reload.reloads_ok.fetch_add(1, Ordering::Relaxed);
                                cprintln!("[i] reloaded {} trails", thousands(stats.loaded as u64));
                            }
                        }
                        Err(e) => {
                            reg_reload.reloads_failed.fetch_add(1, Ordering::Relaxed);
                            output::log_error(&format!("trail reload failed ({e})"), true);
                        }
                    }
                }
            })
            .ok();
    }

    // --- Prometheus endpoint ---------------------------------------------------
    // Opt-in, and never fatal: a sensor that cannot bind its metrics port must still detect.
    if !cfg.stats_address.is_empty() {
        match maltrail_sensor::stats::spawn(&cfg.stats_address, registry.clone(), Instant::now()) {
            Ok(bound) => {
                if !args.quiet {
                    cprintln!("[i] metrics endpoint: http://{bound}/metrics");
                }
            }
            Err(e) => {
                ceprintln!("[!] metrics endpoint disabled: {e}");
                output::log_error(&format!("stats endpoint disabled: {e}"), true);
            }
        }
    }

    // --- metrics thread --------------------------------------------------------
    if cfg.metrics_interval > 0 && !cfg.is_offline_replay() {
        let reg_metrics = registry.clone();
        let shutdown_metrics = shutdown.clone();
        let interval = Duration::from_secs(cfg.metrics_interval);
        std::thread::Builder::new()
            .name("metrics".into())
            .spawn(move || {
                let mut next = Instant::now() + interval;
                loop {
                    std::thread::sleep(Duration::from_millis(500));
                    if shutdown_metrics.load(Ordering::Relaxed) {
                        break;
                    }
                    if Instant::now() >= next {
                        next = Instant::now() + interval;
                        cprintln!("[i] metrics: {}", reg_metrics.summary());
                    }
                }
            })
            .ok();
    }

    // --- run the workers -------------------------------------------------------
    if !args.quiet {
        cprintln!("[^] running...");
    }
    let started = Instant::now();
    // Offline replay is ONE worker over every file, in order. Giving each `-r` file its own
    // worker also gave it its own detection state, so evidence split across a capture set never
    // accumulated and the result depended on how the threads interleaved. A replay has to be
    // deterministic and has to behave like the single stream the analyst captured.
    //
    // Live capture keeps one worker per handle — that is exactly what PACKET_FANOUT parallelises.
    let mut worker_handles: Vec<Vec<Handle>> = if cfg.is_offline_replay() {
        vec![handles.into_iter().map(|(h, _, _)| h).collect()]
    } else {
        handles.into_iter().map(|(h, _, _)| vec![h]).collect()
    };

    let mut threads = Vec::with_capacity(worker_handles.len());
    for (id, group) in worker_handles.drain(..).enumerate() {
        let ctx = WorkerContext {
            id,
            cfg: cfg.clone(),
            whitelist: whitelist.clone(),
            store: store.clone(),
            output: output_cfg.clone(),
            slot: registry.slots[id].clone(),
            shutdown: shutdown.clone(),
        };
        threads.push(
            std::thread::Builder::new()
                .name(format!("capture-{id}"))
                .spawn(move || worker::run_all(group, ctx))
                .expect("spawn capture worker"),
        );
    }

    // Watch for a signal while the workers run.
    let watcher_shutdown = shutdown.clone();
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || loop {
            if SHUTDOWN.load(Ordering::Relaxed) {
                watcher_shutdown.store(true, Ordering::Relaxed);
                break;
            }
            if watcher_shutdown.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        })
        .ok();

    // Wait for the workers. Offline replay ends at EOF; live capture runs until a signal, so
    // there is NO deadline until a shutdown has actually been requested. (An earlier version
    // started the deadline here, which made a healthy live sensor "stop" after 10 seconds.)
    // Once shutdown IS requested, the wait is bounded so a wedged capture handle cannot stop
    // the process from exiting and printing its final metrics.
    // Join results are INSPECTED, not discarded. A capture worker that dies while the sensor is
    // supposed to be monitoring is a detection outage: the process must exit non-zero so
    // `Restart=on-failure` fires, instead of exiting 0 and leaving the host unmonitored with a
    // green systemd unit.
    type WorkerResult = Result<worker::WorkerExit, worker::WorkerError>;
    let mut pending: Vec<Option<std::thread::JoinHandle<WorkerResult>>> = threads.into_iter().map(Some).collect();
    let mut failures: Vec<String> = Vec::new();
    let mut grace_deadline: Option<Instant> = None;
    let mut stuck = 0usize;
    loop {
        for (id, slot) in pending.iter_mut().enumerate() {
            if let Some(handle) = slot.take() {
                if handle.is_finished() {
                    let shutting_down = shutdown.load(Ordering::Relaxed) || SHUTDOWN.load(Ordering::Relaxed);
                    match handle.join() {
                        // The thread unwound past the per-packet catch_unwind.
                        Err(_) => failures.push(format!("worker {id}: {}", worker::WorkerError::Panic)),
                        Ok(Err(e)) => failures.push(format!("worker {id}: {e}")),
                        Ok(Ok(worker::WorkerExit::OfflineEof)) => {}
                        Ok(Ok(worker::WorkerExit::Shutdown)) => {
                            // A live worker leaving its loop when nobody asked it to means the
                            // capture ended on its own. There is no benign reading of that.
                            if !cfg.is_offline_replay() && !shutting_down {
                                failures.push(format!("worker {id}: capture stopped unexpectedly"));
                                shutdown.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                } else {
                    *slot = Some(handle);
                }
            }
        }
        let remaining = pending.iter().filter(|slot| slot.is_some()).count();
        if remaining == 0 {
            break;
        }
        if shutdown.load(Ordering::Relaxed) || SHUTDOWN.load(Ordering::Relaxed) {
            match grace_deadline {
                None => grace_deadline = Some(Instant::now() + Duration::from_secs(10)),
                Some(deadline) if Instant::now() >= deadline => {
                    stuck = remaining;
                    break;
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if stuck > 0 {
        ceprintln!("[!] {stuck} capture worker(s) did not stop within 10s of the shutdown request; exiting anyway");
    }
    shutdown.store(true, Ordering::Relaxed);

    // A worker that failed while the sensor was meant to be capturing is a monitoring outage.
    // Say so on stderr (journald) and exit non-zero, which is what makes `Restart=on-failure`
    // meaningful; exiting 0 here would leave the unit green and the network unwatched.
    if !failures.is_empty() {
        for failure in &failures {
            ceprintln!("[!] {failure}");
        }
        if cfg.is_offline_replay() {
            ceprintln!("[!] the replay did NOT complete — these results are not a clean analysis of the capture");
        } else {
            ceprintln!(
                "[!] {} of {} capture worker(s) failed — this host was NOT being monitored",
                failures.len(),
                registry.slots.len()
            );
        }
    }

    let elapsed = started.elapsed();
    if !args.quiet {
        cprintln!("\r[i] cleaning up...");
        let total = registry.total();
        cprintln!("[i] metrics: {}", registry.summary());
        if elapsed.as_secs_f64() > 0.0 && total.packets_processed > 0 {
            cprintln!(
                "[i] processed {} packet(s) in {:.3}s ({:.0} pps, {:.0} ns/packet of packet-path time, \
                 sampled over {} packet(s))",
                thousands(total.packets_processed),
                elapsed.as_secs_f64(),
                total.packets_processed as f64 / elapsed.as_secs_f64(),
                if total.processing_samples > 0 {
                    total.processing_nanos as f64 / total.processing_samples as f64
                } else {
                    0.0
                },
                thousands(total.processing_samples)
            );
        }
        cprintln!("\n[*] ending @ {}", now_clock());
    }
    if failures.is_empty() {
        0
    } else {
        1
    }
}

/// The heuristics whose evidence is counted PER SOURCE, and which fanout therefore dilutes.
/// `long_domain` and `dns_exhaustion` are per name/domain, so they are unaffected by which
/// worker a packet lands on.
fn scan_heuristics_enabled(cfg: &Config) -> bool {
    ["port_scanning", "udp_scanning", "infection", "web_scanning"].iter().any(|h| cfg.heuristic_enabled(h))
}

#[allow(clippy::too_many_arguments)]
fn print_diagnostics(
    cfg: &Config,
    handles: &[(Handle, String, Option<u16>)],
    trail_summary: &str,
    skipped_regexes: &[String],
    repaired_regexes: usize,
    whitelist: &Whitelist,
    statics: &settings::Statics,
) {
    let backend = if cfg.is_offline_replay() { "pcap (offline replay)" } else { "pcap (libpcap live)" };
    cprintln!("[i] capture backend: {backend}");
    if cfg.is_offline_replay() {
        let names: Vec<&str> = handles.iter().map(|(_, s, _)| s.as_str()).collect();
        cprintln!("[i] replaying: {}", names.join(", "));
        cprintln!(
            "[i] offline timestamps: {}",
            match cfg.offline_timestamps {
                TimestampSource::Pcap => "pcap record timestamps",
                TimestampSource::Wallclock => "wall clock (sensor.py-on-Python-3 compatible)",
            }
        );
    } else {
        cprintln!("[i] interface(s): {}", cfg.monitor_interface);
        let group = handles.first().and_then(|(_, _, g)| *g);
        match group {
            Some(g) => cprintln!(
                "[i] PACKET_FANOUT: enabled (group {}, mode {}, defrag {}) across {} worker socket(s)",
                g,
                cfg.capture_fanout_mode.label(),
                if cfg.capture_fanout_defrag { "on" } else { "off" },
                handles.len()
            ),
            None => cprintln!("[i] PACKET_FANOUT: disabled (single capture socket)"),
        }
        cprintln!(
            "[i] capture: snaplen={} buffer={:.0} MB timeout={}ms immediate={}",
            cfg.capture_snaplen,
            cfg.capture_buffer_size as f64 / (1024.0 * 1024.0),
            cfg.capture_timeout_ms,
            cfg.capture_immediate
        );
        cprintln!(
            "[i] effective BPF filter: {}",
            if cfg.capture_filter.is_empty() { "(none)" } else { cfg.capture_filter.as_str() }
        );
    }
    cprintln!("[i] workers: {} (datalink {})", handles.len(), handles[0].0.datalink());
    // PACKET_FANOUT_HASH splits traffic by FLOW; the scan heuristics count by SOURCE, and a scan
    // is many flows. So each worker sees a fraction of one scanner's probes and a threshold needs
    // roughly N times more of them. Measured on the corpus (tests/multi_worker_parity.rs): 91% of
    // heuristic alerts survive at 2 workers, 86% at 4, 65% at 8. Exact trail matching is per
    // packet and stateless, so IOC detection is unaffected at any worker count — the same test
    // asserts that. This only fires when an operator has opted into fanout: the default is one
    // worker precisely so that nobody pays this cost without asking for it.
    if handles.len() > 1 && cfg.use_heuristics && scan_heuristics_enabled(cfg) {
        cprintln!(
            "[!] {} workers + scan heuristics: fanout hashes by flow but scans are counted per \
             source, so thresholds trip later (~65% of alerts survive at 8 workers). Unset \
             'CAPTURE_FANOUT'/'CAPTURE_WORKERS' for undiluted scan fidelity; trail detection is \
             unaffected.",
            handles.len()
        );
    }
    cprintln!("[i] trails: {trail_summary}");
    if repaired_regexes > 0 {
        // Feeds ship patterns truncated in transit; the intact alternatives are kept and the
        // dangling fragment is dropped (see trails::regexset::repair_truncated). sensor.py drops
        // these indicators entirely, so this is a detection gain, not a problem.
        cprintln!("[i] repaired {repaired_regexes} wildcard trail pattern(s) truncated in the feed");
    }
    if !skipped_regexes.is_empty() {
        // Only patterns that could not be salvaged at all. Truncated to keep the line readable -
        // these can be hundreds of characters long.
        let preview: Vec<String> = skipped_regexes
            .iter()
            .map(|pattern| {
                let head: String = pattern.chars().take(60).collect();
                if pattern.chars().count() > 60 {
                    format!("{head}...")
                } else {
                    head
                }
            })
            .collect();
        cprintln!(
            "[!] {} wildcard trail pattern(s) are unusable and NOT matched: {}",
            skipped_regexes.len(),
            preview.join(", ")
        );
    }
    cprintln!(
        "[i] whitelist: {} entries, {} CIDR range(s)",
        thousands(whitelist.len() as u64),
        whitelist.range_count()
    );
    cprintln!(
        "[i] heuristics: {} (disabled: {})",
        if cfg.use_heuristics { "on" } else { "off" },
        if cfg.disabled_heuristics.is_empty() { "none".to_string() } else { cfg.disabled_heuristics.join(", ") }
    );
    cprintln!(
        "[i] features: scan_window={}s check_host_domains={} check_missing_host={} \
         user_agent_patterns={} sni_extraction={}",
        cfg.scan_window,
        cfg.check_host_domains,
        cfg.check_missing_host,
        if statics.suspicious_ua.is_some() { "loaded" } else { "unavailable" },
        if cfg.use_fast_prefilter && cfg.fast_flow_cutoff > 0 { "on (TLS/QUIC SNI)" } else { "off" }
    );
    match cfg.event_throttle_mode {
        maltrail_sensor::throttle::ThrottleMode::Summarize => cprintln!(
            "[i] event throttle: summarize ({} event(s) per {}s per (ip, trail), then one \
             aggregated line)",
            cfg.event_throttle_burst,
            cfg.event_throttle_window
        ),
        maltrail_sensor::throttle::ThrottleMode::Legacy => cprintln!(
            "[i] event throttle: legacy (sensor.py's 'sec // {}' bucket; suppressed events are \
             discarded, not summarized)",
            handles.len().max(1)
        ),
        maltrail_sensor::throttle::ThrottleMode::Off => {
            cprintln!("[!] event throttle: off - a repeated detection will be logged on EVERY packet")
        }
    }
    let mut sinks = Vec::new();
    if !cfg.disable_local_log_storage {
        sinks.push(format!("file:{}", cfg.log_dir.display()));
    }
    if !cfg.log_server.is_empty() {
        sinks.push(format!("log_server:{}", cfg.log_server));
    }
    if !cfg.syslog_server.is_empty() {
        sinks.push(format!("syslog:{}", cfg.syslog_server));
    }
    if !cfg.logstash_server.is_empty() {
        sinks.push(format!("logstash:{}", cfg.logstash_server));
    }
    if cfg.console {
        sinks.push("console".to_string());
    }
    cprintln!("[i] event sinks: {}", if sinks.is_empty() { "none".to_string() } else { sinks.join(", ") });
    if cfg.use_condensed_storage {
        cprintln!(
            "[i] using '{}' for condensed observable storage",
            maltrail_sensor::meta::meta_db_path(&cfg.log_dir).display()
        );
    }
}

/// Budget-triggered eviction of the condensed observable store (`sensor.py:update_timer()`).
///
/// Never fatal and never noisy on success: this is an auxiliary index, and an operator does not
/// need a line per hour saying nothing was over budget. A failure IS reported, because a store
/// that cannot be pruned will grow without bound.
fn prune_condensed_store(cfg: &Config) {
    if !cfg.use_condensed_storage {
        return;
    }
    let path = maltrail_sensor::meta::meta_db_path(&cfg.log_dir);
    match maltrail_sensor::meta::prune(&path, maltrail_sensor::settings::META_MAX_ROWS) {
        Ok(0) => {}
        Ok(deleted) => {
            if !cfg.quiet {
                cprintln!(
                    "[i] condensed observable store: pruned {deleted} lowest-value rows to the \
                     {} row budget",
                    maltrail_sensor::settings::META_MAX_ROWS
                );
            }
        }
        Err(e) => output::log_error(&format!("condensed observable store: prune failed ({e})"), true),
    }
}

/// One trail-update cycle plus the reporting around it (`sensor.py:init():update_timer()`).
///
/// `startup` distinguishes the synchronous refresh before the first load from the periodic one.
/// A failure is never fatal: the sensor continues with whatever trails it already has, but says
/// so loudly, because running on stale trails means silently missing detections.
fn refresh_trails(cfg: &Config, quiet: bool, startup: bool) {
    match trailupdate::run(cfg) {
        trailupdate::Outcome::Updated => {
            if !quiet && !startup {
                cprintln!("[i] trails updated");
            }
        }
        trailupdate::Outcome::Disabled => {
            if !quiet && startup {
                cprintln!(
                    "[i] trail updates disabled ('DISABLE_TRAIL_UPDATES'); using '{}' as-is",
                    cfg.trails_file.display()
                );
                warn_if_trails_are_stale(cfg);
            }
        }
        trailupdate::Outcome::Unavailable(reason) => {
            ceprintln!("[!] cannot update trails: {reason}");
            ceprintln!(
                "[?] the sensor needs Maltrail's own updater (core/update.py) to refresh '{}'; \
                 without it, IOCs added since that file was written are NOT detected",
                cfg.trails_file.display()
            );
            output::log_error(&format!("trail update unavailable: {reason}"), true);
            warn_if_trails_are_stale(cfg);
        }
        trailupdate::Outcome::Failed(reason) => {
            ceprintln!("[!] trail update failed ({reason}); continuing with the existing trails");
            output::log_error(&format!("trail update failed: {reason}"), true);
            warn_if_trails_are_stale(cfg);
        }
    }
}

/// Loudly flag a trails file older than one update period — the failure mode that cost a live
/// detection: an old file looks perfectly healthy while the sensor quietly misses new IOCs.
fn warn_if_trails_are_stale(cfg: &Config) {
    let Some(age) = trailupdate::trails_age_secs(&cfg.trails_file) else {
        ceprintln!("[!] no trails file at '{}' - the sensor will detect NOTHING", cfg.trails_file.display());
        return;
    };
    if age > cfg.update_period.max(1) {
        let days = age as f64 / 86400.0;
        ceprintln!(
            "[!] '{}' is {:.1} day(s) old (older than UPDATE_PERIOD): every trail added since then \
             is NOT being detected",
            cfg.trails_file.display(),
            days
        );
    }
}

/// Loader options taken from the configuration.
fn load_options(cfg: &Config) -> trails::LoadOptions {
    trails::LoadOptions { repair_truncated_trails: cfg.repair_truncated_trails }
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn default_config_file() -> PathBuf {
    if let Ok(env) = std::env::var("MALTRAIL_CONFIG") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent().map(|p| p.to_path_buf());
        while let Some(dir) = cur {
            let candidate = dir.join("maltrail.conf");
            if candidate.is_file() {
                return candidate;
            }
            cur = dir.parent().map(|p| p.to_path_buf());
        }
    }
    PathBuf::from("maltrail.conf")
}

/// Can this process actually capture packets?
///
/// `sensor.py` tests `geteuid() == 0`, which asks the wrong question in two directions: it refuses
/// to replay a pcap file (which needs no privileges whatsoever) and it refuses to run under
/// capabilities, which is how a packet-capture process *should* be deployed. Opening an
/// `AF_PACKET` socket needs `CAP_NET_RAW`, so that is what is checked — granted by file
/// capabilities (`setcap`), an ambient set (systemd `AmbientCapabilities=`), or being root.
fn have_capture_privileges() -> bool {
    !matches!(maltrail_sensor::selftest::capture_privileges(), maltrail_sensor::selftest::Privileges::None)
}

extern "C" fn handle_signal(_sig: libc::c_int) {
    // Only an atomic store: this must stay async-signal-safe.
    SHUTDOWN.store(true, Ordering::Relaxed);
}

extern "C" fn handle_reload_signal(_sig: libc::c_int) {
    // Only an atomic store: this must stay async-signal-safe.
    RELOAD_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `handle_signal` is an extern "C" fn performing a single relaxed atomic
        // store, which is async-signal-safe.
        unsafe {
            libc::signal(sig, handle_signal as *const () as libc::sighandler_t);
        }
    }
    // SIGHUP = reload the trails now. Standard for a daemon, and the alternative after pushing a
    // fresh trails.csv is waiting for the poll or restarting the sensor and losing its capture
    // ring. SIGHUP's default action is to TERMINATE, so without this a reload attempt kills the
    // sensor.
    // SAFETY: as above — the handler performs a single relaxed atomic store.
    unsafe {
        libc::signal(libc::SIGHUP, handle_reload_signal as *const () as libc::sighandler_t);
    }
}

fn now_clock() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let stamp = maltrail_sensor::event::local_time_string(now, 0);
    let text = stamp.as_str();
    // "%X /%Y-%m-%d/"
    format!("{} /{}/", &text[11..19], &text[..10])
}

fn local_stamp(time: std::time::SystemTime) -> String {
    let secs = time.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let stamp = maltrail_sensor::event::local_time_string(secs, 0);
    stamp.as_str()[..19].to_string()
}

fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_python_cli() {
        let args = parse_args(&["-c".into(), "x.conf".into(), "-r".into(), "a.pcap,b.pcap".into(), "--console".into()])
            .unwrap();
        assert_eq!(args.config_file, PathBuf::from("x.conf"));
        assert_eq!(args.pcap_files.len(), 2);
        assert!(args.console);
        assert!(!args.quiet);

        let args = parse_args(&["--quiet".into(), "--offline".into(), "--debug".into()]).unwrap();
        assert!(args.quiet && args.offline && args.debug);

        assert!(parse_args(&["--nope".into()]).is_err());
        assert!(parse_args(&["-c".into()]).is_err());
        assert!(parse_args(&["--timestamps".into(), "bogus".into()]).is_err());
        assert_eq!(
            parse_args(&["--timestamps".into(), "wallclock".into()]).unwrap().timestamps,
            Some(TimestampSource::Wallclock)
        );
    }

    #[test]
    fn thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1505267), "1,505,267");
    }
}
