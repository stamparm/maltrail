//! `--test-config` — validate a deployment without capturing a packet.
//!
//! Every mature IDS ships this (`suricata -T`, `snort -T`, `nginx -t`) because the alternative is
//! finding out at 3 a.m. that the sensor has been running on an unwritable log directory, a stale
//! trails file, or a BPF filter that silently never matched. Maltrail had no equivalent: the only
//! way to know whether a configuration worked was to start capturing and watch.
//!
//! This runs every check that does not require live capture, prints one line per check, and exits
//! non-zero if anything is wrong — so it is usable as a pre-deployment gate in CI or a systemd
//! `ExecStartPre=`.
//!
//! Deliberately conservative about what it calls a failure: things that *will* break detection are
//! errors, things that *might* are warnings, and it never modifies anything (it does not run a
//! trail update, and it does not create the log directory).

use std::path::Path;

use crate::config::Config;
use crate::trails::LoadOptions;
use crate::whitelist::Whitelist;
use crate::{ceprintln, cprintln};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Level {
    Ok,
    Warn,
    Fail,
}

struct Report {
    worst: Level,
}

impl Report {
    fn line(&mut self, level: Level, what: &str, detail: &str) {
        let marker = match level {
            Level::Ok => "[o]",
            Level::Warn => "[!]",
            Level::Fail => "[x]",
        };
        if detail.is_empty() {
            cprintln!("{marker} {what}");
        } else {
            cprintln!("{marker} {what}: {detail}");
        }
        if level > self.worst {
            self.worst = level;
        }
    }
}

/// Returns the process exit code: 0 = usable, 1 = something will not work.
/// Is this process privileged enough to capture?
///
/// Are we privileged enough to capture without further permission?
///
/// "euid == 0" is the POSIX way to ask. Windows has no uid, and the equivalent question is whether
/// the process token is elevated - `IsUserAnAdmin()`, which is what `core/common.py:check_sudo()`
/// already calls for the server, so the two halves agree on what "privileged" means.
///
/// Answering `false` unconditionally here was tempting and wrong: capture on Windows needs
/// Administrator, so an elevated sensor would have reported "no capture privileges" and sent
/// somebody chasing a permission that was already granted.
#[inline]
fn running_privileged() -> bool {
    #[cfg(not(windows))]
    // SAFETY: geteuid() reads the calling process's own credentials and cannot fail.
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(windows)]
    {
        // shell32 is linked by name rather than through a Windows API crate: one function, one
        // integer return, no dependency.
        #[link(name = "shell32")]
        extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        // SAFETY: takes no arguments, touches no memory of ours, and returns a BOOL.
        unsafe { IsUserAnAdmin() != 0 }
    }
}

/// Who we are, for the message that says a directory is not writable *by us*.
///
/// A uid on Unix. On Windows there is no uid to print - `u32::MAX` was the first answer here and
/// it would have rendered as "as uid 4294967295", which is worse than saying nothing - so the
/// account name stands in.
fn identity() -> String {
    #[cfg(not(windows))]
    {
        // SAFETY: as above.
        format!("uid {}", unsafe { libc::geteuid() })
    }
    #[cfg(windows)]
    {
        match std::env::var("USERNAME") {
            Ok(name) if !name.is_empty() => format!("user {}", name),
            _ => "this account".to_string(),
        }
    }
}

pub fn run(cfg: &Config) -> i32 {
    let mut r = Report { worst: Level::Ok };
    cprintln!("[i] testing configuration '{}'\n", cfg.config_file.display());

    // --- log storage -----------------------------------------------------------------
    if cfg.disable_local_log_storage {
        r.line(Level::Ok, "log storage", "disabled ('DISABLE_LOCAL_LOG_STORAGE')");
    } else if !cfg.log_dir.is_dir() {
        r.line(
            Level::Fail,
            "log directory",
            &format!("'{}' does not exist{}", cfg.log_dir.display(), log_dir_hint(&cfg.log_dir)),
        );
    } else if writable(&cfg.log_dir) {
        r.line(Level::Ok, "log directory", &format!("'{}' is writable", cfg.log_dir.display()));
    } else {
        // Naming the problem is not the same as being useful about it. This check exists to be
        // read by somebody installing the sensor for the first time, and "NOT writable" left
        // them to work out on their own that the fix is an ownership change and what the
        // incantation for it is. `install -d` also repairs an existing directory's owner and
        // mode, so one line covers both this branch and the missing-directory one above.
        r.line(
            Level::Fail,
            "log directory",
            &format!("'{}' is NOT writable as {}{}", cfg.log_dir.display(), identity(), log_dir_hint(&cfg.log_dir)),
        );
    }

    // Event logs are evidence and are never deleted by the sensor, so free space is a real
    // operating limit and not a footnote. A full disk loses detections while the process still
    // looks healthy — the most expensive failure with the cheapest possible warning.
    if !cfg.disable_local_log_storage && cfg.log_dir.is_dir() {
        match crate::output::free_bytes(&cfg.log_dir) {
            Some(free) => {
                const GB: u64 = 1024 * 1024 * 1024;
                let human = format!("{:.1} GB free on '{}'", free as f64 / GB as f64, cfg.log_dir.display());
                if free < GB {
                    r.line(Level::Fail, "log storage", &format!("{human} — detections will be LOST shortly"));
                } else if free < 10 * GB {
                    r.line(
                        Level::Warn,
                        "log storage",
                        &format!("{human} — Maltrail never deletes evidence; ship to LOG_SERVER or archive off-box"),
                    );
                } else {
                    r.line(Level::Ok, "log storage", &human);
                }
            }
            None => r.line(Level::Warn, "log storage", "free space could not be determined"),
        }
    }

    // --- capture filter --------------------------------------------------------------
    // Compiled against a dead handle, so a bad filter is caught here instead of at capture time
    // where the sensor would exit (or, worse, match nothing).
    if cfg.capture_filter.is_empty() {
        r.line(Level::Warn, "capture filter", "empty — every packet crosses into the sensor");
    } else {
        match compile_filter(&cfg.capture_filter) {
            Ok(()) => r.line(Level::Ok, "capture filter", &truncate(&cfg.capture_filter, 68)),
            Err(e) => r.line(Level::Fail, "capture filter", &format!("does not compile ({e})")),
        }
    }

    // --- capture privileges ----------------------------------------------------------
    // Reported here so an operator learns about it from `-T` rather than from a sensor that
    // exits at 3 a.m. after a package upgrade replaced the binary and dropped its capabilities.
    if !cfg.is_offline_replay() {
        match capture_privileges() {
            Privileges::Root => r.line(Level::Ok, "capture privileges", privileged_word()),
            Privileges::NetRaw => r.line(Level::Ok, "capture privileges", "CAP_NET_RAW present"),
            // `DISABLE_CHECK_SUDO` is the operator saying "do not check"; `-T` honours that rather
            // than failing a configuration the sensor itself would happily start with.
            Privileges::None if cfg.disable_check_sudo => r.line(
                Level::Warn,
                "capture privileges",
                &format!("{}, but 'DISABLE_CHECK_SUDO' is set", unprivileged_word()),
            ),
            Privileges::None => r.line(
                Level::Fail,
                "capture privileges",
                &format!("{} — {}", unprivileged_word(), capture_privilege_hint()),
            ),
        }
    }

    // --- interfaces ------------------------------------------------------------------
    if cfg.is_offline_replay() {
        r.line(Level::Ok, "capture source", "offline replay");
    } else {
        let devices: Vec<String> =
            pcap::Device::list().map(|l| l.into_iter().map(|d| d.name).collect()).unwrap_or_default();
        let (resolved, expanded) = crate::capture::resolve_interfaces(&cfg.monitor_interfaces(), &devices);
        if expanded {
            // Say so, rather than silently reporting interfaces the operator never configured.
            r.line(
                Level::Ok,
                "interface",
                &format!("'any' is not a device here; using the {} interface(s) this machine has", resolved.len()),
            );
        }
        for want in &resolved {
            match interface_verdict(want, &devices) {
                Ok(()) => r.line(Level::Ok, "interface", want),
                Err(why) => r.line(Level::Fail, "interface", &why),
            }
        }
        let workers = cfg.capture_workers.max(1);
        if workers > 1 {
            r.line(
                Level::Ok,
                "workers",
                &format!("{workers} (PACKET_FANOUT required; verify with tools/fanout_check.py as root)"),
            );
            // Fanout hashes by flow; the scan heuristics count by source, and a scan is many
            // flows. Measured on the corpus (tests/multi_worker_parity.rs): 91% of heuristic
            // alerts survive at 2 workers, 86% at 4, 65% at 8. Trail detection is per packet and
            // stateless, so it is identical at any worker count — the same test asserts it.
            let scan_heuristics =
                ["port_scanning", "udp_scanning", "infection", "web_scanning"].iter().any(|h| cfg.heuristic_enabled(h));
            if cfg.use_heuristics && scan_heuristics {
                r.line(
                    Level::Warn,
                    "scan fidelity",
                    &format!(
                        "{workers} workers dilute per-source scan evidence (~65% of alerts survive at 8); \
                         'CAPTURE_WORKERS 1' for full fidelity — trail detection is unaffected"
                    ),
                );
            }
        } else {
            // One worker is the DEFAULT and the right answer for almost every host, so this is
            // not a warning. It used to be, back when the default was derived from PROCESS_COUNT
            // and a single worker meant somebody had opted out of throughput; now it means the
            // scan heuristics see every packet from a source, which is the more valuable
            // property. ~865 ns/packet is roughly 1.1M packets/s on one core.
            r.line(
                Level::Ok,
                "workers",
                "1 — undiluted per-source heuristics; raise 'CAPTURE_FANOUT' only if \
                 'maltrail_capture_dropped_total' climbs",
            );
        }
    }

    // --- numeric ranges, and what the sensor will ACTUALLY use -----------------------
    // Every one of these used to be accepted silently: a zero snaplen truncates every packet to
    // nothing, a CAPTURE_TIMEOUT that overflows the C int libpcap wants can end up negative
    // ("block forever"), and a zero throttle window disables the bounding it exists for. The
    // sensor clamps them at load; -T is where the operator finds out that it did.
    for clamp in &cfg.clamps {
        r.line(Level::Warn, "config range", clamp);
    }
    // CAPTURE_BUFFER is per worker, which is the surprise on a many-core box.
    let ring = cfg.estimated_capture_memory_bytes();
    r.line(
        Level::Ok,
        "effective config",
        &format!(
            "snaplen={} B, capture timeout={} ms, workers={}, capture ring≈{:.0} MB total ({:.0} MB × {}), \
             throttle={:?} window={}s burst={} max_keys={}",
            cfg.capture_snaplen,
            cfg.capture_timeout_ms,
            cfg.capture_workers,
            ring as f64 / (1024.0 * 1024.0),
            cfg.capture_buffer_size as f64 / (1024.0 * 1024.0),
            cfg.capture_workers,
            cfg.event_throttle_mode,
            cfg.event_throttle_window,
            cfg.event_throttle_burst,
            cfg.event_throttle_max_keys
        ),
    );

    // --- whitelist -------------------------------------------------------------------
    let whitelist = Whitelist::load(&cfg.root, cfg.user_whitelist.as_deref());
    if whitelist.is_empty() {
        r.line(Level::Warn, "whitelist", "empty — data/whitelist.txt missing or unreadable?");
    } else {
        r.line(
            Level::Ok,
            "whitelist",
            &format!("{} entries, {} CIDR range(s)", whitelist.len(), whitelist.range_count()),
        );
    }

    // --- static trail source ---------------------------------------------------------
    // Matching known-bad infrastructure IS Maltrail, and the static set is the large majority of
    // what it matches on. Without a source for it the sensor starts, loads a far smaller file and
    // reports healthy - which looks exactly like a quiet network. Upgrading from before the trails
    // split arrives here by default: the option is simply absent from an older maltrail.conf.
    //
    // Only when this sensor is the one doing the updating. With DISABLE_TRAIL_UPDATES the file is
    // built by the server or a cron job and where its content came from is not this sensor's call.
    if !cfg.disable_trail_updates {
        let configured =
            cfg.raw.get("STATIC_TRAILS_URL").and_then(|v| v.as_str()).map(|v| !v.trim().is_empty()).unwrap_or(false);
        if !configured {
            r.line(
                Level::Fail,
                "static trails",
                "'STATIC_TRAILS_URL' is not set \u{2014} the static trail set will not be fetched, so this sensor would \
                 match only heuristics and whatever the feeds return. hint: STATIC_TRAILS_URL \
                 https://github.com/stamparm/trails/releases/latest/download/trails.csv.gz",
            );
        }
    }

    // --- trails ----------------------------------------------------------------------
    if !cfg.trails_file.exists() {
        // A missing trails file is only fatal if nothing will ever create it. On a fresh install
        // the sensor builds it at startup, and failing the preflight here would deadlock the
        // shipped systemd unit: ExecStartPre=-T would reject the very state that ExecStart fixes.
        if cfg.disable_trail_updates {
            r.line(
                Level::Fail,
                "trails",
                &format!(
                    "'{}' does not exist and 'DISABLE_TRAIL_UPDATES' is set, so nothing will \
                     create it — the sensor would detect NOTHING",
                    cfg.trails_file.display()
                ),
            );
        } else {
            r.line(
                Level::Warn,
                "trails",
                &format!("'{}' does not exist yet; it is built on first start", cfg.trails_file.display()),
            );
        }
    } else {
        let options = LoadOptions { repair_truncated_trails: cfg.repair_truncated_trails };
        match crate::trails::load_with(&cfg.trails_file, &whitelist, options) {
            Err(e) => r.line(Level::Fail, "trails", &format!("'{}' unreadable ({e})", cfg.trails_file.display())),
            Ok((db, stats)) => {
                if stats.loaded == 0 {
                    // Must agree with the startup check in main(), or `ExecStartPre=-T` blocks a
                    // sensor that the operator has deliberately configured to run trail-less.
                    if cfg.allow_empty_trails {
                        r.line(Level::Warn, "trails", "loaded 0 trails, allowed by 'ALLOW_EMPTY_TRAILS'");
                    } else {
                        r.line(Level::Fail, "trails", "loaded 0 trails — this sensor would detect nothing");
                    }
                } else {
                    r.line(
                        Level::Ok,
                        "trails",
                        &format!(
                            "{} loaded ({} malformed row(s)), ipv4={} ipv4:port={} ipv6={} wildcard={}",
                            stats.loaded,
                            stats.malformed,
                            db.ip4_count(),
                            db.ip4_port_count(),
                            db.ip6_count(),
                            db.regex().len()
                        ),
                    );
                }
                if stats.malformed * 100 > stats.rows.max(1) {
                    r.line(Level::Warn, "trails", "more than 1% of rows are malformed — wrong file?");
                }
                let skipped = db.regex().skipped().len();
                if skipped > 0 {
                    r.line(Level::Warn, "trails", &format!("{skipped} wildcard trail(s) are unusable"));
                }
                // Staleness is the failure that hides: an old file loads perfectly and quietly
                // misses every indicator added since it was written.
                match crate::trailupdate::trails_age_secs(&cfg.trails_file) {
                    Some(age) if age > cfg.update_period.max(1) => r.line(
                        Level::Warn,
                        "trails age",
                        &format!("{:.1} day(s) old, older than UPDATE_PERIOD", age as f64 / 86400.0),
                    ),
                    Some(age) => r.line(Level::Ok, "trails age", &format!("{:.1} day(s)", age as f64 / 86400.0)),
                    None => {}
                }
            }
        }
    }

    // --- trail updating --------------------------------------------------------------
    if cfg.disable_trail_updates {
        r.line(Level::Warn, "trail updates", "disabled — something else must refresh TRAILS_FILE");
    } else {
        let script = crate::trailupdate::updater_script(&cfg.root);
        if !script.is_file() {
            r.line(Level::Fail, "trail updates", &format!("missing '{}'", script.display()));
        } else {
            // Reporting "interpreter present" without checking WHICH interpreter is how a host
            // whose python3 is 3.6 passed `-T` and then built an empty trail set — a sensor that
            // says it is fine and detects nothing. The version is the whole point of the check.
            let (min_major, min_minor) = crate::trailupdate::MIN_PYTHON;
            match crate::trailupdate::python_probe() {
                None => r.line(Level::Fail, "trail updates", "no python3 on PATH (set MALTRAIL_PYTHON)"),
                Some(python) if python.is_supported() => r.line(
                    Level::Ok,
                    "trail updates",
                    &format!("updater present, {} is Python {}", python.command, python.version_string()),
                ),
                Some(python) => r.line(
                    Level::Fail,
                    "trail updates",
                    &format!(
                        "'{}' is Python {}, but the updater needs {}.{}+ — the trail set cannot be \
                         built, so this sensor would detect NOTHING\n      \
                         fix: install a newer Python (openSUSE/SLES: 'sudo zypper install python311') \
                         and point the sensor at it with MALTRAIL_PYTHON=/usr/bin/python3.11",
                        python.command,
                        python.version_string(),
                        min_major,
                        min_minor
                    ),
                ),
            }
        }
    }

    // --- detection features ----------------------------------------------------------
    // `-T` runs before the sensor's normal startup, so the compiled patterns are built here.
    let statics = crate::settings::init(cfg.root.clone());
    if statics.suspicious_ua.is_some() {
        r.line(Level::Ok, "user-agent patterns", "loaded from data/ua.txt");
    } else {
        r.line(Level::Warn, "user-agent patterns", "unavailable — data/ua.txt missing?");
    }
    r.line(
        Level::Ok,
        "heuristics",
        &if cfg.use_heuristics {
            format!(
                "on (disabled: {})",
                if cfg.disabled_heuristics.is_empty() { "none".into() } else { cfg.disabled_heuristics.join(",") }
            )
        } else {
            "OFF — only exact trail matches will fire".to_string()
        },
    );
    if !cfg.use_heuristics {
        r.line(Level::Warn, "heuristics", "USE_HEURISTICS is false");
    }

    // --- remote sinks ----------------------------------------------------------------
    for (name, value) in [
        ("LOG_SERVER", &cfg.log_server),
        ("SYSLOG_SERVER", &cfg.syslog_server),
        ("LOGSTASH_SERVER", &cfg.logstash_server),
    ] {
        if value.is_empty() {
            continue;
        }
        match crate::addr::parse_host_port(value) {
            (host, Some(port)) if !host.is_empty() && port > 0 => r.line(Level::Ok, name, value),
            _ => r.line(Level::Fail, name, &format!("'{value}' is not host:port")),
        }
    }

    if cfg.use_condensed_storage {
        let path = crate::meta::meta_db_path(&cfg.log_dir);
        r.line(Level::Ok, "USE_CONDENSED_STORAGE", &format!("on, writing '{}'", path.display()));
    }

    cprintln!("");
    match r.worst {
        Level::Ok => {
            cprintln!("[i] configuration test PASSED");
            0
        }
        Level::Warn => {
            cprintln!("[i] configuration test PASSED with warnings");
            0
        }
        Level::Fail => {
            ceprintln!("[!] configuration test FAILED — the sensor would not work as configured");
            1
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    format!("{}...", &value[..max])
}

/// The exact command that gives the current user a usable `LOG_DIR`.
///
/// Deliberately emitted as shell to copy rather than as resolved names: `$USER` and `id -gn` are
/// correct on every distribution, whereas printing the two names invites the reader to assume the
/// group is always named after the user. It is not — that assumption is what shipped a broken
/// `install -d -o "$USER" -g "$USER"` in the README, which fails outright on distributions that
/// put everyone in a shared `users` group.
fn log_dir_hint(dir: &Path) -> String {
    format!("\n      fix: sudo install -d -o \"$USER\" -g \"$(id -gn)\" -m 750 '{}'", dir.display())
}

/// Can we actually create a file here? `access(W_OK)` lies under some mount options, and this is
/// the exact operation the sensor performs at runtime.
fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".maltrail-write-test-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

pub enum Privileges {
    Root,
    NetRaw,
    None,
}

/// Is `want` an interface this machine actually has?
///
/// `any` used to be waved through unconditionally, and it is not portable: it is a Linux
/// pseudo-device that libpcap synthesises, and Npcap, macOS and the BSDs have no such thing. So on
/// Windows the SHIPPED default configuration passed `-T` and then died at startup with
///
/// ```text
/// Error opening adapter: The filename, directory name, or volume label syntax is incorrect. (123)
/// ```
///
/// a Win32 error naming nothing an operator could act on. Checking membership like any other name
/// is both simpler and true everywhere - Linux does enumerate `any`, so nothing changes there.
///
/// An empty list means the devices could not be enumerated at all (no privileges, typically),
/// which is not evidence that the name is wrong, so it passes.
fn interface_verdict(want: &str, devices: &[String]) -> Result<(), String> {
    if devices.is_empty() || devices.iter().any(|d| d == want) {
        return Ok(());
    }
    if want.eq_ignore_ascii_case("any") {
        return Err(format!(
            "'any' is a Linux-only pseudo-device and does not exist here — set 'MONITOR_INTERFACE' \
             to a real one (have: {})",
            devices.join(",")
        ));
    }
    Err(format!("'{want}' not found (have: {})", devices.join(",")))
}

/// `CAP_NET_RAW` from `linux/capability.h`.
const CAP_NET_RAW: u32 = 13;

/// What "privileged" is called here. `root` everywhere but Windows, which has no such account.
fn privileged_word() -> &'static str {
    #[cfg(not(windows))]
    {
        "running as root"
    }
    #[cfg(windows)]
    {
        "running elevated (Administrator)"
    }
}

fn unprivileged_word() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "no CAP_NET_RAW"
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        "not root"
    }
    #[cfg(windows)]
    {
        "not elevated"
    }
}

/// How to grant it, on THIS platform.
///
/// `setcap` is a Linux capability tool and nothing else has it. Printing that line on macOS, a BSD
/// or Windows is worse than printing nothing: it reads as an instruction, and following it fails
/// with a command-not-found that explains none of the actual problem.
fn capture_privilege_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "run 'setcap cap_net_raw,cap_net_admin=eip <binary>' (root not required)"
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        // There is no capability to grant: capture privilege here IS ownership of the bpf devices,
        // which is why install.sh does not call setcap on these platforms.
        "capture needs root, or read access to /dev/bpf* (chgrp the devices and add the sensor's user to that group)"
    }
    #[cfg(windows)]
    {
        "capture needs an elevated prompt, and the Npcap driver installed (https://npcap.com)"
    }
}

/// What this process may do, without conflating "can capture" with "is root".
pub fn capture_privileges() -> Privileges {
    if running_privileged() {
        return Privileges::Root;
    }
    let effective = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("CapEff:")).map(|l| l["CapEff:".len()..].trim().to_string()))
        .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
        .unwrap_or(0);
    if effective & (1u64 << CAP_NET_RAW) != 0 {
        Privileges::NetRaw
    } else {
        Privileges::None
    }
}

/// Compile the BPF filter against a dead handle — no privileges, no interface needed.
fn compile_filter(filter: &str) -> Result<(), String> {
    let cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).map_err(|e| e.to_string())?;
    match cap.compile(filter, true) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `-T` must not pass a configuration the sensor cannot then start with.
    ///
    /// Found by running the shipped `maltrail.conf` on a real Windows 10 VM: `-T` printed
    /// `[o] interface: any` and the sensor then refused to open it, because `any` is a Linux
    /// pseudo-device that Npcap does not provide. macOS and the BSDs do not provide it either.
    #[test]
    fn any_is_only_accepted_where_the_platform_actually_has_it() {
        let linux = vec!["any".to_string(), "eth0".to_string(), "lo".to_string()];
        assert!(interface_verdict("any", &linux).is_ok(), "Linux enumerates 'any'; it must pass there");
        assert!(interface_verdict("eth0", &linux).is_ok());

        // What Npcap reports: adapter names, and no 'any'.
        let windows = vec![
            r"\Device\NPF_{6C4D8B1B-0000-0000-0000-000000000001}".to_string(),
            r"\Device\NPF_Loopback".to_string(),
        ];
        let why = interface_verdict("any", &windows).expect_err("'any' does not exist on Windows");
        assert!(why.contains("Linux-only"), "the message must say why, not just 'not found': {why}");
        assert!(why.contains("NPF_Loopback"), "the message must name what IS available: {why}");

        // An unknown name is still an unknown name.
        assert!(interface_verdict("eth9", &linux).is_err());

        // Enumeration failing is not evidence the name is wrong - typically it just means the
        // process cannot list devices without privileges, and refusing there would turn a
        // permission problem into a false "no such interface".
        assert!(interface_verdict("any", &[]).is_ok());
        assert!(interface_verdict("whatever0", &[]).is_ok());
    }

    /// Maltrail v1's sensor.py substituted the real interface names where `any` did not exist.
    /// The same substitution here is what makes the shipped `MONITOR_INTERFACE any` work on
    /// Windows, macOS and the BSDs instead of failing at startup.
    #[test]
    fn any_is_substituted_only_where_the_platform_lacks_it() {
        use crate::capture::resolve_interfaces;
        let want = |s: &str| vec![s.to_string()];

        // Linux enumerates `any`, and the kernel merging is better than opening every device:
        // it must be left completely alone.
        let linux = vec!["any".to_string(), "eth0".to_string(), "lo".to_string()];
        let (got, expanded) = resolve_interfaces(&want("any"), &linux);
        assert_eq!(got, vec!["any".to_string()], "Linux must keep using the real 'any' device");
        assert!(!expanded);

        // Windows has no 'any', so it becomes the adapters that do exist.
        let windows = vec![r"\Device\NPF_{A}".to_string(), r"\Device\NPF_Loopback".to_string()];
        let (got, expanded) = resolve_interfaces(&want("any"), &windows);
        assert_eq!(got, windows, "'any' must become every device the platform has");
        assert!(expanded, "the caller has to know this was substituted, to tolerate an adapter that will not open");

        // An explicitly named interface is never touched, and duplicates collapse.
        let (got, expanded) = resolve_interfaces(&want(r"\Device\NPF_{A}"), &windows);
        assert_eq!(got, vec![r"\Device\NPF_{A}".to_string()]);
        assert!(!expanded);
        let mixed = vec![r"\Device\NPF_{A}".to_string(), "any".to_string()];
        let (got, _) = resolve_interfaces(&mixed, &windows);
        assert_eq!(got, windows, "a name already covered by the substitution must not appear twice");

        // Enumeration failing is not a licence to invent interfaces.
        let (got, expanded) = resolve_interfaces(&want("any"), &[]);
        assert_eq!(got, vec!["any".to_string()]);
        assert!(!expanded);
    }

    /// The released Linux sensor could not capture on the shipped configuration.
    ///
    /// It links libpcap 1.10.5 statically, and that version refuses to activate a handle on the
    /// `any` device when promiscuous mode is requested. Every prebuilt Linux sensor therefore
    /// failed at "opening interface 'any'" with the default `MONITOR_INTERFACE`, while a build
    /// against the system libpcap 1.10.4 worked - so nothing in development ever saw it, and `-T`
    /// could not, because `-T` does not open a capture handle.
    #[test]
    fn promiscuous_mode_is_not_requested_on_the_any_device() {
        use crate::capture::wants_promisc;
        assert!(!wants_promisc("any"), "requesting promisc on 'any' is refused by libpcap 1.10.5");
        assert!(!wants_promisc("ANY"), "the device name is not case-sensitive");
        // Everywhere else it is wanted: without it a real interface only sees its own traffic.
        assert!(wants_promisc("eth0"));
        assert!(wants_promisc("en0"));
        assert!(wants_promisc(r"\Device\NPF_{A}"));
    }
}
