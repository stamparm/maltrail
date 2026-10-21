//! The condensed observable store — `LOG_DIR/meta.sqlite`.
//!
//! Port of `core/meta.py`. One cumulative row per distinct thing seen on the wire (a domain OR
//! an IP) with `first_seen` / `last_seen` / `count`, so the server can answer "have I EVER seen
//! this, since when, how often" — novelty checks, and retro-hunting a newly published IOC
//! against traffic that predates it — without keeping any raw traffic.
//!
//! # This file's shape is a contract, not an implementation detail
//!
//! `core/httpd.py`'s `/meta` endpoint reads this database through `core/meta.py:lookup()`, and
//! an operator may run the Python server against a store this sensor wrote (that is the whole
//! point of writing it). So the schema, the key encoding and the journal mode are all fixed by
//! the Python side and reproduced exactly:
//!
//! * `WITHOUT ROWID`, primary key on `observable`, columns in the same order.
//! * IPs are stored as **4/16-byte BLOBs**, domains as **TEXT**. `lookup()` decides which to
//!   probe by parsing the query string, so an IP written as text would simply never be found.
//! * `journal_mode=DELETE`, **not WAL**. The sensor writes as root and the server usually reads
//!   as a non-root user; WAL would require that reader to create the `-shm` sidecar, which it
//!   cannot, and it would silently fall back to an empty result.
//! * The file is chmod'd world-readable for the same uid-split reason.
//! * The merge keeps `flags` from the first sighting, takes `MIN(first_seen)` / `MAX(last_seen)`
//!   and adds `count`. `core/meta.py` spells it `INSERT OR IGNORE` + `UPDATE` so it runs on SQLite
//!   older than 3.24; the sensor's bundled SQLite does the same as one upsert. The file is the
//!   same either way - the statement is not part of the format.
//!
//! # Concurrency
//!
//! Each worker owns a `MetaStore` and fills it lock-free on the packet path. Draining it is NOT
//! done on the worker: the write took 0.6-0.7 s at 200k keys on NVMe (more on an SD card, plus
//! up to `busy_timeout` waiting on another writer), and a capture thread that stops draining for
//! that long overflows its ring. A worker hands its window to one writer thread instead
//! (`writer()`) and goes back to capturing. Windows arrive out of order, which the merge's
//! `MIN`/`MAX` exist for. Counts are best-effort under a crash, as in Python.
//!
//! # Cost
//!
//! The packet path does one hash bump per endpoint and one per DNS name into a plain map keyed
//! by the *native* `Ip` — no address is rendered to text until a key is first inserted, and
//! never on a repeat sighting. Everything else happens once a minute, off the packet path.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};

use rusqlite::{Connection, OpenFlags};

use crate::addr::Ip;
use crate::fasthash::{FastMap, StrMap};
use crate::settings;

/// `flags` bit 0 — the observable is a DNS name rather than an address.
pub const FLAG_DNS: u8 = 0x1;
/// `flags` bits 1-2 — scope of an address observable.
pub const SCOPE_LOCAL: u8 = 0x1;
pub const SCOPE_REMOTE: u8 = 0x2;

/// One aggregate row, in memory.
#[derive(Clone, Copy, Debug)]
struct Row {
    flags: u8,
    first_seen: u64,
    last_seen: u64,
    count: u64,
}

impl Row {
    #[inline]
    fn new(flags: u8, sec: u64) -> Row {
        Row { flags, first_seen: sec, last_seen: sec, count: 1 }
    }

    #[inline]
    fn bump(&mut self, sec: u64) {
        // Python assigns last_seen unconditionally (`r[2] = sec`) rather than taking a max, and
        // so does this: within one worker the packet clock only moves forward, and the max is
        // applied in SQL where windows really can arrive out of order.
        self.last_seen = sec;
        self.count += 1;
    }
}

/// Per-worker aggregate plus everything needed to drain it.
pub struct MetaStore {
    enabled: bool,
    db_path: PathBuf,
    ips: FastMap<Ip, Row>,
    /// Seeded hasher: these keys are attacker-chosen DNS names.
    names: StrMap<String, Row>,
    max_window_keys: usize,
    flush_period: u64,
    last_flush: u64,
    /// New keys refused because the window cap was already reached. Folded into the sensor's
    /// `state_saturations` metric, so an operator sees "the sensor is dropping detail" without
    /// having to know which structure filled up.
    pub saturations: u64,
    /// Rows merged into SQLite, and flushes that failed, as counted by the writer thread.
    results: Arc<FlushResults>,
}

/// What became of one store's windows, written by the writer thread.
#[derive(Default)]
struct FlushResults {
    flushed: AtomicU64,
    /// The in-RAM window is lost when a flush fails, exactly as in Python.
    errors: AtomicU64,
}

/// One drained window on its way to the writer, or a request to say when it has caught up.
enum Job {
    Write { db_path: PathBuf, ips: FastMap<Ip, Row>, names: StrMap<String, Row>, results: Arc<FlushResults> },
    Barrier(mpsc::Sender<()>),
}

/// Windows waiting for the writer. A worker never blocks on it: past this many, a window is
/// counted as saturation and dropped, like any other refusal to grow without bound.
const WRITER_BACKLOG: usize = 8;

/// The one thread that writes `meta.sqlite`, started on first use.
fn writer() -> &'static Mutex<mpsc::SyncSender<Job>> {
    static WRITER: OnceLock<Mutex<mpsc::SyncSender<Job>>> = OnceLock::new();
    WRITER.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<Job>(WRITER_BACKLOG);
        std::thread::Builder::new()
            .name("meta-writer".into())
            .spawn(move || {
                for job in rx {
                    match job {
                        Job::Write { db_path, ips, names, results } => {
                            let rows = (ips.len() + names.len()) as u64;
                            match write(&db_path, &ips, &names) {
                                Ok(()) => {
                                    results.flushed.fetch_add(rows, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    results.errors.fetch_add(1, Ordering::Relaxed);
                                    crate::output::log_error(
                                        &format!("condensed observable store: flush of {rows} rows failed ({e})"),
                                        true,
                                    );
                                }
                            }
                        }
                        Job::Barrier(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .expect("spawn the meta.sqlite writer");
        Mutex::new(tx)
    })
}

impl MetaStore {
    /// A disabled store. Every hot-path method is a single predictable branch.
    pub fn disabled() -> MetaStore {
        MetaStore {
            enabled: false,
            db_path: PathBuf::new(),
            ips: FastMap::default(),
            names: StrMap::default(),
            max_window_keys: settings::CONDENSED_MAX_WINDOW_KEYS,
            flush_period: settings::CONDENSED_FLUSH_PERIOD,
            last_flush: 0,
            saturations: 0,
            results: Arc::default(),
        }
    }

    /// `core/meta.py:configure()`.
    pub fn new(db_path: PathBuf, max_window_keys: usize, flush_period: u64) -> MetaStore {
        MetaStore {
            enabled: true,
            db_path,
            max_window_keys: if max_window_keys == 0 { settings::CONDENSED_MAX_WINDOW_KEYS } else { max_window_keys },
            flush_period: if flush_period == 0 { settings::CONDENSED_FLUSH_PERIOD } else { flush_period },
            ..MetaStore::disabled()
        }
    }

    /// Build the store a worker should use for this configuration.
    pub fn for_config(cfg: &crate::config::Config) -> MetaStore {
        if !cfg.use_condensed_storage {
            return MetaStore::disabled();
        }
        MetaStore::new(
            meta_db_path(&cfg.log_dir),
            settings::CONDENSED_MAX_WINDOW_KEYS,
            settings::CONDENSED_FLUSH_PERIOD,
        )
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[inline]
    pub fn pending(&self) -> usize {
        self.ips.len() + self.names.len()
    }

    /// Hot path: record both endpoints of a connection. `core/meta.py:observe_conn()`.
    #[inline]
    pub fn observe_conn(&mut self, src: Ip, dst: Ip, sec: u64) {
        if !self.enabled {
            return;
        }
        self.observe_ip(dst, sec);
        self.observe_ip(src, sec);
    }

    #[inline]
    fn observe_ip(&mut self, ip: Ip, sec: u64) {
        if let Some(row) = self.ips.get_mut(&ip) {
            row.bump(sec);
            return;
        }
        if is_junk_ip(ip) {
            return;
        }
        if self.pending() >= self.max_window_keys {
            self.saturations += 1;
            return;
        }
        self.ips.insert(ip, Row::new(ip_flags(ip), sec));
    }

    /// Hot path: record a queried domain name. `core/meta.py:observe_dns()`.
    #[inline]
    pub fn observe_dns(&mut self, name: &str, sec: u64) {
        if !self.enabled || name.is_empty() {
            return;
        }
        if let Some(row) = self.names.get_mut(name) {
            row.bump(sec);
            return;
        }
        if self.pending() >= self.max_window_keys {
            self.saturations += 1;
            return;
        }
        self.names.insert(name.to_string(), Row::new(FLAG_DNS, sec));
    }

    /// Drain into SQLite if the flush period has elapsed. `now` is wall-clock seconds.
    pub fn maybe_flush(&mut self, now: u64) {
        if !self.enabled || self.pending() == 0 {
            return;
        }
        if self.last_flush == 0 {
            self.last_flush = now;
            return;
        }
        if now.saturating_sub(self.last_flush) < self.flush_period {
            return;
        }
        self.last_flush = now;
        self.flush_async();
    }

    /// Hand this worker's aggregate to the writer thread and return at once. `core/meta.py:flush()`.
    ///
    /// A failure loses the window rather than retrying: the alternative is an unbounded in-RAM
    /// backlog on a host whose disk has gone read-only, which would turn a degraded auxiliary
    /// index into an OOM of the sensor itself. The error is logged, and the counter is exported.
    pub fn flush_async(&mut self) {
        if !self.enabled || self.pending() == 0 {
            return;
        }
        let ips = std::mem::take(&mut self.ips);
        let names = std::mem::take(&mut self.names);
        let rows = (ips.len() + names.len()) as u64;
        let job = Job::Write { db_path: self.db_path.clone(), ips, names, results: self.results.clone() };
        let sent = match writer().lock() {
            Ok(tx) => tx.try_send(job).is_ok(),
            Err(_) => false,
        };
        if !sent {
            self.saturations += rows;
        }
    }

    /// `flush_async()`, then wait until the writer has stored everything handed to it so far -
    /// for the last window on the way out, and for tests that read the file back.
    pub fn flush(&mut self) {
        if !self.enabled {
            return;
        }
        if self.pending() > 0 {
            let ips = std::mem::take(&mut self.ips);
            let names = std::mem::take(&mut self.names);
            let job = Job::Write { db_path: self.db_path.clone(), ips, names, results: self.results.clone() };
            // Blocking here is right: nothing is capturing any more, and this window is the tail.
            let tx = match writer().lock() {
                Ok(tx) => tx.clone(),
                Err(_) => return,
            };
            let _ = tx.send(job);
        }
        let (done, wait) = mpsc::channel();
        let tx = match writer().lock() {
            Ok(tx) => tx.clone(),
            Err(_) => return,
        };
        if tx.send(Job::Barrier(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// Rows merged into SQLite so far.
    pub fn flushed(&self) -> u64 {
        self.results.flushed.load(Ordering::Relaxed)
    }

    /// Flushes that failed so far.
    pub fn flush_errors(&self) -> u64 {
        self.results.errors.load(Ordering::Relaxed)
    }
}

/// One window into SQLite, as a single transaction.
fn write(db_path: &Path, ips: &FastMap<Ip, Row>, names: &StrMap<String, Row>) -> rusqlite::Result<()> {
    let mut con = open_rw(db_path)?;
    // IMMEDIATE, not the default DEFERRED: this transaction only ever writes, and taking the
    // reserved lock up front is what lets `busy_timeout` do its job. A deferred transaction
    // that upgrades from read to write mid-way can be handed SQLITE_BUSY without the busy
    // handler being consulted at all, because SQLite cannot rule out a deadlock — which with
    // a server pruning the same file would show up as sporadic lost windows.
    let tx = con.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    {
        // One upsert per row, in key order: a sorted batch walks the primary-key B-tree
        // forwards instead of jumping around it (measured 2.8x faster than the old two
        // statements on a 2M-row store).
        let mut upsert = tx.prepare_cached(
            "INSERT INTO observables (observable, flags, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(observable) DO UPDATE SET first_seen = MIN(first_seen, excluded.first_seen), \
             last_seen = MAX(last_seen, excluded.last_seen), count = count + excluded.count",
        )?;
        let mut packed: Vec<(PackedIp, &Row)> = ips.iter().map(|(ip, row)| (pack_ip(*ip), row)).collect();
        packed.sort_unstable_by(|a, b| a.0.as_slice().cmp(b.0.as_slice()));
        for (key, row) in &packed {
            upsert.execute(rusqlite::params![
                key.as_slice(),
                row.flags,
                row.first_seen as i64,
                row.last_seen as i64,
                row.count as i64
            ])?;
        }
        let mut sorted: Vec<(&String, &Row)> = names.iter().collect();
        sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (name, row) in sorted {
            upsert.execute(rusqlite::params![
                name,
                row.flags,
                row.first_seen as i64,
                row.last_seen as i64,
                row.count as i64
            ])?;
        }
    }
    tx.commit()
}

/// `os.path.join(config.LOG_DIR, META_DB_FILENAME)`.
pub fn meta_db_path(log_dir: &Path) -> PathBuf {
    log_dir.join(settings::META_DB_FILENAME)
}

/// `core/meta.py:_JUNK_IPS` + `_is_mcast()` — never worth a row.
#[inline]
fn is_junk_ip(ip: Ip) -> bool {
    match ip {
        // 0.0.0.0, 255.255.255.255, and 224.0.0.0/4.
        Ip::V4(v) => v == 0 || v == u32::MAX || matches!((v >> 24) as u8, 224..=239),
        // `::`, and ff00::/8.
        Ip::V6(v) => v == 0 || (v >> 120) as u8 == 0xff,
    }
}

/// `core/meta.py:_flags_ip()`.
///
/// The IPv4 half is `core/common.py:is_local()`. The IPv6 half is *not* — meta.py applies its own
/// rule to the **rendered** address (`"::1"`, or a `fe`/`fc`/`fd` prefix), and this reproduces it
/// on the same rendering (`Ip::render()` matches `core/addr.py:inet_ntoa6()` quirks and all), so
/// the two implementations agree on every address including the odd ones.
#[inline]
fn ip_flags(ip: Ip) -> u8 {
    let local = match ip {
        Ip::V4(_) => ip.is_local(),
        Ip::V6(_) => {
            let text = ip.render();
            let s = text.as_str();
            s == "::1"
                || matches!(
                    s.as_bytes().first().zip(s.as_bytes().get(1)),
                    Some((b'f', b'e')) | Some((b'f', b'c')) | Some((b'f', b'd'))
                )
        }
    };
    // kind bit stays 0 (== ip)
    (if local { SCOPE_LOCAL } else { SCOPE_REMOTE }) << 1
}

/// `core/meta.py:_pack()` for addresses: the raw network-order bytes.
#[inline]
fn pack_ip(ip: Ip) -> PackedIp {
    match ip {
        Ip::V4(v) => PackedIp::V4(v.to_be_bytes()),
        Ip::V6(v) => PackedIp::V6(v.to_be_bytes()),
    }
}

enum PackedIp {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl PackedIp {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            PackedIp::V4(b) => b,
            PackedIp::V6(b) => b,
        }
    }
}

/// Open the store for writing, creating and initialising it if needed. `core/meta.py:_connect()`.
fn open_rw(path: &Path) -> rusqlite::Result<Connection> {
    let con = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // See the module header: DELETE (rollback journal), never WAL.
    con.pragma_update(None, "journal_mode", "DELETE")?;
    con.pragma_update(None, "synchronous", "NORMAL")?;
    con.busy_timeout(std::time::Duration::from_millis(8000))?;
    con.execute_batch(
        "CREATE TABLE IF NOT EXISTS observables (observable, flags INTEGER, first_seen INTEGER, last_seen INTEGER, count INTEGER, PRIMARY KEY(observable)) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS meta_info (key TEXT PRIMARY KEY, value);
         INSERT OR IGNORE INTO meta_info (key, value) VALUES ('schema_version', 1);",
    )?;
    // World-readable like the daily event logs: the sensor writes this as root and the server
    // typically reads it as a non-root user.
    make_readable(path);
    Ok(con)
}

/// Make the aggregate world-readable, so a sensor dropped to an unprivileged user can read what
/// a privileged updater wrote.
///
/// Nothing to do on Windows: there is no POSIX mode there, and the ACL a file inherits from its
/// directory is what governs instead.
fn make_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o777 != 0o644 {
                perms.set_mode(0o644);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// One aggregate row as the read side sees it. `core/meta.py:lookup()`'s dict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub observable: String,
    /// `"dns"` or `"ip"`.
    pub kind: &'static str,
    /// `"local"`, `"remote"`, or `""`.
    pub scope: &'static str,
    pub first_seen: i64,
    pub last_seen: i64,
    pub count: i64,
}

/// Read side: an O(1) primary-key lookup, exactly what `/meta` performs.
///
/// This is a port of `core/meta.py:lookup()` rather than a convenience wrapper, and it exists so
/// the writer above can be tested against the semantics the server actually applies — in
/// particular the key classification, which decides whether an observable is probed as a BLOB or
/// as TEXT. Written as text, an address would be stored perfectly and found never.
pub fn lookup(db_path: &Path, observable: &str) -> Option<Observation> {
    if observable.is_empty() || !db_path.exists() {
        return None;
    }
    // Read-only, like the server: no journal sidecar is created, so this works when the file is
    // root-owned and the reader is not.
    let con = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .ok()?;
    let row = |flags: i64, first_seen: i64, last_seen: i64, count: i64| Observation {
        observable: observable.to_string(),
        kind: if flags as u8 & FLAG_DNS != 0 { "dns" } else { "ip" },
        scope: match (flags >> 1) as u8 & 0x3 {
            SCOPE_LOCAL => "local",
            SCOPE_REMOTE => "remote",
            _ => "",
        },
        first_seen,
        last_seen,
        count,
    };
    const SQL: &str = "SELECT flags, first_seen, last_seen, count FROM observables WHERE observable = ?";
    // `core/meta.py:_pack_lookup()`: an IP if it parses as one, otherwise a domain. Deliberately
    // NOT `parse_canonical_ip()` — that one additionally requires the text to be Maltrail's own
    // rendering of the address, which is right for trail keys but wrong here: a user typing
    // `2001:0db8::1` into /meta means the same address as `2001:db8::1` and must find its row.
    let parsed = if observable.contains(':') {
        crate::addr::parse_ipv6(observable).map(Ip::V6)
    } else {
        crate::addr::addr_to_int(observable).map(Ip::V4)
    };
    let found = match parsed {
        Some(ip) => {
            con.query_row(SQL, [pack_ip(ip).as_slice()], |r| Ok(row(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        }
        None => con.query_row(SQL, [observable], |r| Ok(row(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))),
    };
    found.ok()
}

/// `core/meta.py:_score()` — keep-worthiness: recurrence + longevity + mild recency.
fn score(count: f64, first_seen: f64, last_seen: f64) -> f64 {
    let span_days = (last_seen - first_seen).max(0.0) / 86400.0;
    (1.0 + count).log2() + (1.0 + span_days).log2() + last_seen / (30.0 * 86400.0)
}

/// `core/meta.py:prune()` — over budget, delete the lowest-scoring rows first.
///
/// An age cutoff cannot touch a fresh DGA burst, which is exactly the thing that fills this
/// store; scoring sheds `count = 1` zero-span junk and protects established low-and-slow
/// observables, which are the ones a retro-hunt is for. Returns the number of rows deleted.
///
/// Runs on the trail-update thread, off the packet path, like `sensor.py`'s `update_timer()`.
pub fn prune(db_path: &Path, max_rows: usize) -> rusqlite::Result<usize> {
    if !db_path.exists() {
        return Ok(0);
    }
    let con =
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    con.busy_timeout(std::time::Duration::from_millis(8000))?;
    let total: i64 = match con.query_row("SELECT COUNT(*) FROM observables", [], |r| r.get(0)) {
        Ok(n) => n,
        // No table yet: nothing has ever been flushed.
        Err(_) => return Ok(0),
    };
    let total = total.max(0) as usize;
    if total <= max_rows {
        return Ok(0);
    }
    let overflow = total - max_rows;

    con.create_scalar_function(
        "meta_score",
        3,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8 | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| Ok(score(ctx.get::<f64>(0)?, ctx.get::<f64>(1)?, ctx.get::<f64>(2)?)),
    )?;
    // WITHOUT ROWID tables have no rowid, so eviction goes by primary key.
    con.execute(
        "DELETE FROM observables WHERE observable IN (SELECT observable FROM observables ORDER BY meta_score(count, first_seen, last_seen) ASC LIMIT ?)",
        [overflow as i64],
    )?;
    // Reclaim the pages: the point of the budget is a bound on the file, not on the row count.
    con.execute_batch("VACUUM")?;
    Ok(overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ip {
        Ip::V4(u32::from_be_bytes([a, b, c, d]))
    }

    #[test]
    fn junk_filter_matches_python() {
        assert!(is_junk_ip(v4(0, 0, 0, 0)));
        assert!(is_junk_ip(v4(255, 255, 255, 255)));
        assert!(is_junk_ip(v4(239, 255, 255, 250))); // SSDP
        assert!(is_junk_ip(v4(224, 0, 0, 1)));
        assert!(!is_junk_ip(v4(223, 255, 255, 255)));
        assert!(!is_junk_ip(v4(240, 0, 0, 1)));
        assert!(!is_junk_ip(v4(8, 8, 8, 8)));
        assert!(is_junk_ip(Ip::V6(0)));
        assert!(is_junk_ip(Ip::V6(0xff02 << 112)));
        assert!(!is_junk_ip(Ip::V6(1)));
    }

    #[test]
    fn scope_flags_match_python() {
        assert_eq!(ip_flags(v4(192, 168, 0, 5)), SCOPE_LOCAL << 1);
        assert_eq!(ip_flags(v4(10, 1, 2, 3)), SCOPE_LOCAL << 1);
        assert_eq!(ip_flags(v4(172, 16, 0, 1)), SCOPE_LOCAL << 1);
        assert_eq!(ip_flags(v4(8, 8, 8, 8)), SCOPE_REMOTE << 1);
        // ::1 and the unique-local / link-local prefixes, per meta.py's own v6 rule.
        assert_eq!(ip_flags(Ip::V6(1)), SCOPE_LOCAL << 1);
        assert_eq!(ip_flags(Ip::V6(0xfe80 << 112)), SCOPE_LOCAL << 1);
        assert_eq!(ip_flags(Ip::V6(0xfd00 << 112)), SCOPE_LOCAL << 1);
        assert_eq!(ip_flags(Ip::V6(0x2001_0db8 << 96)), SCOPE_REMOTE << 1);
    }

    #[test]
    fn packing_is_four_or_sixteen_bytes() {
        assert_eq!(pack_ip(v4(8, 8, 4, 4)).as_slice(), &[8, 8, 4, 4]);
        assert_eq!(pack_ip(Ip::V6(1)).as_slice().len(), 16);
    }

    #[test]
    fn score_orders_junk_below_established() {
        // 20 days of recurrence beats a one-hit name seen a moment ago.
        let established = score(500.0, 1000.0, 1000.0 + 20.0 * 86400.0);
        let one_hit = score(1.0, 100_000.0, 100_000.0);
        assert!(established > one_hit, "{established} !> {one_hit}");
    }

    #[test]
    fn disabled_store_records_nothing() {
        let mut store = MetaStore::disabled();
        store.observe_conn(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 10);
        store.observe_dns("evil.com", 10);
        assert_eq!(store.pending(), 0);
    }

    #[test]
    fn window_cap_refuses_new_keys_but_still_bumps() {
        let mut store = MetaStore::new(PathBuf::from("/nonexistent/meta.sqlite"), 2, 60);
        store.observe_dns("a.com", 1);
        store.observe_dns("b.com", 1);
        store.observe_dns("c.com", 1); // over cap
        assert_eq!(store.pending(), 2);
        assert_eq!(store.saturations, 1);
        store.observe_dns("a.com", 2); // an existing key bumps regardless
        assert_eq!(store.names["a.com"].count, 2);
        assert_eq!(store.names["a.com"].last_seen, 2);
    }
}
