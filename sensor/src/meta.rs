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
//! an operator may run the Maltrail server against a store this sensor wrote (that is the whole
//! point of writing it). So the schema, the key encoding and the journal mode are all fixed by
//! `core/meta.py` and reproduced exactly:
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
//! * Flushes append to `observables_delta` (same columns, plain rowid table, indexed on
//!   `observable`), which is folded into `observables` past `DELTA_MAX_ROWS`, on each prune and on a
//!   clean shutdown. Readers combine both. The table is additive: a store from before it gains it
//!   on the first flush, and an older reader that ignores it only sees counts as of the last fold.
//!
//! # Concurrency
//!
//! Each worker owns a `MetaStore` and fills it lock-free on the packet path. Draining it is NOT
//! done on the worker: the write took 0.6-0.7 s at 200k keys on NVMe (more on an SD card, plus
//! up to `busy_timeout` waiting on another writer), and a capture thread that stops draining for
//! that long overflows its ring. A worker hands its window to one writer thread instead
//! (`writer()`) and goes back to capturing. Windows arrive out of order, which the merge's
//! `MIN`/`MAX` exist for. Counts are best-effort under a crash.
//!
//! # Cost
//!
//! The packet path does one bump per endpoint and one per DNS name, keyed by the *native* `Ip` —
//! no address is rendered to text until a key is first inserted, and never on a repeat sighting.
//! An IPv4 endpoint seen recently is found through `Recent`, a direct-mapped array, and only
//! otherwise through the map: the two map lookups were 161 of the 1,131 instructions an ICMP
//! echo cost (callgrind, refnet's ICMP), and are ~55 this way. Everything else happens once a
//! minute, off the packet path.

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
        // last_seen is assigned unconditionally rather than taking a max: within one worker the
        // packet clock only moves forward, and the max is applied in SQL where windows really can arrive out of order.
        self.last_seen = sec;
        self.count += 1;
    }
}

/// Per-worker aggregate plus everything needed to drain it.
pub struct MetaStore {
    enabled: bool,
    db_path: PathBuf,
    /// The window's addresses and their rows, in the order first seen; `index` finds one.
    ips: Vec<(Ip, Row)>,
    index: FastMap<Ip, u32>,
    recent: Recent,
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

/// Where recently seen IPv4 addresses are in `MetaStore::ips`: direct-mapped, by a multiplicative
/// hash of the address, so finding one is a multiply, one load and a compare. A slot holds the
/// address and its position plus one (0: empty), and a newer address simply takes the slot over;
/// whatever is not here is in `index`. 8 KB, cleared with the window it points into.
struct Recent(Box<[(u32, u32); RECENT_SLOTS]>);

const RECENT_SLOTS: usize = 1024;

impl Recent {
    fn new() -> Recent {
        Recent(Box::new([(0, 0); RECENT_SLOTS]))
    }

    #[inline]
    fn slot(v4: u32) -> usize {
        (u64::from(v4).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - RECENT_SLOTS.trailing_zeros())) as usize
    }

    #[inline]
    fn get(&self, v4: u32) -> Option<usize> {
        let (addr, at) = self.0[Recent::slot(v4)];
        (at != 0 && addr == v4).then(|| at as usize - 1)
    }

    #[inline]
    fn set(&mut self, v4: u32, at: usize) {
        self.0[Recent::slot(v4)] = (v4, at as u32 + 1);
    }

    fn clear(&mut self) {
        self.0.fill((0, 0));
    }
}

/// What became of one store's windows, written by the writer thread.
#[derive(Default)]
struct FlushResults {
    flushed: AtomicU64,
    /// The in-RAM window is lost when a flush fails.
    errors: AtomicU64,
}

/// One drained window on its way to the writer, or a request to say when it has caught up.
enum Job {
    /// `fold`: also merge the delta table into `observables` (on the way out, and in tests).
    Write {
        db_path: PathBuf,
        ips: Vec<(Ip, Row)>,
        names: StrMap<String, Row>,
        fold: bool,
        results: Arc<FlushResults>,
    },
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
                        Job::Write { db_path, ips, names, fold, results } => {
                            let rows = (ips.len() + names.len()) as u64;
                            match write(&db_path, &ips, &names, fold) {
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
            ips: Vec::new(),
            index: FastMap::default(),
            recent: Recent::new(),
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
        if let Ip::V4(v4) = ip {
            if let Some(at) = self.recent.get(v4) {
                self.ips[at].1.bump(sec);
                return;
            }
        }
        self.observe_ip_slow(ip, sec);
    }

    /// Not in `recent`: the map, and a new row if the address is new.
    #[inline(never)]
    fn observe_ip_slow(&mut self, ip: Ip, sec: u64) {
        let at = if let Some(&at) = self.index.get(&ip) {
            let at = at as usize;
            self.ips[at].1.bump(sec);
            at
        } else {
            if is_junk_ip(ip) {
                return;
            }
            if self.pending() >= self.max_window_keys {
                self.saturations += 1;
                return;
            }
            let at = self.ips.len();
            self.ips.push((ip, Row::new(ip_flags(ip), sec)));
            self.index.insert(ip, at as u32);
            at
        };
        if let Ip::V4(v4) = ip {
            self.recent.set(v4, at);
        }
    }

    /// The window's address rows, leaving it empty.
    fn take_ips(&mut self) -> Vec<(Ip, Row)> {
        self.index.clear();
        self.recent.clear();
        std::mem::take(&mut self.ips)
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
        let ips = self.take_ips();
        let names = std::mem::take(&mut self.names);
        let rows = (ips.len() + names.len()) as u64;
        let job = Job::Write { db_path: self.db_path.clone(), ips, names, fold: false, results: self.results.clone() };
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
        // Sent even when the window is empty: it also folds the delta table, so a clean stop
        // leaves every row in `observables`.
        let ips = self.take_ips();
        let names = std::mem::take(&mut self.names);
        let job = Job::Write { db_path: self.db_path.clone(), ips, names, fold: true, results: self.results.clone() };
        // Blocking here is right: nothing is capturing any more, and this window is the tail.
        let tx = match writer().lock() {
            Ok(tx) => tx.clone(),
            Err(_) => return,
        };
        let _ = tx.send(job);
        let (done, wait) = mpsc::channel();
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

/// Rows the delta table may hold before a flush folds it into `observables`. Bounds the extra file
/// size (~50 B per row with its index) and the rows a lookup aggregates; a fold costs about twice
/// the file whatever the delta holds, so the larger this is the rarer that cost.
const DELTA_MAX_ROWS: i64 = 500_000;

const FOLD_SQL: &str = "INSERT INTO observables (observable, flags, first_seen, last_seen, count) \
     SELECT observable, MAX(flags), MIN(first_seen), MAX(last_seen), SUM(count) FROM observables_delta WHERE true GROUP BY observable \
     ON CONFLICT(observable) DO UPDATE SET first_seen = MIN(first_seen, excluded.first_seen), \
     last_seen = MAX(last_seen, excluded.last_seen), count = count + excluded.count; \
     DELETE FROM observables_delta;";

/// One window into SQLite, as a single transaction.
///
/// The window is APPENDED to `observables_delta`, not upserted into `observables`. Upserting
/// rewrote every 4 KB page a changed row sat on, twice (journal + file): on tripice 371 changed
/// rows, ~9 KB of data, cost 2.8 MB per flush, and at the 2M-row cap a flush cost ~2x the file
/// (76 MB) whatever it held. Appended, the same window is 0.16 MB. The pages are rewritten once
/// per fold instead of once per flush.
fn write(db_path: &Path, ips: &[(Ip, Row)], names: &StrMap<String, Row>, fold: bool) -> rusqlite::Result<()> {
    let mut con = open_rw(db_path)?;
    // IMMEDIATE, not the default DEFERRED: this transaction only ever writes, and taking the
    // reserved lock up front is what lets `busy_timeout` do its job. A deferred transaction
    // that upgrades from read to write mid-way can be handed SQLITE_BUSY without the busy
    // handler being consulted at all, because SQLite cannot rule out a deadlock — which with
    // a server pruning the same file would show up as sporadic lost windows.
    let tx = con.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    {
        let mut append = tx.prepare_cached(
            "INSERT INTO observables_delta (observable, flags, first_seen, last_seen, count) VALUES (?, ?, ?, ?, ?)",
        )?;
        for (ip, row) in ips {
            let key = pack_ip(*ip);
            append.execute(rusqlite::params![
                key.as_slice(),
                row.flags,
                row.first_seen as i64,
                row.last_seen as i64,
                row.count as i64
            ])?;
        }
        for (name, row) in names {
            append.execute(rusqlite::params![
                name,
                row.flags,
                row.first_seen as i64,
                row.last_seen as i64,
                row.count as i64
            ])?;
        }
    }
    // MAX(rowid) is a B-tree edge read, and the table is emptied by every fold, so it is the row count.
    let held: i64 = tx.query_row("SELECT IFNULL(MAX(rowid), 0) FROM observables_delta", [], |r| r.get(0))?;
    if fold || held > DELTA_MAX_ROWS {
        tx.execute_batch(FOLD_SQL)?;
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
         CREATE TABLE IF NOT EXISTS observables_delta (observable, flags INTEGER, first_seen INTEGER, last_seen INTEGER, count INTEGER);
         CREATE INDEX IF NOT EXISTS observables_delta_key ON observables_delta (observable);
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
    // The main row and the not-yet-folded delta rows, combined the way a fold would combine them.
    // A store from before the delta table has only `observables`, and gets the original query.
    const SQL: &str = "SELECT MAX(flags), MIN(first_seen), MAX(last_seen), SUM(count) FROM ( \
        SELECT flags, first_seen, last_seen, count FROM observables WHERE observable = ?1 \
        UNION ALL SELECT flags, first_seen, last_seen, count FROM observables_delta WHERE observable = ?1) HAVING COUNT(*) > 0";
    const SQL_V1: &str = "SELECT flags, first_seen, last_seen, count FROM observables WHERE observable = ?1";
    let has_delta =
        con.query_row("SELECT 1 FROM sqlite_master WHERE name = 'observables_delta'", [], |_| Ok(())).is_ok();
    let sql = if has_delta { SQL } else { SQL_V1 };
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
            con.query_row(sql, [pack_ip(ip).as_slice()], |r| Ok(row(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        }
        None => con.query_row(sql, [observable], |r| Ok(row(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))),
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
/// Runs on the trail-update thread, off the packet path.
pub fn prune(db_path: &Path, max_rows: usize) -> rusqlite::Result<usize> {
    if !db_path.exists() {
        return Ok(0);
    }
    let con =
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    con.busy_timeout(std::time::Duration::from_millis(8000))?;
    // Fold first (runs once per trail update): the budget is on all rows, and this is what keeps a
    // quiet sensor's delta table from growing towards DELTA_MAX_ROWS over weeks.
    if con.query_row("SELECT 1 FROM sqlite_master WHERE name = 'observables_delta'", [], |_| Ok(())).is_ok() {
        con.execute_batch(&format!("BEGIN IMMEDIATE; {FOLD_SQL} COMMIT;"))?;
    }
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

    fn scratch_db(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mt-meta-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("meta.sqlite")
    }

    fn window(names: &[(&str, u64, u64, u64)]) -> StrMap<String, Row> {
        let mut map = StrMap::default();
        for &(name, first, last, count) in names {
            map.insert(name.to_string(), Row { flags: FLAG_DNS, first_seen: first, last_seen: last, count });
        }
        map
    }

    fn rows_in(db: &Path, table: &str) -> i64 {
        Connection::open(db).unwrap().query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_store_from_before_the_delta_table_is_read_upgraded_and_folded() {
        let db = scratch_db("upgrade");
        // Exactly what every existing install has on disk: observables + meta_info, no delta table.
        let con = Connection::open(&db).unwrap();
        con.execute_batch(
            "PRAGMA journal_mode=DELETE;
             CREATE TABLE observables (observable, flags INTEGER, first_seen INTEGER, last_seen INTEGER, count INTEGER, PRIMARY KEY(observable)) WITHOUT ROWID;
             CREATE TABLE meta_info (key TEXT PRIMARY KEY, value);
             INSERT INTO meta_info VALUES ('schema_version', 1);
             INSERT INTO observables VALUES ('evil.com', 1, 100, 200, 5);",
        )
        .unwrap();
        drop(con);
        let got = lookup(&db, "evil.com").expect("old store reads");
        assert_eq!((got.first_seen, got.last_seen, got.count), (100, 200, 5));

        // A flush appends: observables is not touched, the lookup combines both.
        write(&db, &[], &window(&[("evil.com", 50, 300, 2), ("new.com", 400, 400, 1)]), false).unwrap();
        assert_eq!(rows_in(&db, "observables"), 1);
        assert_eq!(rows_in(&db, "observables_delta"), 2);
        let got = lookup(&db, "evil.com").unwrap();
        assert_eq!((got.first_seen, got.last_seen, got.count, got.kind), (50, 300, 7, "dns"));
        let got = lookup(&db, "new.com").unwrap();
        assert_eq!((got.first_seen, got.last_seen, got.count), (400, 400, 1));
        assert!(lookup(&db, "other.com").is_none());

        // Prune folds even under budget, and the answers do not change.
        assert_eq!(prune(&db, 1_000_000).unwrap(), 0);
        assert_eq!(rows_in(&db, "observables_delta"), 0);
        assert_eq!(rows_in(&db, "observables"), 2);
        let got = lookup(&db, "evil.com").unwrap();
        assert_eq!((got.first_seen, got.last_seen, got.count), (50, 300, 7));
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
    }

    #[test]
    fn a_flush_folds_on_request_and_past_the_delta_cap() {
        let db = scratch_db("fold");
        write(&db, &[], &window(&[("a.com", 1, 1, 1)]), false).unwrap();
        assert_eq!((rows_in(&db, "observables"), rows_in(&db, "observables_delta")), (0, 1));
        write(&db, &[], &window(&[("a.com", 2, 2, 1)]), true).unwrap();
        assert_eq!((rows_in(&db, "observables"), rows_in(&db, "observables_delta")), (1, 0));
        // Past the cap the delta folds by itself. MAX(rowid) is the trigger, so jump it there.
        Connection::open(&db)
            .unwrap()
            .execute("INSERT INTO observables_delta (rowid, observable, flags, first_seen, last_seen, count) VALUES (?, 'b.com', 1, 3, 3, 1)", [DELTA_MAX_ROWS])
            .unwrap();
        write(&db, &[], &window(&[("c.com", 4, 4, 1)]), false).unwrap();
        assert_eq!((rows_in(&db, "observables"), rows_in(&db, "observables_delta")), (3, 0));
        assert_eq!(lookup(&db, "a.com").unwrap().count, 2);
        let _ = std::fs::remove_dir_all(db.parent().unwrap());
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
    /// `Recent` is a shortcut only: every row must come out exactly as a plain map keyed by the
    /// address makes it - times, count, flags, and every refusal at the cap - with slots taken
    /// over by colliding addresses, and across windows, whose rows the slots no longer point at.
    #[test]
    fn rows_match_a_plain_map_whatever_the_recent_slots_hold() {
        let mut state = 0x853c_49e6_748f_ea9bu64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let mut shortcuts = 0usize;
        for (cap, pool) in [(10usize, 40u64), (5_000, 3_000), (100_000, 20)] {
            let mut store = MetaStore::new(PathBuf::from("/nonexistent/meta.sqlite"), cap, 60);
            for window in 0..3 {
                let mut reference: std::collections::HashMap<Ip, (u64, u64, u64)> = Default::default();
                let mut refused = 0;
                for sec in 1..30_000u64 {
                    // a pool larger than RECENT_SLOTS in one case, so slots are taken over;
                    // 0.0.0.0 (junk) and IPv6, which never uses the slots, are in every pool
                    let ip = match next(pool + 2) {
                        0 => v4(0, 0, 0, 0),
                        1 => Ip::V6(u128::from(next(4)) << 100),
                        n => Ip::V4(0x0a00_0000 + n as u32 * 7919),
                    };
                    let hit = matches!(ip, Ip::V4(a) if store.recent.get(a).is_some());
                    shortcuts += usize::from(hit);
                    store.observe_ip(ip, sec);
                    if let Some(r) = reference.get_mut(&ip) {
                        r.1 = sec;
                        r.2 += 1;
                    } else if !is_junk_ip(ip) {
                        if reference.len() >= cap {
                            refused += 1;
                        } else {
                            reference.insert(ip, (sec, sec, 1));
                        }
                    }
                }
                assert_eq!(store.saturations, refused, "cap {cap} window {window}");
                store.saturations = 0;
                let rows = store.take_ips();
                assert_eq!(rows.len(), reference.len());
                for (ip, row) in &rows {
                    let (first, last, count) = reference[ip];
                    assert_eq!(
                        (row.first_seen, row.last_seen, row.count, row.flags),
                        (first, last, count, ip_flags(*ip))
                    );
                }
                assert!(cap > 1_000 || refused > 0, "cap {cap} never reached");
            }
        }
        // not vacuous: the slots answered most sightings
        assert!(shortcuts > 100_000, "{shortcuts}");
    }
}
