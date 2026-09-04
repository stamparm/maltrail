//! The condensed observable store, end to end (`src/meta.rs` <-> `core/meta.py`).
//!
//! The unit tests inside `src/meta.rs` cover the classification rules in isolation. These drive
//! the real packet path and then assert on the SQLite file that came out of it, because the file
//! IS the contract: `core/httpd.py` serves `/meta` by reading it with `core/meta.py:lookup()`,
//! and an operator may point the Python server at a store this sensor wrote.
//!
//! Two things are checked that a behavioural test alone would miss:
//!
//!   * the **storage class** of the key column (4/16-byte BLOB for addresses, TEXT for domains).
//!     Get this wrong and every write still succeeds, every row is present, and no lookup ever
//!     matches — a failure mode that is completely invisible from the writing side.
//!   * the **schema** itself (WITHOUT ROWID, `meta_info.schema_version`, rollback journal),
//!     which the Python reader depends on.
//!
//! `core/meta.py` reads the same store, which is what keeps the format a shared contract and
//! diffing the two stores row for row.

use std::path::Path;

use maltrail_sensor::meta::{self, MetaStore};
use maltrail_sensor::testkit::{dns_query, ipv4, tcp, udp, Harness, HarnessOptions};

/// A harness with the store switched on, writing into its own log directory.
fn harness() -> Harness {
    let mut options = HarnessOptions::quiet();
    options.extra.push("USE_CONDENSED_STORAGE true".to_string());
    Harness::with_options(&[], options)
}

fn db_of(h: &Harness) -> std::path::PathBuf {
    meta::meta_db_path(&h.log_dir())
}

fn syn(src: &str, dst: &str, sec: u64, h: &mut Harness) {
    let packet = ipv4(6, src, dst, &tcp(12345, 80, 0x02, b""));
    h.feed_ip(&packet, sec);
}

fn query(name: &str, sec: u64, h: &mut Harness) {
    let packet = ipv4(17, "192.168.0.5", "8.8.8.8", &udp(33333, 53, &dns_query(name, 1, 1, 0x0100)));
    h.feed_ip(&packet, sec);
}

/// One row's raw storage class and byte length, straight from SQLite.
fn key_typeof(db: &Path, sql_where: &str) -> Vec<(String, i64)> {
    let con = rusqlite::Connection::open(db).expect("open store");
    let mut stmt = con
        .prepare(&format!("SELECT typeof(observable), length(observable) FROM observables WHERE {sql_where}"))
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    rows
}

#[test]
fn switched_off_by_default_writes_nothing() {
    // The stock harness config has USE_CONDENSED_STORAGE false.
    let mut h = Harness::new(&[]);
    syn("192.168.0.5", "8.8.8.8", 100, &mut h);
    query("evil.com", 100, &mut h);
    assert!(!h.state.meta.is_enabled());
    assert_eq!(h.state.meta.pending(), 0);
    assert!(!db_of(&h).exists(), "no store file may be created when the switch is off");
}

#[test]
fn both_endpoints_and_the_queried_name_are_recorded() {
    let mut h = harness();
    syn("192.168.0.5", "8.8.8.8", 100, &mut h);
    query("evil.com", 100, &mut h);
    h.state.meta.flush();

    let db = db_of(&h);
    let src = meta::lookup(&db, "192.168.0.5").expect("source endpoint");
    let dst = meta::lookup(&db, "8.8.8.8").expect("destination endpoint");
    let name = meta::lookup(&db, "evil.com").expect("queried name");

    assert_eq!(src.kind, "ip");
    assert_eq!(src.scope, "local");
    assert_eq!(dst.kind, "ip");
    assert_eq!(dst.scope, "remote");
    assert_eq!(name.kind, "dns");
    assert_eq!(name.count, 1);
    assert_eq!(name.first_seen, 100);
}

#[test]
fn addresses_are_packed_blobs_and_domains_stay_text() {
    let mut h = harness();
    syn("8.8.4.4", "1.1.1.1", 100, &mut h);
    let v6 = maltrail_sensor::testkit::ipv6(6, "2001:db8::1", "2001:db8::2", &tcp(1, 2, 0x02, b""));
    h.feed_ip(&v6, 100);
    query("evil.com", 100, &mut h);
    h.state.meta.flush();

    let db = db_of(&h);
    // 8.8.4.4 and 1.1.1.1, plus the two endpoints the DNS packet itself carries.
    assert_eq!(key_typeof(&db, "flags & 1 = 0 AND length(observable) = 4").len(), 4, "four IPv4 rows");
    assert_eq!(key_typeof(&db, "flags & 1 = 0 AND length(observable) = 16").len(), 2, "two IPv6 rows");
    for (class, _) in key_typeof(&db, "flags & 1 = 0") {
        assert_eq!(class, "blob", "addresses must be stored as BLOBs");
    }
    assert_eq!(key_typeof(&db, "flags & 1 = 1"), vec![("text".to_string(), 8)], "evil.com as TEXT");

    // And the whole point of the encoding: a lookup by printable form finds the row.
    for probe in ["8.8.4.4", "1.1.1.1", "2001:db8::1", "2001:db8::2", "evil.com"] {
        assert!(meta::lookup(&db, probe).is_some(), "{probe} must be findable");
    }
}

#[test]
fn schema_matches_the_python_reader() {
    let mut h = harness();
    query("evil.com", 100, &mut h);
    h.state.meta.flush();

    let con = rusqlite::Connection::open(db_of(&h)).expect("open store");
    let ddl: String = con
        .query_row("SELECT sql FROM sqlite_master WHERE name = 'observables'", [], |r| r.get(0))
        .expect("observables table");
    assert!(ddl.contains("WITHOUT ROWID"), "{ddl}");
    assert!(ddl.contains("PRIMARY KEY(observable)"), "{ddl}");

    let version: i64 = con
        .query_row("SELECT value FROM meta_info WHERE key = 'schema_version'", [], |r| r.get(0))
        .expect("schema_version");
    assert_eq!(version, 1);

    // NOT WAL: the server reads this as a non-root user and cannot create the -shm sidecar.
    let journal: String = con.query_row("PRAGMA journal_mode", [], |r| r.get(0)).expect("journal_mode");
    assert_eq!(journal.to_lowercase(), "delete");

    // World-readable for the same uid-split reason as the daily event logs. Windows has no mode
    // to assert - the store inherits its directory's ACL there.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(db_of(&h)).expect("stat store").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "store must be readable by the (non-root) server");
    }
}

#[test]
fn counts_sum_and_bounds_widen_across_out_of_order_flushes() {
    // Two flushes stand in for two workers merging into one file. The second carries an EARLIER
    // window, which is what makes MIN(first_seen) rather than "whatever arrived first" necessary.
    let mut h = harness();
    syn("192.168.0.5", "8.8.8.8", 200, &mut h);
    syn("192.168.0.6", "8.8.8.8", 250, &mut h);
    h.state.meta.flush();
    syn("192.168.0.7", "8.8.8.8", 50, &mut h);
    h.state.meta.flush();

    let row = meta::lookup(&db_of(&h), "8.8.8.8").expect("merged row");
    assert_eq!(row.count, 3, "counts add across flushes");
    assert_eq!(row.first_seen, 50, "MIN even when the earlier window is flushed later");
    assert_eq!(row.last_seen, 250, "MAX");
}

#[test]
fn a_flush_empties_the_window() {
    let mut h = harness();
    query("a.com", 1, &mut h);
    assert_eq!(h.state.meta.pending(), 3); // a.com + both endpoints of the query packet
    h.state.meta.flush();
    assert_eq!(h.state.meta.pending(), 0);
    // A second flush with nothing pending must not fail or duplicate anything.
    h.state.meta.flush();
    assert_eq!(meta::lookup(&db_of(&h), "a.com").expect("a.com").count, 1);
}

#[test]
fn broadcast_and_multicast_never_get_a_row() {
    let mut h = harness();
    syn("0.0.0.0", "255.255.255.255", 10, &mut h);
    syn("192.168.0.9", "239.255.255.250", 10, &mut h); // SSDP
    h.state.meta.flush();

    let db = db_of(&h);
    for junk in ["0.0.0.0", "255.255.255.255", "239.255.255.250"] {
        assert!(meta::lookup(&db, junk).is_none(), "{junk} must be filtered");
    }
    assert!(meta::lookup(&db, "192.168.0.9").is_some(), "the real endpoint survives");
}

#[test]
fn prune_sheds_junk_and_keeps_established_observables() {
    // Mirrors tests/test_meta.py:TestSmartPrune — 20 recurring, long-lived names against 200
    // one-hit DGA names, pruned to a budget of 50.
    let dir = std::env::temp_dir().join(format!("maltrail-meta-prune-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    let db = dir.join("meta.sqlite");

    let mut store = MetaStore::new(db.clone(), 100_000, 60);
    for i in 0..20 {
        let name = format!("good-{i}.net");
        // 500 sightings spread over 20 days.
        for k in 0..500 {
            store.observe_dns(&name, 1000 + (k * 20 * 86400 / 499));
        }
    }
    for i in 0..200 {
        store.observe_dns(&format!("dga-{i}.xyz"), 100_000 + i);
    }
    store.flush();

    let deleted = meta::prune(&db, 50).expect("prune");
    assert_eq!(deleted, 170, "220 rows pruned to a budget of 50");

    let survivors = (0..20).filter(|i| meta::lookup(&db, &format!("good-{i}.net")).is_some()).count();
    assert_eq!(survivors, 20, "every established observable must survive");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prune_is_a_no_op_under_budget_and_on_a_missing_store() {
    let dir = std::env::temp_dir().join(format!("maltrail-meta-nop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    let db = dir.join("meta.sqlite");

    // Never written: nothing to prune, and no file must be created by asking.
    assert_eq!(meta::prune(&db, 10).expect("missing store"), 0);
    assert!(!db.exists());

    let mut store = MetaStore::new(db.clone(), 100_000, 60);
    store.observe_dns("a.com", 1);
    store.flush();
    assert_eq!(meta::prune(&db, 10).expect("under budget"), 0);
    assert!(meta::lookup(&db, "a.com").is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lookup_accepts_any_spelling_of_an_address() {
    let dir = std::env::temp_dir().join(format!("maltrail-meta-spelling-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    let db = dir.join("meta.sqlite");

    let mut store = MetaStore::new(db.clone(), 100_000, 60);
    store.observe_conn(
        maltrail_sensor::addr::Ip::V6(0x2001_0db8_u128 << 96 | 1),
        maltrail_sensor::addr::Ip::V4(u32::from_be_bytes([8, 8, 8, 8])),
        10,
    );
    store.flush();

    // `/meta?observable=...` is typed by a human. Python's reader packs whatever inet_pton
    // accepts, so the expanded form has to resolve to the same row as the compressed one.
    assert!(meta::lookup(&db, "2001:db8::1").is_some());
    assert!(meta::lookup(&db, "2001:0db8:0000:0000:0000:0000:0000:0001").is_some());
    assert!(meta::lookup(&db, "8.8.8.8").is_some());
    assert!(meta::lookup(&db, "8.8.8.9").is_none());
    assert!(meta::lookup(&db, "not-an-address").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_workers_merge_into_one_file_without_losing_a_count() {
    // The Python sensor's workers are processes; these are threads in one process, so several
    // `MetaStore`s really do contend for the same file at the same instant. Every flush must
    // either land whole or fail loudly — a silently dropped window would show up as an
    // undercounted observable, which is invisible unless something checks the arithmetic.
    const WORKERS: u64 = 8;
    const PER_WORKER: u64 = 50;

    let dir = std::env::temp_dir().join(format!("maltrail-meta-concurrent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");
    let db = dir.join("meta.sqlite");

    let mut handles = Vec::new();
    for worker in 0..WORKERS {
        let db = db.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = MetaStore::new(db, 100_000, 60);
            for round in 0..PER_WORKER {
                // One name every worker touches, plus one only this worker touches.
                store.observe_dns("shared.example.net", 1000 + round);
                store.observe_dns(&format!("worker-{worker}.example.net"), 1000 + round);
                if round % 10 == 9 {
                    store.flush();
                }
            }
            store.flush();
            store.flush_errors
        }));
    }
    let errors: u64 = handles.into_iter().map(|h| h.join().expect("worker thread")).sum();
    assert_eq!(errors, 0, "no flush may fail under contention");

    let shared = meta::lookup(&db, "shared.example.net").expect("shared row");
    assert_eq!(shared.count as u64, WORKERS * PER_WORKER, "every sighting is accounted for");
    assert_eq!(shared.first_seen, 1000);
    assert_eq!(shared.last_seen as u64, 1000 + PER_WORKER - 1);
    for worker in 0..WORKERS {
        let row = meta::lookup(&db, &format!("worker-{worker}.example.net")).expect("per-worker row");
        assert_eq!(row.count as u64, PER_WORKER);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failing_flush_does_not_take_the_sensor_down() {
    // The log directory is gone (a mount that vanished, a disk gone read-only). The window is
    // lost and counted; nothing panics and the sensor keeps processing packets.
    let mut store = MetaStore::new(std::path::PathBuf::from("/nonexistent-dir/meta.sqlite"), 100_000, 60);
    store.observe_dns("a.com", 1);
    store.flush();
    assert_eq!(store.flush_errors, 1);
    assert_eq!(store.pending(), 0, "the window is dropped, not retried into an unbounded backlog");
    store.observe_dns("b.com", 2);
    assert_eq!(store.pending(), 1, "and the store keeps accepting observations");
}
