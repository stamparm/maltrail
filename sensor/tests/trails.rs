//! Trail-loading tests, including against a real trails file (`$MALTRAIL_TRAILS`, default
//! `~/.maltrail/trails.csv`) when one is present — skipped with a printed note otherwise, so a
//! machine without trails still passes. The `real trail set` CI job builds one with
//! `sensor/tools/update_trails.py --offline` so those tests are not operator-only.
//!
//! Anything they assert that must hold *everywhere* — above all the trail store's
//! no-false-negative invariant — has a generated-at-scale counterpart here that needs no trails
//! file at all: see `the_negative_filter_never_hides_a_key_at_real_scale`.

use std::path::PathBuf;

use maltrail_sensor::addr::{addr_to_int, parse_ipv6, Ip};
use maltrail_sensor::trails;
use maltrail_sensor::whitelist::Whitelist;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// A private SNAPSHOT of the operator's trails file — `$MALTRAIL_TRAILS` when set, otherwise
/// `~/.maltrail/trails.csv` (the same knob `tools/check.sh` uses for its real-trails parity step).
///
/// These tests read the file more than once — build the store from it, then walk its rows to
/// check each is findable. A running sensor refreshes that same file and installs the new one
/// with `rename()`, so the two reads can legitimately land on different generations, and the
/// test then reports rows "missing" that are simply from the newer file. Observed exactly that:
/// a green suite, a red one moments later, and nothing wrong with the loader.
///
/// Copy once, use the copy for every read. The copy is per-process and cleaned up on drop.
fn real_trails_file() -> Option<PathBuf> {
    use std::sync::OnceLock;
    static SNAPSHOT: OnceLock<Option<PathBuf>> = OnceLock::new();
    SNAPSHOT
        .get_or_init(|| {
            let live = match std::env::var("MALTRAIL_TRAILS") {
                Ok(explicit) if !explicit.is_empty() => PathBuf::from(explicit),
                _ => PathBuf::from(std::env::var("HOME").ok()?).join(".maltrail").join("trails.csv"),
            };
            if !live.is_file() {
                return None;
            }
            let dir = std::env::temp_dir().join(format!("mt-trails-snapshot-{}", std::process::id()));
            std::fs::create_dir_all(&dir).ok()?;
            let snapshot = dir.join("trails.csv");
            // A rename under us during the copy still yields ONE self-consistent generation:
            // the open file handle keeps reading the inode it started with.
            std::fs::copy(&live, &snapshot).ok()?;
            Some(snapshot)
        })
        .clone()
}

fn temp_csv(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("mt-trails-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn loads_every_trail_shape() {
    let path = temp_csv(
        "shapes.csv",
        "evil.com,malware (test),(static)\n\
         1.2.3.4,badnet,(static)\n\
         1.2.3.4:8443,c2,(static)\n\
         dead::beef,badnet6,(static)\n\
         [dead::beef]:443,c26,(static)\n\
         /malicious.php,malware (test),(static)\n\
         host.example/bad/path,malware (test),(static)\n\
         bareword,malware (test),(static)\n\
         \"quoted,comma.com\",\"info, with comma\",(static)\n\
         dga[0-9]+\\.example\\.com,malware (test),(static)\n",
    );
    let wl = Whitelist::default();
    let (db, stats) = trails::load(&path, &wl).unwrap();

    assert_eq!(stats.loaded, 10);
    assert_eq!(stats.malformed, 0);
    assert_eq!(db.len(), 10);

    assert_eq!(db.get("evil.com").unwrap().info, "malware (test)");
    assert_eq!(db.get("/malicious.php").unwrap().reference, "(static)");
    assert_eq!(db.get("host.example/bad/path").unwrap().info, "malware (test)");
    assert_eq!(db.get("bareword").unwrap().info, "malware (test)");
    assert_eq!(db.get("quoted,comma.com").unwrap().info, "info, with comma");

    let v4 = Ip::V4(addr_to_int("1.2.3.4").unwrap());
    assert_eq!(db.get_ip(v4).unwrap().info, "badnet");
    assert_eq!(db.get_ip_port(v4, 8443).unwrap().info, "c2");
    let v6 = Ip::V6(parse_ipv6("dead::beef").unwrap());
    assert_eq!(db.get_ip(v6).unwrap().info, "badnet6");
    assert_eq!(db.get_ip_port(v6, 443).unwrap().info, "c26");

    // the wildcard trail is compiled into the regex fallback, not matched literally
    assert_eq!(db.regex().len(), 1);
    let hit = db.regex().find("dga42.example.com").expect("wildcard match");
    assert_eq!(hit.candidate, "dga[0-9]+\\.example\\.com");
}

#[test]
fn whitelisted_trails_are_dropped_at_load() {
    let path = temp_csv(
        "whitelisted.csv",
        "127.0.0.1,should be dropped,(static)\n\
         localhost,should be dropped,(static)\n\
         66.66.66.66,kept,(static)\n",
    );
    let wl = Whitelist::load(&repo_root(), None);
    let (db, stats) = trails::load(&path, &wl).unwrap();
    assert!(stats.whitelisted >= 2, "{stats:?}", stats = (stats.loaded, stats.whitelisted));
    assert!(db.get("127.0.0.1").is_none());
    assert!(db.get("localhost").is_none());
    assert_eq!(db.get("66.66.66.66").unwrap().info, "kept");
}

#[test]
fn malformed_rows_are_counted_not_fatal() {
    let path = temp_csv(
        "malformed.csv",
        "good.com,info,(static)\n\
         two,columns\n\
         four,columns,here,extra\n\
         \n\
         another.com,info,(static)\n",
    );
    let (db, stats) = trails::load(&path, &Whitelist::default()).unwrap();
    assert_eq!(stats.loaded, 2);
    assert_eq!(stats.malformed, 2);
    assert!(db.contains("good.com") && db.contains("another.com"));
}

#[test]
fn a_missing_trails_file_yields_an_empty_store() {
    let (db, stats) = trails::load(&PathBuf::from("/nonexistent/trails.csv"), &Whitelist::default()).unwrap();
    assert!(db.is_empty());
    assert_eq!(stats.rows, 0);
}

#[test]
fn pairs_are_interned_across_trails() {
    let mut content = String::new();
    for i in 0..5000 {
        content.push_str(&format!("host{i}.example,shared info,(static)\n"));
    }
    let path = temp_csv("interned.csv", &content);
    let (db, _) = trails::load(&path, &Whitelist::default()).unwrap();
    assert_eq!(db.len(), 5000);
    // 5000 trails sharing one (info, reference) pair must not cost 5000 copies of it
    let per_trail = db.memory_bytes() / 5000;
    assert!(per_trail < 200, "{per_trail} bytes per trail is too much");
}

#[test]
fn real_trails_file_loads_completely() {
    let Some(path) = real_trails_file() else {
        println!("[skip] no real trails file ($MALTRAIL_TRAILS or ~/.maltrail/trails.csv) on this machine");
        return;
    };
    let wl = Whitelist::load(&repo_root(), None);
    let started = std::time::Instant::now();
    let (db, stats) = trails::load(&path, &wl).expect("real trails must load");
    let elapsed = started.elapsed();

    println!(
        "[i] {} rows -> {} trails ({} whitelisted, {} malformed) in {:.2}s, {:.1} MB, \
         ipv4={} ipv4:port={} ipv6={} wildcard={}",
        stats.rows,
        stats.loaded,
        stats.whitelisted,
        stats.malformed,
        elapsed.as_secs_f64(),
        db.memory_bytes() as f64 / (1024.0 * 1024.0),
        db.ip4_count(),
        db.ip4_port_count(),
        db.ip6_count(),
        db.regex().len()
    );

    assert!(stats.loaded > 100_000, "expected a sizeable trail set, got {}", stats.loaded);
    assert_eq!(db.len(), stats.loaded);
    // every row is either loaded, whitelisted or malformed
    assert_eq!(stats.rows, stats.loaded + stats.whitelisted + stats.malformed);
    assert!(db.ip4_count() > 1000, "IPv4 trails should be mirrored natively");
    // Some real feed entries ship TRUNCATED regex trails (unbalanced groups) that CPython
    // rejects too - build_trails_regex() drops those on both sides. The agreement itself is
    // asserted from Python-generated vectors in tests/vectors.rs; here we only guard against a
    // systematic engine gap.
    let skipped = db.regex().skipped();
    println!("[i] wildcard trails skipped as uncompilable: {}", skipped.len());
    assert!(
        skipped.len() <= 5,
        "too many wildcard trails rejected ({}), suspect an engine gap: {:?}",
        skipped.len(),
        skipped
    );
    // the wildcard regex must actually be usable
    if !db.regex().is_empty() {
        let _ = db.regex().find("this.is.a.probe.example.com");
    }
}

#[test]
fn real_trails_lookups_agree_between_native_and_text_paths() {
    let Some(path) = real_trails_file() else {
        println!("[skip] no real trails file ($MALTRAIL_TRAILS or ~/.maltrail/trails.csv) on this machine");
        return;
    };
    let wl = Whitelist::load(&repo_root(), None);
    let (db, _) = trails::load(&path, &wl).unwrap();

    // Sample the CSV and check that every canonical IPv4 / IPv4:port trail answers through
    // BOTH the native table and the string table with the same value.
    let text = std::fs::read_to_string(&path).unwrap();
    let mut checked = 0usize;
    for line in text.lines().take(200_000) {
        let mut it = line.splitn(3, ',');
        let Some(trail) = it.next() else { continue };
        if wl.check_whitelisted(trail) {
            continue;
        }
        if let Some(ip) = maltrail_sensor::addr::parse_canonical_ip(trail) {
            let native = db.get_ip(ip);
            let textual = db.get(trail);
            assert_eq!(native, textual, "native/text mismatch for {trail}");
            checked += 1;
        } else if let Some((addr, port)) = trail.rsplit_once(':') {
            if let (Some(ip), Ok(port)) = (maltrail_sensor::addr::parse_canonical_ip(addr), port.parse::<u16>()) {
                if ip.addr_port(port).as_str() == trail {
                    assert_eq!(db.get_ip_port(ip, port), db.get(trail), "native/text mismatch for {trail}");
                    checked += 1;
                }
            }
        }
    }
    println!("[i] cross-checked {checked} native IP lookups against the string table");
    assert!(checked > 100, "expected to cross-check a meaningful number of IP trails");
}

/// Iterate the real CSV exactly the way the loader does (`read_until` + lossy UTF-8, so invalid
/// bytes produce the same key on both sides) and hand each accepted row to `visit`.
fn for_each_real_row(path: &PathBuf, wl: &Whitelist, mut visit: impl FnMut(&str, &str, &str)) -> usize {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::with_capacity(1 << 20, std::fs::File::open(path).unwrap());
    let mut raw: Vec<u8> = Vec::with_capacity(256);
    let mut fields: Vec<String> = Vec::new();
    let mut rows = 0usize;
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw).unwrap() == 0 {
            break;
        }
        while matches!(raw.last(), Some(b'\n') | Some(b'\r')) {
            raw.pop();
        }
        if raw.is_empty() {
            continue;
        }
        let line = String::from_utf8_lossy(&raw);
        let (trail, info, reference) = if raw.contains(&b'"') {
            if trails::split_csv_record(&line, &mut fields) != 3 {
                continue;
            }
            (fields[0].clone(), fields[1].clone(), fields[2].clone())
        } else {
            let mut it = line.splitn(3, ',');
            match (it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c)) if !c.contains(',') => (a.to_string(), b.to_string(), c.to_string()),
                _ => continue,
            }
        };
        if wl.check_whitelisted(&trail) {
            continue;
        }
        rows += 1;
        visit(&trail, &info, &reference);
    }
    rows
}

fn hash64(value: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut h);
    h.finish()
}

#[test]
fn real_trails_every_single_row_is_findable_with_its_own_info() {
    // The most basic invariant there is, and the one whose absence let a stale-trails bug hide:
    // EVERY accepted row of the real trails.csv must be retrievable, with exactly the (info,
    // reference) that row carries. Not a sample - every row.
    let Some(path) = real_trails_file() else {
        println!("[skip] no real trails file ($MALTRAIL_TRAILS or ~/.maltrail/trails.csv) on this machine");
        return;
    };
    let wl = Whitelist::load(&repo_root(), None);
    let (db, stats) = trails::load(&path, &wl).unwrap();
    assert_every_real_row_is_findable(&path, &wl, &db, &stats);
}

/// The body of the test above, for any store - a parsed one or one mapped from a prebuilt file.
fn assert_every_real_row_is_findable(
    path: &PathBuf,
    wl: &Whitelist,
    db: &trails::TrailDb,
    stats: &trails::loader::LoadStats,
) {
    // Pass 1: which keys occur more than once? Hashes only, to stay memory-light on 1.5M rows.
    // (A hash collision can only demote a row to the duplicate path, never fail a good row.)
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::with_capacity(stats.loaded * 2);
    let mut dup: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for_each_real_row(path, wl, |trail, _, _| {
        let h = hash64(trail);
        if !seen.insert(h) {
            dup.insert(h);
        }
    });
    let unique_keys = seen.len();

    // Pass 2: check every row. Duplicated keys must resolve to their LAST value (Python's
    // `trails[trail] = (info, reference)` overwrites), so those are collected and checked after.
    let mut last_of_dup: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    let mut missing: Vec<String> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    let mut native_mismatch: Vec<String> = Vec::new();
    let mut ip_rows = 0usize;
    let mut ip_port_rows = 0usize;

    let rows = for_each_real_row(path, wl, |trail, info, reference| {
        let found = db.get(trail);
        let Some(found) = found else {
            if missing.len() < 20 {
                missing.push(trail.to_string());
            }
            return;
        };
        if dup.contains(&hash64(trail)) {
            last_of_dup.insert(trail.to_string(), (info.to_string(), reference.to_string()));
        } else if (found.info != info || found.reference != reference) && wrong.len() < 20 {
            wrong.push(format!("{trail}: got ({}, {}), want ({info}, {reference})", found.info, found.reference));
        }

        // Every IP-shaped row must answer identically through the native table.
        if let Some(ip) = maltrail_sensor::addr::parse_canonical_ip(trail) {
            ip_rows += 1;
            if db.get_ip(ip) != Some(found) && native_mismatch.len() < 20 {
                native_mismatch.push(format!("{trail} (address)"));
            }
        } else if let Some((addr, port)) = trail.rsplit_once(':') {
            if let (Some(ip), Ok(port)) = (maltrail_sensor::addr::parse_canonical_ip(addr), port.parse::<u16>()) {
                if ip.addr_port(port).as_str() == trail {
                    ip_port_rows += 1;
                    if db.get_ip_port(ip, port) != Some(found) && native_mismatch.len() < 20 {
                        native_mismatch.push(format!("{trail} (address:port)"));
                    }
                }
            }
        }
    });

    assert!(missing.is_empty(), "{} row(s) are not findable, e.g. {:?}", missing.len(), missing);
    assert!(wrong.is_empty(), "{} row(s) carry the wrong info, e.g. {:?}", wrong.len(), wrong);
    assert!(native_mismatch.is_empty(), "native/string disagreement: {native_mismatch:?}");

    for (trail, (info, reference)) in &last_of_dup {
        let found = db.get(trail).expect("duplicate key must still be present");
        assert_eq!(
            (found.info, found.reference),
            (info.as_str(), reference.as_str()),
            "a duplicated trail must keep the LAST row's value, like Python's dict assignment: {trail}"
        );
    }

    println!(
        "[i] verified {rows} rows ({} unique, {} duplicated keys, {ip_rows} addresses, \
         {ip_port_rows} address:port) all findable with the right info",
        stats.loaded,
        last_of_dup.len()
    );
    // This walk accepts exactly the rows the loader accepted, duplicates included.
    assert_eq!(rows, stats.loaded, "the test's CSV walk disagrees with the loader about which rows count");
    assert_eq!(db.len(), unique_keys, "the store must hold exactly as many keys as the CSV has distinct trails");
    assert!(rows > 100_000, "expected a sizeable trail set, got {rows}");
}

#[test]
fn every_real_wildcard_trail_is_either_compiled_or_reported() {
    // Wildcard trails live in the regex, not the hash table, so a lost one leaves no trace in the
    // key set. Each `(static)` wildcard trail with metacharacters must therefore end up in
    // exactly one bucket: compiled, repaired, or reported as skipped. Nothing may vanish.
    // (Whether that classification matches CPython's is asserted in tests/loader_parity.rs.)
    let Some(path) = real_trails_file() else {
        println!("[skip] no real trails file ($MALTRAIL_TRAILS or ~/.maltrail/trails.csv) on this machine");
        return;
    };
    let wl = Whitelist::load(&repo_root(), None);
    let (db, _) = trails::load(&path, &wl).unwrap();
    let regex = db.regex();

    let mut candidates: Vec<String> = Vec::new();
    for_each_real_row(&path, &wl, |trail, _, reference| {
        if reference.contains("static") && trails::is_wildcard_trail(trail) && !candidates.iter().any(|c| c == trail) {
            candidates.push(trail.to_string());
        }
    });

    let mut unaccounted: Vec<String> = Vec::new();
    for trail in &candidates {
        // `re.escape(trail) != trail` — a wildcard-looking trail with no metacharacters is a
        // literal and belongs in the hash table only.
        if maltrail_sensor::pyre::escape(trail) == *trail {
            assert!(db.contains(trail), "a literal trail must be in the key table: {trail}");
            continue;
        }
        let compiled = regex.patterns().iter().any(|p| p == trail);
        let skipped = regex.skipped().iter().any(|p| p == trail);
        if !compiled && !skipped && candidates.len() <= 100 {
            unaccounted.push(trail.clone());
        }
    }

    println!(
        "[i] {} wildcard candidate(s): {} compiled ({} repaired), {} reported as uncompilable",
        candidates.len(),
        regex.len(),
        regex.repaired().len(),
        regex.skipped().len()
    );
    assert!(unaccounted.is_empty(), "wildcard trails silently dropped without being reported: {unaccounted:?}");
    // Every compiled group must map back to a trail that is also a key in the table, otherwise a
    // regex hit could not be resolved to an (info, reference).
    for pattern in regex.patterns() {
        assert!(db.contains(pattern), "a compiled wildcard trail must still be a key: {pattern}");
    }
}

#[test]
fn reload_swaps_the_store_atomically() {
    use std::sync::Arc;
    let first = temp_csv("reload-a.csv", "a.com,i1,(static)\n");
    let second = temp_csv("reload-b.csv", "b.com,i2,(static)\n");
    let wl = Whitelist::default();
    let (db, _) = trails::load(&first, &wl).unwrap();
    let store = Arc::new(trails::TrailStore::new(db));
    let mut view = trails::TrailView::new(store.clone());
    assert!(view.db().contains("a.com"));

    let (db2, _) = trails::load(&second, &wl).unwrap();
    store.publish(db2);
    assert!(view.refresh(), "a published reload must be visible");
    assert!(view.db().contains("b.com"));
    assert!(!view.db().contains("a.com"));
    assert!(!view.refresh(), "no further reload pending");
}

/// The trail store's one probabilistic component, verified at real trail-set scale **without a
/// trails file**.
///
/// `NegativeFilter` short-circuits a lookup whose key it believes absent, and a false negative
/// there is a silently missed detection — the worst failure this codebase has. The definitive
/// check used to be the real-trails row walk above, which self-skips wherever no operator trails
/// file exists (every CI runner until the `real trail set` job, every contributor's first clone),
/// so the invariant behind the filter was asserted by nothing reproducible. This is that check,
/// generated: 1.5M keys in the shapes the loader actually produces, every one walked back.
///
/// Sized deliberately hostile: every table starts at a capacity ~1500x below what it ends up
/// holding, so the string table grows ~11 times under the filter and the filter itself is left
/// saturated far past its design load. Both are cases the estimate-based sizing in
/// `TrailDb::with_estimate` can hit on a trail set that grew since the row estimate was made.
#[test]
fn the_negative_filter_never_hides_a_key_at_real_scale() {
    use maltrail_sensor::trails::table::{IntTable, StrTable};
    use std::fmt::Write as _;

    const KEYS: u32 = 1_500_000;

    // SplitMix64: a fixed seed, so a failure is reproducible and bisectable.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };

    // Same generator, same order, twice: build, then verify. Keeping it a function rather than a
    // 1.5M-entry Vec<String> keeps the test's own footprint next to nothing.
    fn key_into(buf: &mut String, i: u32, r: u64) {
        buf.clear();
        match i % 4 {
            0 => write!(buf, "host{i}.sub{}.example{}.com", r % 9973, r % 97),
            1 => write!(buf, "{}.{}.{}.{}", (r >> 24) as u8, (r >> 16) as u8, (r >> 8) as u8, r as u8),
            2 => write!(buf, "{}.{}.{}.{}:{}", (r >> 24) as u8, (r >> 16) as u8, (r >> 8) as u8, r as u8, r as u16 | 1),
            _ => write!(buf, "domain{i}.example/path/{}/{}.php", r % 7919, r % 31),
        }
        .unwrap();
    }

    let mut randoms: Vec<u64> = Vec::with_capacity(KEYS as usize);
    for _ in 0..KEYS {
        randoms.push(next());
    }

    let mut strings = StrTable::with_capacity(1024, 1 << 16);
    let mut ip4: IntTable<u32> = IntTable::with_capacity(1024);
    let mut ip4_port: IntTable<u64> = IntTable::with_capacity(1024);
    let mut ip6: IntTable<u128> = IntTable::with_capacity(1024);

    let mut buf = String::with_capacity(96);
    for (i, &r) in randoms.iter().enumerate() {
        let i = i as u32;
        key_into(&mut buf, i, r);
        strings.insert(&buf, i + 1);
        ip4.insert(r as u32, i + 1);
        ip4_port.insert(r | 1, i + 1);
        ip6.insert((r as u128) << 64 | i as u128, i + 1);
    }
    assert!(strings.len() > KEYS as usize / 2, "generator produced too many duplicate keys");

    // The invariant: an inserted key is NEVER answered "absent". Values may legitimately differ
    // (the generator can repeat a key, and the later insert wins), so this asserts findability,
    // which is what the filter can break. The real-trails walk asserts the values.
    let mut hidden = Vec::new();
    for (i, &r) in randoms.iter().enumerate() {
        let i = i as u32;
        key_into(&mut buf, i, r);
        if strings.get(&buf).is_none() && hidden.len() < 10 {
            hidden.push(buf.clone());
        }
        if ip4.get(r as u32).is_none() && hidden.len() < 10 {
            hidden.push(format!("ip4 {r:#x}"));
        }
        if ip4_port.get(r | 1).is_none() && hidden.len() < 10 {
            hidden.push(format!("ip4_port {r:#x}"));
        }
        if ip6.get((r as u128) << 64 | i as u128).is_none() && hidden.len() < 10 {
            hidden.push(format!("ip6 {r:#x}/{i}"));
        }
    }
    assert!(hidden.is_empty(), "the negative filter hid inserted keys - missed detections: {hidden:?}");

    // And the other half of being useful: absent keys must still be rejected, and none of them may
    // resolve to an entry the table does not hold.
    let mut invented = 0usize;
    for i in 0..100_000u32 {
        if strings.get(&format!("absent{i}.nowhere.invalid")).is_some() {
            invented += 1;
        }
    }
    assert_eq!(invented, 0, "the table invented entries for keys never inserted");
}

// -------------------------------------------------------------------------------------------------
// The prebuilt trail store (src/trails/store.rs). A store is a cache of the CSV; the property that
// matters is that it can never answer for a CSV it was not built from, and never answers anything a
// parse would not.
// -------------------------------------------------------------------------------------------------

use maltrail_sensor::trails::{LoadOptions, StoreConfig, TrailDb};

fn store_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mt-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn with_store(store: &std::path::Path, whitelist_hash: u64) -> LoadOptions {
    LoadOptions {
        store: Some(StoreConfig { path: store.to_path_buf(), whitelist_hash, write: true }),
        ..LoadOptions::default()
    }
}

/// Every shape a store has to carry, and the keys to ask it about.
fn varied_csv() -> (Vec<u8>, Vec<String>) {
    let mut csv: Vec<u8> = b"# a licence header, not a trail\n".to_vec();
    let mut keys = Vec::new();
    for i in 0..120_000u32 {
        let key = match i % 6 {
            0 => format!("host{i}.example"),
            1 => format!("{}.{}.{}.{}", 11 + i % 200, (i >> 8) & 255, i & 255, (i >> 16) & 255),
            2 => format!("{}.{}.{}.{}:{}", 11 + i % 200, (i >> 8) & 255, i & 255, (i >> 16) & 255, 1 + i % 65000),
            3 => format!("/path{i}.php"),
            4 => format!("2001:db8::{:x}", i + 1),
            _ => format!("[2001:db8::{:x}]:{}", i + 1, 1 + i % 65000),
        };
        csv.extend_from_slice(format!("{key},info {} (malware),(static)\n", i % 37).as_bytes());
        keys.push(key);
    }
    csv.extend_from_slice(
        b"dup.example,first info,(static)\n\
          \"has,comma.example\",\"info, with comma\",(static)\n\
          crlf.example,ok,(static)\r\n\
          evil[0-9]+\\.example,wildcard (malware),(static)\n\
          bad.*\\.example,wildcard (malware),(static)\n\
          d190f828263095de150a20b19136e314,ja3 (malware),(custom)\n\
          two,fields\n\
          four,fields,here,too\n\
          caf\xc3\xa9.example,unicode,(static)\n\
          bro\xffken.example,invalid utf-8,(static)\n\
          dup.example,LAST info wins,(static)\n",
    );
    keys.extend(
        ["dup.example", "has,comma.example", "crlf.example", "evil[0-9]+\\.example", "café.example", "nope.example"]
            .map(String::from),
    );
    keys.push("d190f828263095de150a20b19136e314".into());
    (csv, keys)
}

/// Two stores must answer every question identically.
fn assert_same_answers(want: &TrailDb, got: &TrailDb, keys: &[String]) {
    use maltrail_sensor::trails::{FP_CERT, FP_JA3, FP_JA4};
    assert_eq!(got.len(), want.len());
    assert_eq!(got.ip4_count(), want.ip4_count());
    assert_eq!(got.ip4_port_count(), want.ip4_port_count());
    assert_eq!(got.ip6_count(), want.ip6_count());
    for fp in [FP_JA3, FP_JA4, FP_CERT] {
        assert_eq!(got.has_fingerprints(fp), want.has_fingerprints(fp));
    }
    assert_eq!(got.regex().source(), want.regex().source());
    assert_eq!(got.regex().patterns(), want.regex().patterns());
    assert_eq!(got.regex().skipped(), want.regex().skipped());
    assert_eq!(got.regex().repaired(), want.regex().repaired());
    for query in ["x.evil42.example", "bad-thing.example", "evil.example", "www.host7.example"] {
        let (w, g) = (want.regex().find(query), got.regex().find(query));
        assert_eq!(w.map(|h| (h.start, h.end, h.candidate)), g.map(|h| (h.start, h.end, h.candidate)), "{query}");
        assert_eq!(got.contains_domain_member(query), want.contains_domain_member(query), "{query}");
    }
    for key in keys {
        assert_eq!(got.get(key), want.get(key), "{key:?}");
        if let Some(ip) = maltrail_sensor::addr::parse_canonical_ip(key) {
            assert_eq!(got.get_ip(ip), want.get_ip(ip), "{key:?}");
        }
        let (addr, port) = match key.strip_prefix('[') {
            Some(rest) => rest.split_once("]:").unwrap_or(("", "")),
            None => key.rsplit_once(':').unwrap_or(("", "")),
        };
        if let (Some(ip), Ok(port)) = (maltrail_sensor::addr::parse_canonical_ip(addr), port.parse::<u16>()) {
            assert_eq!(got.get_ip_port(ip, port), want.get_ip_port(ip, port), "{key:?}");
        }
    }
}

#[test]
fn a_prebuilt_store_answers_exactly_like_a_parse() {
    let dir = store_dir("parity");
    let csv = dir.join("trails.csv");
    let store = dir.join("trails.csv.store");
    let (content, keys) = varied_csv();
    std::fs::write(&csv, &content).unwrap();
    let wl = Whitelist::load(&repo_root(), None);

    let (parsed, pstats) = trails::load_with(&csv, &wl, LoadOptions::default()).unwrap();
    assert!(!parsed.is_prebuilt() && !store.exists(), "no store unless one is configured");

    let (cold, cstats) = trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    assert!(!cstats.from_store, "the first load must parse");
    assert!(store.is_file(), "the first load must write the store");
    assert!(cstats.store_note.is_none(), "{:?}", cstats.store_note);
    // positive control: the cold load already serves from the store it just wrote
    assert!(cold.is_prebuilt(), "the written store must be mapped back and used");

    let (warm, wstats) = trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    assert!(wstats.from_store && warm.is_prebuilt(), "the second load must come from the store");
    assert_eq!(
        (wstats.rows, wstats.loaded, wstats.whitelisted, wstats.malformed),
        (pstats.rows, pstats.loaded, pstats.whitelisted, pstats.malformed)
    );
    assert!(pstats.malformed >= 2, "the fixture's malformed rows must count, or this proves nothing");

    assert_eq!(parsed.get("dup.example").map(|v| v.info), Some("LAST info wins"));
    assert!(parsed.has_fingerprints(trails::FP_JA3) && !parsed.regex().is_empty());
    assert_same_answers(&parsed, &cold, &keys);
    assert_same_answers(&parsed, &warm, &keys);
    assert!(trails::store::verify(&store).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Set a file's mtime, to the nanosecond.
#[cfg(unix)]
fn set_mtime(path: &std::path::Path, secs: i64, nanos: i64) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
        libc::timespec { tv_sec: secs as libc::time_t, tv_nsec: nanos as _ },
    ];
    assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) }, 0);
}

#[test]
#[cfg(unix)]
fn a_changed_trails_file_is_never_served_from_the_store() {
    use std::os::unix::fs::MetadataExt;
    let dir = store_dir("changed");
    let csv = dir.join("trails.csv");
    let store = dir.join("trails.csv.store");
    let wl = Whitelist::default();
    std::fs::write(&csv, "known.example,old (malware),(static)\n1.2.3.4,old (malware),(static)\n").unwrap();
    trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    let (_, stats) = trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    assert!(stats.from_store, "positive control: the unchanged file is served from the store");

    // An appended row: size and mtime change.
    let mut f = std::fs::OpenOptions::new().append(true).open(&csv).unwrap();
    std::io::Write::write_all(&mut f, b"added-today.example,new (malware),(static)\n").unwrap();
    drop(f);
    let (db, stats) = trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    assert!(!stats.from_store);
    assert!(db.get("added-today.example").is_some(), "the new row must be detected");
    assert!(stats.store_note.as_deref().is_some_and(|n| n.contains("changed")), "{:?}", stats.store_note);
    let (db, stats) = trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    assert!(stats.from_store && db.get("added-today.example").is_some(), "the rebuilt store carries it");

    // The paranoid case: same length, different content, mtime put back to the nanosecond - what
    // `cp -p` or a restored backup produces. Only the content hash can tell.
    let before = std::fs::metadata(&csv).unwrap();
    let text = std::fs::read_to_string(&csv).unwrap().replace("added-today", "added-twice");
    std::fs::write(&csv, text).unwrap();
    set_mtime(&csv, before.mtime(), before.mtime_nsec());
    let after = std::fs::metadata(&csv).unwrap();
    assert_eq!((after.len(), after.mtime(), after.mtime_nsec()), (before.len(), before.mtime(), before.mtime_nsec()));
    let (db, stats) = trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    assert!(!stats.from_store, "a same-size, same-mtime rewrite must not be served from the old store");
    assert!(db.get("added-twice.example").is_some() && db.get("added-today.example").is_none());
    assert!(stats.store_note.as_deref().is_some_and(|n| n.contains("content")), "{:?}", stats.store_note);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_changed_whitelist_or_repair_setting_misses_the_store() {
    let dir = store_dir("identity");
    let csv = dir.join("trails.csv");
    let store = dir.join("trails.csv.store");
    let wl = Whitelist::default();
    std::fs::write(&csv, "known.example,x (malware),(static)\n").unwrap();
    trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap();
    assert!(trails::load_with(&csv, &wl, with_store(&store, 1)).unwrap().1.from_store);

    let (_, stats) = trails::load_with(&csv, &wl, with_store(&store, 2)).unwrap();
    assert!(!stats.from_store, "a store built under another whitelist must not be used");
    assert!(stats.store_note.as_deref().is_some_and(|n| n.contains("whitelist")), "{:?}", stats.store_note);

    let strict = LoadOptions { repair_truncated_trails: false, ..with_store(&store, 2) };
    let (_, stats) = trails::load_with(&csv, &wl, strict).unwrap();
    assert!(!stats.from_store, "a store built with another REPAIR_TRUNCATED_TRAILS must not be used");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unwritable_store_still_loads_the_trails() {
    let dir = store_dir("unwritable");
    let csv = dir.join("trails.csv");
    std::fs::write(&csv, "known.example,x (malware),(static)\n").unwrap();
    let store = PathBuf::from("/nonexistent/maltrail/trails.csv.store");
    let (db, stats) = trails::load_with(&csv, &Whitelist::default(), with_store(&store, 1)).unwrap();
    assert!(db.get("known.example").is_some());
    assert!(!stats.from_store && !db.is_prebuilt());
    assert!(stats.store_note.as_deref().is_some_and(|n| n.contains("could not write")), "{:?}", stats.store_note);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_trails_prebuilt_store_round_trip() {
    let Some(path) = real_trails_file() else {
        println!("[skip] no real trails file ($MALTRAIL_TRAILS or ~/.maltrail/trails.csv) on this machine");
        return;
    };
    let dir = store_dir("real");
    let store = dir.join("trails.csv.store");
    let wl = Whitelist::load(&repo_root(), None);
    let whitelist_hash = trails::store::whitelist_hash(&repo_root(), None);

    let started = std::time::Instant::now();
    let (_, parse_stats) = trails::load_with(&path, &wl, LoadOptions::default()).unwrap();
    let parse = started.elapsed();
    let started = std::time::Instant::now();
    let (cold, _) = trails::load_with(&path, &wl, with_store(&store, whitelist_hash)).unwrap();
    let build = started.elapsed();
    assert!(cold.is_prebuilt(), "the cold load must have written and mapped its store");
    drop(cold);
    let started = std::time::Instant::now();
    let (db, stats) = trails::load_with(&path, &wl, with_store(&store, whitelist_hash)).unwrap();
    let warm = started.elapsed();
    println!(
        "[i] real trails: parse {:.3}s, parse + write store {:.3}s, load from store {:.3}s ({:.1} MB)",
        parse.as_secs_f64(),
        build.as_secs_f64(),
        warm.as_secs_f64(),
        std::fs::metadata(&store).unwrap().len() as f64 / (1024.0 * 1024.0)
    );
    assert!(stats.from_store && db.is_prebuilt(), "the warm load must come from the store");
    assert_eq!(stats.loaded, parse_stats.loaded);
    // Positive control that it did not quietly fall back to parsing (a store load hashes the CSV,
    // which is all it reads, so it has to be clearly cheaper than a parse).
    assert!(warm * 3 < parse, "a store load ({warm:?}) is not clearly faster than a parse ({parse:?})");
    trails::store::verify(&store).expect("a freshly written store must verify");
    assert_every_real_row_is_findable(&path, &wl, &db, &stats);
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}
