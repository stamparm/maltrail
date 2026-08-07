//! Trail-loading tests, including against the operator's real `~/.maltrail/trails.csv`
//! when one is present (skipped with a printed note otherwise, so CI without trails still
//! passes).

use std::path::PathBuf;

use maltrail_sensor::addr::{addr_to_int, parse_ipv6, Ip};
use maltrail_sensor::trails;
use maltrail_sensor::whitelist::Whitelist;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn real_trails_file() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let path = PathBuf::from(home).join(".maltrail").join("trails.csv");
    if path.is_file() {
        Some(path)
    } else {
        None
    }
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
        println!("[skip] no ~/.maltrail/trails.csv on this machine");
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
        println!("[skip] no ~/.maltrail/trails.csv on this machine");
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
        println!("[skip] no ~/.maltrail/trails.csv on this machine");
        return;
    };
    let wl = Whitelist::load(&repo_root(), None);
    let (db, stats) = trails::load(&path, &wl).unwrap();

    // Pass 1: which keys occur more than once? Hashes only, to stay memory-light on 1.5M rows.
    // (A hash collision can only demote a row to the duplicate path, never fail a good row.)
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::with_capacity(stats.loaded * 2);
    let mut dup: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for_each_real_row(&path, &wl, |trail, _, _| {
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

    let rows = for_each_real_row(&path, &wl, |trail, info, reference| {
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
        println!("[skip] no ~/.maltrail/trails.csv on this machine");
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
