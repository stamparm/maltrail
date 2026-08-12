//! Trail CSV loading — `core/common.py:load_trails()`.
//!
//! Reads `TRAILS_FILE` (the existing, unchanged Maltrail CSV: `trail,info,reference`),
//! drops whitelisted trails, interns the `(info, reference)` pairs and builds the
//! lookup tables plus the wildcard-trail regex, in CSV order (which is the order Python
//! iterates, and therefore the order the regex groups get).

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::Path;

use super::regexset::TrailRegexBuilder;
use super::{NativeKey, TrailDb, TrailDbBuilder};
use crate::whitelist::Whitelist;

/// Split one CSV record the way Python's `csv.reader(delimiter=',', quotechar='"')` does
/// (doublequote, non-strict, no escapechar). Returns the field count actually produced.
///
/// The `out` buffer is reused across records so loading 1.5M rows performs no per-row
/// allocation.
pub fn split_csv_record(line: &str, out: &mut Vec<String>) -> usize {
    out.clear();
    let bytes = line.as_bytes();
    let mut field = String::new();
    let mut i = 0usize;
    let mut in_quotes = false;
    let mut field_started_quoted = false;

    while i < bytes.len() {
        let c = bytes[i];
        if in_quotes {
            if c == b'"' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                    field.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = false;
                i += 1;
                continue;
            }
            // Multi-byte UTF-8 is copied through verbatim.
            let start = i;
            let mut end = i + 1;
            while end < bytes.len() && (bytes[end] & 0xc0) == 0x80 {
                end += 1;
            }
            field.push_str(&line[start..end]);
            i = end;
            continue;
        }
        match c {
            b',' => {
                out.push(std::mem::take(&mut field));
                field_started_quoted = false;
                i += 1;
            }
            b'"' if field.is_empty() && !field_started_quoted => {
                in_quotes = true;
                field_started_quoted = true;
                i += 1;
            }
            _ => {
                let start = i;
                let mut end = i + 1;
                while end < bytes.len() && (bytes[end] & 0xc0) == 0x80 {
                    end += 1;
                }
                field.push_str(&line[start..end]);
                i = end;
            }
        }
    }
    out.push(field);
    out.len()
}

/// Load-time options. Defaults reproduce the shipped sensor behaviour.
#[derive(Clone, Copy)]
pub struct LoadOptions {
    /// Repair feed-mangled wildcard patterns rather than dropping them silently. `false` gives
    /// byte-exact `build_trails_regex()` parity with `sensor.py`.
    pub repair_truncated_trails: bool,
}

impl Default for LoadOptions {
    fn default() -> LoadOptions {
        LoadOptions { repair_truncated_trails: true }
    }
}

pub struct LoadStats {
    pub rows: usize,
    pub loaded: usize,
    pub whitelisted: usize,
    pub malformed: usize,
}

/// Bytes read per round. Big enough to give every thread a worthwhile slice, small enough that
/// the batch buffer and the borrowed rows pointing into it stay a rounding error next to the
/// tables being built.
const BATCH_BYTES: usize = 8 << 20;

/// Below this the threads cost more than they save (they also have to be spawned).
const PARALLEL_MIN_BYTES: usize = 4 << 20;

/// More than this buys nothing: past ~8 slices the serial insert pass, not the parsing, is
/// what the load costs, and the sensor should not seize every core on a busy box at startup.
const MAX_PARSE_THREADS: usize = 8;

/// How far ahead of the insert the drain warms the string table. Roughly the number of
/// outstanding cache misses the core can keep in flight, which is what decides whether the
/// serial pass runs at memory bandwidth or at memory latency.
const PREFETCH_DISTANCE: usize = 8;

/// One surviving CSV row, still borrowing the batch buffer.
///
/// `hash` and `native` are carried rather than recomputed in the drain: both depend only on the
/// key text, so the parse threads produce them for free and the serial pass is left with nothing
/// but the table writes.
struct Row<'a> {
    trail: Cow<'a, str>,
    hash: u64,
    native: NativeKey,
    /// index into the owning shard's `pairs`
    pair: u32,
}

/// What one thread produces from one slice of one batch. Everything here is per-thread, so the
/// parse pass needs no synchronisation at all; the serial drain then replays it in file order,
/// which is what makes the result identical to a single-threaded load.
struct Shard<'a> {
    rows: Vec<Row<'a>>,
    pairs: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    /// hash of `info`+`reference` -> candidate indices into `pairs` (verified on hit). Keyed by
    /// hash rather than by the pair itself so a lookup does not have to own the two strings
    /// first: the real file has ~3,100 distinct pairs across 1.6 M rows.
    pair_index: HashMap<u64, Vec<u32>>,
    /// trails that might belong in the wildcard alternation, in CSV order. The real decision
    /// (and the global 100-group cap) stays with `TrailRegexBuilder` in the serial drain; this
    /// only front-loads the scan that rejects ~every trail.
    wildcards: Vec<(String, String)>,
    stats: LoadStats,
}

impl<'a> Shard<'a> {
    /// `expected_rows` sizes `rows` in one go. Letting it grow from empty meant ~11 reallocations
    /// and copies of a buffer on its way to a megabyte, per slice, per batch.
    fn with_capacity(expected_rows: usize) -> Shard<'a> {
        Shard {
            rows: Vec::with_capacity(expected_rows),
            pairs: Vec::new(),
            pair_index: HashMap::new(),
            wildcards: Vec::new(),
            stats: LoadStats { rows: 0, loaded: 0, whitelisted: 0, malformed: 0 },
        }
    }

    fn intern(&mut self, info: Cow<'a, str>, reference: Cow<'a, str>) -> u32 {
        let h =
            super::table::hash_bytes(info.as_bytes()) ^ super::table::hash_bytes(reference.as_bytes()).rotate_left(17);
        let bucket = self.pair_index.entry(h).or_default();
        for &idx in bucket.iter() {
            // The hash narrows it down; the strings decide. A 64-bit collision between two real
            // (info, reference) pairs would otherwise mis-label every trail from one of them.
            let (i, r) = &self.pairs[idx as usize];
            if i.as_ref() == info.as_ref() && r.as_ref() == reference.as_ref() {
                return idx;
            }
        }
        let idx = self.pairs.len() as u32;
        bucket.push(idx);
        self.pairs.push((info, reference));
        idx
    }
}

/// Split one line into `(trail, info, reference)`, borrowing where it can.
///
/// Byte-for-byte the same decisions the single-threaded loader made: lossy UTF-8, the quoted
/// path only when a `"` is present, and a third field containing a comma is malformed.
fn parse_row<'a>(raw: &'a [u8], fields: &mut Vec<String>) -> Option<(Cow<'a, str>, Cow<'a, str>, Cow<'a, str>)> {
    let line = String::from_utf8_lossy(raw);
    if memchr::memchr(b'"', raw).is_some() {
        if split_csv_record(&line, fields) != 3 {
            return None;
        }
        // Taken, not cloned: `split_csv_record` clears `fields` before it writes, so leaving
        // empty `String`s behind costs the next row nothing.
        return Some((
            Cow::Owned(std::mem::take(&mut fields[0])),
            Cow::Owned(std::mem::take(&mut fields[1])),
            Cow::Owned(std::mem::take(&mut fields[2])),
        ));
    }
    match line {
        // The overwhelmingly common case: valid UTF-8, unquoted — three slices of the batch
        // buffer, no allocation.
        Cow::Borrowed(s) => {
            let mut it = s.splitn(3, ',');
            match (it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c)) if !c.contains(',') => {
                    Some((Cow::Borrowed(a), Cow::Borrowed(b), Cow::Borrowed(c)))
                }
                _ => None,
            }
        }
        // Invalid UTF-8: the replacement characters live in a temporary, so this row has to own
        // its fields.
        Cow::Owned(s) => {
            let mut it = s.splitn(3, ',');
            match (it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c)) if !c.contains(',') => {
                    Some((Cow::Owned(a.to_string()), Cow::Owned(b.to_string()), Cow::Owned(c.to_string())))
                }
                _ => None,
            }
        }
    }
}

/// Parse one line-aligned slice into `shard`. Pure function of the slice and the whitelist —
/// this is the part that runs on every thread.
fn parse_slice<'a>(slice: &'a [u8], whitelist: &Whitelist, shard: &mut Shard<'a>) {
    let mut fields: Vec<String> = Vec::with_capacity(4);
    let mut pos = 0usize;
    while pos < slice.len() {
        let end = memchr::memchr(b'\n', &slice[pos..]).map(|i| pos + i + 1).unwrap_or(slice.len());
        let mut raw = &slice[pos..end];
        pos = end;
        while matches!(raw.last(), Some(b'\n') | Some(b'\r')) {
            raw = &raw[..raw.len() - 1];
        }
        if raw.is_empty() {
            continue;
        }
        shard.stats.rows += 1;

        let Some((trail, info, reference)) = parse_row(raw, &mut fields) else {
            shard.stats.malformed += 1;
            continue;
        };

        if whitelist.check_whitelisted(&trail) {
            shard.stats.whitelisted += 1;
            continue;
        }

        if reference.contains("static") && super::regexset::is_wildcard_trail(&trail) {
            shard.wildcards.push((trail.to_string(), reference.to_string()));
        }

        let pair = shard.intern(info, reference);
        let hash = super::table::hash_bytes(trail.as_bytes());
        let native = NativeKey::of(&trail);
        shard.rows.push(Row { trail, hash, native, pair });
        shard.stats.loaded += 1;
    }
}

/// Cut `region` (which ends on a line boundary) into at most `parts` line-aligned pieces.
fn split_lines(region: &[u8], parts: usize) -> Vec<(usize, usize)> {
    let mut bounds = Vec::with_capacity(parts);
    let mut start = 0usize;
    for p in 1..parts {
        let target = region.len() * p / parts;
        if target <= start {
            continue;
        }
        let cut = match memchr::memchr(b'\n', &region[target..]) {
            Some(i) => target + i + 1,
            None => region.len(),
        };
        if cut > start {
            bounds.push((start, cut));
            start = cut;
        }
        if start >= region.len() {
            break;
        }
    }
    if start < region.len() {
        bounds.push((start, region.len()));
    }
    bounds
}

/// `load_trails()`. Returns the store plus load statistics for startup diagnostics.
///
/// The file is read in bounded BATCHES rather than slurped: a real trails.csv is ~90 MB, and
/// reading it whole would add that much to peak RSS on top of the tables being built.
///
/// Each batch is cut into line-aligned slices that are parsed in parallel — parsing, the
/// whitelist test and the wildcard scan are ~60% of the load and are per-row independent — and
/// the surviving rows are then inserted **serially, in file order**. That order is not an
/// implementation detail: duplicate trails must resolve to the last row that mentions them, the
/// interned `(info, reference)` pairs must come out in first-appearance order, and the wildcard
/// alternation's group numbering (and its 100-group cap) is positional. Draining shard by shard,
/// row by row, reproduces all three exactly, so a parallel load and a serial one build the same
/// store.
pub fn load_trails(path: &Path, whitelist: &Whitelist, options: LoadOptions) -> std::io::Result<(TrailDb, LoadStats)> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Python: a missing trails file yields an empty store (the sensor still runs).
            return Ok((TrailDb::empty(), LoadStats { rows: 0, loaded: 0, whitelisted: 0, malformed: 0 }));
        }
        Err(e) => return Err(e),
    };
    let file_len = file.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let mut reader = BufReader::with_capacity(1 << 20, file);

    // Estimate from the average real-world record length; the tables grow if it is off.
    let estimated_rows = file_len / 48 + 16;
    let mut builder = TrailDbBuilder::new(estimated_rows, file_len / 3);
    let mut regex_builder = TrailRegexBuilder::with_repair(options.repair_truncated_trails);
    let mut pair_index: HashMap<(String, String), u32> = HashMap::with_capacity(8192);
    let mut stats = LoadStats { rows: 0, loaded: 0, whitelisted: 0, malformed: 0 };

    let threads = if file_len < PARALLEL_MIN_BYTES {
        1
    } else {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, MAX_PARSE_THREADS)
    };

    // Never bigger than the file. A sensor whose trail set is one small custom list should not
    // pay 8 MB of buffer for it — and it would pay it again on every reload.
    let batch_bytes = (file_len + 1).clamp(64 * 1024, BATCH_BYTES);
    let mut buf: Vec<u8> = vec![0u8; batch_bytes];
    let mut filled = 0usize;
    let mut eof = false;
    let mut local_to_global: Vec<u32> = Vec::new();

    loop {
        while !eof && filled < buf.len() {
            match reader.read(&mut buf[filled..])? {
                0 => eof = true,
                n => filled += n,
            }
        }
        if filled == 0 {
            break;
        }
        // Never hand a thread half a line: cut the batch at the last newline and carry the rest.
        let end = if eof {
            filled
        } else {
            match memchr::memrchr(b'\n', &buf[..filled]) {
                Some(i) => i + 1,
                // One line longer than the whole batch buffer. Grow and read more.
                None => {
                    buf.resize(buf.len() * 2, 0);
                    continue;
                }
            }
        };

        {
            let region = &buf[..end];
            let bounds = split_lines(region, threads);
            // 48 bytes is the average real-world record length; over-shooting a little is
            // cheaper than the realloc chain under-shooting causes.
            let per_slice_rows = region.len() / bounds.len().max(1) / 40 + 64;
            let mut shards: Vec<Shard> = (0..bounds.len()).map(|_| Shard::with_capacity(per_slice_rows)).collect();
            if shards.len() == 1 {
                parse_slice(region, whitelist, &mut shards[0]);
            } else {
                std::thread::scope(|scope| {
                    for (shard, &(a, b)) in shards.iter_mut().zip(bounds.iter()) {
                        let slice = &region[a..b];
                        scope.spawn(move || parse_slice(slice, whitelist, shard));
                    }
                });
            }

            for shard in &shards {
                local_to_global.clear();
                for (info, reference) in &shard.pairs {
                    let key = (info.to_string(), reference.to_string());
                    let idx = match pair_index.get(&key) {
                        Some(idx) => *idx,
                        None => {
                            let idx = builder.intern_pair(info, reference);
                            pair_index.insert(key, idx);
                            idx
                        }
                    };
                    local_to_global.push(idx);
                }
                for (trail, reference) in &shard.wildcards {
                    regex_builder.offer(trail, reference);
                }
                for (i, row) in shard.rows.iter().enumerate() {
                    if let Some(ahead) = shard.rows.get(i + PREFETCH_DISTANCE) {
                        builder.prefetch(ahead.hash);
                    }
                    builder.insert_prepared(&row.trail, row.hash, local_to_global[row.pair as usize], row.native);
                }
                stats.rows += shard.stats.rows;
                stats.loaded += shard.stats.loaded;
                stats.whitelisted += shard.stats.whitelisted;
                stats.malformed += shard.stats.malformed;
            }
        }

        buf.copy_within(end..filled, 0);
        filled -= end;
        if eof && filled == 0 {
            break;
        }
    }

    Ok((builder.finish(regex_builder.build()), stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        split_csv_record(line, &mut out);
        out
    }

    #[test]
    fn plain_records() {
        assert_eq!(split("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(split("evil.com,malware,(static)"), vec!["evil.com", "malware", "(static)"]);
    }

    #[test]
    fn quoted_records_match_python_csv() {
        assert_eq!(split(r#"a,"b,c",d"#), vec!["a", "b,c", "d"]);
        assert_eq!(split(r#"a,"b""c",d"#), vec!["a", "b\"c", "d"]);
        assert_eq!(split(r#""quoted",x,y"#), vec!["quoted", "x", "y"]);
        // a bare quote inside an unquoted field stays literal (non-strict mode)
        assert_eq!(split(r#"a"b,c,d"#), vec!["a\"b", "c", "d"]);
    }

    #[test]
    fn loads_a_temporary_csv() {
        let dir = std::env::temp_dir().join("mt-trail-load-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv");
        std::fs::write(
            &path,
            "evil.com,malware (test),(static)\n\
             1.2.3.4,badnet,(static)\n\
             1.2.3.4:8443,c2,(static)\n\
             dead::beef,badnet6,(static)\n\
             /malicious.php,malware (test),(static)\n\
             \"has,comma.com\",\"info, with comma\",(static)\n\
             127.0.0.1,should be whitelisted,(static)\n\
             short,row\n",
        )
        .unwrap();

        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
        let wl = Whitelist::load(&root, None);
        let (db, stats) = load_trails(&path, &wl, LoadOptions::default()).unwrap();

        assert_eq!(stats.malformed, 1, "the 2-column row must be skipped");
        assert!(stats.whitelisted >= 1, "127.0.0.1 is in data/whitelist.txt");
        assert_eq!(db.len(), stats.loaded);

        assert_eq!(db.get("evil.com").map(|v| v.info), Some("malware (test)"));
        assert_eq!(db.get("has,comma.com").map(|v| v.info), Some("info, with comma"));
        assert_eq!(db.get("/malicious.php").map(|v| v.reference), Some("(static)"));
        assert!(db.get("127.0.0.1").is_none());

        use crate::addr::{addr_to_int, parse_ipv6, Ip};
        let ip = Ip::V4(addr_to_int("1.2.3.4").unwrap());
        assert_eq!(db.get_ip(ip).map(|v| v.info), Some("badnet"));
        assert_eq!(db.get_ip_port(ip, 8443).map(|v| v.info), Some("c2"));
        assert!(db.get_ip_port(ip, 80).is_none());
        let v6 = Ip::V6(parse_ipv6("dead::beef").unwrap());
        assert_eq!(db.get_ip(v6).map(|v| v.info), Some("badnet6"));
    }

    #[test]
    fn line_boundaries_survive_the_batch_and_slice_cuts() {
        // `split_lines` is the one place a record can be torn in half. Every piece must start at
        // the beginning of a line and end just past a '\n'.
        let region = b"aaa\nbb\nc\ndddd\ne\n";
        for parts in 1..=8 {
            let bounds = split_lines(region, parts);
            assert_eq!(bounds.first().map(|b| b.0), Some(0), "parts={parts}");
            assert_eq!(bounds.last().map(|b| b.1), Some(region.len()), "parts={parts}");
            for (i, &(a, b)) in bounds.iter().enumerate() {
                assert!(a < b, "empty piece at {i}, parts={parts}");
                assert_eq!(region[b - 1], b'\n', "piece {i} does not end on a line, parts={parts}");
                if i > 0 {
                    assert_eq!(bounds[i - 1].1, a, "gap or overlap before piece {i}, parts={parts}");
                }
            }
            // Reassembling the pieces must give the region back, byte for byte.
            let rejoined: Vec<u8> = bounds.iter().flat_map(|&(a, b)| region[a..b].to_vec()).collect();
            assert_eq!(rejoined, region, "parts={parts}");
        }
        // A region of one line cannot be split, however many parts are asked for.
        assert_eq!(split_lines(b"only one line\n", 8), vec![(0, 14)]);
    }

    /// The awkward records, in the order a load must resolve them.
    const AWKWARD: &str = "dup.example,first info,(static)\n\
         1.2.3.4,badnet,(static)\n\
         \"has,comma.example\",\"info, with comma\",(static)\n\
         blank-follows.example,ok,(static)\n\
         \n\
         crlf.example,ok,(static)\r\n\
         1.2.3.4:8443,c2,(static)\n\
         dead::beef,badnet6,(static)\n\
         [dead::beef]:53,c26,(static)\n\
         evil.*\\.example,wildcard,(static)\n\
         two,fields\n\
         four,fields,here,too\n\
         dup.example,LAST info wins,(static)\n";

    /// Load the same records through the serial path and the parallel one and compare.
    ///
    /// The parallel loader only engages above `PARALLEL_MIN_BYTES`, so the two are reached by
    /// padding: the small file loads on one thread in one batch, the padded one crosses several
    /// 8 MB batches with eight slices each. The awkward records are re-emitted throughout the
    /// padding, so they land at slice cuts and batch cuts rather than only at the start.
    #[test]
    fn a_parallel_load_builds_the_same_store_as_a_serial_one() {
        let dir = std::env::temp_dir().join("mt-trail-parallel-test");
        std::fs::create_dir_all(&dir).unwrap();

        let small = dir.join("small.csv");
        std::fs::write(&small, AWKWARD).unwrap();

        // Comfortably over two batches. The padding keys are distinct so they cannot affect how
        // the awkward ones resolve.
        let big = dir.join("big.csv");
        let mut text = String::with_capacity(20 << 20);
        let mut pad = 0usize;
        while text.len() < (BATCH_BYTES * 2) + (BATCH_BYTES / 3) {
            for _ in 0..500 {
                text.push_str(&format!("pad-{pad}.example,padding,(static)\n"));
                pad += 1;
            }
            text.push_str(AWKWARD);
        }
        std::fs::write(&big, &text).unwrap();
        assert!(std::fs::metadata(&small).unwrap().len() < PARALLEL_MIN_BYTES as u64, "small must load serially");
        assert!(std::fs::metadata(&big).unwrap().len() > (BATCH_BYTES * 2) as u64, "big must cross batches");

        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
        let wl = Whitelist::load(&root, None);
        let (serial, sstats) = load_trails(&small, &wl, LoadOptions::default()).unwrap();
        let (parallel, pstats) = load_trails(&big, &wl, LoadOptions::default()).unwrap();

        // Every awkward record resolves identically on both paths.
        use crate::addr::{addr_to_int, parse_ipv6, Ip};
        for key in [
            "dup.example",
            "1.2.3.4",
            "has,comma.example",
            "blank-follows.example",
            "crlf.example",
            "1.2.3.4:8443",
            "dead::beef",
            "[dead::beef]:53",
            "evil.*\\.example",
        ] {
            let (a, b) = (serial.get(key), parallel.get(key));
            assert_eq!(a.map(|v| (v.info, v.reference)), b.map(|v| (v.info, v.reference)), "{key:?} differs");
            assert!(a.is_some(), "{key:?} was not loaded at all");
        }
        // Last row wins, on both paths — this is what forces the drain to stay in file order.
        assert_eq!(serial.get("dup.example").map(|v| v.info), Some("LAST info wins"));
        assert_eq!(parallel.get("dup.example").map(|v| v.info), Some("LAST info wins"));
        // ...and the quoted record is still split like Python's csv module.
        assert_eq!(parallel.get("has,comma.example").map(|v| v.info), Some("info, with comma"));

        let v4 = Ip::V4(addr_to_int("1.2.3.4").unwrap());
        let v6 = Ip::V6(parse_ipv6("dead::beef").unwrap());
        for db in [&serial, &parallel] {
            assert_eq!(db.get_ip(v4).map(|v| v.info), Some("badnet"));
            assert_eq!(db.get_ip_port(v4, 8443).map(|v| v.info), Some("c2"));
            assert_eq!(db.get_ip(v6).map(|v| v.info), Some("badnet6"));
            assert_eq!(db.get_ip_port(v6, 53).map(|v| v.info), Some("c26"));
            assert!(db.get_ip_port(v4, 80).is_none());
        }

        // The wildcard alternation is positional, so both paths must produce the same patterns in
        // the same order — the parallel one collects candidates per slice and replays them.
        assert_eq!(serial.regex().patterns(), &["evil.*\\.example"]);
        assert_eq!(parallel.regex().patterns()[0], "evil.*\\.example");

        // Statistics: 12 non-blank rows per copy, 2 of them malformed, 11 distinct keys.
        assert_eq!(sstats.rows, 12, "the blank line is not a row");
        assert_eq!(sstats.malformed, 2, "2-field and 4-field rows are both malformed");
        assert_eq!(sstats.loaded, 10);
        assert_eq!(serial.len(), 9, "dup.example is one key, written twice");

        let copies = text.matches("dup.example,first info").count();
        assert_eq!(pstats.rows, 12 * copies + pad, "every padded copy must be seen exactly once");
        assert_eq!(pstats.malformed, 2 * copies);
        assert_eq!(pstats.loaded, 10 * copies + pad);
        assert_eq!(parallel.len(), 9 + pad);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_longer_than_the_batch_buffer_still_loads() {
        // The batch buffer grows when a single line fills it, which is the one path in the reader
        // that can loop. A trails file with a pathologically long row must load, not hang.
        let dir = std::env::temp_dir().join("mt-trail-longline-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv");
        let long_key = "a".repeat(BATCH_BYTES + 4096);
        std::fs::write(&path, format!("{long_key},huge,(static)\nafter.example,ok,(static)\n")).unwrap();

        let (db, stats) = load_trails(&path, &Whitelist::default(), LoadOptions::default()).unwrap();
        assert_eq!(stats.rows, 2);
        assert_eq!(stats.loaded, 2);
        assert_eq!(db.get(&long_key).map(|v| v.info), Some("huge"));
        assert_eq!(db.get("after.example").map(|v| v.info), Some("ok"), "the row after the long one is not lost");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_with_no_trailing_newline_keeps_its_last_row() {
        let dir = std::env::temp_dir().join("mt-trail-notrailing-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv");
        std::fs::write(&path, "one.example,a,(static)\nlast.example,b,(static)").unwrap();
        let (db, stats) = load_trails(&path, &Whitelist::default(), LoadOptions::default()).unwrap();
        assert_eq!(stats.rows, 2);
        assert_eq!(db.get("last.example").map(|v| v.info), Some("b"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_utf8_is_replaced_the_way_python_reads_it() {
        // Python reads trails.csv with errors="replace", so a bad byte becomes U+FFFD and the row
        // still loads under that key. The parallel loader has to own such a row rather than
        // borrow it, which is the one place its two paths differ.
        let dir = std::env::temp_dir().join("mt-trail-utf8-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv");
        let mut bytes = b"bad".to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice(b".example,mangled,(static)\ngood.example,ok,(static)\n");
        std::fs::write(&path, &bytes).unwrap();

        let (db, stats) = load_trails(&path, &Whitelist::default(), LoadOptions::default()).unwrap();
        assert_eq!(stats.loaded, 2);
        assert_eq!(db.get("bad\u{fffd}.example").map(|v| v.info), Some("mangled"));
        assert_eq!(db.get("good.example").map(|v| v.info), Some("ok"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
