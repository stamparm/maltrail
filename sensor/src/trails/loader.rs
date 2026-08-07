//! Trail CSV loading — `core/common.py:load_trails()`.
//!
//! Reads `TRAILS_FILE` (the existing, unchanged Maltrail CSV: `trail,info,reference`),
//! drops whitelisted trails, interns the `(info, reference)` pairs and builds the
//! lookup tables plus the wildcard-trail regex, in CSV order (which is the order Python
//! iterates, and therefore the order the regex groups get).

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::regexset::TrailRegexBuilder;
use super::{TrailDb, TrailDbBuilder};
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

/// `load_trails()`. Returns the store plus load statistics for startup diagnostics.
///
/// The file is STREAMED rather than slurped: a real trails.csv is ~75 MB, and reading it whole
/// would add that much to peak RSS on top of the tables being built. Lines are read into one
/// reused buffer, so the loader allocates per *trail*, not per file.
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
    let mut fields: Vec<String> = Vec::with_capacity(4);
    let mut stats = LoadStats { rows: 0, loaded: 0, whitelisted: 0, malformed: 0 };

    let mut raw: Vec<u8> = Vec::with_capacity(256);
    loop {
        raw.clear();
        let read = reader.read_until(b'\n', &mut raw)?;
        if read == 0 {
            break;
        }
        while matches!(raw.last(), Some(b'\n') | Some(b'\r')) {
            raw.pop();
        }
        if raw.is_empty() {
            continue;
        }
        stats.rows += 1;

        let line = String::from_utf8_lossy(&raw);
        // Fast path: the overwhelming majority of rows have no quoting.
        let (trail, info, reference) = if raw.contains(&b'"') {
            if split_csv_record(&line, &mut fields) != 3 {
                stats.malformed += 1;
                continue;
            }
            (fields[0].as_str(), fields[1].as_str(), fields[2].as_str())
        } else {
            let mut it = line.splitn(3, ',');
            match (it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c)) if !c.contains(',') => (a, b, c),
                _ => {
                    stats.malformed += 1;
                    continue;
                }
            }
        };

        if whitelist.check_whitelisted(trail) {
            stats.whitelisted += 1;
            continue;
        }

        let pair = match pair_index.get(&(info.to_string(), reference.to_string())) {
            Some(idx) => *idx,
            None => {
                let idx = builder.intern_pair(info, reference);
                pair_index.insert((info.to_string(), reference.to_string()), idx);
                idx
            }
        };

        regex_builder.offer(trail, reference);
        builder.insert(trail, pair);
        stats.loaded += 1;
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
        assert!(stats.whitelisted >= 1, "127.0.0.1 is in misc/whitelist.txt");
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
}
