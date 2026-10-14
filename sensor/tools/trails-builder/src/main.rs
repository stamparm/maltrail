// trails-builder: streaming replacement for maltrail's core/update.py::update_trails()
// static-aggregate merge step.
//
// Why this exists: fetch_static_trails()/update_trails() build one Python dict holding
// every trail (the static aggregate alone is ~1.6M entries) before writing trails.csv.
// On a 221MB-RAM host that dict alone exceeds physical memory. This binary gets the same
// *output* without ever building that dict in Python: Python just writes RAW, UNMERGED
// rows for feeds+custom+local-static (one feed's dict at a time, never all of them
// combined - see sensor/tools/update_trails.py; a single feed alone can run 25-45k
// entries, so "small" is relative, not literally small), and this binary resolves
// cross-source precedence itself via merge_one() as it streams the small CSV in, then
// streams the static aggregate the same way. Peak memory is O(feeds+custom+local-static
// combined, held compactly in Rust) + O(one static row at a time), not O(1.6M Python
// dict entries).
//
// Network fetch/caching/sha256 verification of the static aggregate stays in Python
// (core/update.py::fetch_static_trails is reused unmodified for that) - this binary only
// consumes the already-decompressed, already-verified CSV it leaves on disk.
//
// Merge precedence and the cleanup/filter pipeline below are a direct line-by-line port of
// core/update.py::update_trails()'s `_merge` closure and its two post-processing loops.
// Keep it that way: this is security-relevant filtering (whitelist/bogon/CDN), not a place
// to "simplify" without checking against the Python original.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

const LOW_PRIORITY_INFO_KEYWORDS: &[&str] = &[
    "reputation", "attacker", "spammer", "abuser", "malicious", "dnspod", "nicru",
    "crawler", "compromised", "bad history",
];
const HIGH_PRIORITY_INFO_KEYWORDS: &[&str] = &["mass scanner", "ipinfo"];
const HIGH_PRIORITY_REFERENCES: &[&str] = &["(static)", "(custom)"];
const BAD_TRAIL_PREFIXES: &[&str] = &["127.", "192.168.", "localhost"];

struct Args {
    small_csv: String,
    static_csv: String,
    data_dir: String,
    user_whitelist: Option<String>,
    output: String,
    ip_minimum_feeds: usize,
}

fn parse_args() -> Args {
    let mut a = Args {
        small_csv: String::new(),
        static_csv: String::new(),
        data_dir: String::new(),
        user_whitelist: None,
        output: String::new(),
        ip_minimum_feeds: 3,
    };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--small" => { a.small_csv = args[i + 1].clone(); i += 2; }
            "--static" => { a.static_csv = args[i + 1].clone(); i += 2; }
            "--data-dir" => { a.data_dir = args[i + 1].clone(); i += 2; }
            "--user-whitelist" => { a.user_whitelist = Some(args[i + 1].clone()); i += 2; }
            "--output" => { a.output = args[i + 1].clone(); i += 2; }
            "--ip-minimum-feeds" => { a.ip_minimum_feeds = args[i + 1].parse().unwrap_or(3); i += 2; }
            _ => { i += 1; }
        }
    }
    a
}

fn addr_to_int(value: &str) -> Option<u32> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() < 4 {
        return None;
    }
    let mut v: u32 = 0;
    for p in &parts[0..4] {
        let n: u64 = p.parse().ok()?;
        v = v.wrapping_shl(8).wrapping_add((n & 0xff) as u32); // truncating, matches Python's masked comparisons downstream
    }
    Some(v)
}

fn make_mask(bits: u32) -> u32 {
    if bits == 0 { return 0; }
    0xffff_ffffu32 ^ ((1u32.wrapping_shl(32 - bits)).wrapping_sub(1))
}

struct RangeSet {
    buckets: HashMap<String, Vec<(u32, u32)>>,
}
impl RangeSet {
    fn new() -> Self { RangeSet { buckets: HashMap::new() } }
    fn load(path: &str) -> std::io::Result<Self> {
        let mut rs = RangeSet::new();
        let f = match File::open(path) { Ok(f) => f, Err(_) => return Ok(rs) };
        for line in BufReader::new(f).lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let key = line.split('.').next().unwrap_or("").to_string();
            if let Some((prefix, mask)) = line.split_once('/') {
                if let (Some(p), Ok(m)) = (addr_to_int(prefix), mask.parse::<u32>()) {
                    let mask_val = make_mask(m);
                    rs.buckets.entry(key).or_default().push((p & mask_val, mask_val));
                }
            }
        }
        Ok(rs)
    }
    fn contains(&self, address: &str) -> bool {
        let key = match address.split('.').next() { Some(k) => k, None => return false };
        let addr = match addr_to_int(address) { Some(a) => a, None => return false };
        if let Some(ranges) = self.buckets.get(key) {
            for (prefix, mask) in ranges {
                if addr & mask == *prefix { return true; }
            }
        }
        false
    }
}

struct Whitelist {
    literal: HashSet<String>,
    ranges: Vec<(u32, u32)>,
    ipv4_only: Regex,
}
impl Whitelist {
    fn load(data_dir: &str, user_whitelist: &Option<String>) -> std::io::Result<Self> {
        let mut literal = HashSet::new();
        let mut ranges = Vec::new();
        let cidr_re = Regex::new(r"^\d+\.\d+\.\d+\.\d+/\d+$").unwrap();
        let mut paths = vec![format!("{}/whitelist.txt", data_dir)];
        if let Some(u) = user_whitelist { paths.push(u.clone()); }
        for path in paths {
            let f = match File::open(&path) { Ok(f) => f, Err(_) => continue };
            for line in BufReader::new(f).lines() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if cidr_re.is_match(line) {
                    if let Some((prefix, mask)) = line.split_once('/') {
                        if let (Some(p), Ok(m)) = (addr_to_int(prefix), mask.parse::<u32>()) {
                            let mask_val = make_mask(m);
                            ranges.push((p & mask_val, mask_val));
                            continue;
                        }
                    }
                    literal.insert(line.to_string());
                } else {
                    literal.insert(line.to_string());
                }
            }
        }
        Ok(Whitelist { literal, ranges, ipv4_only: Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}$").unwrap() })
    }
    fn contains(&self, trail: &str) -> bool {
        if self.literal.contains(trail) { return true; }
        if self.ipv4_only.is_match(trail) {
            if let Some(addr) = addr_to_int(trail) {
                for (prefix, mask) in &self.ranges {
                    if addr & mask == *prefix { return true; }
                }
            }
        }
        false
    }
}

fn leading_ipv4(value: &str, re: &Regex) -> Option<String> {
    if value.is_empty() || !value.as_bytes()[0].is_ascii_digit() { return None; }
    re.captures(value).map(|c| c[1].to_string())
}

fn confidence_score(reference: &str, agreeing_sources: usize) -> u32 {
    if reference.contains("custom") || reference.contains("static") { return 100; }
    let bounded = agreeing_sources.min(4);
    (40 + 15 * bounded).min(100) as u32
}

/// Port of update_trails()'s `_merge` closure: decides whether an incoming (key,info,reference)
/// wins over whatever `trails` already holds for that key, and records cross-source duplicates.
fn merge_one(
    mut key: String, info: String, reference: String,
    trails: &mut HashMap<String, (String, String)>,
    duplicates: &mut HashMap<String, HashSet<String>>,
) {
    if key.starts_with("www.") && !key.contains('/') {
        key = key[4..].to_string();
    }
    let existing = trails.get(&key).cloned();
    if let Some(ref e) = existing {
        let set = duplicates.entry(key.clone()).or_insert_with(|| {
            let mut s = HashSet::new();
            s.insert(e.1.clone());
            s
        });
        set.insert(reference.clone());
    }
    let key_exists = existing.is_some();
    let new_has_low = LOW_PRIORITY_INFO_KEYWORDS.iter().any(|k| info.contains(k));
    let existing_is_high_ref = existing.as_ref().map_or(false, |e| HIGH_PRIORITY_REFERENCES.contains(&e.1.as_str()));
    let cond1 = !(key_exists && (new_has_low || existing_is_high_ref));
    let cond2 = HIGH_PRIORITY_REFERENCES.contains(&reference.as_str()) && !info.contains("history");
    let cond3 = HIGH_PRIORITY_INFO_KEYWORDS.iter().any(|k| info.contains(k));
    if cond1 || cond2 || cond3 {
        trails.insert(key, (info, reference));
    }
}

struct Filters {
    alpha_only: Regex,
    ipv4_exact: Regex,
    leading_ipv4: Regex,
    whitelist: Whitelist,
    bogon: RangeSet,
    cdn: RangeSet,
    ip_minimum_feeds: usize,
}

/// Port of update_trails()'s two post-processing loops, applied to one already-merge-resolved
/// (key, info, reference) triple. Returns None if the Python original would have deleted it.
fn cleanup_and_filter(
    key: String, info: String, reference: String,
    duplicates: &HashMap<String, HashSet<String>>,
    f: &Filters,
) -> Option<(String, String, String)> {
    let mut key = key;
    let mut info = info;
    let mut reference = reference;

    // ascii-lowercase normalization (idna/punycode for non-ascii is approximated with
    // Unicode-aware lowercasing - true idna only matters for the rare non-ASCII phishing
    // domain case, and Rust's to_lowercase() still normalizes case correctly there)
    let lowered = key.to_lowercase();
    if lowered != key { key = lowered; }

    let is_custom_or_static = reference.contains("custom") || reference.contains("static");
    if key.is_empty() || (f.alpha_only.is_match(&key) && !is_custom_or_static) {
        return None;
    }

    if f.ipv4_exact.is_match(&key) {
        if info == "malware" {
            info = "potential malware site".to_string();
        }
        if f.ip_minimum_feeds > 1 {
            let dup_count = duplicates.get(&key).map_or(0, |s| s.len());
            if dup_count < f.ip_minimum_feeds && !is_custom_or_static {
                return None;
            }
        }
        if key.split('.').any(|p| p.parse::<u32>().map_or(true, |n| n > 255)) {
            return None;
        }
    }

    if info == "ransomware" {
        info = "ransomware (malware)".to_string();
    }

    if key.starts_with("www.") && !key.contains('/') {
        key = key[4..].to_string();
        if key.is_empty() { return None; }
    }

    if key.contains('?') && !key.starts_with('/') {
        key = key.split('?').next().unwrap_or("").to_string();
        if key.is_empty() { return None; }
    }

    if key.contains("//") {
        key = key.replace("//", "/");
    }

    let lowered = key.to_lowercase();
    if lowered != key { key = lowered; }

    if let Some(set) = duplicates.get(&key) {
        let mut others: Vec<&str> = set.iter().filter(|r| r.as_str() != reference).map(|s| s.as_str()).collect();
        others.sort_unstable();
        if !others.is_empty() && !reference.contains(" (+") {
            reference = format!("{} (+{})", reference, others.join(","));
        }
    }

    // second pass: whitelist / bad-prefix / bogon / cdn
    if f.whitelist.contains(&key) || BAD_TRAIL_PREFIXES.iter().any(|p| key.starts_with(p)) {
        return None;
    }
    if let Some(address) = leading_ipv4(&key, &f.leading_ipv4) {
        let is_parking_or_sinkhole = info.contains("parking") || info.contains("sinkhole");
        if !is_parking_or_sinkhole && (f.bogon.contains(&address) || f.cdn.contains(&address)) {
            return None;
        }
    }

    Some((key, info, reference))
}

fn main() -> std::io::Result<()> {
    let args = parse_args();

    // 1. stream the small CSV (feeds+custom+local-static+remote-custom, RAW/unmerged - Python
    //    no longer resolves precedence itself, see sensor/tools/update_trails.py) through the
    //    same merge_one() precedence rule static rows get below. This is what makes a
    //    duplicate key from two different feeds resolve the same way it always did, and is
    //    where `duplicates` (used for confidence scoring) actually gets populated now.
    let mut trails: HashMap<String, (String, String)> = HashMap::new();
    let mut duplicates: HashMap<String, HashSet<String>> = HashMap::new();

    if !args.small_csv.is_empty() {
        let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_path(&args.small_csv)?;
        let mut small_rows: u64 = 0;
        for result in rdr.records() {
            let record = result?;
            if record.len() == 3 {
                small_rows += 1;
                merge_one(record[0].to_string(), record[1].to_string(), record[2].to_string(), &mut trails, &mut duplicates);
            }
        }
        eprintln!("[i] small-source raw rows: {}", small_rows);
    }

    eprintln!("[i] baseline (feeds+custom+local-static) after merge: {} keys", trails.len());

    let filters = Filters {
        alpha_only: Regex::new(r"^(?i)\.?[a-z]+$").unwrap(),
        ipv4_exact: Regex::new(r"^\d+\.\d+\.\d+\.\d+$").unwrap(),
        leading_ipv4: Regex::new(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:[:/ ]|$)").unwrap(),
        whitelist: Whitelist::load(&args.data_dir, &args.user_whitelist)?,
        bogon: RangeSet::load(&format!("{}/bogon_ranges.txt", args.data_dir))?,
        cdn: RangeSet::load(&format!("{}/cdn_ranges.txt", args.data_dir))?,
        ip_minimum_feeds: args.ip_minimum_feeds,
    };

    let tmp_output = format!("{}.new", args.output);
    let tmp_confidence = format!("{}.confidence.new", args.output);
    let out_f = BufWriter::new(File::create(&tmp_output)?);
    let mut writer = csv::WriterBuilder::new().from_writer(out_f);
    let mut conf_f = BufWriter::new(File::create(&tmp_confidence)?);

    let mut written: u64 = 0;

    // 2. stream the static aggregate: resolve merge precedence against the small baseline,
    //    then run it through the identical cleanup/filter pipeline, writing survivors straight out
    if !args.static_csv.is_empty() {
        let static_file = File::open(&args.static_csv)?;
        let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(BufReader::new(static_file));
        let mut count: u64 = 0;
        for result in rdr.records() {
            let record = match result { Ok(r) => r, Err(_) => continue };
            count += 1;
            if count % 200_000 == 0 {
                eprintln!("[i] static rows processed: {}", count);
            }
            if record.len() != 3 { continue; }
            let raw_key = record[0].to_string();
            let info = record[1].to_string();
            let reference = record[2].to_string();

            merge_one(raw_key.clone(), info.clone(), reference.clone(), &mut trails, &mut duplicates);

            // did the static entry just become (or already was, and stays) the winner for this key?
            let winner_key = if raw_key.starts_with("www.") && !raw_key.contains('/') {
                raw_key[4..].to_string()
            } else {
                raw_key.clone()
            };
            let now = trails.get(&winner_key);
            let static_is_winner = now.map_or(false, |v| *v == (info.clone(), reference.clone()));

            if static_is_winner {
                // remove from baseline now - it'll be written here, not in the baseline flush below
                trails.remove(&winner_key);
                let dup_count = duplicates.get(&winner_key).map_or(0, |s| s.len());
                if let Some((k, i, r)) = cleanup_and_filter(winner_key, info, reference, &duplicates, &filters) {
                    writer.write_record(&[&k, &i, &r])?;
                    writeln!(conf_f, "{}\t{}", k, confidence_score(&r, dup_count))?;
                    written += 1;
                }
            }
        }
        eprintln!("[i] static rows total: {}", count);
    } else {
        eprintln!("[!] no static aggregate supplied - only feeds/custom/local-static will be in trails.csv");
    }

    // 3. flush whatever's left in the baseline (feeds/custom/local-static entries that never
    //    lost to a static collision, plus any that won against static)
    let remaining: Vec<(String, (String, String))> = trails.into_iter().collect();
    for (key, (info, reference)) in remaining {
        let dup_count = duplicates.get(&key).map_or(0, |s| s.len());
        if let Some((k, i, r)) = cleanup_and_filter(key, info, reference, &duplicates, &filters) {
            writer.write_record(&[&k, &i, &r])?;
            writeln!(conf_f, "{}\t{}", k, confidence_score(&r, dup_count))?;
            written += 1;
        }
    }

    writer.flush()?;
    conf_f.flush()?;
    std::fs::rename(&tmp_output, &args.output)?;
    std::fs::rename(&tmp_confidence, &format!("{}.confidence", args.output))?;

    eprintln!("[i] trails written: {}", written);
    Ok(())
}
