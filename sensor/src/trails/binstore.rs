//! The mmap-backed trail-store cache: `{trails.csv}.rsbin`.
//!
//! `write()` serializes a freshly CSV-built (Owned) `TrailDb` to this file; `open()` mmaps it
//! back into a `TrailDb` whose big tables read directly from the mapping instead of a per-
//! process heap copy. See `table.rs`'s mmap section for why that matters (file-backed pages are
//! reclaimable under memory pressure; anonymous heap pages are not).
//!
//! On-disk layout (all integers little-endian, fixed field order - do not reorder without
//! bumping `VERSION`):
//!
//!   magic        8 bytes  "MTSNSB1\0"
//!   version      u64
//!   total_len    u64      TrailDb::len() - the string table's distinct-key count
//!   str_cap      u64      StrTable slot-array capacity (power of two)
//!   str_fw       u64      StrTable filter, length in u64 words
//!   str_fm       u64      StrTable filter's own bit-mask (NOT cap - 1; see `NegativeFilter`)
//!   str_arena    u64      StrTable arena length, bytes
//!   ip4_cap/fw/fm/len     same four shapes, for the IPv4 table
//!   ip4p_cap/fw/fm/len    for the IPv4:port table
//!   ip6_cap/fw/fm/len     for the IPv6 table
//!   tail_len     u64      JSON tail blob length, bytes
//!   -- sections, back to back, in the order the fields above list them --
//!   str filter bits   (str_fw words)
//!   str slots         (str_cap * 16 bytes: tag:u32, off:u32, len:u32, val:u32)
//!   str arena         (str_arena bytes, raw key text)
//!   ip4 filter bits   (ip4_fw words)
//!   ip4 slots         (ip4_cap * 8 bytes: key:u32, val:u32)
//!   ip4p filter bits  (ip4p_fw words)
//!   ip4p slots        (ip4p_cap * 12 bytes: key:u64, val:u32)
//!   ip6 filter bits   (ip6_fw words)
//!   ip6 slots         (ip6_cap * 20 bytes: key:u128, val:u32)
//!   tail blob         (tail_len bytes, JSON - see `TailBlob`)
//!
//! Every slot (occupied or empty) is written in original slot-index order, sentinel value
//! `u32::MAX` for empty - this reproduces the exact open-addressing layout the Owned table had,
//! which is what lets the mapped read view replay the identical linear-probe sequence.
//!
//! The tail blob is JSON, not bincode: it is always small (interned pairs, a handful of IPv6:port
//! entries, the wildcard-regex source - never the multi-million-entry arrays above, which are
//! hand-packed binary instead), so the format doesn't matter for size, and JSON is trivially
//! inspectable when something goes wrong with a cache file in the field.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::regexset::TrailRegex;
use super::table::{IntTable, MappedIntTable, MappedKeyWidth, MappedStrTable, StrTable};
use super::{IntBacking128, IntBacking32, IntBacking64, StrBacking, TrailDb};

const MAGIC: &[u8; 8] = b"MTSNSB1\0";
const VERSION: u64 = 1;
const HEADER_FIELDS_AFTER_MAGIC: usize = 19; // version, total_len, 4*(str) is 4, 4*3 int tables is 12, tail_len = 2+4+12+1
const HEADER_SIZE: usize = 8 + HEADER_FIELDS_AFTER_MAGIC * 8;

#[derive(serde::Serialize, serde::Deserialize)]
struct TailBlob {
    pairs: Vec<(String, String)>,
    /// (ip_hi, ip_lo, port, pair_index) - u128 split into two u64 halves for JSON portability.
    ip6_port: Vec<(u64, u64, u16, u32)>,
    regex_source: String,
    regex_patterns: Vec<String>,
    regex_skipped: Vec<String>,
    regex_repaired: Vec<String>,
    regex_fancy: bool,
}

pub fn cache_path(trails_csv: &Path) -> PathBuf {
    let mut p = trails_csv.as_os_str().to_os_string();
    p.push(".rsbin");
    PathBuf::from(p)
}

/// The same staleness rule `core/common.py:trails_bin_stale()` uses for its own (Python-side,
/// server-process) binary trail cache: valid iff not older than `trails.csv`.
pub fn is_fresh(cache: &Path, csv: &Path) -> bool {
    let cache_m = std::fs::metadata(cache).and_then(|m| m.modified());
    let csv_m = std::fs::metadata(csv).and_then(|m| m.modified());
    match (cache_m, csv_m) {
        (Ok(c), Ok(s)) => c >= s,
        _ => false,
    }
}

fn invalid(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

#[inline]
fn w_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn r_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// Appends one `StrTable`'s filter bits, slots (every slot, empty ones included - see module
/// doc) and arena to `buf`. Returns (cap, filter_words, filter_mask, arena_len).
fn write_str_table(buf: &mut Vec<u8>, t: &StrTable) -> (u64, u64, u64, u64) {
    let filter_bits = t.raw_filter_bits();
    for w in filter_bits {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let cap = t.raw_mask() + 1;
    t.for_each_raw_slot(|slot| match slot {
        None => {
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        Some((tag, off, len, val)) => {
            buf.extend_from_slice(&tag.to_le_bytes());
            buf.extend_from_slice(&off.to_le_bytes());
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&val.to_le_bytes());
        }
    });
    buf.extend_from_slice(t.raw_arena());
    (cap as u64, filter_bits.len() as u64, t.raw_filter_mask() as u64, t.raw_arena().len() as u64)
}

/// Appends one `IntTable<u32>`'s filter bits and slots. Returns (cap, filter_words, filter_mask, len).
fn write_int_table_u32(buf: &mut Vec<u8>, t: &IntTable<u32>) -> (u64, u64, u64, u64) {
    let filter_bits = t.raw_filter_bits();
    for w in filter_bits {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let cap = t.raw_mask() + 1;
    t.for_each_raw_slot(|slot| match slot {
        None => {
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        Some((k, v)) => {
            buf.extend_from_slice(&k.to_le_bytes());
            buf.extend_from_slice(&v.to_le_bytes());
        }
    });
    (cap as u64, filter_bits.len() as u64, t.raw_filter_mask() as u64, t.len() as u64)
}

fn write_int_table_u64(buf: &mut Vec<u8>, t: &IntTable<u64>) -> (u64, u64, u64, u64) {
    let filter_bits = t.raw_filter_bits();
    for w in filter_bits {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let cap = t.raw_mask() + 1;
    t.for_each_raw_slot(|slot| match slot {
        None => {
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        Some((k, v)) => {
            buf.extend_from_slice(&k.to_le_bytes());
            buf.extend_from_slice(&v.to_le_bytes());
        }
    });
    (cap as u64, filter_bits.len() as u64, t.raw_filter_mask() as u64, t.len() as u64)
}

fn write_int_table_u128(buf: &mut Vec<u8>, t: &IntTable<u128>) -> (u64, u64, u64, u64) {
    let filter_bits = t.raw_filter_bits();
    for w in filter_bits {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let cap = t.raw_mask() + 1;
    t.for_each_raw_slot(|slot| match slot {
        None => {
            buf.extend_from_slice(&0u128.to_le_bytes());
            buf.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        Some((k, v)) => {
            buf.extend_from_slice(&k.to_le_bytes());
            buf.extend_from_slice(&v.to_le_bytes());
        }
    });
    (cap as u64, filter_bits.len() as u64, t.raw_filter_mask() as u64, t.len() as u64)
}

/// Serializes `db` (which must be the Owned/CSV-built variant - the only caller is right after
/// a fresh build) to `path`, atomically (temp file + rename, same pattern used throughout this
/// project's Python side for trails.csv itself).
pub fn write(path: &Path, db: &TrailDb) -> std::io::Result<()> {
    let (strings, ip4, ip4_port, ip6) = match (&db.strings, &db.ip4, &db.ip4_port, &db.ip6) {
        (StrBacking::Owned(s), IntBacking32::Owned(a), IntBacking64::Owned(b), IntBacking128::Owned(c)) => (s, a, b, c),
        _ => return Err(invalid("write() called on a TrailDb that is not CSV-built (already mmap-backed)")),
    };

    let mut body = Vec::new();
    let (str_cap, str_fw, str_fm, str_arena_len) = write_str_table(&mut body, strings);
    let (ip4_cap, ip4_fw, ip4_fm, ip4_len) = write_int_table_u32(&mut body, ip4);
    let (ip4p_cap, ip4p_fw, ip4p_fm, ip4p_len) = write_int_table_u64(&mut body, ip4_port);
    let (ip6_cap, ip6_fw, ip6_fm, ip6_len) = write_int_table_u128(&mut body, ip6);

    let tail = TailBlob {
        pairs: db.pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
        ip6_port: db.ip6_port.iter().map(|(&(ip, port), &val)| ((ip >> 64) as u64, ip as u64, port, val)).collect(),
        regex_source: db.regex.source().to_string(),
        regex_patterns: db.regex.patterns().to_vec(),
        regex_skipped: db.regex.skipped().to_vec(),
        regex_repaired: db.regex.repaired().to_vec(),
        regex_fancy: db.regex.uses_backtracking(),
    };
    let tail_bytes = serde_json::to_vec(&tail).map_err(|e| invalid(format!("tail blob encode failed: {e}")))?;
    body.extend_from_slice(&tail_bytes);

    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(MAGIC);
    w_u64(&mut header, VERSION);
    w_u64(&mut header, db.len as u64);
    w_u64(&mut header, str_cap);
    w_u64(&mut header, str_fw);
    w_u64(&mut header, str_fm);
    w_u64(&mut header, str_arena_len);
    w_u64(&mut header, ip4_cap);
    w_u64(&mut header, ip4_fw);
    w_u64(&mut header, ip4_fm);
    w_u64(&mut header, ip4_len);
    w_u64(&mut header, ip4p_cap);
    w_u64(&mut header, ip4p_fw);
    w_u64(&mut header, ip4p_fm);
    w_u64(&mut header, ip4p_len);
    w_u64(&mut header, ip6_cap);
    w_u64(&mut header, ip6_fw);
    w_u64(&mut header, ip6_fm);
    w_u64(&mut header, ip6_len);
    w_u64(&mut header, tail_bytes.len() as u64);
    debug_assert_eq!(header.len(), HEADER_SIZE);

    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = PathBuf::from(tmp_name);
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(&header)?;
        f.write_all(&body)?;
    }
    std::fs::rename(&tmp_path, path)
}

/// Opens and mmaps a cache file written by `write()`, returning a `TrailDb` whose big tables
/// read from the mapping. Fails (never panics) on a missing, truncated, wrong-version, or
/// corrupt file - the caller falls back to the normal CSV loader in every such case.
pub fn open(path: &Path) -> std::io::Result<TrailDb> {
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };

    if mmap.len() < HEADER_SIZE {
        return Err(invalid("trail store cache too small"));
    }
    if &mmap[0..8] != MAGIC {
        return Err(invalid("trail store cache: bad magic"));
    }
    let mut off = 8;
    let mut next = || {
        let v = r_u64(&mmap, off);
        off += 8;
        v
    };
    let version = next();
    if version != VERSION {
        return Err(invalid(format!("trail store cache: version {version}, expected {VERSION}")));
    }
    let total_len = next();
    let str_cap = next();
    let str_fw = next();
    let str_fm = next();
    let str_arena_len = next();
    let ip4_cap = next();
    let ip4_fw = next();
    let ip4_fm = next();
    let ip4_len = next();
    let ip4p_cap = next();
    let ip4p_fw = next();
    let ip4p_fm = next();
    let ip4p_len = next();
    let ip6_cap = next();
    let ip6_fw = next();
    let ip6_fm = next();
    let ip6_len = next();
    let tail_len = next();
    debug_assert_eq!(off, HEADER_SIZE);

    let mut pos = HEADER_SIZE;
    let str_filter_off = pos;
    pos += str_fw as usize * 8;
    let str_slots_off = pos;
    pos += str_cap as usize * 16;
    let str_arena_off = pos;
    pos += str_arena_len as usize;

    let ip4_filter_off = pos;
    pos += ip4_fw as usize * 8;
    let ip4_slots_off = pos;
    pos += ip4_cap as usize * 8;

    let ip4p_filter_off = pos;
    pos += ip4p_fw as usize * 8;
    let ip4p_slots_off = pos;
    pos += ip4p_cap as usize * 12;

    let ip6_filter_off = pos;
    pos += ip6_fw as usize * 8;
    let ip6_slots_off = pos;
    pos += ip6_cap as usize * 20;

    let tail_off = pos;
    pos += tail_len as usize;

    if mmap.len() < pos {
        return Err(invalid(format!("trail store cache truncated (have {}, need {pos})", mmap.len())));
    }

    let tail: TailBlob = serde_json::from_slice(&mmap[tail_off..tail_off + tail_len as usize])
        .map_err(|e| invalid(format!("trail store cache: bad tail blob ({e})")))?;

    let pairs: Vec<(Box<str>, Box<str>)> =
        tail.pairs.into_iter().map(|(a, b)| (a.into_boxed_str(), b.into_boxed_str())).collect();

    let mut ip6_port = crate::fasthash::FastMap::default();
    for (hi, lo, port, val) in tail.ip6_port {
        let ip = ((hi as u128) << 64) | lo as u128;
        ip6_port.insert((ip, port), val);
    }

    let regex = TrailRegex::from_parts(
        tail.regex_source,
        tail.regex_patterns,
        tail.regex_skipped,
        tail.regex_repaired,
        tail.regex_fancy,
    );

    let mmap = Arc::new(mmap);

    let strings = MappedStrTable {
        mmap: mmap.clone(),
        filter_off: str_filter_off,
        filter_mask: str_fm as usize,
        slots_off: str_slots_off,
        cap: str_cap as usize,
        mask: str_cap as usize - 1,
        arena_off: str_arena_off,
        arena_len: str_arena_len as usize,
        len: total_len as usize,
    };
    let ip4 = MappedIntTable {
        mmap: mmap.clone(),
        filter_off: ip4_filter_off,
        filter_mask: ip4_fm as usize,
        slots_off: ip4_slots_off,
        cap: ip4_cap as usize,
        mask: ip4_cap as usize - 1,
        len: ip4_len as usize,
        width: MappedKeyWidth::U32,
    };
    let ip4_port = MappedIntTable {
        mmap: mmap.clone(),
        filter_off: ip4p_filter_off,
        filter_mask: ip4p_fm as usize,
        slots_off: ip4p_slots_off,
        cap: ip4p_cap as usize,
        mask: ip4p_cap as usize - 1,
        len: ip4p_len as usize,
        width: MappedKeyWidth::U64,
    };
    let ip6 = MappedIntTable {
        mmap: mmap.clone(),
        filter_off: ip6_filter_off,
        filter_mask: ip6_fm as usize,
        slots_off: ip6_slots_off,
        cap: ip6_cap as usize,
        mask: ip6_cap as usize - 1,
        len: ip6_len as usize,
        width: MappedKeyWidth::U128,
    };

    Ok(TrailDb::from_mapped(pairs, strings, ip4, ip4_port, ip6, ip6_port, regex, total_len as usize))
}

#[cfg(test)]
mod tests {
    use super::super::regexset::TrailRegexBuilder;
    use super::super::TrailDbBuilder;
    use super::*;

    fn build(entries: &[(&str, &str, &str)]) -> TrailDb {
        let mut b = TrailDbBuilder::new(entries.len(), 256);
        let mut rb = TrailRegexBuilder::default();
        for (trail, info, reference) in entries {
            let pair = b.intern_pair(info, reference);
            rb.offer(trail, reference);
            b.insert(trail, pair);
        }
        b.finish(rb.build())
    }

    #[test]
    fn round_trip_preserves_every_lookup() {
        let entries: &[(&str, &str, &str)] = &[
            ("1.2.3.4", "malware", "(static)"),
            ("1.2.3.4:443", "c2", "(static)"),
            ("dead::beef", "badnet6", "(static)"),
            ("[dead::beef]:53", "c26", "(static)"),
            ("evil.example", "phishing", "(custom)"),
            ("evil.*", "wildcard", "(static)"),
        ];
        let db = build(entries);
        let dir = std::env::temp_dir().join(format!("trailsbin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv.rsbin");
        write(&path, &db).unwrap();
        let mapped = open(&path).unwrap();

        assert_eq!(mapped.len(), db.len());
        assert!(mapped.contains("1.2.3.4"));
        assert!(mapped.contains("evil.example"));
        assert!(!mapped.contains("nope.example"));
        assert_eq!(mapped.get("1.2.3.4").map(|t| t.info), Some("malware"));
        assert_eq!(mapped.get("evil.example").map(|t| t.info), Some("phishing"));

        use crate::addr::{addr_to_int, parse_ipv6, Ip};
        let v4 = Ip::V4(addr_to_int("1.2.3.4").unwrap());
        let v6 = Ip::V6(parse_ipv6("dead::beef").unwrap());
        assert_eq!(mapped.get_ip(v4).map(|t| t.info), Some("malware"));
        assert_eq!(mapped.get_ip_port(v4, 443).map(|t| t.info), Some("c2"));
        assert_eq!(mapped.get_ip(v6).map(|t| t.info), Some("badnet6"));
        assert_eq!(mapped.get_ip_port(v6, 53).map(|t| t.info), Some("c26"));

        assert!(!mapped.regex().is_empty());
        assert_eq!(mapped.regex().patterns(), db.regex().patterns());
        // "evil.*" legitimately matches the "evil.org" substring of this query - the regex
        // round-tripped correctly, and this checks the mapped copy agrees with the original.
        let original_hit = db.regex().find("www.evil.org");
        let mapped_hit = mapped.regex().find("www.evil.org");
        assert_eq!(original_hit.as_ref().map(|h| h.candidate), mapped_hit.map(|h| h.candidate));
        assert_eq!(original_hit.map(|h| h.candidate), Some("evil.*"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_check() {
        let dir = std::env::temp_dir().join(format!("trailsbin-fresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("trails.csv");
        std::fs::write(&csv, "1.2.3.4,malware,(static)\n").unwrap();
        let cache = cache_path(&csv);
        assert!(!is_fresh(&cache, &csv)); // cache does not exist yet

        let db = build(&[("1.2.3.4", "malware", "(static)")]);
        write(&cache, &db).unwrap();
        assert!(is_fresh(&cache, &csv));

        // touch the csv forward in time -> cache is now stale
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&csv, "1.2.3.4,malware,(static)\nmore,data,(static)\n").unwrap();
        assert!(!is_fresh(&cache, &csv));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
