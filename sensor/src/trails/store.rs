//! The prebuilt trail store: `<TRAILS_FILE>.store`, the tables `loader.rs` builds, kept on disk.
//!
//! Parsing a 1.9M-row `trails.csv` is ~0.4 s on a desktop and several seconds on a Raspberry Pi,
//! and the sensor did it on every start, every `-T` and every reload. The tables it builds are
//! already position-independent - string slots point into the key arena by offset, integer slots
//! hold their keys - so they can be written out once and mapped back read-only, which costs a page
//! table and nothing else. The mapped pages are page cache: they cost what the box can spare, and a
//! reload that replaces the file leaves the store in use intact until its last reader drops it.
//!
//! It is a CACHE of the CSV, never a source. A store is used only when its header proves it was
//! built from exactly this CSV (size, mtime AND content hash), with exactly this whitelist (rows
//! are whitelisted at load), with the same `REPAIR_TRUNCATED_TRAILS`, by a build with the same table
//! layout and the same hash functions. Anything else - including a store that is merely damaged -
//! is a miss, and the CSV is parsed exactly as before. A store that answered for yesterday's CSV
//! would be the worst kind of failure here: a sensor that starts, reports healthy, and does not
//! detect what was added today. That is what every check below is for; none of them is optional.
//!
//! Layout (native byte order, recorded and checked): a 4096-byte header of 64 `u64` words, then
//! the nine table sections and a small tail, each starting on a 4096-byte boundary so every
//! section is aligned for its element type. The tail holds what does not live in a table region:
//! the `(info, reference)` pairs, the wildcard-regex offers (replayed through `TrailRegexBuilder`,
//! which reproduces the regex exactly), the IPv6:port map, and canary lookups that must resolve to
//! the recorded value before the store is trusted.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::loader::LoadStats;
use super::regexset::TrailRegexBuilder;
use super::region::{Arena, FileMap, Pod, Region};
use super::table::{hash_bytes, IntKey, IntSlot, IntTable, NegativeFilter, SlotCheck, StrSlot, StrTable};
use super::TrailDb;

/// Bump on ANY change to the layout below or to what a section holds.
pub const FORMAT: u64 = 1;
const MAGIC: u64 = u64::from_le_bytes(*b"MTSTORE\0");
/// Written natively; a store from a host of the other byte order reads back as something else.
const ENDIAN: u64 = 0x0102_0304_0506_0708;
const PAGE: usize = 4096;
const HEADER_WORDS: usize = 64;

// Header word indices.
const W_MAGIC: usize = 0;
const W_FORMAT: usize = 1;
const W_ENDIAN: usize = 2;
const W_LAYOUT: usize = 3;
const W_PROBE: usize = 4;
const W_VERSION: usize = 5; // 4 words: the sensor version, NUL-padded
const W_REPAIR: usize = 9;
const W_FINGERPRINTS: usize = 10;
const W_SRC_LEN: usize = 11;
const W_SRC_MTIME_S: usize = 12;
const W_SRC_MTIME_NS: usize = 13;
const W_SRC_HASH: usize = 14;
const W_WL_HASH: usize = 15;
const W_COUNTS: usize = 16; // 4 words: strings, ip4, ip4:port, ip6
const W_MASKS: usize = 20; // 4 words: the four negative-filter masks
const W_DB_LEN: usize = 24;
const W_STATS: usize = 25; // 4 words: rows, loaded, whitelisted, malformed
const W_SECTIONS: usize = 29; // SECTIONS x (offset, length in bytes)
const W_SECTION_HASH: usize = W_SECTIONS + 2 * SECTIONS;
const W_HEADER_HASH: usize = HEADER_WORDS - 1;

const SEC_ARENA: usize = 0;
const SEC_STR_SLOTS: usize = 1;
const SEC_STR_BITS: usize = 2;
const SEC_IP4_SLOTS: usize = 3;
const SEC_IP4_BITS: usize = 4;
const SEC_IP4P_SLOTS: usize = 5;
const SEC_IP4P_BITS: usize = 6;
const SEC_IP6_SLOTS: usize = 7;
const SEC_IP6_BITS: usize = 8;
const SEC_TAIL: usize = 9;
const SECTIONS: usize = 10;

// The header fits its page and its fields do not overlap - checked at compile time.
const _: () =
    assert!(W_SECTION_HASH + SECTIONS <= W_HEADER_HASH && HEADER_WORDS * 8 <= PAGE && W_STATS + 4 <= W_SECTIONS);

const STR_CANARIES: usize = 64;
const INT_CANARIES: usize = 16;

/// Where the store lives and the whitelist it must have been built with.
#[derive(Clone, Debug)]
pub struct StoreConfig {
    pub path: PathBuf,
    pub whitelist_hash: u64,
    /// Write a new store when there is no usable one. `-T` reads but never writes: a test must not
    /// change the deployment.
    pub write: bool,
}

impl StoreConfig {
    /// `<trails>.store`, keyed to the whitelist files the loader will apply.
    pub fn for_trails(trails: &Path, root: &Path, user_whitelist: Option<&Path>) -> StoreConfig {
        StoreConfig { path: store_path(trails), whitelist_hash: whitelist_hash(root, user_whitelist), write: true }
    }
}

pub fn store_path(trails: &Path) -> PathBuf {
    let mut name = trails.as_os_str().to_owned();
    name.push(".store");
    PathBuf::from(name)
}

/// Every whitelist file the sensor reads (`Whitelist::load`), content and order. A missing file
/// hashes as empty, so creating one later changes the hash.
pub fn whitelist_hash(root: &Path, user_whitelist: Option<&Path>) -> u64 {
    let mut h = ContentHash::new();
    let files = std::iter::once(root.join("data").join("whitelist.txt")).chain(user_whitelist.map(Path::to_path_buf));
    for file in files {
        let bytes = std::fs::read(&file).unwrap_or_default();
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    h.finish()
}

/// Why a store was not used. `Absent` is the normal first start and not worth a line.
#[derive(Debug)]
pub enum Miss {
    Absent,
    Rejected(String),
}

impl std::fmt::Display for Miss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Miss::Absent => write!(f, "no store yet"),
            Miss::Rejected(why) => write!(f, "{why}"),
        }
    }
}

fn reject<T>(why: impl Into<String>) -> Result<T, Miss> {
    Err(Miss::Rejected(why.into()))
}

// ---------------------------------------------------------------------------------------------
// content hash
// ---------------------------------------------------------------------------------------------

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

/// A streaming 64-bit checksum, four independent lanes (the xxHash64 round and finalisation).
///
/// Not SHA-256 on purpose: the question is "did this file change", not "did an attacker forge it"
/// (anyone who can write the store can write the CSV), and a Raspberry Pi 3/4 has no SHA
/// instructions - SHA-256 there would cost about a second per 100 MB on every start, which is a
/// good part of what the store saves. This runs at memory speed.
#[derive(Clone)]
pub struct ContentHash {
    acc: [u64; 4],
    buf: [u8; 32],
    buf_len: usize,
    total: u64,
}

impl Default for ContentHash {
    fn default() -> ContentHash {
        ContentHash::new()
    }
}

#[inline]
fn round(acc: u64, value: u64) -> u64 {
    acc.wrapping_add(value.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

#[inline]
fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
}

impl ContentHash {
    pub fn new() -> ContentHash {
        ContentHash { acc: [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)], buf: [0; 32], buf_len: 0, total: 0 }
    }

    #[inline]
    fn block(&mut self, b: &[u8]) {
        self.acc[0] = round(self.acc[0], word(&b[0..8]));
        self.acc[1] = round(self.acc[1], word(&b[8..16]));
        self.acc[2] = round(self.acc[2], word(&b[16..24]));
        self.acc[3] = round(self.acc[3], word(&b[24..32]));
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (32 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 32 {
                return;
            }
            let buf = self.buf;
            self.block(&buf);
            self.buf_len = 0;
        }
        let mut blocks = data.chunks_exact(32);
        for b in &mut blocks {
            self.block(b);
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finish(&self) -> u64 {
        let [a, b, c, d] = self.acc;
        let mut h = a
            .rotate_left(1)
            .wrapping_add(b.rotate_left(7))
            .wrapping_add(c.rotate_left(12))
            .wrapping_add(d.rotate_left(18));
        for lane in self.acc {
            h = (h ^ round(0, lane)).wrapping_mul(P1).wrapping_add(P4);
        }
        h = h.wrapping_add(self.total);
        let mut tail = &self.buf[..self.buf_len];
        while tail.len() >= 8 {
            h = (h ^ round(0, word(tail))).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            tail = &tail[8..];
        }
        for &byte in tail {
            h = (h ^ u64::from(byte).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^ (h >> 32)
    }

    pub fn of(data: &[u8]) -> u64 {
        let mut h = ContentHash::new();
        h.update(data);
        h.finish()
    }
}

pub fn hash_file(path: &Path) -> std::io::Result<u64> {
    let mut file = std::fs::File::open(path)?;
    let mut h = ContentHash::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finish());
        }
        h.update(&buf[..n]);
    }
}

// ---------------------------------------------------------------------------------------------
// what a store must agree with
// ---------------------------------------------------------------------------------------------

fn layout_word() -> u64 {
    (std::mem::size_of::<StrSlot>() as u64) << 48
        | (std::mem::size_of::<IntSlot<u32>>() as u64) << 32
        | (std::mem::size_of::<IntSlot<u64>>() as u64) << 16
        | std::mem::size_of::<IntSlot<u128>>() as u64
        | (std::mem::size_of::<usize>() as u64) << 56
}

/// Slots sit where the hash functions put them. A build that hashes differently would probe the
/// wrong slots of an old store and miss every key, so the hashes of fixed inputs are part of the
/// identity of a store.
fn probe_word() -> u64 {
    hash_bytes(b"maltrail trail store probe")
        ^ 0x0102_0304u32.hash_key().rotate_left(16)
        ^ 0x0102_0304_0506_0708u64.hash_key().rotate_left(32)
        ^ 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128.hash_key().rotate_left(48)
}

fn version_words() -> [u64; 4] {
    let mut bytes = [0u8; 32];
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    let n = version.len().min(32);
    bytes[..n].copy_from_slice(&version[..n]);
    let mut out = [0u64; 4];
    for (i, w) in out.iter_mut().enumerate() {
        *w = word(&bytes[i * 8..i * 8 + 8]);
    }
    out
}

fn mtime_parts(meta: &std::fs::Metadata) -> (u64, u64) {
    match meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
        Some(d) => (d.as_secs(), u64::from(d.subsec_nanos())),
        None => (0, 0),
    }
}

fn header_hash(words: &[u64; HEADER_WORDS]) -> u64 {
    let mut h = ContentHash::new();
    for (i, w) in words.iter().enumerate() {
        h.update(&(if i == W_HEADER_HASH { 0 } else { *w }).to_ne_bytes());
    }
    h.finish()
}

fn read_header(bytes: &[u8]) -> Result<[u64; HEADER_WORDS], Miss> {
    if bytes.len() < PAGE {
        return reject("shorter than its header");
    }
    let mut words = [0u64; HEADER_WORDS];
    for (i, w) in words.iter_mut().enumerate() {
        let b = &bytes[i * 8..i * 8 + 8];
        *w = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    }
    if words[W_MAGIC] != MAGIC || words[W_ENDIAN] != ENDIAN {
        return reject("not a trail store written by this platform");
    }
    if words[W_FORMAT] != FORMAT {
        return reject(format!("store format {} (this sensor reads {FORMAT})", words[W_FORMAT]));
    }
    if header_hash(&words) != words[W_HEADER_HASH] {
        return reject("header checksum mismatch");
    }
    Ok(words)
}

/// The checks that need neither the CSV's content nor the store's body.
fn check_identity(
    h: &[u64; HEADER_WORDS],
    cfg: &StoreConfig,
    csv_meta: &std::fs::Metadata,
    repair: bool,
) -> Result<(), Miss> {
    if h[W_VERSION..W_VERSION + 4] != version_words() {
        return reject("built by another sensor version");
    }
    if h[W_LAYOUT] != layout_word() || h[W_PROBE] != probe_word() {
        return reject("built with another table layout");
    }
    if h[W_REPAIR] != u64::from(repair) {
        return reject("built with another REPAIR_TRUNCATED_TRAILS");
    }
    if h[W_WL_HASH] != cfg.whitelist_hash {
        return reject("the whitelist changed");
    }
    let (secs, nanos) = mtime_parts(csv_meta);
    if h[W_SRC_LEN] != csv_meta.len() || h[W_SRC_MTIME_S] != secs || h[W_SRC_MTIME_NS] != nanos {
        return reject("the trails file changed");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// reading
// ---------------------------------------------------------------------------------------------

/// Use the store at `cfg.path` if, and only if, it was built from exactly the CSV at `csv`.
///
/// The cheap checks come first; the CSV's content hash - the one that reads the whole file - is
/// the last gate before the body is touched. Size and mtime alone are what the reload poll trusts,
/// but an updater that rewrites a file to the same length and keeps its mtime (`cp -p`, `rsync -t`,
/// a restored backup) would pass them, and the result would be yesterday's trails, reported healthy.
pub fn try_load(
    cfg: &StoreConfig,
    csv: &Path,
    csv_meta: &std::fs::Metadata,
    repair: bool,
) -> Result<(TrailDb, LoadStats), Miss> {
    let map = match FileMap::open(&cfg.path) {
        Ok(map) => map,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Miss::Absent),
        Err(e) => return reject(format!("unreadable ({e})")),
    };
    let header = read_header(map.bytes())?;
    check_identity(&header, cfg, csv_meta, repair)?;
    match hash_file(csv) {
        Ok(hash) if hash == header[W_SRC_HASH] => {}
        Ok(_) => return reject("the trails file changed (content)"),
        Err(e) => return reject(format!("could not hash the trails file ({e})")),
    }
    assemble(&map, &header, repair)
}

/// Map a store this process has just written, checking it against the hash the loader computed
/// while it parsed - so the CSV is not read a second time.
fn reopen(
    cfg: &StoreConfig,
    csv_meta: &std::fs::Metadata,
    source_hash: u64,
    repair: bool,
) -> Result<(TrailDb, LoadStats), Miss> {
    let map = FileMap::open(&cfg.path).map_err(|e| Miss::Rejected(format!("unreadable ({e})")))?;
    let header = read_header(map.bytes())?;
    check_identity(&header, cfg, csv_meta, repair)?;
    if header[W_SRC_HASH] != source_hash {
        return reject("replaced while it was being written");
    }
    assemble(&map, &header, repair)
}

fn section(h: &[u64; HEADER_WORDS], index: usize) -> (usize, usize) {
    (h[W_SECTIONS + 2 * index] as usize, h[W_SECTIONS + 2 * index + 1] as usize)
}

fn region<T: Pod>(map: &Arc<FileMap>, h: &[u64; HEADER_WORDS], index: usize) -> Result<Region<T>, Miss> {
    let (offset, bytes) = section(h, index);
    let size = std::mem::size_of::<T>();
    if offset % PAGE != 0 || bytes % size != 0 {
        return reject(format!("section {index} is misaligned"));
    }
    Region::borrowed(map, offset, bytes / size)
        .ok_or_else(|| Miss::Rejected(format!("section {index} is out of bounds")))
}

fn filter(map: &Arc<FileMap>, h: &[u64; HEADER_WORDS], index: usize, which: usize) -> Result<NegativeFilter, Miss> {
    NegativeFilter::from_parts(region::<u64>(map, h, index)?, h[W_MASKS + which] as usize)
        .ok_or_else(|| Miss::Rejected(format!("filter {which} does not match its bits")))
}

/// A table is safe to probe only when every key is in bounds, every value names a real pair, at
/// least one slot is empty (a full table makes a miss probe forever), and the count is what the
/// header says.
fn check_slots(what: &str, check: SlotCheck, capacity: usize, expected: u64, pairs: usize) -> Result<(), Miss> {
    if !check.in_bounds {
        return reject(format!("{what}: a key points outside the arena"));
    }
    if check.occupied as u64 != expected || check.occupied >= capacity {
        return reject(format!("{what}: {} of {capacity} slots occupied, header says {expected}", check.occupied));
    }
    if check.max_val.is_some_and(|v| v as usize >= pairs) {
        return reject(format!("{what}: a slot names a pair that does not exist"));
    }
    Ok(())
}

fn int_table<K: IntKey>(
    map: &Arc<FileMap>,
    h: &[u64; HEADER_WORDS],
    slots: usize,
    bits: usize,
    which: usize,
) -> Result<IntTable<K>, Miss> {
    let slots = region::<IntSlot<K>>(map, h, slots)?;
    let filter = filter(map, h, bits, which)?;
    Ok(IntTable::from_parts(slots, filter, h[W_COUNTS + which] as usize))
}

fn assemble(map: &Arc<FileMap>, h: &[u64; HEADER_WORDS], repair: bool) -> Result<(TrailDb, LoadStats), Miss> {
    for index in 0..SECTIONS {
        let (offset, bytes) = section(h, index);
        if offset.checked_add(bytes).map_or(true, |end| end > map.len()) {
            return reject(format!("section {index} is out of bounds (truncated store?)"));
        }
    }
    let (tail_offset, tail_len) = section(h, SEC_TAIL);
    let tail = &map.bytes()[tail_offset..tail_offset + tail_len];
    if ContentHash::of(tail) != h[W_SECTION_HASH + SEC_TAIL] {
        return reject("tail checksum mismatch");
    }

    let strings = StrTable::from_parts(
        Arena::Frozen(region::<u8>(map, h, SEC_ARENA)?),
        region::<StrSlot>(map, h, SEC_STR_SLOTS)?,
        filter(map, h, SEC_STR_BITS, 0)?,
        h[W_COUNTS] as usize,
    );
    let ip4: IntTable<u32> = int_table(map, h, SEC_IP4_SLOTS, SEC_IP4_BITS, 1)?;
    let ip4_port: IntTable<u64> = int_table(map, h, SEC_IP4P_SLOTS, SEC_IP4P_BITS, 2)?;
    let ip6: IntTable<u128> = int_table(map, h, SEC_IP6_SLOTS, SEC_IP6_BITS, 3)?;

    let mut t = TailReader { bytes: tail, pos: 0 };
    let mut pairs: Vec<(Box<str>, Box<str>)> = Vec::new();
    for _ in 0..t.u32()? {
        pairs.push((t.str()?.into(), t.str()?.into()));
    }

    check_slots("strings", strings.validate(), strings.slots().len(), h[W_COUNTS], pairs.len())?;
    check_slots("ipv4", ip4.validate(), ip4.slots().len(), h[W_COUNTS + 1], pairs.len())?;
    check_slots("ipv4:port", ip4_port.validate(), ip4_port.slots().len(), h[W_COUNTS + 2], pairs.len())?;
    check_slots("ipv6", ip6.validate(), ip6.slots().len(), h[W_COUNTS + 3], pairs.len())?;
    if h[W_DB_LEN] != h[W_COUNTS] {
        return reject("trail count does not match the string table");
    }

    let mut regex = TrailRegexBuilder::with_repair(repair);
    for _ in 0..t.u32()? {
        let (trail, reference) = (t.str()?, t.str()?);
        regex.offer(trail, reference);
    }
    let mut ip6_port = crate::fasthash::FastMap::default();
    for _ in 0..t.u32()? {
        let (key, port, pair) = (t.u128()?, t.u16()?, t.u32()?);
        if pair as usize >= pairs.len() {
            return reject("ipv6:port names a pair that does not exist");
        }
        ip6_port.insert((key, port), pair);
    }

    // Canaries: lookups through the mapped tables - hash, negative filter, probe - that must give
    // back what the writer recorded. A body that is plausible but wrong (zeroed, truncated and
    // padded, another store's) fails these without the whole body being read.
    for _ in 0..t.u32()? {
        let (key, val) = (t.str()?, t.u32()?);
        if strings.get(key) != Some(val) {
            return reject(format!("canary '{key}' does not resolve"));
        }
    }
    for _ in 0..t.u32()? {
        let (key, val) = (t.u32()?, t.u32()?);
        if ip4.get(key) != Some(val) {
            return reject("an ipv4 canary does not resolve");
        }
    }
    for _ in 0..t.u32()? {
        let (key, val) = (t.u64()?, t.u32()?);
        if ip4_port.get(key) != Some(val) {
            return reject("an ipv4:port canary does not resolve");
        }
    }
    for _ in 0..t.u32()? {
        let (key, val) = (t.u128()?, t.u32()?);
        if ip6.get(key) != Some(val) {
            return reject("an ipv6 canary does not resolve");
        }
    }
    if t.pos != tail.len() {
        return reject("trailing bytes in the tail");
    }

    let db = TrailDb {
        pairs,
        strings,
        ip4,
        ip4_port,
        ip6,
        ip6_port,
        regex: regex.build(),
        len: h[W_DB_LEN] as usize,
        fingerprints: h[W_FINGERPRINTS] as u8,
        prebuilt: true,
    };
    let stats = LoadStats {
        rows: h[W_STATS] as usize,
        loaded: h[W_STATS + 1] as usize,
        whitelisted: h[W_STATS + 2] as usize,
        malformed: h[W_STATS + 3] as usize,
        ..LoadStats::default()
    };
    Ok((db, stats))
}

struct TailReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> TailReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Miss> {
        let end = self.pos.checked_add(n).filter(|&end| end <= self.bytes.len());
        let Some(end) = end else { return reject("tail is truncated") };
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, Miss> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Miss> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, Miss> {
        Ok(word(self.take(8)?))
    }

    fn u128(&mut self) -> Result<u128, Miss> {
        let b = self.take(16)?;
        Ok(u128::from(word(&b[..8])) | u128::from(word(&b[8..])) << 64)
    }

    fn str(&mut self) -> Result<&'a str, Miss> {
        let n = self.u32()? as usize;
        std::str::from_utf8(self.take(n)?).map_err(|_| Miss::Rejected("tail holds invalid UTF-8".into()))
    }
}

// ---------------------------------------------------------------------------------------------
// writing
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct TailWriter(Vec<u8>);

impl TailWriter {
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u128(&mut self, v: u128) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn len(&mut self, n: usize) {
        self.u32(n as u32);
    }
    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
}

/// Every `step`-th item, at most `max` of them, spread across the whole sequence.
fn sample<T>(items: impl Iterator<Item = T>, total: usize, max: usize) -> Vec<T> {
    let step = (total / max.max(1)).max(1);
    items.step_by(step).take(max).collect()
}

fn encode_tail(db: &TrailDb) -> Vec<u8> {
    let mut t = TailWriter::default();
    t.len(db.pairs.len());
    for (info, reference) in &db.pairs {
        t.str(info);
        t.str(reference);
    }
    let offers = db.regex.offers();
    t.len(offers.len());
    for (trail, reference) in offers {
        t.str(trail);
        t.str(reference);
    }
    let mut ip6_port: Vec<(&(u128, u16), &u32)> = db.ip6_port.iter().collect();
    ip6_port.sort(); // a deterministic file for the same input
    t.len(ip6_port.len());
    for (&(key, port), &pair) in ip6_port {
        t.u128(key);
        t.u16(port);
        t.u32(pair);
    }
    let canaries = sample(db.strings.iter(), db.strings.len(), STR_CANARIES);
    t.len(canaries.len());
    for (key, val) in canaries {
        t.str(key);
        t.u32(val);
    }
    let canaries = sample(db.ip4.iter(), db.ip4.len(), INT_CANARIES);
    t.len(canaries.len());
    for (key, val) in canaries {
        t.u32(key);
        t.u32(val);
    }
    let canaries = sample(db.ip4_port.iter(), db.ip4_port.len(), INT_CANARIES);
    t.len(canaries.len());
    for (key, val) in canaries {
        t.u64(key);
        t.u32(val);
    }
    let canaries = sample(db.ip6.iter(), db.ip6.len(), INT_CANARIES);
    t.len(canaries.len());
    for (key, val) in canaries {
        t.u128(key);
        t.u32(val);
    }
    t.0
}

fn align(n: usize) -> usize {
    (n + PAGE - 1) & !(PAGE - 1)
}

/// Write `db` as the store for the CSV described by `csv_meta`/`source_hash`, atomically: a
/// temporary file in the same directory, synced, then renamed over the old store. A reader never
/// sees a half-written store, and a power cut leaves either the old one or the new one.
pub fn write(
    cfg: &StoreConfig,
    db: &TrailDb,
    stats: &LoadStats,
    csv_meta: &std::fs::Metadata,
    source_hash: u64,
    repair: bool,
) -> std::io::Result<()> {
    let dir = match cfg.path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = cfg.path.file_name().and_then(|n| n.to_str()).unwrap_or("trails.store");
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp); // left by a crashed run with this pid
    let result = write_to(&tmp, db, stats, cfg, csv_meta, source_hash, repair)
        .and_then(|()| read_only_like(&tmp, csv_meta))
        .and_then(|()| std::fs::rename(&tmp, &cfg.path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    // The rename itself must survive a power cut on an SD card.
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The CSV's read bits and no write bits.
///
/// A running sensor maps the store, and a mapped file truncated or rewritten IN PLACE (`cp` over
/// it, `> trails.csv.store`) is a SIGBUS on the next page fault - a crash no `catch_unwind` can
/// contain. This writer never does that (it renames a new file into place), and a read-only file
/// makes the same mistake by anyone else fail with "Permission denied" instead. Deleting it is
/// always safe: the sensor keeps the unlinked inode until it lets go.
fn read_only_like(path: &Path, csv_meta: &std::fs::Metadata) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = csv_meta.permissions().mode() & 0o444;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode.max(0o400)))?;
    }
    #[cfg(not(unix))]
    let _ = (path, csv_meta);
    Ok(())
}

fn write_to(
    tmp: &Path,
    db: &TrailDb,
    stats: &LoadStats,
    cfg: &StoreConfig,
    csv_meta: &std::fs::Metadata,
    source_hash: u64,
    repair: bool,
) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(tmp)?;
    let tail = encode_tail(db);
    let bodies: [&[u8]; SECTIONS] = [
        &db.strings.arena()[..],
        db.strings.slots().as_bytes(),
        db.strings.filter().bits().as_bytes(),
        db.ip4.slots().as_bytes(),
        db.ip4.filter().bits().as_bytes(),
        db.ip4_port.slots().as_bytes(),
        db.ip4_port.filter().bits().as_bytes(),
        db.ip6.slots().as_bytes(),
        db.ip6.filter().bits().as_bytes(),
        &tail,
    ];

    let mut h = [0u64; HEADER_WORDS];
    h[W_MAGIC] = MAGIC;
    h[W_FORMAT] = FORMAT;
    h[W_ENDIAN] = ENDIAN;
    h[W_LAYOUT] = layout_word();
    h[W_PROBE] = probe_word();
    h[W_VERSION..W_VERSION + 4].copy_from_slice(&version_words());
    h[W_REPAIR] = u64::from(repair);
    h[W_FINGERPRINTS] = u64::from(db.fingerprints);
    let (secs, nanos) = mtime_parts(csv_meta);
    h[W_SRC_LEN] = csv_meta.len();
    h[W_SRC_MTIME_S] = secs;
    h[W_SRC_MTIME_NS] = nanos;
    h[W_SRC_HASH] = source_hash;
    h[W_WL_HASH] = cfg.whitelist_hash;
    h[W_COUNTS..W_COUNTS + 4].copy_from_slice(&[
        db.strings.len() as u64,
        db.ip4.len() as u64,
        db.ip4_port.len() as u64,
        db.ip6.len() as u64,
    ]);
    h[W_MASKS..W_MASKS + 4].copy_from_slice(&[
        db.strings.filter().mask() as u64,
        db.ip4.filter().mask() as u64,
        db.ip4_port.filter().mask() as u64,
        db.ip6.filter().mask() as u64,
    ]);
    h[W_DB_LEN] = db.len as u64;
    h[W_STATS..W_STATS + 4].copy_from_slice(&[
        stats.rows as u64,
        stats.loaded as u64,
        stats.whitelisted as u64,
        stats.malformed as u64,
    ]);
    let mut offset = PAGE;
    for (i, body) in bodies.iter().enumerate() {
        h[W_SECTIONS + 2 * i] = offset as u64;
        h[W_SECTIONS + 2 * i + 1] = body.len() as u64;
        h[W_SECTION_HASH + i] = ContentHash::of(body);
        offset = align(offset + body.len());
    }
    h[W_HEADER_HASH] = header_hash(&h);

    // The alignment gaps are holes: set_len extends with zeroes without writing them.
    file.set_len(h[W_SECTIONS + 2 * SEC_TAIL] + tail.len() as u64)?;
    for (i, body) in bodies.iter().enumerate() {
        file.seek(SeekFrom::Start(h[W_SECTIONS + 2 * i]))?;
        file.write_all(body)?;
    }
    let mut header = vec![0u8; PAGE];
    for (i, w) in h.iter().enumerate() {
        header[i * 8..i * 8 + 8].copy_from_slice(&w.to_ne_bytes());
    }
    // Header last: until it is written the file is not a store at all.
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.sync_all()
}

/// Write the store for a freshly parsed `db`, then map it back and return THAT, so the running
/// sensor serves from the store (page cache, not heap) and the reader is proven on the spot. Any
/// failure returns the parsed `db` unchanged with the reason.
pub fn write_and_reopen(
    cfg: &StoreConfig,
    db: TrailDb,
    stats: LoadStats,
    csv_meta: &std::fs::Metadata,
    source_hash: u64,
    repair: bool,
) -> (TrailDb, LoadStats, Option<String>) {
    if let Err(e) = write(cfg, &db, &stats, csv_meta, source_hash, repair) {
        return (db, stats, Some(format!("could not write '{}' ({e})", cfg.path.display())));
    }
    match reopen(cfg, csv_meta, source_hash, repair) {
        Ok((mapped, _)) if mapped.len() == db.len() => (mapped, stats, None),
        Ok(_) => (db, stats, Some(format!("'{}' read back with a different trail count", cfg.path.display()))),
        Err(miss) => (db, stats, Some(format!("'{}' did not read back ({miss})", cfg.path.display()))),
    }
}

/// Full verification: the header, and the checksum of every section. Reads the whole store, so it
/// is for `--verify-trail-store` and tests, not for every start.
pub fn verify(path: &Path) -> Result<String, String> {
    let map = FileMap::open(path).map_err(|e| format!("'{}' unreadable ({e})", path.display()))?;
    let h = read_header(map.bytes()).map_err(|m| m.to_string())?;
    for index in 0..SECTIONS {
        let (offset, bytes) = section(&h, index);
        let Some(body) = offset.checked_add(bytes).and_then(|end| map.bytes().get(offset..end)) else {
            return Err(format!("section {index} is out of bounds (truncated store?)"));
        };
        if ContentHash::of(body) != h[W_SECTION_HASH + index] {
            return Err(format!("section {index} checksum mismatch"));
        }
    }
    Ok(format!(
        "{} trails, {:.1} MB, every section checksum matches",
        h[W_DB_LEN],
        map.len() as f64 / (1024.0 * 1024.0)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trails::loader::{load_trails, LoadOptions};
    use crate::whitelist::Whitelist;

    struct Fixture {
        dir: PathBuf,
        csv: PathBuf,
        cfg: StoreConfig,
    }

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let dir = std::env::temp_dir().join(format!("mt-store-unit-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let csv = dir.join("trails.csv");
            let mut text = String::new();
            for i in 0..30_000u32 {
                match i % 3 {
                    0 => text.push_str(&format!("host{i}.example,info {} (malware),(static)\n", i % 7)),
                    1 => text.push_str(&format!(
                        "10.{}.{}.{},scanner,(static)\n",
                        (i >> 16) & 255,
                        (i >> 8) & 255,
                        i & 255
                    )),
                    _ => text.push_str(&format!(
                        "10.{}.{}.{}:{},c2,(static)\n",
                        (i >> 16) & 255,
                        (i >> 8) & 255,
                        i & 255,
                        1 + i % 999
                    )),
                }
            }
            std::fs::write(&csv, text).unwrap();
            let cfg = StoreConfig { path: dir.join("trails.csv.store"), whitelist_hash: 7, write: true };
            Fixture { dir, csv, cfg }
        }

        fn load(&self) -> (TrailDb, LoadStats) {
            let options = LoadOptions { store: Some(self.cfg.clone()), ..LoadOptions::default() };
            load_trails(&self.csv, &Whitelist::default(), options).unwrap()
        }

        fn replace_store(&self, damage: impl FnOnce(&mut Vec<u8>)) {
            let mut bytes = std::fs::read(&self.cfg.path).unwrap();
            damage(&mut bytes);
            let damaged = self.dir.join("damaged");
            std::fs::write(&damaged, &bytes).unwrap();
            std::fs::rename(&damaged, &self.cfg.path).unwrap();
        }

        fn section(&self, index: usize) -> (usize, usize) {
            section(&read_header(&std::fs::read(&self.cfg.path).unwrap()).unwrap(), index)
        }

        /// Damage the store on disk, then prove the next load does not use it, answers like a
        /// parse, and leaves a good store behind.
        ///
        /// The damaged copy is written to a new file and renamed into place. Rewriting the mapped
        /// file in place would SIGBUS any live mapping of it - see `read_only_like`.
        fn damage_and_reload(&self, what: &str, damage: impl FnOnce(&mut Vec<u8>)) {
            let (in_use, _) = self.load();
            assert!(in_use.is_prebuilt(), "{what}: positive control, the store was in use");
            drop(in_use);
            let reference = load_trails(&self.csv, &Whitelist::default(), LoadOptions::default()).unwrap().0;
            self.replace_store(damage);
            let (db, stats) = self.load();
            assert!(!stats.from_store, "{what}: a damaged store was used");
            assert!(stats.store_note.is_some(), "{what}: a rejected store must say why");
            for i in (0..30_000u32).step_by(97) {
                let key = format!("host{i}.example");
                assert_eq!(db.get(&key), reference.get(&key), "{what}: {key}");
            }
            assert_eq!(db.len(), reference.len(), "{what}");
            verify(&self.cfg.path).unwrap_or_else(|e| panic!("{what}: the rebuilt store does not verify: {e}"));
            assert!(self.load().1.from_store, "{what}: the rebuilt store must be used again");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_damaged_store_is_a_miss_not_a_wrong_answer() {
        let f = Fixture::new("damage");
        let _ = f.load(); // writes the store
        f.damage_and_reload("truncated by one byte", |b| {
            b.pop();
        });
        f.damage_and_reload("truncated to its header", |b| b.truncate(PAGE));
        f.damage_and_reload("a header word changed", |b| b[8 * W_COUNTS] ^= 1);
        f.damage_and_reload("the format bumped", |b| b[8 * W_FORMAT] ^= 0x80);
        let (tail, len) = f.section(SEC_TAIL);
        f.damage_and_reload("a tail byte flipped", |b| b[tail + len / 2] ^= 0x10);
        // Body damage the header cannot see: what the slot validation and the canaries are for.
        let (slots, len) = f.section(SEC_STR_SLOTS);
        f.damage_and_reload("the string slots zeroed", |b| b[slots..slots + len].fill(0));
        f.damage_and_reload("the string slots all-ones", |b| b[slots..slots + len].fill(0xff));
        let (arena, len) = f.section(SEC_ARENA);
        f.damage_and_reload("the key arena zeroed", |b| b[arena..arena + len].fill(0));
        let (bits, len) = f.section(SEC_STR_BITS);
        f.damage_and_reload("the string filter cleared", |b| b[bits..bits + len].fill(0));
        let (ip4, len) = f.section(SEC_IP4_SLOTS);
        f.damage_and_reload("the ipv4 slots zeroed", |b| b[ip4..ip4 + len].fill(0));
    }

    /// A single flipped bit inside a section can slip past the load-time checks - they deliberately
    /// do not read the whole body - but it can never index out of bounds, and `verify` sees it.
    #[test]
    fn verify_catches_what_the_load_checks_do_not_read() {
        let f = Fixture::new("verify");
        let _ = f.load();
        assert!(verify(&f.cfg.path).is_ok(), "positive control: a fresh store verifies");
        let (slots, len) = f.section(SEC_STR_SLOTS);
        f.replace_store(|bytes| {
            for k in 0..64 {
                bytes[slots + (k * 7919 * 16) % len] ^= 0x04;
            }
        });
        let err = verify(&f.cfg.path).expect_err("a flipped body byte must fail verification");
        assert!(err.contains("section 1"), "{err}");
        // Whatever the load decides, it must not panic, and every answer must be a real pair.
        let (db, _) = f.load();
        for i in 0..30_000u32 {
            let _ = db.get(&format!("host{i}.example"));
        }
    }

    /// An in-place overwrite of a mapped store crashes the sensor, so the store is written without
    /// write permission and that mistake fails instead.
    #[test]
    #[cfg(unix)]
    fn the_store_is_written_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("readonly");
        let _ = f.load();
        let mode = std::fs::metadata(&f.cfg.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o222, 0, "store mode {mode:o} is writable");
        assert_ne!(mode & 0o400, 0, "store mode {mode:o} is not readable by its owner");
    }

    #[test]
    fn content_hash_is_independent_of_how_the_input_is_cut() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        let whole = ContentHash::of(&data);
        for cut in [1usize, 7, 31, 32, 33, 64, 999, 4096] {
            let mut h = ContentHash::new();
            for piece in data.chunks(cut) {
                h.update(piece);
            }
            assert_eq!(h.finish(), whole, "cut={cut}");
        }
        // positive control: one changed byte, and one byte fewer, are different inputs
        let mut changed = data.clone();
        changed[5000] ^= 1;
        assert_ne!(ContentHash::of(&changed), whole);
        assert_ne!(ContentHash::of(&data[..data.len() - 1]), whole);
        assert_ne!(ContentHash::of(b""), ContentHash::of(b"\0"));
    }
}
