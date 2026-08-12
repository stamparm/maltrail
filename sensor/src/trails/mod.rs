//! The trail store: `core/trailsdict.py:TrailsDict` plus `core/common.py:load_trails()`.
//!
//! External format is unchanged (`~/.maltrail/trails.csv`). Internally the store keeps
//!
//!  * one interned `(info, reference)` pair table (millions of trails share a few
//!    thousand distinct pairs, exactly as Python's `_pairs` interning exploits),
//!  * a string-keyed table for every trail (needed for domain/URL/path/word lookups),
//!  * native side tables for IPv4, IPv4:port, IPv6 and IPv6:port trails so the packet
//!    path never renders an address to text just to test membership,
//!  * the wildcard-trail regex.
//!
//! The store is immutable once built. Reloads publish a fresh `Arc` through `TrailStore`,
//! which workers pick up with a single relaxed atomic load — no lock on the packet path.

pub mod loader;
pub mod regexset;
pub mod table;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::addr::Ip;
use regexset::TrailRegex;
use table::{IntTable, StrTable};

/// A trail's `(info, reference)` pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TrailInfo<'a> {
    pub info: &'a str,
    pub reference: &'a str,
}

pub struct TrailDb {
    pairs: Vec<(Box<str>, Box<str>)>,
    strings: StrTable,
    ip4: IntTable<u32>,
    ip4_port: IntTable<u64>,
    ip6: IntTable<u128>,
    /// FxHash, not SipHash: the key set of the trail store is fixed when `trails.csv` is loaded
    /// and cannot be grown by traffic, so there is nothing for a collision flood to insert. The
    /// HashDoS argument that keeps SipHash on the domain/URL/UA caches does not apply here.
    ip6_port: crate::fasthash::FastMap<(u128, u16), u32>,
    regex: TrailRegex,
    len: usize,
}

#[inline]
fn ip4_port_key(ip: u32, port: u16) -> u64 {
    ((ip as u64) << 16) | port as u64
}

impl TrailDb {
    pub fn empty() -> TrailDb {
        TrailDbBuilder::new(0, 0).finish(regexset::TrailRegexBuilder::default().build())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn pair(&self, idx: u32) -> TrailInfo<'_> {
        let (info, reference) = &self.pairs[idx as usize];
        TrailInfo { info, reference }
    }

    /// `trails[key]` / `trails.get(key)`
    #[inline]
    pub fn get(&self, key: &str) -> Option<TrailInfo<'_>> {
        self.strings.get(key).map(|idx| self.pair(idx))
    }

    /// `key in trails`
    #[inline]
    pub fn contains(&self, key: &str) -> bool {
        self.strings.contains(key)
    }

    /// `<rendered ip> in trails`, without rendering.
    #[inline]
    pub fn get_ip(&self, ip: Ip) -> Option<TrailInfo<'_>> {
        let idx = match ip {
            Ip::V4(v) => self.ip4.get(v),
            Ip::V6(v) => self.ip6.get(v),
        }?;
        Some(self.pair(idx))
    }

    /// `addr_port(ip, port) in trails`, without rendering.
    #[inline]
    pub fn get_ip_port(&self, ip: Ip, port: u16) -> Option<TrailInfo<'_>> {
        let idx = match ip {
            Ip::V4(v) => self.ip4_port.get(ip4_port_key(v, port)),
            Ip::V6(v) => self.ip6_port.get(&(v, port)).copied(),
        }?;
        Some(self.pair(idx))
    }

    pub fn regex(&self) -> &TrailRegex {
        &self.regex
    }

    /// `_check_domain_member(query, trails)` — used by the NXDOMAIN heuristic.
    pub fn contains_domain_member(&self, query: &str) -> bool {
        crate::whitelist::check_domain_member(query, |candidate| self.contains(candidate))
    }

    pub fn memory_bytes(&self) -> usize {
        self.strings.arena_bytes()
            + self.strings.slot_bytes()
            + self.ip4.slot_bytes()
            + self.ip4_port.slot_bytes()
            + self.ip6.slot_bytes()
            + self.pairs.iter().map(|(a, b)| a.len() + b.len() + 32).sum::<usize>()
    }

    pub fn ip4_count(&self) -> usize {
        self.ip4.len()
    }

    pub fn ip4_port_count(&self) -> usize {
        self.ip4_port.len()
    }

    pub fn ip6_count(&self) -> usize {
        self.ip6.len() + self.ip6_port.len()
    }
}

pub struct TrailDbBuilder {
    pairs: Vec<(Box<str>, Box<str>)>,
    strings: StrTable,
    ip4: IntTable<u32>,
    ip4_port: IntTable<u64>,
    ip6: IntTable<u128>,
    ip6_port: crate::fasthash::FastMap<(u128, u16), u32>,
    len: usize,
}

impl TrailDbBuilder {
    pub fn new(estimated_rows: usize, arena_hint: usize) -> TrailDbBuilder {
        TrailDbBuilder {
            pairs: Vec::with_capacity(4096),
            strings: StrTable::with_capacity(estimated_rows, arena_hint),
            ip4: IntTable::with_capacity(estimated_rows / 8 + 16),
            ip4_port: IntTable::with_capacity(estimated_rows / 8 + 16),
            ip6: IntTable::with_capacity(64),
            ip6_port: crate::fasthash::FastMap::default(),
            len: 0,
        }
    }

    pub fn intern_pair(&mut self, info: &str, reference: &str) -> u32 {
        let idx = self.pairs.len() as u32;
        self.pairs.push((info.into(), reference.into()));
        idx
    }

    /// Insert a trail key. Native side tables get a mirror only when the key is the exact
    /// text Maltrail would render for that address, which keeps the native lookups
    /// equivalent to Python's string comparison.
    pub fn insert(&mut self, trail: &str, pair: u32) {
        let hash = table::hash_bytes(trail.as_bytes());
        self.insert_prepared(trail, hash, pair, NativeKey::of(trail));
    }

    /// `insert()` with the two things that can be derived from the key text alone already
    /// derived. The trail loader does both on its parse threads; what is left here is only the
    /// table writes, which are what the serial pass is actually for.
    pub fn insert_prepared(&mut self, trail: &str, hash: u64, pair: u32, native: NativeKey) {
        if self.strings.insert_hashed(trail, hash, pair) {
            self.len += 1;
        }
        match native {
            NativeKey::None => {}
            NativeKey::Ip(Ip::V4(v)) => self.ip4.insert(v, pair),
            NativeKey::Ip(Ip::V6(v)) => self.ip6.insert(v, pair),
            NativeKey::IpPort(Ip::V4(v), port) => self.ip4_port.insert(ip4_port_key(v, port), pair),
            NativeKey::IpPort(Ip::V6(v), port) => {
                self.ip6_port.insert((v, port), pair);
            }
        }
    }

    /// Warm the string table for a key whose hash is already known (see `StrTable::prefetch`).
    #[inline]
    pub fn prefetch(&self, hash: u64) {
        self.strings.prefetch(hash);
    }

    pub fn finish(self, regex: TrailRegex) -> TrailDb {
        TrailDb {
            pairs: self.pairs,
            strings: self.strings,
            ip4: self.ip4,
            ip4_port: self.ip4_port,
            ip6: self.ip6,
            ip6_port: self.ip6_port,
            regex,
            len: self.len,
        }
    }
}

/// Parse `1.2.3.4:443` / `[dead::beef]:443`, accepting only the canonical rendering
/// (`core/addr.py:addr_port`).
fn parse_canonical_addr_port(trail: &str) -> Option<(Ip, u16)> {
    let (addr, port) = if let Some(rest) = trail.strip_prefix('[') {
        let idx = rest.find("]:")?;
        (&rest[..idx], &rest[idx + 2..])
    } else {
        let idx = trail.rfind(':')?;
        (&trail[..idx], &trail[idx + 1..])
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    let ip = crate::addr::parse_canonical_ip(addr)?;
    // The bracketed form is only used for IPv6 and vice versa.
    if (ip.is_v6() && !trail.starts_with('[')) || (!ip.is_v6() && trail.starts_with('[')) {
        return None;
    }
    if ip.addr_port(port).as_str() != trail {
        return None;
    }
    Some((ip, port))
}

/// The native (integer) mirror a trail key qualifies for, if any.
///
/// Derived from the key text alone, so it can be computed anywhere — which is the point: the
/// loader computes it on its parse threads rather than inside the serial insert pass.
#[derive(Clone, Copy)]
pub enum NativeKey {
    None,
    Ip(Ip),
    IpPort(Ip, u16),
}

impl NativeKey {
    pub fn of(trail: &str) -> NativeKey {
        if let Some(ip) = crate::addr::parse_canonical_ip(trail) {
            return NativeKey::Ip(ip);
        }
        if let Some((ip, port)) = parse_canonical_addr_port(trail) {
            return NativeKey::IpPort(ip, port);
        }
        NativeKey::None
    }
}

/// Publishes an immutable `TrailDb` to the workers.
pub struct TrailStore {
    generation: AtomicU64,
    current: Mutex<Arc<TrailDb>>,
}

impl TrailStore {
    pub fn new(db: TrailDb) -> TrailStore {
        TrailStore { generation: AtomicU64::new(1), current: Mutex::new(Arc::new(db)) }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> (u64, Arc<TrailDb>) {
        // Acquire pairs with the Release store in publish(), so a worker that observes a
        // new generation also observes the fully built table behind it.
        let gen = self.generation.load(Ordering::Acquire);
        let db = self.current.lock().map(|g| g.clone()).unwrap_or_else(|e| e.into_inner().clone());
        (gen, db)
    }

    pub fn publish(&self, db: TrailDb) {
        if let Ok(mut guard) = self.current.lock() {
            *guard = Arc::new(db);
        }
        self.generation.fetch_add(1, Ordering::Release);
    }
}

/// A worker's cached view. Checking for a reload costs one relaxed atomic load.
pub struct TrailView {
    store: Arc<TrailStore>,
    generation: u64,
    db: Arc<TrailDb>,
}

impl TrailView {
    pub fn new(store: Arc<TrailStore>) -> TrailView {
        let (generation, db) = store.snapshot();
        TrailView { store, generation, db }
    }

    #[inline]
    pub fn db(&self) -> &TrailDb {
        &self.db
    }

    /// Adopt a newer store if one has been published. Called from the worker loop between
    /// packets, never mid-packet, so a trail lookup sequence always sees one snapshot.
    #[inline]
    pub fn refresh(&mut self) -> bool {
        if self.store.generation() == self.generation {
            return false;
        }
        let (generation, db) = self.store.snapshot();
        self.generation = generation;
        self.db = db;
        true
    }
}

/// Load the store from `TRAILS_FILE`.
pub fn load(path: &Path, whitelist: &crate::whitelist::Whitelist) -> std::io::Result<(TrailDb, loader::LoadStats)> {
    loader::load_trails(path, whitelist, loader::LoadOptions::default())
}

/// Load with explicit options (`REPAIR_TRUNCATED_TRAILS`).
pub fn load_with(
    path: &Path,
    whitelist: &crate::whitelist::Whitelist,
    options: loader::LoadOptions,
) -> std::io::Result<(TrailDb, loader::LoadStats)> {
    loader::load_trails(path, whitelist, options)
}

pub use loader::{split_csv_record, LoadOptions};
pub use regexset::is_wildcard_trail;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{addr_to_int, parse_ipv6};

    fn db_with(entries: &[(&str, &str, &str)]) -> TrailDb {
        let mut b = TrailDbBuilder::new(entries.len(), 256);
        let mut rb = regexset::TrailRegexBuilder::default();
        for (trail, info, reference) in entries {
            let pair = b.intern_pair(info, reference);
            rb.offer(trail, reference);
            b.insert(trail, pair);
        }
        b.finish(rb.build())
    }

    #[test]
    fn trailsdict_doctest_behaviour() {
        let db = db_with(&[("1.2.3.4", "malware", "(static)"), ("evil.example", "phishing", "(custom)")]);
        assert!(db.contains("1.2.3.4"));
        assert_eq!(db.get("1.2.3.4"), Some(TrailInfo { info: "malware", reference: "(static)" }));
        assert!(db.get("missing.example").is_none());
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn native_ip_lookups_are_equivalent_to_text() {
        let db = db_with(&[
            ("1.2.3.4", "badnet", "(static)"),
            ("1.2.3.4:443", "c2", "(static)"),
            ("dead::beef", "badnet6", "(static)"),
            ("[dead::beef]:53", "c26", "(static)"),
        ]);
        let v4 = Ip::V4(addr_to_int("1.2.3.4").unwrap());
        let v6 = Ip::V6(parse_ipv6("dead::beef").unwrap());
        assert_eq!(db.get_ip(v4).unwrap().info, "badnet");
        assert_eq!(db.get_ip_port(v4, 443).unwrap().info, "c2");
        assert_eq!(db.get_ip(v6).unwrap().info, "badnet6");
        assert_eq!(db.get_ip_port(v6, 53).unwrap().info, "c26");
        assert!(db.get_ip_port(v4, 444).is_none());
        // and the text form still resolves through the string table
        assert!(db.contains("1.2.3.4:443"));
        assert!(db.contains("[dead::beef]:53"));
    }

    #[test]
    fn non_canonical_ip_text_is_not_mirrored() {
        // "01.2.3.4" parses to the same integer but is NOT the text Python compares, so it
        // must not answer a native lookup for 1.2.3.4.
        let db = db_with(&[("01.2.3.4", "badnet", "(static)")]);
        assert!(db.get_ip(Ip::V4(addr_to_int("1.2.3.4").unwrap())).is_none());
        assert!(db.contains("01.2.3.4"));
    }

    #[test]
    fn addr_port_parsing_is_strict() {
        assert!(parse_canonical_addr_port("1.2.3.4:443").is_some());
        assert!(parse_canonical_addr_port("[dead::beef]:443").is_some());
        assert!(parse_canonical_addr_port("dead::beef:443").is_none()); // v6 needs brackets
        assert!(parse_canonical_addr_port("[1.2.3.4]:443").is_none());
        assert!(parse_canonical_addr_port("host.com:443").is_none());
        assert!(parse_canonical_addr_port("1.2.3.4:").is_none());
        assert!(parse_canonical_addr_port("1.2.3.4:99999").is_none());
    }

    #[test]
    fn domain_member_lookup() {
        let db = db_with(&[("evil.com", "malware", "(static)")]);
        assert!(db.contains_domain_member("www.evil.com"));
        assert!(db.contains_domain_member("evil.com"));
        assert!(!db.contains_domain_member("evil.com.br"));
    }

    #[test]
    fn store_reload_is_visible_to_views() {
        let store = Arc::new(TrailStore::new(db_with(&[("a.com", "i1", "(static)")])));
        let mut view = TrailView::new(store.clone());
        assert!(view.db().contains("a.com"));
        assert!(!view.refresh());
        store.publish(db_with(&[("b.com", "i2", "(static)")]));
        assert!(view.refresh());
        assert!(view.db().contains("b.com"));
        assert!(!view.db().contains("a.com"));
    }
}
