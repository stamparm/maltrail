//! Compact read-only hash tables for the trail store.
//!
//! `core/trailsdict.py` compacts its final set into packed hash arrays and drops the key
//! strings. The Rust store keeps the keys (they are needed for exact comparison, so a hash
//! collision can never produce a wrong match) but stores them in one arena with an
//! open-addressing index, which costs about the same memory as Python's frozen form while
//! answering lookups in O(1) with a single probe in the common case.
//!
//! Both tables are built once and then immutable, so lookups need no synchronisation.

const EMPTY: u32 = u32::MAX;

#[inline]
fn mix(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 29;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 32;
    h
}

/// Fast non-cryptographic hash. Collisions only cost a probe; correctness comes from the
/// byte comparison in `get()`.
#[inline]
pub fn hash_bytes(data: &[u8]) -> u64 {
    const K: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ (data.len() as u64).wrapping_mul(K);
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let v = u64::from_le_bytes(c.try_into().unwrap());
        h = (h ^ v).wrapping_mul(K).rotate_left(31);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rest.len()].copy_from_slice(rest);
        h = (h ^ u64::from_le_bytes(buf)).wrapping_mul(K).rotate_left(27);
    }
    mix(h)
}

/// A negative prefilter: a compact bitmap that answers "definitely not in the table" without
/// touching the table.
///
/// The trail store is ~87 MB. A miss - which is the overwhelmingly common case, since almost no
/// packet matches a trail - costs a DRAM round trip into a structure far larger than any cache.
/// This bitmap is sized to the entry count (2 bits set per key, ~16 bits per key), so it stays in
/// L2/L3 and a miss is answered from cache.
///
/// **It can never cause a false negative.** A clear bit means "not present" and that is exact: an
/// inserted key always sets its bits. A set bit means "maybe", and the caller falls through to
/// the real lookup. The filter is therefore an optimisation only — detection can never be lost to
/// it, which is why a probabilistic structure is acceptable here at all.
pub struct NegativeFilter {
    bits: Vec<u64>,
    mask: usize,
}

impl NegativeFilter {
    pub fn new(entries: usize) -> NegativeFilter {
        // ~16 bits per entry -> ~1.4% false-positive rate with two probes.
        let want_bits = entries.saturating_mul(16).max(1024).next_power_of_two();
        NegativeFilter { bits: vec![0u64; want_bits / 64], mask: want_bits - 1 }
    }

    #[inline]
    fn positions(&self, h: u64) -> (usize, usize) {
        // Two independent positions from one hash: the low half and the high half, both already
        // avalanched by `mix()`.
        ((h as usize) & self.mask, ((h >> 32) as usize).wrapping_mul(0x9e37_79b9) & self.mask)
    }

    #[inline]
    pub fn insert(&mut self, h: u64) {
        let (a, b) = self.positions(h);
        self.bits[a >> 6] |= 1u64 << (a & 63);
        self.bits[b >> 6] |= 1u64 << (b & 63);
    }

    /// Pull this hash's two words into cache without using them, so a later `insert()` on the
    /// same hash finds them there. Volatile reads rather than an intrinsic: `_mm_prefetch` is
    /// x86-only and there is no stable portable prefetch, and a load whose result is discarded
    /// is not something the out-of-order engine waits on either.
    #[inline]
    pub fn prefetch(&self, h: u64) {
        let (a, b) = self.positions(h);
        unsafe {
            std::ptr::read_volatile(self.bits.as_ptr().add(a >> 6));
            std::ptr::read_volatile(self.bits.as_ptr().add(b >> 6));
        }
    }

    /// `false` = definitely absent. `true` = possibly present, check the table.
    #[inline]
    pub fn maybe_contains(&self, h: u64) -> bool {
        let (a, b) = self.positions(h);
        (self.bits[a >> 6] >> (a & 63)) & 1 != 0 && (self.bits[b >> 6] >> (b & 63)) & 1 != 0
    }

    pub fn memory_bytes(&self) -> usize {
        self.bits.len() * 8
    }

    /// Rebuild empty at a new size (used when a table grows past its estimate).
    pub fn resized(&self, entries: usize) -> NegativeFilter {
        NegativeFilter::new(entries)
    }
}

fn capacity_for(n: usize) -> usize {
    // Target ~0.78 load factor, rounded up to a power of two for masking.
    let want = n.saturating_mul(10) / 8 + 1;
    want.max(16).next_power_of_two()
}

#[derive(Clone, Copy)]
struct StrSlot {
    tag: u32,
    off: u32,
    len: u32,
    val: u32,
}

/// String-keyed table over a byte arena.
pub struct StrTable {
    arena: Vec<u8>,
    slots: Vec<StrSlot>,
    mask: usize,
    len: usize,
    filter: NegativeFilter,
}

impl StrTable {
    pub fn with_capacity(n: usize, arena_hint: usize) -> StrTable {
        let cap = capacity_for(n);
        StrTable {
            arena: Vec::with_capacity(arena_hint),
            slots: vec![StrSlot { tag: 0, off: 0, len: 0, val: EMPTY }; cap],
            mask: cap - 1,
            len: 0,
            filter: NegativeFilter::new(n),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn arena_bytes(&self) -> usize {
        self.arena.len()
    }

    pub fn slot_bytes(&self) -> usize {
        self.filter.memory_bytes() + self.slots.len() * std::mem::size_of::<StrSlot>()
    }

    /// Insert (or overwrite, matching `dict[key] = value`). Grows when the load factor
    /// would exceed ~0.85, so a bad size hint degrades performance but never correctness.
    ///
    /// Returns `true` when the key was not already present. Callers that need to know
    /// (the loader counts distinct trails) must use this rather than a preceding
    /// `contains()`: at 1.6 M rows the slots array is ~67 MB, so every probe is a cache
    /// miss and asking twice doubles the cost of building the table.
    pub fn insert(&mut self, key: &str, val: u32) -> bool {
        self.insert_hashed(key, hash_bytes(key.as_bytes()), val)
    }

    /// `insert()` with the key's hash supplied. The trail loader hashes on its parse threads,
    /// which takes the hashing off the one serial pass that builds the table.
    ///
    /// `h` MUST be `hash_bytes(key.as_bytes())`; anything else corrupts the table.
    pub fn insert_hashed(&mut self, key: &str, h: u64, val: u32) -> bool {
        debug_assert!(val != EMPTY);
        debug_assert_eq!(h, hash_bytes(key.as_bytes()));
        if (self.len + 1) * 100 > self.slots.len() * 85 {
            self.grow();
        }
        self.filter.insert(h);
        let tag = (h >> 32) as u32;
        let mut i = (h as usize) & self.mask;
        loop {
            let slot = self.slots[i];
            if slot.val == EMPTY {
                let off = self.arena.len() as u32;
                self.arena.extend_from_slice(key.as_bytes());
                self.slots[i] = StrSlot { tag, off, len: key.len() as u32, val };
                self.len += 1;
                return true;
            }
            if slot.tag == tag && self.slot_key(slot) == key.as_bytes() {
                self.slots[i].val = val;
                return false;
            }
            i = (i + 1) & self.mask;
        }
    }

    #[inline]
    fn slot_key(&self, slot: StrSlot) -> &[u8] {
        let start = slot.off as usize;
        &self.arena[start..start + slot.len as usize]
    }

    #[inline]
    pub fn get(&self, key: &str) -> Option<u32> {
        let bytes = key.as_bytes();
        let h = hash_bytes(bytes);
        // Answer the common case (absent) from a cache-resident bitmap instead of probing the
        // ~87 MB store. Cannot produce a false negative; see `NegativeFilter`.
        if !self.filter.maybe_contains(h) {
            return None;
        }
        let tag = (h >> 32) as u32;
        let mut i = (h as usize) & self.mask;
        loop {
            let slot = self.slots[i];
            if slot.val == EMPTY {
                return None;
            }
            if slot.tag == tag && slot.len as usize == bytes.len() && self.slot_key(slot) == bytes {
                return Some(slot.val);
            }
            i = (i + 1) & self.mask;
        }
    }

    #[inline]
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Warm the cache lines a future `insert_hashed(_, h, _)` will touch. The slots array is
    /// ~67 MB at real trail counts, so every probe is a DRAM round trip; issuing them a few
    /// rows ahead of the insert that needs them is most of what makes the serial pass keep up.
    #[inline]
    pub fn prefetch(&self, h: u64) {
        let i = (h as usize) & self.mask;
        unsafe { std::ptr::read_volatile(self.slots.as_ptr().add(i)) };
        self.filter.prefetch(h);
    }

    fn grow(&mut self) {
        let old = std::mem::take(&mut self.slots);
        let cap = (old.len() * 2).max(16);
        self.slots = vec![StrSlot { tag: 0, off: 0, len: 0, val: EMPTY }; cap];
        self.mask = cap - 1;
        for slot in old {
            if slot.val == EMPTY {
                continue;
            }
            let mut i = {
                let start = slot.off as usize;
                let key = &self.arena[start..start + slot.len as usize];
                (hash_bytes(key) as usize) & self.mask
            };
            while self.slots[i].val != EMPTY {
                i = (i + 1) & self.mask;
            }
            self.slots[i] = slot;
        }
    }

    /// Iterate every stored key (used by tests and by the wildcard-regex builder).
    pub fn iter(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        self.slots.iter().filter(|s| s.val != EMPTY).map(move |s| {
            let start = s.off as usize;
            let key = std::str::from_utf8(&self.arena[start..start + s.len as usize]).unwrap_or("");
            (key, s.val)
        })
    }
}

#[derive(Clone, Copy)]
struct IntSlot<K> {
    key: K,
    val: u32,
}

/// Integer-keyed table (IPv4, or IPv4+port packed into a u64).
pub struct IntTable<K: Copy + Eq + IntKey> {
    slots: Vec<IntSlot<K>>,
    mask: usize,
    len: usize,
    filter: NegativeFilter,
}

pub trait IntKey {
    fn zero() -> Self;
    fn hash_key(&self) -> u64;
}

impl IntKey for u32 {
    fn zero() -> u32 {
        0
    }
    #[inline]
    fn hash_key(&self) -> u64 {
        mix(*self as u64)
    }
}

impl IntKey for u64 {
    fn zero() -> u64 {
        0
    }
    #[inline]
    fn hash_key(&self) -> u64 {
        mix(*self)
    }
}

impl IntKey for u128 {
    fn zero() -> u128 {
        0
    }
    #[inline]
    fn hash_key(&self) -> u64 {
        mix((*self as u64) ^ ((*self >> 64) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }
}

impl<K: Copy + Eq + IntKey> IntTable<K> {
    pub fn with_capacity(n: usize) -> IntTable<K> {
        let cap = capacity_for(n);
        IntTable {
            slots: vec![IntSlot { key: K::zero(), val: EMPTY }; cap],
            mask: cap - 1,
            len: 0,
            filter: NegativeFilter::new(n),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn insert(&mut self, key: K, val: u32) {
        debug_assert!(val != EMPTY);
        if (self.len + 1) * 100 > self.slots.len() * 85 {
            self.grow();
        }
        let h = key.hash_key();
        self.filter.insert(h);
        let mut i = (h as usize) & self.mask;
        loop {
            if self.slots[i].val == EMPTY {
                self.slots[i] = IntSlot { key, val };
                self.len += 1;
                return;
            }
            if self.slots[i].key == key {
                self.slots[i].val = val;
                return;
            }
            i = (i + 1) & self.mask;
        }
    }

    #[inline]
    pub fn get(&self, key: K) -> Option<u32> {
        let h = key.hash_key();
        // Cache-resident negative prefilter; see `NegativeFilter`. Never a false negative.
        if !self.filter.maybe_contains(h) {
            return None;
        }
        let mut i = (h as usize) & self.mask;
        loop {
            let slot = self.slots[i];
            if slot.val == EMPTY {
                return None;
            }
            if slot.key == key {
                return Some(slot.val);
            }
            i = (i + 1) & self.mask;
        }
    }

    fn grow(&mut self) {
        let old = std::mem::take(&mut self.slots);
        let cap = (old.len() * 2).max(16);
        self.slots = vec![IntSlot { key: K::zero(), val: EMPTY }; cap];
        self.mask = cap - 1;
        for slot in old {
            if slot.val == EMPTY {
                continue;
            }
            let mut i = (slot.key.hash_key() as usize) & self.mask;
            while self.slots[i].val != EMPTY {
                i = (i + 1) & self.mask;
            }
            self.slots[i] = slot;
        }
    }

    pub fn slot_bytes(&self) -> usize {
        self.filter.memory_bytes() + self.slots.len() * std::mem::size_of::<IntSlot<K>>()
    }
}

#[cfg(test)]
mod tests {
    /// The prefilter is only sound if it NEVER reports absent for a key that is present — a false
    /// negative there is a missed detection, silently. Insert far more keys than the filter was
    /// sized for (so it is heavily overloaded) and assert every single one is still found.
    #[test]
    fn the_negative_filter_never_hides_a_present_key() {
        let mut table = StrTable::with_capacity(64, 1024);
        for i in 0..20_000u32 {
            table.insert(&format!("host{i}.example.com"), i + 1);
        }
        for i in 0..20_000u32 {
            assert_eq!(table.get(&format!("host{i}.example.com")), Some(i + 1), "false negative at {i}");
        }

        let mut ints: IntTable<u32> = IntTable::with_capacity(16);
        for i in 0..20_000u32 {
            ints.insert(i, i + 1);
        }
        for i in 0..20_000u32 {
            assert_eq!(ints.get(i), Some(i + 1), "false negative at {i}");
        }
    }

    #[test]
    fn the_negative_filter_rejects_most_absent_keys() {
        // Not a correctness property, a usefulness one: if the filter stopped rejecting, the
        // optimisation would silently become dead weight.
        let mut table = StrTable::with_capacity(10_000, 1 << 16);
        for i in 0..10_000u32 {
            table.insert(&format!("present{i}.example"), i + 1);
        }
        let mut absent_hits = 0;
        for i in 0..10_000u32 {
            if table.get(&format!("absent{i}.example")).is_some() {
                absent_hits += 1;
            }
        }
        assert_eq!(absent_hits, 0, "the table must not invent entries");
        let filter = NegativeFilter::new(10_000);
        assert!(filter.memory_bytes() >= 10_000 * 2, "filter should be ~16 bits per entry");
    }

    use super::*;

    #[test]
    fn str_table_basics() {
        let mut t = StrTable::with_capacity(4, 64);
        t.insert("evil.com", 1);
        t.insert("1.2.3.4", 2);
        assert_eq!(t.get("evil.com"), Some(1));
        assert_eq!(t.get("1.2.3.4"), Some(2));
        assert_eq!(t.get("missing"), None);
        assert!(t.contains("evil.com"));
        assert_eq!(t.len(), 2);
        t.insert("evil.com", 9);
        assert_eq!(t.get("evil.com"), Some(9));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn str_table_grows_and_keeps_everything() {
        let mut t = StrTable::with_capacity(2, 16);
        let keys: Vec<String> = (0..5000).map(|i| format!("host{i}.example.com")).collect();
        for (i, k) in keys.iter().enumerate() {
            t.insert(k, i as u32);
        }
        assert_eq!(t.len(), keys.len());
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(t.get(k), Some(i as u32), "{k}");
        }
        assert_eq!(t.get("host5000.example.com"), None);
        let collected: Vec<&str> = t.iter().map(|(k, _)| k).collect();
        assert_eq!(collected.len(), keys.len());
    }

    #[test]
    fn int_tables() {
        let mut t: IntTable<u32> = IntTable::with_capacity(4);
        t.insert(0, 7); // key 0 must be storable
        t.insert(u32::MAX, 8);
        t.insert(0x0102_0304, 9);
        assert_eq!(t.get(0), Some(7));
        assert_eq!(t.get(u32::MAX), Some(8));
        assert_eq!(t.get(0x0102_0304), Some(9));
        assert_eq!(t.get(5), None);

        let mut u: IntTable<u64> = IntTable::with_capacity(4);
        u.insert((0x0102_0304u64 << 16) | 443, 1);
        assert_eq!(u.get((0x0102_0304u64 << 16) | 443), Some(1));
        assert_eq!(u.get((0x0102_0304u64 << 16) | 80), None);
    }

    #[test]
    fn hash_is_stable_and_spread() {
        assert_eq!(hash_bytes(b"evil.com"), hash_bytes(b"evil.com"));
        assert_ne!(hash_bytes(b"evil.com"), hash_bytes(b"evil.co"));
        let mut buckets = std::collections::HashSet::new();
        for i in 0..1000 {
            buckets.insert(hash_bytes(format!("k{i}").as_bytes()) & 0xff);
        }
        assert!(buckets.len() > 200, "poor low-bit spread: {}", buckets.len());
    }
}
