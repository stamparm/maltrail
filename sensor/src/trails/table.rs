//! Compact read-only hash tables for the trail store.
//!
//! `core/trailsdict.py` compacts its final set into packed hash arrays and drops the key
//! strings. The Rust store keeps the keys (they are needed for exact comparison, so a hash
//! collision can never produce a wrong match) but stores them in one arena with an
//! open-addressing index, which costs about the same memory as `core/trailsdict.py`'s frozen form while
//! answering lookups in O(1) with a single probe in the common case.
//!
//! Both tables are built once and then immutable, so lookups need no synchronisation.

use super::region::{Arena, Pod, Region, Spill};

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
        h = (h ^ crate::fasthash::tail_word(rest)).wrapping_mul(K).rotate_left(27);
    }
    mix(h)
}

/// A negative prefilter: a compact bitmap that answers "definitely not in the table" without
/// touching the table.
///
/// The trail store runs ~1.4x the size of the trails CSV - ~100 MB at the time of writing, and it
/// only grows. A miss - which is the overwhelmingly common case, since almost no
/// packet matches a trail - costs a DRAM round trip into a structure far larger than any cache.
/// This bitmap is sized to the entry count (2 bits set per key, ~16 bits per key), so it stays in
/// L2/L3 and a miss is answered from cache.
///
/// **It can never cause a false negative.** A clear bit means "not present" and that is exact: an
/// inserted key always sets its bits. A set bit means "maybe", and the caller falls through to
/// the real lookup. The filter is therefore an optimisation only — detection can never be lost to
/// it, which is why a probabilistic structure is acceptable here at all.
pub struct NegativeFilter {
    bits: Region<u64>,
    mask: usize,
}

impl NegativeFilter {
    pub fn new(entries: usize) -> NegativeFilter {
        NegativeFilter::new_in(entries, None)
    }

    pub fn new_in(entries: usize, spill: Option<&Spill>) -> NegativeFilter {
        // ~16 bits per entry -> ~1.4% false-positive rate with two probes.
        let want_bits = entries.saturating_mul(16).max(1024).next_power_of_two();
        NegativeFilter { bits: Region::filled(want_bits / 64, 0u64, spill), mask: want_bits - 1 }
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

    /// `false` = definitely absent. `true` = possibly present, check the table.
    #[inline]
    pub fn maybe_contains(&self, h: u64) -> bool {
        let (a, b) = self.positions(h);
        (self.bits[a >> 6] >> (a & 63)) & 1 != 0 && (self.bits[b >> 6] >> (b & 63)) & 1 != 0
    }

    pub fn memory_bytes(&self) -> usize {
        self.bits.len() * 8
    }

    pub(super) fn bits(&self) -> &Region<u64> {
        &self.bits
    }

    pub(super) fn mask(&self) -> usize {
        self.mask
    }

    /// A filter over bits read back from a prebuilt store. The mask must cover the bits exactly,
    /// or `positions()` would index past them.
    pub(super) fn from_parts(bits: Region<u64>, mask: usize) -> Option<NegativeFilter> {
        let size = mask.checked_add(1)?;
        (size.is_power_of_two() && Some(size) == bits.len().checked_mul(64)).then_some(NegativeFilter { bits, mask })
    }
}

/// What a prebuilt table's slots were found to hold (`StrTable::validate`, `IntTable::validate`).
pub(super) struct SlotCheck {
    /// occupied slots
    pub occupied: usize,
    /// the largest pair index any slot holds
    pub max_val: Option<u32>,
    /// every key lies inside the arena (always true for integer tables)
    pub in_bounds: bool,
}

// There is deliberately no `resize()`/`resized()` here. Both table types keep their filter across
// `grow()` precisely because a rebuilt filter would start with every bit clear, and a clear bit is
// the exact answer "absent" - so re-sizing a live filter without re-inserting every key already in
// the table turns straight into false negatives, i.e. missed detections. An under-sized filter
// (more keys than the estimate it was built for) only loses rejection rate, which is a performance
// question. One of those is a bug and the other is a trade-off; this keeps only the trade-off.

/// Slots for `n` entries: a 0.8 load factor, NOT rounded up to a power of two. Rounding made the
/// table double in steps - 1.63M trails sat in 4,194,304 slots (64 MiB, 39% full), and 2.9% more
/// trails would have doubled it again - so slots are indexed with `slot_of` instead of a mask.
fn capacity_for(n: usize) -> usize {
    (n.saturating_mul(10) / 8 + 1).max(16)
}

/// The home slot of hash `h` in a table of `cap` slots: a multiply-shift onto `0..cap` (Lemire's
/// "fastrange"), as cheap as a mask but for any size. It uses the LOW 32 bits of `h`, so it stays
/// independent of `StrSlot::tag`, which is the high 32.
#[inline]
fn slot_of(h: u64, cap: usize) -> usize {
    (((h & 0xffff_ffff) * cap as u64) >> 32) as usize
}

/// The next slot of a linear probe.
#[inline]
fn next_slot(i: usize, cap: usize) -> usize {
    if i + 1 == cap {
        0
    } else {
        i + 1
    }
}

/// `repr(C)` and padding-free: the prebuilt store (`store.rs`) writes slots to disk byte for byte.
#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct StrSlot {
    tag: u32,
    off: u32,
    len: u32,
    val: u32,
}

unsafe impl Pod for StrSlot {}

const EMPTY_STR_SLOT: StrSlot = StrSlot { tag: 0, off: 0, len: 0, val: EMPTY };

/// String-keyed table over a byte arena.
pub struct StrTable {
    arena: Arena,
    slots: Region<StrSlot>,
    len: usize,
    filter: NegativeFilter,
    spill: Option<Spill>,
}

impl StrTable {
    pub fn with_capacity(n: usize, arena_hint: usize) -> StrTable {
        StrTable::with_capacity_in(n, arena_hint, None)
    }

    /// `with_capacity()`, file-backed when `spill` is given (see `region.rs`).
    pub fn with_capacity_in(n: usize, arena_hint: usize, spill: Option<&Spill>) -> StrTable {
        let cap = capacity_for(n);
        StrTable {
            arena: Arena::with_capacity(arena_hint, spill),
            slots: Region::filled(cap, EMPTY_STR_SLOT, spill),
            len: 0,
            filter: NegativeFilter::new_in(n, spill),
            spill: spill.cloned(),
        }
    }

    /// Whether the slots live in a file-backed mapping rather than on the heap.
    pub fn is_mapped(&self) -> bool {
        self.slots.is_mapped()
    }

    /// Start writing the built table back, so its pages become reclaimable (see `region.rs`).
    pub fn flush_async(&self) {
        self.arena.flush_async();
        self.slots.flush_async();
        self.filter.bits.flush_async();
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
    /// `contains()`: at 1.6 M rows the slots array is ~34 MB, so every probe is a cache
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
        let mut i = slot_of(h, self.slots.len());
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
            i = next_slot(i, self.slots.len());
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
        // ~100 MB store. Cannot produce a false negative; see `NegativeFilter`.
        if !self.filter.maybe_contains(h) {
            return None;
        }
        let tag = (h >> 32) as u32;
        let mut i = slot_of(h, self.slots.len());
        loop {
            let slot = self.slots[i];
            if slot.val == EMPTY {
                return None;
            }
            if slot.tag == tag && slot.len as usize == bytes.len() && self.slot_key(slot) == bytes {
                return Some(slot.val);
            }
            i = next_slot(i, self.slots.len());
        }
    }

    #[inline]
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    fn grow(&mut self) {
        let cap = (self.slots.len() + self.slots.len() / 2).max(16);
        let old = std::mem::replace(&mut self.slots, Region::filled(cap, EMPTY_STR_SLOT, self.spill.as_ref()));
        for &slot in old.iter() {
            if slot.val == EMPTY {
                continue;
            }
            let mut i = {
                let start = slot.off as usize;
                let key = &self.arena[start..start + slot.len as usize];
                slot_of(hash_bytes(key), cap)
            };
            while self.slots[i].val != EMPTY {
                i = next_slot(i, self.slots.len());
            }
            self.slots[i] = slot;
        }
    }

    pub(super) fn arena(&self) -> &Arena {
        &self.arena
    }

    pub(super) fn slots(&self) -> &Region<StrSlot> {
        &self.slots
    }

    pub(super) fn filter(&self) -> &NegativeFilter {
        &self.filter
    }

    /// A table over parts read back from a prebuilt store. Run `validate()` before trusting it.
    pub(super) fn from_parts(arena: Arena, slots: Region<StrSlot>, filter: NegativeFilter, len: usize) -> StrTable {
        StrTable { arena, slots, len, filter, spill: None }
    }

    /// One pass over the slots. `get()` slices the arena with each slot's offset and length, and
    /// probes until it meets an empty slot - so a prebuilt table is only safe to use when every
    /// key is in bounds and at least one slot is empty. The caller checks both.
    pub(super) fn validate(&self) -> SlotCheck {
        // Branch-free, because this reads every slot of the store on every start: `EMPTY` is
        // `u32::MAX`, so `val + 1` wraps an empty slot to 0, and an empty slot's key is 0..0 (the
        // writer never leaves anything else in one). On a Pi Zero the branchy loop was 15% of a start.
        let (mut occupied, mut top, mut end) = (0usize, 0u32, 0u64);
        for slot in self.slots.iter() {
            occupied += usize::from(slot.val != EMPTY);
            top = top.max(slot.val.wrapping_add(1));
            end = end.max(u64::from(slot.off) + u64::from(slot.len));
        }
        SlotCheck { occupied, max_val: top.checked_sub(1), in_bounds: end <= self.arena.len() as u64 }
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

/// `repr(C)` with the padding spelled out, so a slot has no unspecified bytes: the prebuilt store
/// (`store.rs`) writes slots to disk byte for byte, and reading padding is undefined behaviour.
#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct IntSlot<K: IntKey> {
    key: K,
    val: u32,
    pad: K::Pad,
}

unsafe impl<K: IntKey> Pod for IntSlot<K> {}

/// Integer-keyed table (IPv4, or IPv4+port packed into a u64).
pub struct IntTable<K: IntKey> {
    slots: Region<IntSlot<K>>,
    len: usize,
    filter: NegativeFilter,
    spill: Option<Spill>,
}

/// Only the three key widths below: plain integers, so an `IntSlot` of one is plain old data.
pub trait IntKey: Copy + Eq + 'static {
    /// Explicit padding filling the slot up to the key's alignment (see `IntSlot`).
    type Pad: Copy + Default + 'static;
    fn zero() -> Self;
    fn hash_key(&self) -> u64;
}

impl IntKey for u32 {
    type Pad = [u32; 0];
    fn zero() -> u32 {
        0
    }
    #[inline]
    fn hash_key(&self) -> u64 {
        mix(*self as u64)
    }
}

impl IntKey for u64 {
    type Pad = [u32; 1];
    fn zero() -> u64 {
        0
    }
    #[inline]
    fn hash_key(&self) -> u64 {
        mix(*self)
    }
}

impl IntKey for u128 {
    type Pad = [u32; 3];
    fn zero() -> u128 {
        0
    }
    #[inline]
    fn hash_key(&self) -> u64 {
        mix((*self as u64) ^ ((*self >> 64) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }
}

impl<K: IntKey> IntTable<K> {
    pub fn with_capacity(n: usize) -> IntTable<K> {
        IntTable::with_capacity_in(n, None)
    }

    /// `with_capacity()`, file-backed when `spill` is given (see `region.rs`).
    pub fn with_capacity_in(n: usize, spill: Option<&Spill>) -> IntTable<K> {
        let cap = capacity_for(n);
        IntTable {
            slots: Region::filled(cap, IntSlot { key: K::zero(), val: EMPTY, pad: K::Pad::default() }, spill),
            len: 0,
            filter: NegativeFilter::new_in(n, spill),
            spill: spill.cloned(),
        }
    }

    pub fn flush_async(&self) {
        self.slots.flush_async();
        self.filter.bits.flush_async();
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
        let mut i = slot_of(h, self.slots.len());
        loop {
            if self.slots[i].val == EMPTY {
                self.slots[i] = IntSlot { key, val, pad: K::Pad::default() };
                self.len += 1;
                return;
            }
            if self.slots[i].key == key {
                self.slots[i].val = val;
                return;
            }
            i = next_slot(i, self.slots.len());
        }
    }

    #[inline]
    pub fn get(&self, key: K) -> Option<u32> {
        let h = key.hash_key();
        // Cache-resident negative prefilter; see `NegativeFilter`. Never a false negative.
        if !self.filter.maybe_contains(h) {
            return None;
        }
        let mut i = slot_of(h, self.slots.len());
        loop {
            let slot = self.slots[i];
            if slot.val == EMPTY {
                return None;
            }
            if slot.key == key {
                return Some(slot.val);
            }
            i = next_slot(i, self.slots.len());
        }
    }

    fn grow(&mut self) {
        let cap = (self.slots.len() + self.slots.len() / 2).max(16);
        let old = std::mem::replace(
            &mut self.slots,
            Region::filled(cap, IntSlot { key: K::zero(), val: EMPTY, pad: K::Pad::default() }, self.spill.as_ref()),
        );
        for &slot in old.iter() {
            if slot.val == EMPTY {
                continue;
            }
            let mut i = slot_of(slot.key.hash_key(), cap);
            while self.slots[i].val != EMPTY {
                i = next_slot(i, self.slots.len());
            }
            self.slots[i] = slot;
        }
    }

    pub fn slot_bytes(&self) -> usize {
        self.filter.memory_bytes() + self.slots.len() * std::mem::size_of::<IntSlot<K>>()
    }

    pub(super) fn slots(&self) -> &Region<IntSlot<K>> {
        &self.slots
    }

    pub(super) fn filter(&self) -> &NegativeFilter {
        &self.filter
    }

    /// Every stored `(key, value)`, in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (K, u32)> + '_ {
        self.slots.iter().filter(|s| s.val != EMPTY).map(|s| (s.key, s.val))
    }

    /// A table over parts read back from a prebuilt store. Run `validate()` before trusting it.
    pub(super) fn from_parts(slots: Region<IntSlot<K>>, filter: NegativeFilter, len: usize) -> IntTable<K> {
        IntTable { slots, len, filter, spill: None }
    }

    /// See `StrTable::validate`.
    pub(super) fn validate(&self) -> SlotCheck {
        let (mut occupied, mut top) = (0usize, 0u32);
        for slot in self.slots.iter() {
            occupied += usize::from(slot.val != EMPTY);
            top = top.max(slot.val.wrapping_add(1));
        }
        SlotCheck { occupied, max_val: top.checked_sub(1), in_bounds: true }
    }
}

#[cfg(test)]
mod tests {
    /// `validate()` is what makes a mapped store safe to probe; its branch-free form must give the
    /// plain loop's answers, including for a key pushed past the arena.
    #[test]
    fn validate_matches_the_plain_definition() {
        let reference = |t: &StrTable| {
            let used: Vec<StrSlot> = t.slots.iter().copied().filter(|s| s.val != EMPTY).collect();
            let in_bounds = used.iter().all(|s| s.off as usize + s.len as usize <= t.arena.len());
            (used.len(), used.iter().map(|s| s.val).max(), in_bounds)
        };
        let check = |t: &StrTable| {
            let c = t.validate();
            assert_eq!((c.occupied, c.max_val, c.in_bounds), reference(t));
            c
        };
        let mut table = StrTable::with_capacity(64, 1024);
        assert_eq!(check(&table).max_val, None, "an empty table has no largest value");
        for i in 0..40u32 {
            table.insert(&format!("host{i}.example"), i * 3);
        }
        assert!(check(&table).in_bounds);
        let i = table.slots.iter().position(|s| s.val != EMPTY).unwrap();
        table.slots[i].len = table.arena.len() as u32;
        assert!(!check(&table).in_bounds, "a key past the arena must be caught");
    }

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

    /// The prebuilt store's file format depends on these exact sizes (and records them in its
    /// header, so a change is a store miss rather than a misread).
    #[test]
    fn slot_types_have_the_sizes_the_store_format_assumes() {
        assert_eq!(std::mem::size_of::<StrSlot>(), 16);
        assert_eq!(std::mem::size_of::<IntSlot<u32>>(), 8);
        assert_eq!(std::mem::size_of::<IntSlot<u64>>(), 16);
        assert_eq!(std::mem::size_of::<IntSlot<u128>>(), 32);
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
