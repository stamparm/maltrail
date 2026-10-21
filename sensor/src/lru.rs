//! Bounded cache map, the role of `core/datatype.py:LRUDict`: capacity-bounded, and a hit
//! keeps an entry around.
//!
//! Eviction is SIEVE (NSDI '24), not LRU. A hit only sets a bit, where LRU relinked the entry
//! to the front of the list - four scattered writes on every DNS query, twice. The hand walks
//! from the oldest entry, clearing bits, and evicts the first entry not hit since it last
//! passed; one-shot names (scans, DGA floods) leave quickly and recurring ones stay. Every user
//! is a pure cache, so the policy decides only what gets recomputed, never a verdict.
//!
//! Intrusive doubly-linked list over a slab: O(1) lookups and inserts, amortized O(1)
//! evictions, no allocation on the steady-state hot path.

use std::borrow::Borrow;
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};

const NIL: u32 = u32::MAX;

struct Node<K, V> {
    key: K,
    /// The key's seeded hash: the index key, and what eviction removes by.
    hash: u64,
    value: V,
    prev: u32,
    next: u32,
    visited: bool,
}

/// The index is keyed by the key's seeded hash, already computed, so it hashes nothing again.
#[derive(Default)]
struct PreHashed(u64);

impl Hasher for PreHashed {
    fn write(&mut self, _: &[u8]) {
        unreachable!("only u64 hashes are indexed")
    }
    fn write_u64(&mut self, h: u64) {
        self.0 = h;
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Keyed by hash rather than by key: one hash per operation (the doorkeeper reuses it), and the
/// key is stored once, in its node, instead of twice. Two keys sharing a 64-bit seeded hash
/// only displace each other - a hit compares the stored key, and these are caches.
pub struct LruMap<K: Eq + Hash + Clone, V> {
    index: std::collections::HashMap<u64, u32, BuildHasherDefault<PreHashed>>,
    nodes: Vec<Node<K, V>>,
    free: Vec<u32>,
    head: u32, // newest
    tail: u32, // oldest
    /// SIEVE's hand: the next eviction candidate, walking from the tail towards the head.
    hand: u32,
    capacity: usize,
    /// Admission filter for `insert_if_seen_before`; empty when the map admits unconditionally.
    doorkeeper: Vec<u64>,
}

impl<K: Eq + Hash + Clone, V> LruMap<K, V> {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        LruMap {
            index: std::collections::HashMap::with_capacity_and_hasher(capacity.min(4096), Default::default()),
            nodes: Vec::with_capacity(capacity.min(4096)),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
            hand: NIL,
            capacity,
            doorkeeper: Vec::new(),
        }
    }

    /// Enable second-sighting admission with a `slots`-entry fingerprint table (rounded up to a
    /// power of two). 4096 slots is 32 kB — L1/L2 resident, so the check is a single load.
    pub fn with_admission_filter(mut self, slots: usize) -> Self {
        self.doorkeeper = vec![0u64; slots.max(64).next_power_of_two()];
        self
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn clear(&mut self) {
        self.index.clear();
        self.nodes.clear();
        self.free.clear();
        self.head = NIL;
        self.tail = NIL;
        self.hand = NIL;
    }

    /// The hash every `*_hashed` method takes, so a lookup and the insert after it hash once.
    /// `Hash for String` delegates to `str`, so an owned and a borrowed key hash alike.
    #[inline]
    pub fn hash_of<Q: Hash + ?Sized>(&self, key: &Q) -> u64 {
        crate::fasthash::SeededBuildHasher::default().hash_one(key)
    }

    #[inline]
    fn slot<Q>(&self, h: u64, key: &Q) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let idx = *self.index.get(&h)? as usize;
        (self.nodes[idx].key.borrow() == key).then_some(idx)
    }

    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let h = self.hash_of(key);
        self.get_hashed(h, key)
    }

    /// `get` with `h = hash_of(key)` already computed.
    #[inline]
    pub fn get_hashed<Q>(&mut self, h: u64, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let idx = self.slot(h, key)?;
        self.nodes[idx].visited = true;
        Some(&self.nodes[idx].value)
    }

    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.slot(self.hash_of(key), key).is_some()
    }

    /// Insert only if this key has been seen BEFORE — a cache-admission doorkeeper.
    ///
    /// Measured on a 1M-query DNS flood, `insert` was **15% of all instructions the sensor
    /// executed**, roughly 1,570 per packet: it clones the key, evicts the oldest entry (a hash
    /// remove), inserts into the index (a hash insert) and relinks the slab. The computation it
    /// caches — a whitelist parent walk — costs about 2.4x LESS than that. So for traffic that
    /// never repeats a name, the cache was strictly more expensive than having no cache at all.
    ///
    /// That is a leftover from the Python original, where the cached work was expensive enough
    /// that caching always won. Here it does not.
    ///
    /// The doorkeeper is a small direct-mapped table of hash fingerprints: a key is admitted to
    /// the LRU only on its second sighting, so a one-shot name (a DGA flood, a scan) costs one
    /// array store instead of a full LRU insert, while a recurring name still lands in the cache
    /// and gets its hits. Correctness is unaffected — these are pure caches, so a skipped insert
    /// only means the verdict is recomputed later.
    pub fn insert_if_seen_before(&mut self, key: K, value: V) {
        let h = self.hash_of(&key);
        if self.admit(h) {
            self.insert_hashed(h, key, value);
        }
    }

    /// `insert_if_seen_before()` without allocating the key first.
    ///
    /// The doorkeeper turns a first sighting away, and for the traffic it exists for — a DGA
    /// flood, a scan, any stream of names that never repeats — that IS the common case. Taking
    /// the key by value made the caller allocate the `String` the doorkeeper was about to
    /// discard: on the DNS path, one heap allocation per query, twice (the clean-domain cache
    /// and the whitelist-verdict cache), for nothing.
    pub fn insert_if_seen_before_borrowed<Q>(&mut self, key: &Q, value: V)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized + ToOwned<Owned = K>,
    {
        let h = self.hash_of(key);
        self.insert_if_seen_before_hashed(h, key, value);
    }

    /// `insert_if_seen_before_borrowed` with `h = hash_of(key)` already computed.
    #[inline]
    pub fn insert_if_seen_before_hashed<Q>(&mut self, h: u64, key: &Q, value: V)
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized + ToOwned<Owned = K>,
    {
        if self.admit(h) {
            self.insert_hashed(h, key.to_owned(), value);
        }
    }

    /// The doorkeeper: true on a key's second sighting (or always, without one).
    #[inline]
    fn admit(&mut self, h: u64) -> bool {
        if self.doorkeeper.is_empty() {
            return true;
        }
        let slot = (h as usize) & (self.doorkeeper.len() - 1);
        // Reserve 0 as "empty"; a fingerprint that hashes to 0 simply never gets promoted early.
        let fingerprint = (h >> 16) | 1;
        if self.doorkeeper[slot] == fingerprint {
            return true;
        }
        self.doorkeeper[slot] = fingerprint;
        false
    }

    pub fn insert(&mut self, key: K, value: V) {
        let h = self.hash_of(&key);
        self.insert_hashed(h, key, value);
    }

    fn insert_hashed(&mut self, h: u64, key: K, value: V) {
        if let Some(&idx) = self.index.get(&h) {
            // The same key, or one sharing its hash, which it replaces.
            let node = &mut self.nodes[idx as usize];
            node.visited = node.key == key;
            node.key = key;
            node.value = value;
            return;
        }

        if self.index.len() >= self.capacity {
            self.evict();
        }

        let node = Node { key, hash: h, value, prev: NIL, next: NIL, visited: false };
        let idx = match self.free.pop() {
            Some(i) => {
                self.nodes[i as usize] = node;
                i
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        };
        self.index.insert(h, idx);
        self.push_front(idx);
    }

    /// SIEVE: from the hand towards the head, clear visited bits and evict the first entry
    /// without one; the hand stays where it stopped. Terminates within one lap, because every
    /// entry it passes loses its bit.
    fn evict(&mut self) {
        let mut idx = if self.hand == NIL { self.tail } else { self.hand };
        if idx == NIL {
            return;
        }
        while self.nodes[idx as usize].visited {
            self.nodes[idx as usize].visited = false;
            idx = match self.nodes[idx as usize].prev {
                NIL => self.tail,
                prev => prev,
            };
        }
        self.hand = self.nodes[idx as usize].prev;
        self.detach(idx);
        self.index.remove(&self.nodes[idx as usize].hash);
        self.free.push(idx);
    }

    fn detach(&mut self, idx: u32) {
        let (prev, next) = {
            let n = &self.nodes[idx as usize];
            (n.prev, n.next)
        };
        if prev != NIL {
            self.nodes[prev as usize].next = next;
        } else if self.head == idx {
            self.head = next;
        }
        if next != NIL {
            self.nodes[next as usize].prev = prev;
        } else if self.tail == idx {
            self.tail = prev;
        }
        let n = &mut self.nodes[idx as usize];
        n.prev = NIL;
        n.next = NIL;
    }

    fn push_front(&mut self, idx: u32) {
        let old = self.head;
        self.nodes[idx as usize].next = old;
        self.nodes[idx as usize].prev = NIL;
        if old != NIL {
            self.nodes[old as usize].prev = idx;
        }
        self.head = idx;
        if self.tail == NIL {
            self.tail = idx;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lrudict_doctest() {
        // >>> foo = LRUDict(capacity=2); foo["first"]=1; foo["second"]=2; foo["third"]=3
        let mut foo: LruMap<String, i32> = LruMap::new(2);
        foo.insert("first".into(), 1);
        foo.insert("second".into(), 2);
        foo.insert("third".into(), 3);
        assert!(!foo.contains("first"));
        assert!(foo.contains("third"));
        assert_eq!(foo.len(), 2);
    }

    #[test]
    fn a_hit_survives_the_next_eviction() {
        let mut m: LruMap<u32, u32> = LruMap::new(2);
        m.insert(1, 1);
        m.insert(2, 2);
        assert_eq!(m.get(&1), Some(&1));
        m.insert(3, 3);
        assert!(m.contains(&1), "1 was hit and must survive");
        assert!(!m.contains(&2));
    }

    #[test]
    fn sieve_keeps_hot_keys_through_a_flood_of_one_shot_keys() {
        let mut m: LruMap<u32, u32> = LruMap::new(16);
        for i in 0..8 {
            m.insert(i, i);
        }
        for round in 0..100u32 {
            for i in 0..8 {
                assert_eq!(m.get(&i), Some(&i), "hot key {i} lost in round {round}");
            }
            for j in 0..4 {
                m.insert(1000 + round * 4 + j, 0); // never seen again
            }
            assert!(m.len() <= 16 && m.nodes.len() <= 16);
        }
    }

    #[test]
    fn reuses_slots_and_stays_bounded() {
        let mut m: LruMap<u32, u32> = LruMap::new(8);
        for i in 0..1000 {
            m.insert(i, i);
            assert!(m.len() <= 8);
        }
        // slab must not grow beyond capacity
        assert!(m.nodes.len() <= 8);
        assert_eq!(m.get(&999), Some(&999));
    }

    #[test]
    fn the_doorkeeper_admits_on_the_second_sighting() {
        let mut m: LruMap<String, u32> = LruMap::new(64).with_admission_filter(64);
        m.insert_if_seen_before("once.example".to_string(), 1);
        assert!(!m.contains("once.example"), "a first sighting must not be admitted");
        m.insert_if_seen_before("once.example".to_string(), 1);
        assert!(m.contains("once.example"), "a second sighting must be");
    }

    #[test]
    fn the_borrowed_doorkeeper_promotes_on_the_same_sighting_as_the_owned_one() {
        // The two forms must agree, not merely both work: they share one fingerprint table, and
        // `check_domain_whitelisted` and the clean-domain cache would otherwise promote a name at
        // different times depending on which call site saw it.
        let keys: Vec<String> = (0..200).map(|i| format!("name-{i}.example")).collect();

        let mut owned: LruMap<String, u32> = LruMap::new(64).with_admission_filter(64);
        let mut borrowed: LruMap<String, u32> = LruMap::new(64).with_admission_filter(64);
        // Two rounds, so both the reject-and-remember and the admit path are exercised.
        for _ in 0..2 {
            for k in &keys {
                owned.insert_if_seen_before(k.clone(), 1);
                borrowed.insert_if_seen_before_borrowed(k.as_str(), 1);
                assert_eq!(owned.contains(k.as_str()), borrowed.contains(k.as_str()), "{k} diverged");
            }
        }
        assert_eq!(owned.len(), borrowed.len());
        assert!(!owned.is_empty(), "the second round must have admitted something");

        // And mixing them is the same as using either alone.
        let mut mixed: LruMap<String, u32> = LruMap::new(64).with_admission_filter(64);
        mixed.insert_if_seen_before(keys[0].clone(), 1);
        assert!(!mixed.contains(keys[0].as_str()));
        mixed.insert_if_seen_before_borrowed(keys[0].as_str(), 1);
        assert!(mixed.contains(keys[0].as_str()), "the borrowed form must see the owned form's fingerprint");
    }

    #[test]
    fn keys_sharing_a_hash_displace_each_other_and_never_alias() {
        let mut m: LruMap<String, u32> = LruMap::new(4);
        m.insert_hashed(7, "a".to_string(), 1);
        m.insert_hashed(7, "b".to_string(), 2);
        assert_eq!(m.get_hashed(7, "a"), None, "a different key with the same hash is not a hit");
        assert_eq!(m.get_hashed(7, "b"), Some(&2));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn overwrite_keeps_len() {
        let mut m: LruMap<u32, u32> = LruMap::new(4);
        m.insert(1, 1);
        m.insert(1, 2);
        assert_eq!(m.len(), 1);
        assert_eq!(m.get(&1), Some(&2));
    }
}
