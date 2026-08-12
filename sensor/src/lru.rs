//! Bounded LRU map, equivalent to `core/datatype.py:LRUDict` (capacity-bounded,
//! most-recently-used on both get and set, oldest evicted first).
//!
//! Intrusive doubly-linked list over a slab so lookups and evictions are O(1) and the
//! steady-state hot path performs no allocation.

use crate::fasthash::StrMap;
use std::borrow::Borrow;
use std::hash::Hash;

const NIL: u32 = u32::MAX;

struct Node<K, V> {
    key: K,
    value: V,
    prev: u32,
    next: u32,
}

pub struct LruMap<K: Eq + Hash + Clone, V> {
    index: StrMap<K, u32>,
    nodes: Vec<Node<K, V>>,
    free: Vec<u32>,
    head: u32, // most recently used
    tail: u32, // least recently used
    capacity: usize,
    /// Admission filter for `insert_if_seen_before`; empty when the map admits unconditionally.
    doorkeeper: Vec<u64>,
}

impl<K: Eq + Hash + Clone, V> LruMap<K, V> {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        LruMap {
            index: StrMap::with_capacity_and_hasher(capacity.min(4096), Default::default()),
            nodes: Vec::with_capacity(capacity.min(4096)),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
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
    }

    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = *self.index.get(key)?;
        self.detach(idx);
        self.push_front(idx);
        Some(&self.nodes[idx as usize].value)
    }

    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.index.contains_key(key)
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
    pub fn insert_if_seen_before(&mut self, key: K, value: V)
    where
        K: Hash,
    {
        if self.doorkeeper.is_empty() {
            self.insert(key, value);
            return;
        }
        let h = {
            use std::hash::BuildHasher;
            crate::fasthash::SeededBuildHasher::default().hash_one(&key)
        };
        let slot = (h as usize) & (self.doorkeeper.len() - 1);
        // Reserve 0 as "empty"; a fingerprint that hashes to 0 simply never gets promoted early.
        let fingerprint = (h >> 16) | 1;
        if self.doorkeeper[slot] == fingerprint {
            self.insert(key, value);
        } else {
            self.doorkeeper[slot] = fingerprint;
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
        if self.doorkeeper.is_empty() {
            self.insert(key.to_owned(), value);
            return;
        }
        // `Hash for String` delegates to `str`, so this is the same fingerprint the owned
        // version computes — a key promoted by one is promoted by the other.
        let h = {
            use std::hash::BuildHasher;
            crate::fasthash::SeededBuildHasher::default().hash_one(key)
        };
        let slot = (h as usize) & (self.doorkeeper.len() - 1);
        let fingerprint = (h >> 16) | 1;
        if self.doorkeeper[slot] == fingerprint {
            self.insert(key.to_owned(), value);
        } else {
            self.doorkeeper[slot] = fingerprint;
        }
    }

    pub fn insert(&mut self, key: K, value: V) {
        if let Some(&idx) = self.index.get(&key) {
            self.nodes[idx as usize].value = value;
            self.detach(idx);
            self.push_front(idx);
            return;
        }

        if self.index.len() >= self.capacity {
            self.evict_oldest();
        }

        let idx = match self.free.pop() {
            Some(i) => {
                self.nodes[i as usize].key = key.clone();
                self.nodes[i as usize].value = value;
                self.nodes[i as usize].prev = NIL;
                self.nodes[i as usize].next = NIL;
                i
            }
            None => {
                self.nodes.push(Node { key: key.clone(), value, prev: NIL, next: NIL });
                (self.nodes.len() - 1) as u32
            }
        };
        self.index.insert(key, idx);
        self.push_front(idx);
    }

    fn evict_oldest(&mut self) {
        let idx = self.tail;
        if idx == NIL {
            return;
        }
        self.detach(idx);
        let key = self.nodes[idx as usize].key.clone();
        self.index.remove(&key);
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
    fn get_refreshes_recency() {
        let mut m: LruMap<u32, u32> = LruMap::new(2);
        m.insert(1, 1);
        m.insert(2, 2);
        assert_eq!(m.get(&1), Some(&1));
        m.insert(3, 3);
        assert!(m.contains(&1), "1 was refreshed and must survive");
        assert!(!m.contains(&2));
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
    fn overwrite_keeps_len() {
        let mut m: LruMap<u32, u32> = LruMap::new(4);
        m.insert(1, 1);
        m.insert(1, 2);
        assert_eq!(m.len(), 1);
        assert_eq!(m.get(&1), Some(&2));
    }
}
