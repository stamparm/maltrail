//! A fast hasher for the packet path.
//!
//! `std`'s default is SipHash-1-3, chosen to be HashDoS-resistant. That matters for maps keyed by
//! attacker-controlled *variable-length* data; it is dead weight for maps keyed by a fixed-size
//! tuple of integers (`(Ip, Ip)`, `(Ip, u16)`), which is what every accumulator on the packet path
//! uses. SipHash costs ~20 ns on those keys — several times the cost of the lookup it protects.
//!
//! This is the FxHash used by rustc: a multiply-xor-rotate chain, a handful of cycles per word.
//! Inlined here rather than pulled in as a dependency because it is fifteen lines.
//!
//! **Not for attacker-chosen keys.** Anything keyed by a domain, URL, path or User-Agent uses
//! `SeededHasher` below instead: FxHash is trivially collidable by someone who picks the keys, and
//! a collision flood there is a real denial-of-service against the sensor.

use std::hash::{BuildHasherDefault, Hasher};

const SEED64: u64 = 0x51_7c_c1_b7_27_22_0a_95;

#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline]
    fn add_to_hash(&mut self, i: u64) {
        self.hash = (self.hash.rotate_left(5) ^ i).wrapping_mul(SEED64);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            self.add_to_hash(u64::from_ne_bytes(chunk.try_into().unwrap()));
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rest.len()].copy_from_slice(rest);
            self.add_to_hash(u64::from_ne_bytes(buf));
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add_to_hash(i);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.add_to_hash(i as u64);
        self.add_to_hash((i >> 64) as u64);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        // Final avalanche: FxHash leaves the low bits weak, and hashbrown takes the TOP 7 bits for
        // its control byte and the low bits for the bucket index, so both ends must be mixed.
        let mut h = self.hash;
        h ^= h >> 32;
        h = h.wrapping_mul(0xd6e8_feb8_6659_fd93);
        h ^= h >> 32;
        h
    }
}

pub type FxBuildHasher = BuildHasherDefault<FxHasher>;

// ---------------------------------------------------------------------------------------
// Seeded hash for attacker-chosen keys
// ---------------------------------------------------------------------------------------

/// A fast, *seeded* hash for keys an attacker controls — domains, URLs, paths, User-Agents.
///
/// Those maps cannot use `FxHasher`: an attacker who can pick the keys can pick collisions and
/// turn every lookup into a linear scan. They also do not need SipHash, which a callgrind profile
/// put at 2.3% of the packet path. This is a wyhash-style 64x64->128 multiply-fold, which has no
/// published practical collision attack, keyed with a per-process random seed so an offline attack
/// has nothing to target.
///
/// The seed is drawn once from the OS via `RandomState` (the same source `std`'s HashMap uses),
/// so two runs of the sensor hash differently and a collision set cannot be precomputed.
#[derive(Clone, Copy)]
pub struct SeededHasher {
    seed: u64,
    hash: u64,
}

const WY0: u64 = 0xa076_1d64_78bd_642f;
const WY1: u64 = 0xe703_7ed1_a0b4_28db;

#[inline]
fn wymix(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

fn process_seed() -> u64 {
    use std::sync::OnceLock;
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        use std::hash::BuildHasher;
        // RandomState pulls from the OS on first use; hashing a constant through it yields a
        // value that differs per process.
        let a = std::collections::hash_map::RandomState::new().hash_one(0x5eedu64);
        let b = std::collections::hash_map::RandomState::new().hash_one(0xda7au64);
        wymix(a ^ WY0, b ^ WY1) | 1
    })
}

impl Default for SeededHasher {
    fn default() -> SeededHasher {
        let seed = process_seed();
        SeededHasher { seed, hash: seed }
    }
}

impl Hasher for SeededHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.hash ^ WY0.wrapping_mul(bytes.len() as u64 | 1);
        let mut chunks = bytes.chunks_exact(16);
        for c in &mut chunks {
            let a = u64::from_le_bytes(c[..8].try_into().unwrap());
            let b = u64::from_le_bytes(c[8..].try_into().unwrap());
            h = wymix(a ^ h ^ WY0, b ^ h ^ WY1);
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut a = [0u8; 8];
            let mut b = [0u8; 8];
            let split = rest.len().min(8);
            a[..split].copy_from_slice(&rest[..split]);
            if rest.len() > 8 {
                b[..rest.len() - 8].copy_from_slice(&rest[8..]);
            }
            h = wymix(u64::from_le_bytes(a) ^ h ^ WY0, u64::from_le_bytes(b) ^ h ^ WY1);
        }
        self.hash = h;
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.hash = wymix(self.hash ^ WY0, i as u64 ^ WY1);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.hash = wymix(self.hash ^ WY0, i ^ WY1);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        wymix(self.hash ^ self.seed, WY1)
    }
}

pub type SeededBuildHasher = BuildHasherDefault<SeededHasher>;
/// A `HashMap` for keys an attacker can choose (domains, paths, User-Agents).
pub type StrMap<K, V> = std::collections::HashMap<K, V, SeededBuildHasher>;
/// A `HashSet` for keys an attacker can choose.
pub type StrSet<K> = std::collections::HashSet<K, SeededBuildHasher>;
/// A `HashMap` for fixed-size, non-adversarial keys on the packet path.
pub type FastMap<K, V> = std::collections::HashMap<K, V, FxBuildHasher>;
/// A `HashSet` for fixed-size, non-adversarial keys on the packet path.
pub type FastSet<K> = std::collections::HashSet<K, FxBuildHasher>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hash;

    fn hash_of<T: Hash>(value: &T) -> u64 {
        let mut h = FxHasher::default();
        value.hash(&mut h);
        h.finish()
    }

    #[test]
    fn distinct_keys_hash_distinctly() {
        // Not a quality proof, just a guard against a hasher that ignores part of its input -
        // which would silently turn every accumulator into a linked list.
        let mut seen = std::collections::HashSet::new();
        for a in 0..256u32 {
            for b in 0..256u32 {
                seen.insert(hash_of(&(a, b)));
            }
        }
        assert_eq!(seen.len(), 256 * 256, "hash collisions on 16-bit key space");
    }

    #[test]
    fn low_and_high_bits_both_vary() {
        // hashbrown uses the top 7 bits as a control byte and the low bits as the bucket index;
        // a hasher that only mixes one end degrades one of the two.
        let mut low = std::collections::HashSet::new();
        let mut high = std::collections::HashSet::new();
        for i in 0..4096u64 {
            let h = hash_of(&i);
            low.insert(h & 0xfff);
            high.insert(h >> 57);
        }
        // 4096 keys into 4096 low-bit slots: a good hash lands on 4096*(1-1/e) ~= 2589 distinct
        // slots, not 4096. Anything well below that means the low bits are not being mixed.
        assert!(low.len() > 2400, "low bits barely vary ({})", low.len());
        assert_eq!(high.len(), 128, "top 7 bits should cover their whole range");
    }

    #[test]
    fn the_seeded_hash_is_seeded_and_mixes() {
        // Distinct short strings must not collide en masse, and the seed must actually be used:
        // two hashers built from `default()` share the process seed (so a map is self-consistent),
        // but a different seed must produce different output for the same input.
        let mut seen = std::collections::HashSet::new();
        for i in 0..20_000u32 {
            let key = format!("host{i}.example.com");
            let mut h = SeededHasher::default();
            key.hash(&mut h);
            seen.insert(h.finish());
        }
        assert_eq!(seen.len(), 20_000, "collisions on distinct domain-shaped keys");

        let mut a = SeededHasher::default();
        "evil.example".hash(&mut a);
        let mut b = SeededHasher { seed: 0x1234_5678_9abc_def0, hash: 0x1234_5678_9abc_def0 };
        "evil.example".hash(&mut b);
        assert_ne!(a.finish(), b.finish(), "the seed must affect the digest");
    }

    #[test]
    fn seeded_maps_behave_like_std_maps() {
        let mut m: StrMap<String, u32> = StrMap::default();
        for i in 0..5_000u32 {
            m.insert(format!("k{i}"), i);
        }
        assert_eq!(m.len(), 5_000);
        for i in 0..5_000u32 {
            assert_eq!(m.get(&format!("k{i}")), Some(&i));
        }
        assert_eq!(m.get("missing"), None);
    }

    #[test]
    fn maps_behave_like_std_maps() {
        let mut m: FastMap<(u32, u16), u32> = FastMap::default();
        for i in 0..10_000u32 {
            m.insert((i, (i % 7) as u16), i);
        }
        assert_eq!(m.len(), 10_000);
        for i in 0..10_000u32 {
            assert_eq!(m.get(&(i, (i % 7) as u16)), Some(&i));
        }
        assert_eq!(m.get(&(10_001, 0)), None);
    }
}
