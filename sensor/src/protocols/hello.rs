//! Reassembly of a ClientHello that does not fit in one packet: a TLS ClientHello split across TCP
//! segments, or a QUIC one split across Initial packets.
//!
//! The post-quantum key share (X25519MLKEM768, 1,216 bytes) pushed browser ClientHellos to ~2 KB,
//! past one 1,448-byte segment. Chrome also shuffles its extension order, so the SNI lands in the
//! second part about half of the time (122 of 240 measured), and a JA3/JA4 taken from the first
//! part alone is computed over a truncated extension list.
//!
//! Memory is fixed: `SLOTS` slots of `CAP` bytes (~300 KB per worker), allocated on first use and
//! never grown. A seeded flow hash picks a pair of slots; a new handshake takes a free one or
//! replaces the older, so an abandoned half-sent ClientHello gives way before a live one, and a
//! flood costs reassemblies, never memory. Packets of a flow with nothing pending are not even
//! hashed, and nothing at all is done once every slot is older than `TTL`.

use crate::addr::Ip;
use crate::fasthash::SeededHasher;
use std::hash::{Hash, Hasher};

pub const SLOTS: usize = 64;
/// Largest ClientHello reassembled; anything longer is parsed as far as this reaches.
pub const CAP: usize = 4096;
/// The parts of a ClientHello are sent back to back; a slot this old is abandoned.
const TTL: u64 = 3;

struct Slot {
    key: u64,
    /// TCP: the sequence number of the ClientHello's first byte. QUIC: 0 (CRYPTO offsets).
    base: u32,
    need: usize,
    sec: u64,
    /// `Assembler::ticks` at `start`, to tell the older of a pair apart within one second.
    tick: u64,
    reported: bool,
    filled: [u64; CAP / 64],
    buf: [u8; CAP],
}

impl Slot {
    const EMPTY: Slot =
        Slot { key: 0, base: 0, need: 0, sec: 0, tick: 0, reported: false, filled: [0; CAP / 64], buf: [0; CAP] };

    /// Bytes present without a gap from offset 0.
    fn prefix(&self) -> usize {
        let mut n = 0;
        for w in self.filled.iter() {
            let ones = w.trailing_ones() as usize;
            n += ones;
            if ones < 64 {
                break;
            }
        }
        n.min(self.need)
    }
}

/// Set bits `start..end`, a word at a time.
fn mark(filled: &mut [u64; CAP / 64], start: usize, end: usize) {
    let mut b = start;
    while b < end {
        let bit = b % 64;
        let n = (64 - bit).min(end - b);
        let ones = if n == 64 { u64::MAX } else { ((1u64 << n) - 1) << bit };
        filled[b / 64] |= ones;
        b += n;
    }
}

/// What the caller gets back when a slot completes.
pub struct Done<'a> {
    pub bytes: &'a [u8],
    /// The SNI was already checked from the first part.
    pub reported: bool,
}

#[derive(Default)]
pub struct Assembler {
    slots: Vec<Slot>,
    /// Second of the most recent `start`; when `TTL` has passed, every slot is stale.
    newest: u64,
    /// Occupied slots, so a packet of a flow with nothing pending is not even hashed.
    live: usize,
    ticks: u64,
}

/// The two slots a key may occupy.
fn pair(key: u64) -> [usize; 2] {
    let i = (key >> 32) as usize % SLOTS;
    [i, i ^ 1]
}

pub fn flow_key(src: Ip, src_port: u16, dst: Ip, dst_port: u16, extra: &[u8]) -> u64 {
    let mut h = SeededHasher::default();
    (src, src_port, dst, dst_port).hash(&mut h);
    h.write(extra);
    h.finish() | 1
}

impl Assembler {
    /// Begin a ClientHello of `need` bytes (5-byte record header included for TCP).
    pub fn start(&mut self, key: u64, base: u32, need: usize, sec: u64, reported: bool) {
        if self.slots.is_empty() {
            self.slots = (0..SLOTS).map(|_| Slot::EMPTY).collect();
        }
        // Its own slot (a retransmitted first segment), else a free one, else the older.
        let [a, b] = pair(key);
        let (sa, sb) = (&self.slots[a], &self.slots[b]);
        let i = if sa.key == key {
            a
        } else if sb.key == key || sa.key != 0 && (sb.key == 0 || sb.tick < sa.tick) {
            b
        } else {
            a
        };
        self.ticks += 1;
        let s = &mut self.slots[i];
        if s.key == 0 {
            self.live += 1;
        }
        s.key = key;
        s.tick = self.ticks;
        s.base = base;
        s.need = need.min(CAP);
        s.sec = sec;
        s.reported = reported;
        s.filled = [0; CAP / 64];
        self.newest = sec;
    }

    /// Whether any ClientHello can be pending at `sec` - the check made before hashing a flow.
    #[inline]
    pub fn idle(&mut self, sec: u64) -> bool {
        if self.live > 0 && sec > self.newest + TTL {
            for s in self.slots.iter_mut() {
                s.key = 0;
            }
            self.live = 0;
        }
        self.live == 0
    }

    fn free(&mut self, i: usize) {
        self.slots[i].key = 0;
        self.live -= 1;
    }

    /// The pending slot for `key`, if any; stale slots are dropped here.
    fn find(&mut self, key: u64, sec: u64) -> Option<usize> {
        if self.idle(sec) {
            return None;
        }
        let i = pair(key).into_iter().find(|&i| self.slots[i].key == key)?;
        if sec > self.slots[i].sec + TTL {
            self.free(i);
            return None;
        }
        Some(i)
    }

    pub fn pending(&mut self, key: u64, sec: u64) -> bool {
        self.find(key, sec).is_some()
    }

    /// The TCP base sequence of a pending slot.
    pub fn base(&mut self, key: u64, sec: u64) -> Option<u32> {
        self.find(key, sec).map(|i| self.slots[i].base)
    }

    /// Copy `data` in at `off`. Returns the completed ClientHello once every byte up to `need`
    /// is present, and frees the slot (the caller parses `bytes` before the next call).
    pub fn put(&mut self, key: u64, sec: u64, off: usize, data: &[u8]) -> Option<Done<'_>> {
        let i = self.find(key, sec)?;
        let s = &mut self.slots[i];
        if off < s.need {
            let end = off.saturating_add(data.len()).min(s.need);
            s.buf[off..end].copy_from_slice(&data[..end - off]);
            mark(&mut s.filled, off, end);
        }
        if s.prefix() < s.need {
            return None;
        }
        self.free(i);
        let s = &self.slots[i];
        Some(Done { bytes: &s.buf[..s.need], reported: s.reported })
    }

    /// Bytes present without a gap from offset 0, for a pending slot.
    pub fn prefix(&mut self, key: u64, sec: u64) -> Option<&[u8]> {
        let i = self.find(key, sec)?;
        let s = &self.slots[i];
        Some(&s.buf[..s.prefix()])
    }

    pub fn mark_reported(&mut self, key: u64, sec: u64) {
        if let Some(i) = self.find(key, sec) {
            self.slots[i].reported = true;
        }
    }

    pub fn forget(&mut self, key: u64, sec: u64) {
        if let Some(i) = self.find(key, sec) {
            self.free(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ip = Ip::V4(0x0a00_0001);
    const B: Ip = Ip::V4(0x0a00_0002);

    #[test]
    fn completes_in_order_and_out_of_order() {
        let mut a = Assembler::default();
        let k = flow_key(A, 1000, B, 443, &[]);
        a.start(k, 0, 10, 100, false);
        assert!(a.put(k, 100, 0, b"01234").is_none());
        assert_eq!(a.put(k, 100, 5, b"56789").unwrap().bytes, b"0123456789");
        assert!(!a.pending(k, 100), "a completed slot is freed");

        a.start(k, 0, 10, 100, true);
        assert!(a.put(k, 100, 5, b"56789").is_none());
        assert_eq!(a.prefix(k, 100).unwrap(), b"", "a gap at 0 leaves no usable prefix");
        let done = a.put(k, 100, 0, b"01234").unwrap();
        assert_eq!(done.bytes, b"0123456789");
        assert!(done.reported);
    }

    #[test]
    fn bounded_and_expiring() {
        let mut a = Assembler::default();
        let k = flow_key(A, 1000, B, 443, &[]);
        a.start(k, 0, 1 << 20, 100, false);
        let big = vec![7u8; 1 << 20];
        let done = a.put(k, 100, 0, &big).unwrap();
        assert_eq!(done.bytes.len(), CAP, "a ClientHello longer than CAP is cut at CAP");

        a.start(k, 0, 10, 100, false);
        assert!(a.pending(k, 100 + TTL));
        assert!(!a.pending(k, 101 + TTL), "stale after TTL");
        assert!(a.put(k, 101 + TTL, 0, b"0123456789").is_none());

        // Flooding every slot never grows the table.
        for p in 0..10_000u16 {
            a.start(flow_key(A, p, B, 443, &[]), 0, CAP, 200, false);
        }
        assert_eq!(a.slots.len(), SLOTS);
        assert_eq!(a.live, SLOTS);
        assert!(a.idle(201 + TTL), "everything is stale after TTL");
        assert_eq!(a.live, 0);
        // An offset past the end, or a retransmission before the start, is ignored.
        let k = flow_key(A, 1, B, 443, &[]);
        a.start(k, 0, 10, 300, false);
        assert!(a.put(k, 300, usize::MAX, b"x").is_none());
        assert!(a.pending(k, 300));
    }

    #[test]
    fn marks_exactly_the_written_range() {
        for (start, end) in [(0, 1), (0, 64), (3, 64), (63, 65), (5, 300), (64, 128), (100, CAP)] {
            let mut f = [0u64; CAP / 64];
            mark(&mut f, start, end);
            for b in 0..CAP {
                assert_eq!(f[b / 64] >> (b % 64) & 1 == 1, (start..end).contains(&b), "{start}..{end} bit {b}");
            }
        }
    }

    #[test]
    fn a_pair_keeps_two_handshakes_and_evicts_the_older() {
        let mut a = Assembler::default();
        // Three keys landing on the same pair.
        let mut same = Vec::new();
        let mut p = 0u16;
        while same.len() < 3 {
            let k = flow_key(A, p, B, 443, &[]);
            if same.is_empty() || pair(k)[0] / 2 == pair(same[0])[0] / 2 {
                same.push(k);
            }
            p += 1;
        }
        a.start(same[0], 0, 10, 100, false);
        a.start(same[1], 0, 10, 100, false);
        assert!(a.pending(same[0], 100) && a.pending(same[1], 100), "two colliding handshakes both kept");
        a.start(same[0], 0, 10, 100, false); // a retransmitted first segment refreshes its own slot
        a.start(same[2], 0, 10, 100, false);
        assert!(!a.pending(same[1], 100), "the older one gives way");
        assert!(a.pending(same[0], 100) && a.pending(same[2], 100));
        assert_eq!(a.live, 2);
    }

    #[test]
    fn keys_separate_flows_and_directions() {
        assert_ne!(flow_key(A, 1000, B, 443, &[]), flow_key(B, 443, A, 1000, &[]));
        assert_ne!(flow_key(A, 1000, B, 443, b"x"), flow_key(A, 1000, B, 443, b"y"));
        let mut a = Assembler::default();
        a.start(flow_key(A, 1000, B, 443, &[]), 0, 10, 100, false);
        assert!(!a.pending(flow_key(A, 1001, B, 443, &[]), 100));
    }
}
