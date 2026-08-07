//! Sliding-window scan accumulators — `sensor.py:_scan_track()` and the per-second sweep
//! at the top of `_process_packet()`.
//!
//! Memory is bounded exactly like Python: at most `SCAN_TRACK_PER_KEY` items per key and
//! `SCAN_MAX_KEYS` keys in total. The total cap is shared across the port-scan and
//! infection accumulators because Python keeps both in the single `_connect_src_dst` dict
//! (discriminated by whether the second tuple element is an int).

use crate::addr::Ip;
use crate::fasthash::{FastMap, FastSet};

/// `sensor.py:_SCAN_TRACK_PER_KEY`
pub const SCAN_TRACK_PER_KEY: usize = 1024;
/// `sensor.py:_SCAN_MAX_KEYS`
pub const SCAN_MAX_KEYS: usize = 50000;

/// The representative detail tuple Python later pulls out with `next(iter(details))` /
/// `details.pop()`. Python's choice is arbitrary (set iteration order); the first inserted
/// detail is used here so events are deterministic.
#[derive(Clone, Copy, Debug)]
pub struct PortDetail {
    pub sec: u64,
    pub usec: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct InfectionDetail {
    pub sec: u64,
    pub usec: u32,
    pub src_port: u16,
    pub dst_ip: Ip,
}

#[derive(Clone, Debug)]
pub struct PathDetail {
    pub sec: u64,
    pub usec: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// The distinct items seen under one accumulator key.
///
/// Starts as a fixed inline array and only spills to a hash set past `INLINE`. The overwhelming
/// majority of `(src, dst)` pairs are ordinary traffic touching one or two ports, and allocating a
/// `HashSet` for each of them put ~13% of the SYN path in malloc/free. The detection thresholds
/// (10 for port/UDP/web scanning) are below `INLINE`, so a scan is *recognised* before the set
/// ever allocates; the spill only exists to keep counting up to `SCAN_TRACK_PER_KEY`.
enum Items<T, S> {
    Inline { len: u8, slots: [Option<T>; INLINE] },
    Spilled(std::collections::HashSet<T, S>),
}

const INLINE: usize = 12;

impl<T: std::hash::Hash + Eq + Clone, S: std::hash::BuildHasher + Default> Default for Items<T, S> {
    fn default() -> Self {
        Items::Inline { len: 0, slots: std::array::from_fn(|_| None) }
    }
}

impl<T: std::hash::Hash + Eq + Clone, S: std::hash::BuildHasher + Default> Items<T, S> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Items::Inline { len, .. } => *len as usize,
            Items::Spilled(set) => set.len(),
        }
    }

    /// Borrowed lookup, so a `Box<str>` set can be probed with a `&str` and nothing is allocated
    /// just to ask the question.
    #[inline]
    fn contains<Q>(&self, item: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        match self {
            // A linear scan over <=12 inline entries beats hashing them.
            Items::Inline { len, slots } => {
                slots[..*len as usize].iter().any(|s| s.as_ref().map(|v| v.borrow()) == Some(item))
            }
            Items::Spilled(set) => set.contains(item),
        }
    }

    /// Returns true when the item was NEW.
    fn insert(&mut self, item: T) -> bool {
        match self {
            Items::Inline { len, slots } => {
                if slots[..*len as usize].iter().any(|s| s.as_ref() == Some(&item)) {
                    return false;
                }
                if (*len as usize) < INLINE {
                    slots[*len as usize] = Some(item);
                    *len += 1;
                    return true;
                }
                let mut set: std::collections::HashSet<T, S> = std::collections::HashSet::default();
                for slot in slots.iter_mut() {
                    if let Some(v) = slot.take() {
                        set.insert(v);
                    }
                }
                let fresh = set.insert(item);
                *self = Items::Spilled(set);
                fresh
            }
            Items::Spilled(set) => set.insert(item),
        }
    }
}

/// `S` selects the hasher for the spilled form: `FxBuildHasher` for integer items (ports,
/// addresses), `SeededBuildHasher` for items an attacker chooses (URL path segments).
struct Bucket<T, D, S = crate::fasthash::FxBuildHasher> {
    items: Items<T, S>,
    detail: Option<D>,
}

impl<T: std::hash::Hash + Eq + Clone, D, S: std::hash::BuildHasher + Default> Default for Bucket<T, D, S> {
    fn default() -> Self {
        Bucket { items: Items::default(), detail: None }
    }
}

/// Insert into a bucket and report whether this insert took it PAST `threshold`.
///
/// The crossing happens exactly once per key per window (the length only ever grows by one), so
/// the caller can queue the key for the sweep instead of the sweep rescanning every key.
#[inline]
fn insert_and_crossed<T: std::hash::Hash + Eq + Clone, D, S: std::hash::BuildHasher + Default>(
    bucket: &mut Bucket<T, D, S>,
    item: T,
    threshold: usize,
) -> bool {
    if bucket.items.len() >= SCAN_TRACK_PER_KEY {
        return false;
    }
    if !bucket.items.insert(item) {
        return false;
    }
    bucket.items.len() == threshold + 1
}

/// Thresholds a key must EXCEED to become a sweep candidate. Held here so `track_*` can detect
/// the crossing as it happens; the values come from `settings` and never change at runtime.
/// The `A.B.` prefix of a tracked source address, without text.
///
/// Python computes `re.sub(r"\d+\.\d+\Z", "", rendered)`, which strips the last two octets of an
/// IPv4 address and leaves an IPv6 address untouched (the pattern cannot match one).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum PrefixKey {
    /// top 16 bits of an IPv4 address -> "A.B."
    V4(u16),
    /// an IPv6 source contributes its whole rendered form
    V6(u128),
}

impl PrefixKey {
    #[inline]
    fn of(ip: Ip) -> PrefixKey {
        match ip {
            Ip::V4(v) => PrefixKey::V4((v >> 16) as u16),
            Ip::V6(v) => PrefixKey::V6(v),
        }
    }

    /// The text Python would have produced. Only called when the prefix is actually needed.
    fn render(self) -> String {
        match self {
            PrefixKey::V4(top) => format!("{}.{}.", top >> 8, top & 0xff),
            PrefixKey::V6(v) => Ip::V6(v).render().as_str().to_string(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Thresholds {
    pub port: usize,
    pub infection: usize,
    pub web: usize,
    pub udp: usize,
}

pub struct ScanState {
    /// `(src_ip, dst_ip) -> {dst_port}` — port scanning (SYN and stealth flags)
    port_scan: FastMap<(Ip, Ip), Bucket<u16, PortDetail>>,
    /// `(src_ip, dst_port) -> {dst_ip}` — infection scanning
    infection: FastMap<(Ip, u16), Bucket<Ip, InfectionDetail>>,
    /// `(src_ip, dst_ip) -> {first path segment}` — web scanning
    web_scan: FastMap<(Ip, Ip), Bucket<Box<str>, PathDetail, crate::fasthash::SeededBuildHasher>>,
    /// `(src_ip, dst_ip) -> {udp dst_port}` — UDP scanning
    udp_scan: FastMap<(Ip, Ip), Bucket<u16, PortDetail>>,

    alerted_port: FastSet<(Ip, Ip)>,
    alerted_infection: FastSet<(Ip, u16)>,
    alerted_path: FastSet<(Ip, Ip)>,
    alerted_udp: FastSet<(Ip, Ip)>,

    // Keys that have crossed their threshold, queued as it happens.
    //
    // The sweep used to filter all four accumulators on every pass, once per second. With
    // SCAN_MAX_KEYS = 50,000 that is 200,000 hash-map entries visited and four vectors sorted
    // per second of traffic - work proportional to how much the sensor is TRACKING rather than
    // to how much it is DETECTING. Queueing the crossing makes the sweep proportional to the
    // number of alerts instead.
    ready_port: Vec<(Ip, Ip)>,
    ready_infection: Vec<(Ip, u16)>,
    ready_web: Vec<(Ip, Ip)>,
    ready_udp: Vec<(Ip, Ip)>,

    /// `_get_local_prefix()` support: how many tracked source addresses share each `A.B.`
    /// prefix, keyed NATIVELY. Rendering the address and hashing the resulting `String` showed up
    /// as ~7% of the SYN path (a `String` allocation plus SipHash per new accumulator key); the
    /// prefix of an IPv4 address is just its top 16 bits, and the text form is only needed when
    /// `local_prefix()` is actually asked for — once per second at most.
    prefix_counts: FastMap<PrefixKey, usize>,

    thresholds: Thresholds,
    /// Shared key budget across port_scan + infection (Python's single dict).
    connect_keys: usize,
    pub window_start: u64,
}

impl Default for ScanState {
    fn default() -> ScanState {
        ScanState::new(Thresholds {
            port: crate::settings::PORT_SCANNING_THRESHOLD,
            infection: crate::settings::INFECTION_SCANNING_THRESHOLD,
            web: crate::settings::WEB_SCANNING_THRESHOLD,
            udp: crate::settings::PORT_SCANNING_THRESHOLD,
        })
    }
}

impl ScanState {
    pub fn new(thresholds: Thresholds) -> ScanState {
        ScanState {
            port_scan: FastMap::default(),
            infection: FastMap::default(),
            web_scan: FastMap::default(),
            udp_scan: FastMap::default(),
            alerted_port: FastSet::default(),
            alerted_infection: FastSet::default(),
            alerted_path: FastSet::default(),
            alerted_udp: FastSet::default(),
            ready_port: Vec::new(),
            ready_infection: Vec::new(),
            ready_web: Vec::new(),
            ready_udp: Vec::new(),
            prefix_counts: FastMap::default(),
            thresholds,
            connect_keys: 0,
            window_start: 0,
        }
    }

    /// Count one more tracked source address towards its `A.B.` prefix (`_get_local_prefix`).
    /// Called once per NEW accumulator key, not per packet. Distinct prefixes are few, so the
    /// `get_mut` path hits almost always and nothing is allocated.
    #[inline]
    fn note_source(&mut self, src: Ip) {
        *self.prefix_counts.entry(PrefixKey::of(src)).or_insert(0) += 1;
    }

    /// `_scan_track(_connect_src_dst, ..., (src, dst), dst_port, ...)`
    pub fn track_port(&mut self, src: Ip, dst: Ip, port: u16, detail: PortDetail) {
        let threshold = self.thresholds.port;
        match self.port_scan.get_mut(&(src, dst)) {
            Some(bucket) => {
                if bucket.detail.is_none() {
                    bucket.detail = Some(detail);
                }
                if insert_and_crossed(bucket, port, threshold) {
                    self.ready_port.push((src, dst));
                }
            }
            None => {
                if self.connect_keys >= SCAN_MAX_KEYS {
                    return;
                }
                self.connect_keys += 1;
                let mut bucket = Bucket::default();
                bucket.items.insert(port);
                bucket.detail = Some(detail);
                self.port_scan.insert((src, dst), bucket);
                if 1 > threshold {
                    self.ready_port.push((src, dst));
                }
                self.note_source(src);
            }
        }
    }

    /// `_scan_track(_connect_src_dst, ..., (src, dst_port), dst_ip, ...)`
    pub fn track_infection(&mut self, src: Ip, dst_port: u16, dst: Ip, detail: InfectionDetail) {
        let threshold = self.thresholds.infection;
        match self.infection.get_mut(&(src, dst_port)) {
            Some(bucket) => {
                if bucket.detail.is_none() {
                    bucket.detail = Some(detail);
                }
                if insert_and_crossed(bucket, dst, threshold) {
                    self.ready_infection.push((src, dst_port));
                }
            }
            None => {
                if self.connect_keys >= SCAN_MAX_KEYS {
                    return;
                }
                self.connect_keys += 1;
                let mut bucket = Bucket::default();
                bucket.items.insert(dst);
                bucket.detail = Some(detail);
                self.infection.insert((src, dst_port), bucket);
                if 1 > threshold {
                    self.ready_infection.push((src, dst_port));
                }
                self.note_source(src);
            }
        }
    }

    /// `_scan_track(_path_src_dst, ..., (src, dst), first_segment, ...)`
    pub fn track_path(&mut self, src: Ip, dst: Ip, segment: &str, detail: PathDetail) {
        let threshold = self.thresholds.web;
        match self.web_scan.get_mut(&(src, dst)) {
            Some(bucket) => {
                if bucket.detail.is_none() {
                    bucket.detail = Some(detail);
                }
                // `contains` first: the segment is only turned into an owned Box<str> when it is
                // genuinely new, so a client hammering one path allocates nothing per packet.
                if bucket.items.len() < SCAN_TRACK_PER_KEY && !bucket.items.contains(segment) {
                    bucket.items.insert(segment.into());
                    if bucket.items.len() == threshold + 1 {
                        self.ready_web.push((src, dst));
                    }
                }
            }
            None => {
                if self.web_scan.len() >= SCAN_MAX_KEYS {
                    return;
                }
                let mut bucket = Bucket::default();
                bucket.items.insert(segment.into());
                bucket.detail = Some(detail);
                self.web_scan.insert((src, dst), bucket);
                if 1 > threshold {
                    self.ready_web.push((src, dst));
                }
            }
        }
    }

    /// `_scan_track(_udp_scan, ..., (src, dst), dst_port, ...)`
    pub fn track_udp(&mut self, src: Ip, dst: Ip, port: u16, detail: PortDetail) {
        let threshold = self.thresholds.udp;
        match self.udp_scan.get_mut(&(src, dst)) {
            Some(bucket) => {
                if bucket.detail.is_none() {
                    bucket.detail = Some(detail);
                }
                if insert_and_crossed(bucket, port, threshold) {
                    self.ready_udp.push((src, dst));
                }
            }
            None => {
                if self.udp_scan.len() >= SCAN_MAX_KEYS {
                    return;
                }
                let mut bucket = Bucket::default();
                bucket.items.insert(port);
                bucket.detail = Some(detail);
                self.udp_scan.insert((src, dst), bucket);
                if 1 > threshold {
                    self.ready_udp.push((src, dst));
                }
            }
        }
    }

    /// Candidates for the sweep, in a stable order so events are deterministic.
    ///
    /// Drawn from the queue of keys that crossed the threshold, minus the ones already alerted.
    /// A key that the sweep looks at but does NOT alert on (a whitelisted source, an infection
    /// candidate outside the current local prefix) stays queued, because the decision can change
    /// as the prefix evolves - that is what re-scanning every second used to provide.
    pub fn port_scan_candidates(&mut self, _threshold: usize) -> Vec<(Ip, Ip, PortDetail)> {
        let alerted = &self.alerted_port;
        self.ready_port.retain(|k| !alerted.contains(k));
        let mut out: Vec<(Ip, Ip, PortDetail)> = self
            .ready_port
            .iter()
            .filter_map(|(src, dst)| self.port_scan.get(&(*src, *dst)).and_then(|b| b.detail).map(|d| (*src, *dst, d)))
            .collect();
        out.sort_by_key(|(src, dst, _)| (*src, *dst));
        out
    }

    pub fn infection_candidates(&mut self, _threshold: usize) -> Vec<(Ip, u16, InfectionDetail)> {
        let alerted = &self.alerted_infection;
        self.ready_infection.retain(|k| !alerted.contains(k));
        let mut out: Vec<(Ip, u16, InfectionDetail)> = self
            .ready_infection
            .iter()
            .filter_map(|(src, port)| {
                self.infection.get(&(*src, *port)).and_then(|b| b.detail).map(|d| (*src, *port, d))
            })
            .collect();
        out.sort_by_key(|(src, port, _)| (*src, *port));
        out
    }

    pub fn web_scan_candidates(&mut self, _threshold: usize) -> Vec<(Ip, Ip, PathDetail)> {
        let alerted = &self.alerted_path;
        self.ready_web.retain(|k| !alerted.contains(k));
        let mut out: Vec<(Ip, Ip, PathDetail)> = self
            .ready_web
            .iter()
            .filter_map(|(src, dst)| {
                self.web_scan.get(&(*src, *dst)).and_then(|b| b.detail.clone()).map(|d| (*src, *dst, d))
            })
            .collect();
        out.sort_by_key(|(src, dst, _)| (*src, *dst));
        out
    }

    pub fn udp_scan_candidates(&mut self, _threshold: usize) -> Vec<(Ip, Ip, PortDetail)> {
        let alerted = &self.alerted_udp;
        self.ready_udp.retain(|k| !alerted.contains(k));
        let mut out: Vec<(Ip, Ip, PortDetail)> = self
            .ready_udp
            .iter()
            .filter_map(|(src, dst)| self.udp_scan.get(&(*src, *dst)).and_then(|b| b.detail).map(|d| (*src, *dst, d)))
            .collect();
        out.sort_by_key(|(src, dst, _)| (*src, *dst));
        out
    }

    pub fn mark_port_alerted(&mut self, src: Ip, dst: Ip) {
        self.alerted_port.insert((src, dst));
    }

    pub fn mark_infection_alerted(&mut self, src: Ip, port: u16) {
        self.alerted_infection.insert((src, port));
    }

    pub fn mark_path_alerted(&mut self, src: Ip, dst: Ip) {
        self.alerted_path.insert((src, dst));
    }

    pub fn mark_udp_alerted(&mut self, src: Ip, dst: Ip) {
        self.alerted_udp.insert((src, dst));
    }

    /// The most common `A.B.` prefix among tracked source addresses (`_get_local_prefix`).
    /// O(distinct prefixes) rather than O(tracked keys). Ties break on the larger string, which
    /// is what Python's `sorted(..., reverse=True)` does.
    pub fn local_prefix(&self) -> Option<String> {
        // Ties break on the LARGER rendered string (Python's `sorted(..., reverse=True)`), so the
        // few distinct prefixes are rendered here rather than stored as text all along.
        self.prefix_counts
            .iter()
            .map(|(key, count)| (key.render(), *count))
            .max_by(|(a_key, a_count), (b_key, b_count)| a_count.cmp(b_count).then_with(|| a_key.cmp(b_key)))
            .map(|(key, _)| key)
            .filter(|key| !key.is_empty())
    }

    /// The sliding-window boundary clear.
    pub fn clear_window(&mut self, sec: u64) {
        self.port_scan.clear();
        self.infection.clear();
        self.web_scan.clear();
        self.udp_scan.clear();
        self.alerted_port.clear();
        self.alerted_infection.clear();
        self.alerted_path.clear();
        self.alerted_udp.clear();
        self.ready_port.clear();
        self.ready_infection.clear();
        self.ready_web.clear();
        self.ready_udp.clear();
        self.prefix_counts.clear();
        self.connect_keys = 0;
        self.window_start = sec;
    }

    pub fn key_count(&self) -> usize {
        self.connect_keys + self.web_scan.len() + self.udp_scan.len()
    }

    #[cfg(test)]
    pub fn port_scan_len(&self, src: Ip, dst: Ip) -> usize {
        self.port_scan.get(&(src, dst)).map(|b| b.items.len()).unwrap_or(0)
    }

    #[cfg(test)]
    pub fn connect_key_count(&self) -> usize {
        self.connect_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(v: u32) -> Ip {
        Ip::V4(v)
    }

    fn detail() -> PortDetail {
        PortDetail { sec: 1, usec: 0, src_port: 40000, dst_port: 80 }
    }

    #[test]
    fn per_key_and_total_caps() {
        // Mirrors tests/test_sensor.py:TestScanTrackMemoryBound
        let mut s = ScanState::default();
        for p in 0..(SCAN_TRACK_PER_KEY * 4) {
            s.track_port(ip(1), ip(2), (p % 65536) as u16, detail());
        }
        assert!(s.port_scan_len(ip(1), ip(2)) <= SCAN_TRACK_PER_KEY);

        let mut s2 = ScanState::default();
        for i in 0..(SCAN_MAX_KEYS + 5000) {
            s2.track_port(ip(i as u32), ip(0xffff_ffff), 80, detail());
        }
        assert!(s2.connect_key_count() <= SCAN_MAX_KEYS);
    }

    #[test]
    fn shared_key_budget_across_both_accumulators() {
        let mut s = ScanState::default();
        for i in 0..SCAN_MAX_KEYS {
            s.track_port(ip(i as u32), ip(9), 80, detail());
        }
        // the infection accumulator must be refused too, because Python shares one dict
        s.track_infection(ip(12345), 445, ip(7), InfectionDetail { sec: 1, usec: 0, src_port: 1, dst_ip: ip(7) });
        assert_eq!(s.connect_key_count(), SCAN_MAX_KEYS);
        assert!(s.infection_candidates(0).is_empty());
    }

    #[test]
    fn candidates_respect_threshold_and_alert_marks() {
        let mut s = ScanState::default();
        for p in 0..11u16 {
            s.track_port(ip(1), ip(2), 1000 + p, detail());
        }
        assert_eq!(s.port_scan_candidates(10).len(), 1);
        s.mark_port_alerted(ip(1), ip(2));
        assert!(s.port_scan_candidates(10).is_empty());
        assert_eq!(s.port_scan_candidates(11).len(), 0);
    }

    #[test]
    fn window_clear_resets_everything() {
        let mut s = ScanState::default();
        for p in 0..11u16 {
            s.track_port(ip(1), ip(2), 1000 + p, detail());
        }
        s.mark_port_alerted(ip(1), ip(2));
        s.clear_window(100);
        assert_eq!(s.key_count(), 0);
        assert_eq!(s.window_start, 100);
        for p in 0..11u16 {
            s.track_port(ip(1), ip(2), 1000 + p, detail());
        }
        assert_eq!(s.port_scan_candidates(10).len(), 1, "alert marks must be cleared with the window");
    }

    #[test]
    fn deterministic_candidate_order() {
        let mut s = ScanState::default();
        for src in [5u32, 1, 3] {
            for p in 0..11u16 {
                s.track_port(ip(src), ip(9), 1000 + p, detail());
            }
        }
        let got: Vec<u32> = s
            .port_scan_candidates(10)
            .into_iter()
            .map(|(src, _, _)| match src {
                Ip::V4(v) => v,
                _ => 0,
            })
            .collect();
        assert_eq!(got, vec![1, 3, 5]);
    }
}
