//! Event-log throttling.
//!
//! ## Why this is not a straight port
//!
//! `core/log.py` throttles with
//!
//! ```text
//! current_bucket = sec // config.PROCESS_COUNT
//! if _thread_data.log_bucket != current_bucket:   # new bucket -> forget everything
//!     _thread_data.log_bucket = current_bucket
//!     _thread_data.log_trails = set()
//! else:                                           # same bucket -> at most one more
//!     if (src_ip, trail) in log_trails or (dst_ip, trail) in log_trails: return
//!     log_trails.add(...)
//! ```
//!
//! Three things fall out of that which are hard to defend as intended behaviour:
//!
//!  1. **The suppression window is `PROCESS_COUNT` seconds.** The number of CPU cores decides how
//!     long a repeated detection stays silent — 16 s on a 16-core box, 4 s on a 4-core one. The
//!     same traffic produces different logs on different hardware.
//!  2. **Exactly two events per bucket get through, not one.** A bucket change resets the set but
//!     does not record the current pair, so the first event of a bucket is logged *and* not
//!     remembered; the second is logged and remembered; the third is dropped. The "one per
//!     bucket" reading of the code is wrong, and the off-by-one is invisible.
//!  3. **Suppressed events vanish.** Ninety-seven dropped duplicates leave no trace in the log,
//!     so a burst is indistinguishable from a trickle.
//!
//! Because the state is per worker, the aggregate rate also scales with the worker count: the
//! same host logs 16x more lines with 16 workers than with one.
//!
//! ## What this does instead
//!
//! Standard alert-suppression behaviour (Suricata `threshold type both`, Snort `event_filter`,
//! Zeek's `suppress_for`): **log a small burst immediately, then summarize.**
//!
//! For each key — `(ip, trail)`, checked for the source and the destination, as Maltrail does:
//!
//!  * the first `burst` events in a `window` are written verbatim (an operator sees a new
//!    detection at once, which is the whole point of an IDS);
//!  * further events in that window are held, not dropped;
//!  * when the window closes, the held events are emitted as ONE line using Maltrail's own
//!    aggregation idiom (`core/log.py:flush_condensed_events`): the fields that vary — source
//!    port, destination address, destination port, protocol — become comma-joined lists in place.
//!    The line still has its eleven columns, so the server, fail2ban and any SIEM keep parsing it.
//!
//! So a hundred DNS lookups of one malware domain in five seconds produce `burst` immediate lines
//! plus one summary line naming every source port involved, instead of "some arbitrary number of
//! lines, decided by the core count".
//!
//! The window is wall-independent (it uses the packet clock), the key table is bounded, and
//! everything is per worker and lock-free, exactly as before.
//!
//! `EVENT_THROTTLE_MODE legacy` restores the Python behaviour verbatim, quirks included, which is
//! what the strict-parity harness runs with.

use std::collections::HashMap;

use crate::event::{Event, Field};
use crate::settings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleMode {
    /// Burst, then one aggregated summary per window (default).
    Summarize,
    /// `core/log.py` verbatim: two events per `sec // PROCESS_COUNT` bucket, remainder discarded.
    Legacy,
    /// No throttling at all: every event is written.
    Off,
}

impl ThrottleMode {
    pub fn parse(value: &str) -> Option<ThrottleMode> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "summarize" | "smart" => Some(ThrottleMode::Summarize),
            "legacy" | "python" | "compat" => Some(ThrottleMode::Legacy),
            "off" | "none" | "false" | "disabled" => Some(ThrottleMode::Off),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ThrottleMode::Summarize => "summarize",
            ThrottleMode::Legacy => "legacy",
            ThrottleMode::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ThrottleConfig {
    pub mode: ThrottleMode,
    /// Suppression window, in seconds of packet time.
    pub window: u64,
    /// Events written verbatim per key per window before summarizing.
    pub burst: u32,
    /// Cap on tracked keys, so a flood of distinct trails cannot grow memory without bound.
    pub max_keys: usize,
    /// `sec / divisor` bucket width for `Legacy` (sensor.py's `PROCESS_COUNT`).
    pub legacy_divisor: u32,
}

impl Default for ThrottleConfig {
    fn default() -> ThrottleConfig {
        ThrottleConfig { mode: ThrottleMode::Summarize, window: 60, burst: 3, max_keys: 50_000, legacy_divisor: 1 }
    }
}

/// What the sink should do with an event.
#[derive(Debug, PartialEq)]
pub enum Decision {
    /// Write it.
    Write,
    /// Hold it back; it will come out in a later summary (or not at all, in legacy mode).
    Suppress,
}

struct KeyState {
    /// second the current window opened
    window_start: u64,
    /// events written verbatim in this window
    written: u32,
    /// events held for the summary (capped at `MAX_CONDENSED_EVENTS`)
    held: Vec<Event>,
    /// how many were held in total, including those past the cap
    held_total: u64,
    /// last time this key saw anything, for eviction
    last_seen: u64,
}

/// 64-bit digest of an (address, trail) pair, allocation-free.
///
/// FxHash over the two byte strings with a separator, so "10.0.0.1" + "x.com" cannot collide with
/// "10.0.0" + "1x.com".
#[inline]
fn hash_field(h: &mut crate::fasthash::FxHasher, field: &Field) {
    use std::hash::{Hash, Hasher};
    match field {
        // An integer field never needs the string it would have been rendered as.
        Field::Int(i) => i.hash(h),
        Field::Text(s) => s.as_bytes().hash(h),
    }
    let _ = h.finish();
}

/// Digest of a plain address string against a trail field.
#[inline]
fn digest_field(addr: &str, trail: &Field) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = crate::fasthash::FxHasher::default();
    addr.as_bytes().hash(&mut h);
    0xffu8.hash(&mut h);
    hash_field(&mut h, trail);
    h.finish()
}

/// Digest of two fields, for the destination side where the address is itself a `Field`.
#[inline]
fn digest_field_pair(addr: &Field, trail: &Field) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = crate::fasthash::FxHasher::default();
    hash_field(&mut h, addr);
    0xffu8.hash(&mut h);
    hash_field(&mut h, trail);
    h.finish()
}

pub struct Throttle {
    cfg: ThrottleConfig,
    keys: HashMap<u64, KeyState, crate::fasthash::FxBuildHasher>,
    // --- legacy mode state (a direct port of the two thread-locals) ---
    legacy_bucket: Option<u64>,
    legacy_trails: std::collections::HashSet<u64, crate::fasthash::FxBuildHasher>,
    /// keys dropped because `max_keys` was reached
    pub evicted: u64,
    /// events held back (summarized or, in legacy mode, discarded)
    pub suppressed: u64,
    /// summary lines emitted
    pub summaries: u64,
}

impl Throttle {
    pub fn new(cfg: ThrottleConfig) -> Throttle {
        Throttle {
            cfg,
            keys: HashMap::default(),
            legacy_bucket: None,
            legacy_trails: std::collections::HashSet::default(),
            evicted: 0,
            suppressed: 0,
            summaries: 0,
        }
    }

    pub fn mode(&self) -> ThrottleMode {
        self.cfg.mode
    }

    /// The key an event throttles under. Maltrail keys on the trail plus either endpoint, so one
    /// noisy host cannot be masked by another talking to the same trail.
    /// The two throttle keys for an event, as 64-bit digests of (address, trail).
    ///
    /// This used to return `[(String, String); 2]`, which allocated FOUR strings on every single
    /// event - two clones of the source address and destination, two of the trail - and then
    /// hashed two `(String, String)` tuples to look them up. Under a detection storm that is the
    /// packet path: measured on 3M all-detection packets, throttling cost 4,100 ns/packet, more
    /// than half of the 7,922 ns total, and the same run with throttling off ran at 253k pps
    /// against 149k. Live, that gap is what made the kernel drop 9.9M packets and lose 62% of
    /// injected detections - a mechanism for bounding log volume destroying the detections it
    /// exists to record.
    ///
    /// Digesting the bytes in place allocates nothing and hashes once. A collision would make two
    /// unrelated (address, trail) pairs share one budget; at 50,000 live keys that is around one
    /// chance in 10^10, and the consequence is a held event that comes out in a summary rather
    /// than verbatim - never a lost detection.
    fn keys_for(event: &Event) -> [u64; 2] {
        [digest_field(&event.src_ip, &event.trail), digest_field_pair(&event.dst_ip, &event.trail)]
    }

    /// Decide what happens to `event`, and return any summary events that became due.
    ///
    /// Summaries are returned rather than written directly so the caller keeps sole ownership of
    /// the log handles (and so this is testable without touching the filesystem).
    pub fn admit(&mut self, event: &Event) -> (Decision, Vec<Event>) {
        match self.cfg.mode {
            ThrottleMode::Off => (Decision::Write, Vec::new()),
            ThrottleMode::Legacy => (self.admit_legacy(event), Vec::new()),
            ThrottleMode::Summarize => self.admit_summarizing(event),
        }
    }

    /// `core/log.py` verbatim, including the reset-without-recording quirk that lets two events
    /// through per bucket.
    fn admit_legacy(&mut self, event: &Event) -> Decision {
        let bucket = event.sec / self.cfg.legacy_divisor.max(1) as u64;
        if self.legacy_bucket != Some(bucket) {
            self.legacy_bucket = Some(bucket);
            self.legacy_trails.clear();
            return Decision::Write;
        }
        let [src_key, dst_key] = Self::keys_for(event);
        if self.legacy_trails.contains(&src_key) || self.legacy_trails.contains(&dst_key) {
            self.suppressed += 1;
            return Decision::Suppress;
        }
        self.legacy_trails.insert(src_key);
        self.legacy_trails.insert(dst_key);
        Decision::Write
    }

    fn admit_summarizing(&mut self, event: &Event) -> (Decision, Vec<Event>) {
        let sec = event.sec;
        let [src_key, dst_key] = Self::keys_for(event);
        let mut due = Vec::new();

        // Which key is already tracking this pair? The source key is canonical for new pairs; an
        // existing destination-side entry wins so both directions share one budget.
        let key = if self.keys.contains_key(&src_key) {
            src_key
        } else if self.keys.contains_key(&dst_key) {
            dst_key
        } else {
            src_key
        };

        if let Some(state) = self.keys.get_mut(&key) {
            // The window is measured on the packet clock, so a replay behaves like live traffic.
            // `sec < window_start` (a pcap that goes backwards, a clock step) closes the window
            // too: better to summarize early than to hold events indefinitely.
            let expired = sec.saturating_sub(state.window_start) >= self.cfg.window || sec < state.window_start;
            if expired {
                if let Some(summary) = Self::summarize(state) {
                    due.push(summary);
                    self.summaries += 1;
                }
                state.window_start = sec;
                state.written = 1;
                state.last_seen = sec;
                return (Decision::Write, due);
            }

            state.last_seen = sec;
            if state.written < self.cfg.burst {
                state.written += 1;
                return (Decision::Write, due);
            }
            state.held_total += 1;
            self.suppressed += 1;
            if state.held.len() < settings::MAX_CONDENSED_EVENTS {
                state.held.push(event.clone());
            }
            return (Decision::Suppress, due);
        }

        // A new key. Make room first: evicting a stale entry can itself produce a summary, which
        // is exactly what we want (nothing is dropped silently).
        if self.keys.len() >= self.cfg.max_keys {
            due.extend(self.evict_batch());
        }
        self.keys
            .insert(key, KeyState { window_start: sec, written: 1, held: Vec::new(), held_total: 0, last_seen: sec });
        (Decision::Write, due)
    }

    /// Turn a key's held events into one aggregated event, resetting its buffer.
    ///
    /// `held` is capped at MAX_CONDENSED_EVENTS while `held_total` counts everything the burst
    /// absorbed, so without the "(+N more)" suffix a long flood would summarise as if only the
    /// cap had arrived - 5000 hits reading as 1000. The suffix keeps the line honest about the
    /// volume while still bounding its size.
    fn summarize(state: &mut KeyState) -> Option<Event> {
        let held = std::mem::take(&mut state.held);
        let total = std::mem::replace(&mut state.held_total, 0);
        if held.is_empty() {
            return None;
        }
        let mut merged = crate::output::merge_events(&held)?;
        let overflow = total.saturating_sub(held.len() as u64);
        if overflow > 0 {
            merged.info = format!("{} (+{} more)", merged.info, overflow);
        }
        Some(merged)
    }

    /// Drop the least recently used ~1% of keys, emitting their pending summaries.
    ///
    /// Evicting ONE key per new key meant a full O(`max_keys`) scan per new key: at the shipped
    /// 50,000 that measured **349 us**, on the capture thread, for traffic an attacker chooses by
    /// inventing distinct (src_ip, trail) pairs. The packet path budgets ~500 ns, so every new key
    /// cost roughly 700 packets' worth of time — capture drops, which on this project means
    /// missed detections.
    ///
    /// Batching is what makes it cheap, and it deliberately does NOT add an index. An earlier
    /// `BTreeSet<(last_seen, key)>` attempt desynchronised from the key table (caught by
    /// `the_key_table_is_bounded_and_evictions_are_summarized`) and was reverted; there is still
    /// exactly one source of truth here. One pass over the timestamps picks a cutoff by linear
    /// selection, a second removes everything at or below it, and the cost amortises to
    /// O(`max_keys` / batch) per new key.
    ///
    /// Nothing is dropped silently: every evicted key still emits its pending summary.
    fn evict_batch(&mut self) -> Vec<Event> {
        let mut due = Vec::new();
        if self.keys.is_empty() {
            return due;
        }
        // Never evict the whole table: a batch that emptied it would throw away the state of keys
        // that are still active, and the next packet would just refill it.
        let target = (self.cfg.max_keys / 100).max(1).min(self.keys.len().saturating_sub(1).max(1));

        let mut stamps: Vec<u64> = self.keys.values().map(|s| s.last_seen).collect();
        let (_, cutoff, _) = stamps.select_nth_unstable(target - 1);
        let cutoff = *cutoff;

        let mut evicted = 0u64;
        let mut summaries = 0u64;
        // Ties on `last_seen` are common (one packet-second covers many keys), so this can remove
        // more than `target`. That is fine - it is a bound, not a quota - and `retain` keeps it to
        // a single pass with no key cloning.
        self.keys.retain(|_, state| {
            if state.last_seen > cutoff {
                return true;
            }
            if let Some(summary) = Self::summarize(state) {
                due.push(summary);
                summaries += 1;
            }
            evicted += 1;
            false
        });
        self.evicted += evicted;
        self.summaries += summaries;
        due
    }

    /// Emit summaries for every window that has closed as of `now`, and forget idle keys.
    /// Called periodically so a burst that simply stops still gets reported.
    pub fn flush_due(&mut self, now: u64) -> Vec<Event> {
        if self.cfg.mode != ThrottleMode::Summarize {
            return Vec::new();
        }
        let mut due = Vec::new();
        let window = self.cfg.window;
        let mut idle: Vec<u64> = Vec::new();
        for (key, state) in self.keys.iter_mut() {
            if now.saturating_sub(state.window_start) < window && now >= state.window_start {
                continue;
            }
            if let Some(summary) = Self::summarize(state) {
                due.push(summary);
            }
            // A key with nothing held and a closed window carries no information; dropping it
            // keeps the table proportional to ACTIVE detections rather than to all of history.
            if state.held.is_empty() && now.saturating_sub(state.last_seen) >= window {
                idle.push(*key);
            } else {
                state.window_start = now;
                state.written = 0;
            }
        }
        self.summaries += due.len() as u64;
        for key in idle {
            self.keys.remove(&key);
        }
        due
    }

    /// Flush everything, whatever the window says (shutdown).
    pub fn flush_all(&mut self) -> Vec<Event> {
        let mut due = Vec::new();
        for state in self.keys.values_mut() {
            if let Some(summary) = Self::summarize(state) {
                due.push(summary);
            }
        }
        self.summaries += due.len() as u64;
        self.keys.clear();
        due
    }

    pub fn tracked_keys(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, Field};

    fn event(sec: u64, src_port: u16, trail: &str) -> Event {
        Event {
            sec,
            usec: 0,
            src_ip: "10.0.0.1".to_string(),
            src_port: Field::Int(src_port as i64),
            dst_ip: Field::Text("1.1.1.1".to_string()),
            dst_port: Field::Int(53),
            proto: Field::Text("UDP".to_string()),
            trail_type: crate::event::trail_type::DNS,
            trail: Field::Text(trail.to_string()),
            info: "malware (test)".to_string(),
            reference: "(static)".to_string(),
        }
    }

    fn cfg(mode: ThrottleMode) -> ThrottleConfig {
        ThrottleConfig { mode, window: 60, burst: 3, max_keys: 8, legacy_divisor: 16 }
    }

    #[test]
    fn a_burst_is_written_then_summarized() {
        let mut t = Throttle::new(cfg(ThrottleMode::Summarize));
        let mut written = 0;
        for i in 0..100u16 {
            let (decision, due) = t.admit(&event(1000, 40000 + i, "evil.example"));
            assert!(due.is_empty(), "no summary is due inside the window");
            if decision == Decision::Write {
                written += 1;
            }
        }
        assert_eq!(written, 3, "the configured burst, no more");
        assert_eq!(t.suppressed, 97);

        // The window closes: one summary, carrying every suppressed source port.
        let due = t.flush_due(1000 + 60);
        assert_eq!(due.len(), 1, "exactly one summary line");
        let ports = due[0].src_port.as_plain();
        assert!(ports.contains(','), "the summary must merge the varying ports: {ports}");
        assert_eq!(ports.split(',').count(), crate::settings::MAX_CONDENSED_EVENTS.min(97));
        // ... and the line still has its usual shape.
        assert_eq!(due[0].trail.as_plain(), "evil.example");
        assert_eq!(due[0].info, "malware (test)");
    }

    #[test]
    fn a_flood_past_the_held_cap_reports_its_true_volume() {
        let mut t = Throttle::new(cfg(ThrottleMode::Summarize));
        // burst + the full held cap + extra: `held` stops growing at the cap but `held_total`
        // keeps counting, so the summary must say how many hits the buffer could not carry.
        let total = 3 + crate::settings::MAX_CONDENSED_EVENTS as u16 + 137;
        for i in 0..total {
            t.admit(&event(1000, 40000 + i % 10, "evil.example"));
        }
        let due = t.flush_due(1000 + 60);
        assert_eq!(due.len(), 1);
        assert_eq!(
            due[0].info,
            format!("malware (test) (+{} more)", total - 3 - crate::settings::MAX_CONDENSED_EVENTS as u16)
        );
    }

    #[test]
    fn a_new_window_starts_writing_again() {
        let mut t = Throttle::new(cfg(ThrottleMode::Summarize));
        for i in 0..10u16 {
            t.admit(&event(1000, 40000 + i, "evil.example"));
        }
        // First event past the window: written, and it flushes the previous window's summary.
        let (decision, due) = t.admit(&event(1000 + 60, 50000, "evil.example"));
        assert_eq!(decision, Decision::Write);
        assert_eq!(due.len(), 1, "the closed window must be summarized, not forgotten");
        let (decision, _) = t.admit(&event(1000 + 61, 50001, "evil.example"));
        assert_eq!(decision, Decision::Write, "the burst budget is fresh");
    }

    #[test]
    fn different_trails_and_hosts_have_independent_budgets() {
        let mut t = Throttle::new(cfg(ThrottleMode::Summarize));
        for i in 0..10u16 {
            assert_eq!(t.admit(&event(1000, 40000 + i, &format!("evil{i}.example"))).0, Decision::Write);
        }
        let mut other = event(1000, 41000, "evil.example");
        other.src_ip = "10.0.0.2".to_string();
        assert_eq!(t.admit(&other).0, Decision::Write);
    }

    #[test]
    fn the_key_table_is_bounded_and_evictions_are_summarized() {
        let mut t = Throttle::new(cfg(ThrottleMode::Summarize));
        // fill the table, holding one event under the first key so eviction has something to say
        for i in 0..8u16 {
            t.admit(&event(1000 + i as u64, 40000, &format!("evil{i}.example")));
        }
        for i in 0..5u16 {
            t.admit(&event(1000, 42000 + i, "evil0.example"));
        }
        assert_eq!(t.tracked_keys(), 8);
        let (_, due) = t.admit(&event(2000, 43000, "fresh.example"));
        assert_eq!(t.tracked_keys(), 8, "the table must stay bounded");
        assert_eq!(t.evicted, 1);
        assert_eq!(due.len(), 1, "the evicted key's held events must still be reported");
    }

    #[test]
    fn evictions_are_batched_and_lose_nothing() {
        // The guard above runs at max_keys=8, where a 1% batch is one key - so it passes just as
        // well against the per-key eviction this replaced. This one runs at a realistic cap, where
        // evicting one key per new key cost a full O(max_keys) scan: 349 us per new key at 50,000,
        // on the capture thread, for traffic an attacker picks by inventing distinct trails.
        const MAX: usize = 1_000;
        let mut t = Throttle::new(ThrottleConfig {
            mode: ThrottleMode::Summarize,
            window: 60,
            burst: 3,
            max_keys: MAX,
            legacy_divisor: 16,
        });

        // Fill the table, pushing each key PAST `burst` so it is holding something a summary owes.
        for i in 0..MAX {
            for port in 0..(3 + 2u16) {
                t.admit(&event(1000 + i as u64, 40000 + port, &format!("evil{i}.example")));
            }
        }
        assert_eq!(t.tracked_keys(), MAX);

        // Push well past the cap and watch the occupancy. Per-key eviction pins it at exactly MAX
        // forever; batching drops it and lets it refill, which is what makes the amortised cost
        // O(max_keys / batch) instead of O(max_keys).
        let mut summaries = 0;
        let mut dipped_below_cap = false;
        for i in 0..(MAX / 2) {
            let (_, due) = t.admit(&event(5000, 43000, &format!("fresh{i}.example")));
            summaries += due.len();
            assert!(t.tracked_keys() <= MAX, "the table must never exceed its cap");
            if t.tracked_keys() < MAX {
                dipped_below_cap = true;
            }
        }
        assert!(dipped_below_cap, "eviction must happen in batches, not one key per insert");
        // Every evicted key was holding an event, so nothing was discarded quietly.
        assert!(summaries > 0, "evicted keys must still report what they were holding");
        assert_eq!(summaries as u64, t.summaries, "summary accounting must match what was emitted");
        assert!(t.evicted >= (MAX / 2) as u64, "every new key past the cap costs an eviction");
    }

    #[test]
    fn shutdown_flushes_everything() {
        let mut t = Throttle::new(cfg(ThrottleMode::Summarize));
        for i in 0..10u16 {
            t.admit(&event(1000, 40000 + i, "evil.example"));
        }
        let due = t.flush_all();
        assert_eq!(due.len(), 1, "held events must not be lost on shutdown");
        assert_eq!(t.tracked_keys(), 0);
    }

    #[test]
    fn legacy_mode_reproduces_core_log_py_exactly() {
        // Measured against core/log.py itself: PROCESS_COUNT=16, one worker, 100 events spread
        // over five seconds -> 4 lines (two per `sec // 16` bucket, and five seconds spans two).
        let mut t = Throttle::new(cfg(ThrottleMode::Legacy));
        let mut written = 0;
        for i in 0..100u16 {
            let sec = 1786091293 + (i as u64) / 20;
            if t.admit(&event(sec, 40000 + i, "malware.bakewithdavid.com")).0 == Decision::Write {
                written += 1;
            }
        }
        assert_eq!(written, 4, "legacy mode must match the Python sensor line for line");
        assert!(t.flush_due(1786091400).is_empty(), "legacy mode never summarizes");
    }

    #[test]
    fn legacy_divisor_one_matches_python_with_process_count_one() {
        // Same measurement with PROCESS_COUNT=1 -> 10 lines (two per second, five seconds).
        let mut t = Throttle::new(ThrottleConfig { legacy_divisor: 1, ..cfg(ThrottleMode::Legacy) });
        let mut written = 0;
        for i in 0..100u16 {
            let sec = 1786091293 + (i as u64) / 20;
            if t.admit(&event(sec, 40000 + i, "malware.bakewithdavid.com")).0 == Decision::Write {
                written += 1;
            }
        }
        assert_eq!(written, 10);
    }

    #[test]
    fn off_mode_writes_everything() {
        let mut t = Throttle::new(cfg(ThrottleMode::Off));
        for i in 0..100u16 {
            assert_eq!(t.admit(&event(1000, 40000 + i, "evil.example")).0, Decision::Write);
        }
        assert_eq!(t.suppressed, 0);
    }

    #[test]
    fn modes_parse_like_the_documented_names() {
        assert_eq!(ThrottleMode::parse(""), Some(ThrottleMode::Summarize));
        assert_eq!(ThrottleMode::parse("summarize"), Some(ThrottleMode::Summarize));
        assert_eq!(ThrottleMode::parse("LEGACY"), Some(ThrottleMode::Legacy));
        assert_eq!(ThrottleMode::parse("off"), Some(ThrottleMode::Off));
        assert_eq!(ThrottleMode::parse("nonsense"), None);
    }
}
