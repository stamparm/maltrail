//! Periodic-beacon detection — a NEW heuristic, with no `sensor.py` counterpart.
//!
//! An implant that phones home does the one thing neither a human nor an exploit kit does
//! reliably: it reconnects to the same address on a timer. Maltrail's existing heuristics all
//! answer "how MUCH is this host talking"; this one answers "how REGULARLY", which survives
//! exactly the traffic the volume heuristics miss - a low-and-slow C2 channel deliberately
//! staying under any per-second threshold.
//!
//! The statistic is the coefficient of variation of the inter-arrival gaps between consecutive
//! SYNs to one `(src_ip, dst_ip, dst_port)`: mean/stddev at or below [`MAX_CV`] over at least
//! [`MIN_INTERVALS`] gaps. CV is used instead of raw stdev because it is scale-free - a 30 s and
//! a 30 min beacon score identically - which is what lets the interval bounds stay wide.
//!
//! False-positive honesty: anything built as a poller scores as a beacon, because it IS one -
//! uptime monitors, mail clients, license checks. That is why every event is rated
//! `potential periodic beaconing` (suspicious, `(heuristic)`), never `malware`, and why the
//! whole heuristic can be silenced by name through `DISABLED_HEURISTICS beaconing`.
//!
//! Cost discipline: the hot path here is one hash lookup plus O(1) arithmetic on the crossing
//! check; the variance is only computed when a new gap is appended. State is bounded two ways -
//! new flows are refused at [`super::HEURISTIC_MAX_KEYS`] (counted in `state_saturations`), and
//! an hourly tick drops flows silent for [`STALE_AFTER_SECS`].

use crate::addr::Ip;
use crate::fasthash::FastMap;

/// Distinct inter-arrival gaps required before a verdict (so 9 connections).
pub const MIN_INTERVALS: usize = 8;

/// Coefficient of variation (stdev/mean) at or below which the gaps count as periodic.
pub const MAX_CV: f64 = 0.2;

/// Gaps outside this range are not implant timers: below ~5 s is retransmission/backoff noise,
/// above 6 h is longer than any dwell this sensor can plausibly confirm within its state budget.
pub const MIN_INTERVAL_SECS: u64 = 5;
pub const MAX_INTERVAL_SECS: u64 = 6 * 3600;

/// An hourly tick drops flows whose last SYN is older than this.
pub const STALE_AFTER_SECS: u64 = 24 * 3600;

/// How many recent gaps are kept. More history would only sharpen the estimate past the point
/// where the CV bound already separates timers from humans.
const KEPT_INTERVALS: usize = MIN_INTERVALS * 2;

#[derive(Clone, Copy)]
struct Flow {
    last_sec: u64,
    /// Ring buffer of the most recent accepted gaps, seconds.
    gaps: [u16; KEPT_INTERVALS],
    len: usize,
    head: usize,
    alerted: bool,
}

impl Flow {
    fn new(sec: u64) -> Flow {
        Flow { last_sec: sec, gaps: [0; KEPT_INTERVALS], len: 0, head: 0, alerted: false }
    }

    fn push_gap(&mut self, gap: u64) {
        self.gaps[self.head] = gap.min(u16::MAX as u64) as u16;
        self.head = (self.head + 1) % KEPT_INTERVALS;
        self.len = (self.len + 1).min(KEPT_INTERVALS);
    }

    /// Coefficient of variation over the `len` freshest gaps.
    fn cv(&self) -> f64 {
        let n = self.len;
        if n < 2 {
            return f64::INFINITY;
        }
        let mut sum = 0u64;
        for i in 0..n {
            sum += self.gaps[i] as u64;
        }
        let mean = sum as f64 / n as f64;
        if mean <= 0.0 {
            return f64::INFINITY;
        }
        let mut var = 0.0;
        for i in 0..n {
            let d = self.gaps[i] as f64 - mean;
            var += d * d;
        }
        (var / n as f64).sqrt() / mean
    }
}

#[derive(Default)]
pub struct BeaconTracker {
    flows: FastMap<(Ip, Ip, u16), Flow>,
    /// New keys refused because `HEURISTIC_MAX_KEYS` was reached. Folded into the sensor's
    /// `state_saturations` metric like the other heuristics'.
    saturations: u64,
    pruned_hour: Option<u64>,
}

impl BeaconTracker {
    /// Record one connection attempt; `true` exactly when THIS packet completes the verdict.
    ///
    /// Gap handling: below `MIN_INTERVAL_SECS` the attempt is treated as part of the same burst
    /// (the clock does not move, so a retry storm cannot manufacture tiny regular gaps);
    /// above `MAX_INTERVAL_SECS` the pattern is considered broken and the history resets.
    pub fn observe(&mut self, src: Ip, dst: Ip, dst_port: u16, sec: u64) -> bool {
        match self.flows.get_mut(&(src, dst, dst_port)) {
            Some(flow) => {
                if sec <= flow.last_sec {
                    return false; // replayed/reordered pcap clock: no gap at all
                }
                let gap = sec - flow.last_sec;
                flow.last_sec = sec;
                if gap > MAX_INTERVAL_SECS {
                    flow.len = 0;
                    flow.head = 0;
                    return false;
                }
                if gap < MIN_INTERVAL_SECS {
                    return false;
                }
                flow.push_gap(gap);
                if flow.alerted || flow.len < MIN_INTERVALS {
                    return false;
                }
                if flow.cv() <= MAX_CV {
                    flow.alerted = true;
                    true
                } else {
                    false
                }
            }
            None => {
                if self.flows.len() >= super::HEURISTIC_MAX_KEYS {
                    self.saturations += 1;
                    return false;
                }
                self.flows.insert((src, dst, dst_port), Flow::new(sec));
                false
            }
        }
    }

    /// Hourly prune of flows gone quiet (`maybe_prune` idiom shared with the NX counters).
    pub fn maybe_prune(&mut self, sec: u64) {
        let hour = sec / 3600;
        if self.pruned_hour == Some(hour) {
            return;
        }
        self.pruned_hour = Some(hour);
        self.flows.retain(|_, flow| sec.saturating_sub(flow.last_sec) <= STALE_AFTER_SECS);
    }

    pub fn saturations(&self) -> u64 {
        self.saturations
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_regular_timer_is_caught_exactly_once() {
        let mut b = BeaconTracker::default();
        let mut fired = 0;
        for i in 0..=MIN_INTERVALS + 3 {
            // first SYN seeds the flow, then MIN_INTERVALS regular 30 s gaps
            if b.observe(Ip::V4(1), Ip::V4(2), 443, 1000 + 30 * i as u64) {
                fired += 1;
            }
        }
        assert_eq!(fired, 1, "one alert at the eighth regular gap, never again");
    }

    #[test]
    fn human_jitter_does_not_cross() {
        let mut b = BeaconTracker::default();
        // ±35% swing around 60 s - well past what any timer produces
        let gaps = [52u64, 71, 44, 83, 39, 66, 91, 48, 77, 55];
        let mut sec = 10_000u64;
        let mut fired = false;
        for g in gaps {
            sec += g;
            fired |= b.observe(Ip::V4(1), Ip::V4(2), 443, sec);
        }
        assert!(!fired);
    }

    #[test]
    fn retries_do_not_count_as_gaps() {
        let mut b = BeaconTracker::default();
        // nine regular 30 s beacons, each preceded by 1 s/2 s SYN retransmissions
        let mut fired_at = None;
        for beacon in 0..12u64 {
            let base = 1000 + 30 * beacon;
            for retry in [0u64, 1, 3] {
                if b.observe(Ip::V4(1), Ip::V4(2), 443, base + retry) && fired_at.is_none() {
                    fired_at = Some(beacon);
                }
            }
        }
        assert_eq!(fired_at, Some(8), "fires on the ninth beacon (eighth full gap), retries ignored");
    }

    #[test]
    fn a_long_outage_resets_the_pattern() {
        let mut b = BeaconTracker::default();
        for i in 0..=MIN_INTERVALS {
            b.observe(Ip::V4(1), Ip::V4(2), 443, 1000 + 30 * i as u64);
        }
        // the outage itself must not be read as a verdict
        assert!(!b.observe(Ip::V4(1), Ip::V4(2), 443, 1000 + 30 * MIN_INTERVALS as u64 + MAX_INTERVAL_SECS + 1));
        let before = b.len();
        // after the reset the counter starts from scratch: no second alert from stale history
        let mut fired = false;
        for i in 0..MIN_INTERVALS {
            fired |= b.observe(Ip::V4(1), Ip::V4(2), 443, 20_000 + 30 * i as u64);
        }
        assert!(!fired, "history must have been wiped by the outage");
        assert_eq!(b.len(), before);
    }

    #[test]
    fn the_flow_table_is_bounded_and_pruned() {
        let mut b = BeaconTracker::default();
        for i in 0..super::super::HEURISTIC_MAX_KEYS + 100 {
            b.observe(Ip::V4(i as u32), Ip::V4(2), 443, 10);
        }
        assert_eq!(b.len(), super::super::HEURISTIC_MAX_KEYS);
        assert!(b.saturations() > 0);

        // an hourly tick drops everything silent for over STALE_AFTER_SECS
        b.maybe_prune(25 * 3600); // 24 h + a bit past the sec=10 seeds
        assert!(b.is_empty());
        b.observe(Ip::V4(7), Ip::V4(8), 443, 25 * 3600 + 1);
        b.maybe_prune(25 * 3600 + 5); // same hour: no-op
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn distinct_destinations_are_independent() {
        let mut b = BeaconTracker::default();
        for i in 0..=MIN_INTERVALS {
            assert!(!b.observe(Ip::V4(1), Ip::V4(2), 443 + (i % 2) as u16, 1000 + 30 * i as u64));
        }
        // alternating ports split the history: neither side reaches MIN_INTERVALS
        assert!(!b.observe(Ip::V4(1), Ip::V4(2), 443, 1000 + 30 * (MIN_INTERVALS + 1) as u64));
    }
}
