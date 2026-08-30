//! Worker-local counters plus a lock-free periodic aggregation.
//!
//! Counters are plain `u64` fields owned by the worker (no atomics on the packet path).
//! A worker publishes a snapshot into a shared slot every aggregation tick; the reporter
//! thread sums those slots.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default, Clone, Copy, Debug)]
pub struct WorkerMetrics {
    pub packets_received: u64,
    pub packets_processed: u64,
    pub packets_ignored: u64,
    pub packets_malformed: u64,
    pub packets_truncated: u64,
    pub packets_fragment: u64,
    /// Packets that carried another packet and were unwrapped (VXLAN/GENEVE/GRE/ERSPAN/IP-in-IP).
    pub packets_decapsulated: u64,
    pub events: u64,
    pub events_written: u64,
    /// Local event-log open/write failures: non-zero means detections were produced and LOST.
    pub log_write_errors: u64,
    /// Remote-sink delivery failures: with DISABLE_LOCAL_LOG_STORAGE these are detections LOST.
    pub remote_log_errors: u64,
    /// events the throttle held back, and the aggregated summary lines emitted for them
    pub events_throttled: u64,
    pub events_summarized: u64,
    /// Throttle keys dropped at `max_keys`. Distinct from `events_summarized`, which counts every
    /// summary including the ordinary end-of-window ones.
    pub throttle_evictions: u64,
    pub trail_lookups: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub panics_recovered: u64,
    /// Times a bounded state map refused a NEW key because it was at its cap. Non-zero means
    /// the sensor is running with narrowed heuristics — exact trail matching is unaffected.
    pub state_saturations: u64,
    /// Observables merged into `meta.sqlite`, and flushes that failed. See src/meta.rs.
    pub meta_flushed: u64,
    pub meta_flush_errors: u64,
    pub capture_received: u64,
    pub capture_dropped: u64,
    pub capture_ifdropped: u64,
    pub processing_nanos: u64,
    /// packets actually timed (the packet path is sampled, not timed per packet)
    pub processing_samples: u64,
}

impl WorkerMetrics {
    pub fn add(&mut self, other: &WorkerMetrics) {
        self.packets_received += other.packets_received;
        self.packets_processed += other.packets_processed;
        self.packets_ignored += other.packets_ignored;
        self.packets_malformed += other.packets_malformed;
        self.packets_truncated += other.packets_truncated;
        self.packets_fragment += other.packets_fragment;
        self.packets_decapsulated += other.packets_decapsulated;
        self.events += other.events;
        self.events_written += other.events_written;
        self.log_write_errors += other.log_write_errors;
        self.remote_log_errors += other.remote_log_errors;
        self.events_throttled += other.events_throttled;
        self.events_summarized += other.events_summarized;
        self.throttle_evictions += other.throttle_evictions;
        self.trail_lookups += other.trail_lookups;
        self.cache_hits += other.cache_hits;
        self.cache_misses += other.cache_misses;
        self.panics_recovered += other.panics_recovered;
        self.state_saturations += other.state_saturations;
        self.meta_flushed += other.meta_flushed;
        self.meta_flush_errors += other.meta_flush_errors;
        self.capture_received += other.capture_received;
        self.capture_dropped += other.capture_dropped;
        self.capture_ifdropped += other.capture_ifdropped;
        self.processing_nanos += other.processing_nanos;
        self.processing_samples += other.processing_samples;
    }
}

/// The published, atomically readable form of `WorkerMetrics`.
///
/// `alive`/`last_heartbeat_unix` are lifecycle, not counters: they are what turns "the process
/// is up" into "the process is still capturing". A worker that has died stops updating its
/// heartbeat, and `maltrail_up` goes to 0 even though the HTTP thread is happily answering.
#[derive(Default)]
pub struct MetricsSlot {
    /// false until the worker starts its capture loop, and again once it has left it
    pub alive: AtomicBool,
    /// wall-clock seconds at the worker's last housekeeping tick (0 = never ran)
    pub last_heartbeat_unix: AtomicU64,
    pub packets_received: AtomicU64,
    pub packets_processed: AtomicU64,
    pub packets_ignored: AtomicU64,
    pub packets_malformed: AtomicU64,
    pub packets_truncated: AtomicU64,
    pub packets_fragment: AtomicU64,
    pub packets_decapsulated: AtomicU64,
    pub events: AtomicU64,
    pub events_written: AtomicU64,
    pub log_write_errors: AtomicU64,
    pub remote_log_errors: AtomicU64,
    pub events_throttled: AtomicU64,
    pub events_summarized: AtomicU64,
    pub throttle_evictions: AtomicU64,
    pub trail_lookups: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub panics_recovered: AtomicU64,
    pub state_saturations: AtomicU64,
    pub meta_flushed: AtomicU64,
    pub meta_flush_errors: AtomicU64,
    pub capture_received: AtomicU64,
    pub capture_dropped: AtomicU64,
    pub capture_ifdropped: AtomicU64,
    pub processing_nanos: AtomicU64,
    pub processing_samples: AtomicU64,
}

impl MetricsSlot {
    /// Called by the worker as it enters its capture loop.
    pub fn mark_alive(&self) {
        self.alive.store(true, Ordering::Relaxed);
        self.heartbeat();
    }

    /// Called by the worker as it leaves its capture loop, for ANY reason.
    pub fn mark_dead(&self) {
        self.alive.store(false, Ordering::Relaxed);
    }

    /// Refreshed on the housekeeping tick. A stalled worker keeps `alive` but stops advancing
    /// this, which is the only way to distinguish "wedged" from "idle interface" externally.
    pub fn heartbeat(&self) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        self.last_heartbeat_unix.store(now, Ordering::Relaxed);
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn last_heartbeat(&self) -> u64 {
        self.last_heartbeat_unix.load(Ordering::Relaxed)
    }

    pub fn publish(&self, m: &WorkerMetrics) {
        self.packets_received.store(m.packets_received, Ordering::Relaxed);
        self.packets_processed.store(m.packets_processed, Ordering::Relaxed);
        self.packets_ignored.store(m.packets_ignored, Ordering::Relaxed);
        self.packets_malformed.store(m.packets_malformed, Ordering::Relaxed);
        self.packets_truncated.store(m.packets_truncated, Ordering::Relaxed);
        self.packets_fragment.store(m.packets_fragment, Ordering::Relaxed);
        self.packets_decapsulated.store(m.packets_decapsulated, Ordering::Relaxed);
        self.events.store(m.events, Ordering::Relaxed);
        self.events_written.store(m.events_written, Ordering::Relaxed);
        self.log_write_errors.store(m.log_write_errors, Ordering::Relaxed);
        self.remote_log_errors.store(m.remote_log_errors, Ordering::Relaxed);
        self.events_throttled.store(m.events_throttled, Ordering::Relaxed);
        self.events_summarized.store(m.events_summarized, Ordering::Relaxed);
        self.throttle_evictions.store(m.throttle_evictions, Ordering::Relaxed);
        self.trail_lookups.store(m.trail_lookups, Ordering::Relaxed);
        self.cache_hits.store(m.cache_hits, Ordering::Relaxed);
        self.cache_misses.store(m.cache_misses, Ordering::Relaxed);
        self.panics_recovered.store(m.panics_recovered, Ordering::Relaxed);
        self.state_saturations.store(m.state_saturations, Ordering::Relaxed);
        self.meta_flushed.store(m.meta_flushed, Ordering::Relaxed);
        self.meta_flush_errors.store(m.meta_flush_errors, Ordering::Relaxed);
        self.capture_received.store(m.capture_received, Ordering::Relaxed);
        self.capture_dropped.store(m.capture_dropped, Ordering::Relaxed);
        self.capture_ifdropped.store(m.capture_ifdropped, Ordering::Relaxed);
        self.processing_nanos.store(m.processing_nanos, Ordering::Relaxed);
        self.processing_samples.store(m.processing_samples, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> WorkerMetrics {
        WorkerMetrics {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            packets_ignored: self.packets_ignored.load(Ordering::Relaxed),
            packets_malformed: self.packets_malformed.load(Ordering::Relaxed),
            packets_truncated: self.packets_truncated.load(Ordering::Relaxed),
            packets_fragment: self.packets_fragment.load(Ordering::Relaxed),
            packets_decapsulated: self.packets_decapsulated.load(Ordering::Relaxed),
            events: self.events.load(Ordering::Relaxed),
            events_written: self.events_written.load(Ordering::Relaxed),
            log_write_errors: self.log_write_errors.load(Ordering::Relaxed),
            remote_log_errors: self.remote_log_errors.load(Ordering::Relaxed),
            events_throttled: self.events_throttled.load(Ordering::Relaxed),
            events_summarized: self.events_summarized.load(Ordering::Relaxed),
            throttle_evictions: self.throttle_evictions.load(Ordering::Relaxed),
            trail_lookups: self.trail_lookups.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            panics_recovered: self.panics_recovered.load(Ordering::Relaxed),
            state_saturations: self.state_saturations.load(Ordering::Relaxed),
            meta_flushed: self.meta_flushed.load(Ordering::Relaxed),
            meta_flush_errors: self.meta_flush_errors.load(Ordering::Relaxed),
            capture_received: self.capture_received.load(Ordering::Relaxed),
            capture_dropped: self.capture_dropped.load(Ordering::Relaxed),
            capture_ifdropped: self.capture_ifdropped.load(Ordering::Relaxed),
            processing_nanos: self.processing_nanos.load(Ordering::Relaxed),
            processing_samples: self.processing_samples.load(Ordering::Relaxed),
        }
    }
}

/// All workers' published metrics plus the trail generation currently in use.
pub struct Registry {
    pub slots: Vec<Arc<MetricsSlot>>,
    pub trail_generation: AtomicU64,
    pub trail_count: AtomicU64,
    pub reloads_ok: AtomicU64,
    pub reloads_failed: AtomicU64,
    /// Reloads that PARSED cleanly but were refused for losing too much of the trail set.
    /// Distinct from `reloads_failed`: nothing errored, the data was simply not credible.
    pub reloads_rejected: AtomicU64,
    /// Where events are written, so the metrics endpoint can report the free space there.
    /// `None` when local log storage is disabled (the sensor ships everything off-box).
    pub log_dir: Option<std::path::PathBuf>,
}

impl Registry {
    pub fn new(workers: usize) -> Registry {
        Registry {
            slots: (0..workers).map(|_| Arc::new(MetricsSlot::default())).collect(),
            trail_generation: AtomicU64::new(0),
            trail_count: AtomicU64::new(0),
            reloads_ok: AtomicU64::new(0),
            reloads_failed: AtomicU64::new(0),
            reloads_rejected: AtomicU64::new(0),
            log_dir: None,
        }
    }

    /// Point the free-space gauge at the directory events are actually written to.
    pub fn with_log_dir(mut self, log_dir: Option<std::path::PathBuf>) -> Registry {
        self.log_dir = log_dir;
        self
    }

    pub fn total(&self) -> WorkerMetrics {
        let mut out = WorkerMetrics::default();
        for slot in &self.slots {
            let s = slot.snapshot();
            out.add(&s);
        }
        out
    }

    /// How many capture workers are still in their loop.
    ///
    /// This is the sensor's real health signal. `maltrail_up` used to be the constant 1, which
    /// only ever proved the metrics thread was scheduled — a sensor whose every worker had died
    /// reported itself perfectly healthy while monitoring nothing.
    pub fn workers_alive(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_alive()).count()
    }

    /// One-line operational summary, printed on the `METRICS_INTERVAL` tick and at exit.
    pub fn summary(&self) -> String {
        let t = self.total();
        let per_worker: Vec<String> = self
            .slots
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let m = s.snapshot();
                format!("w{}={}/{}", i, m.packets_processed, m.events)
            })
            .collect();
        let ns_per_packet =
            if t.processing_samples > 0 { t.processing_nanos as f64 / t.processing_samples as f64 } else { 0.0 };
        format!(
            "received={} processed={} ignored={} malformed={} truncated={} fragments={} events={} written={} \
             throttled={} summarized={} \
             trail_lookups={} capture_drops={} if_drops={} panics={} ns/packet={:.0} trails={} generation={} \
             reloads={}/{} [{}]",
            t.packets_received,
            t.packets_processed,
            t.packets_ignored,
            t.packets_malformed,
            t.packets_truncated,
            t.packets_fragment,
            t.events,
            t.events_written,
            t.events_throttled,
            t.events_summarized,
            t.trail_lookups,
            t.capture_dropped,
            t.capture_ifdropped,
            t.panics_recovered,
            ns_per_packet,
            self.trail_count.load(Ordering::Relaxed),
            self.trail_generation.load(Ordering::Relaxed),
            self.reloads_ok.load(Ordering::Relaxed),
            self.reloads_failed.load(Ordering::Relaxed),
            per_worker.join(" ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregation_sums_workers() {
        let reg = Registry::new(2);
        let a = WorkerMetrics { packets_processed: 10, events: 1, ..Default::default() };
        let b = WorkerMetrics { packets_processed: 5, events: 2, ..Default::default() };
        reg.slots[0].publish(&a);
        reg.slots[1].publish(&b);
        let total = reg.total();
        assert_eq!(total.packets_processed, 15);
        assert_eq!(total.events, 3);
        let summary = reg.summary();
        assert!(summary.contains("processed=15"), "{summary}");
        assert!(summary.contains("w0=10/1 w1=5/2"), "{summary}");
    }
}
