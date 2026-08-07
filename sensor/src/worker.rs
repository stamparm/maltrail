//! The run-to-completion capture worker.
//!
//! One worker owns one capture handle, its own detection state and its own event sink, so
//! the packet path performs no locking and no cross-thread hand-off. This replaces
//! `sensor.py`'s capture thread + shared mmap ring + `PROCESS_COUNT` worker processes.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::capture::Handle;
use crate::config::{Config, TimestampSource};
use crate::metrics::MetricsSlot;
use crate::output::{EventSink, OutputConfig};
use crate::process;
use crate::state::WorkerState;
use crate::trails::{TrailStore, TrailView};
use crate::whitelist::Whitelist;

/// How many packets between housekeeping checks (trail reload, condense flush, metrics
/// publish, shutdown). Coarse enough that the per-packet cost is a single compare.
const HOUSEKEEPING_INTERVAL: u64 = 1024;

pub struct WorkerContext {
    pub id: usize,
    pub cfg: Arc<Config>,
    pub whitelist: Arc<Whitelist>,
    pub store: Arc<TrailStore>,
    pub output: Arc<OutputConfig>,
    pub slot: Arc<MetricsSlot>,
    pub shutdown: Arc<AtomicBool>,
}

/// Drive one capture handle to completion. Returns when the handle reaches EOF (offline) or
/// shutdown is requested (live).
pub fn run(mut handle: Handle, ctx: WorkerContext) {
    let offline = handle.is_offline();
    let datalink = handle.datalink();
    let snaplen = ctx.cfg.capture_snaplen;
    let use_wallclock = offline && ctx.cfg.offline_timestamps == TimestampSource::Wallclock;

    let sink = EventSink::new(ctx.output.clone());
    let view = TrailView::new(ctx.store.clone());
    let mut st = WorkerState::new(ctx.id, ctx.cfg.clone(), ctx.whitelist.clone(), view, sink);

    let mut since_housekeeping = 0u64;
    let mut scratch: Vec<u8> = Vec::new();
    // Live handles are non-blocking (see capture::Handle::open_live), so an idle interface is
    // waited on with poll() here instead of inside libpcap. That keeps the shutdown check on a
    // bounded leash - at most `capture_timeout_ms` - without a busy spin.
    let poll_fd = handle.selectable_fd();
    let poll_timeout = ctx.cfg.capture_timeout_ms.max(1);
    // Housekeeping runs after this many packets OR after this long, whichever comes first, so a
    // quiet interface still publishes fresh metrics instead of waiting for 1024 packets.
    let mut last_housekeeping = Instant::now();
    const HOUSEKEEPING_MAX_IDLE: std::time::Duration = std::time::Duration::from_secs(1);
    // Packet-path timing is sampled (see below); every Nth packet is measured.
    const TIMING_SAMPLE_STRIDE: u32 = 64;
    let mut timing_countdown: u32 = 1;

    loop {
        if ctx.shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Drain everything currently available, bounded so housekeeping still runs under load.
        let mut drained = 0u32;
        let mut fatal = false;
        loop {
            match handle.next_packet() {
                Ok(Some(captured)) => {
                    st.metrics.packets_received += 1;
                    drained += 1;

                    // pcapy.open_live() caps packets at SNAP_LEN but open_offline() does not, so
                    // a pcap recorded with `-s 0` can exceed it. Truncating here matches what
                    // live capture enforces at capture time.
                    let data: &[u8] = if captured.data.len() > snaplen {
                        scratch.clear();
                        scratch.extend_from_slice(&captured.data[..snaplen]);
                        &scratch
                    } else {
                        captured.data
                    };

                    let (sec, usec) = if use_wallclock { now_parts() } else { (captured.sec, captured.usec) };

                    // Time one packet in TIMING_SAMPLE_STRIDE, not every one. `Instant::now()` is
                    // a vDSO clock_gettime; the pair around the packet path measured 56 ns, which
                    // was ~6% of the sensor's whole per-packet budget - a metric that expensive
                    // distorts the thing it reports. Sampling costs <1 ns/packet and the estimate
                    // is within a couple of percent on any realistic packet mix.
                    timing_countdown -= 1;
                    let started = if timing_countdown == 0 {
                        timing_countdown = TIMING_SAMPLE_STRIDE;
                        Some(Instant::now())
                    } else {
                        None
                    };
                    let ip_offset = st.dlt.resolve(datalink, data);
                    if let Some(offset) = ip_offset {
                        // Mirrors sensor.py's blanket `except Exception` around
                        // _process_packet: a parser bug must never take the sensor down.
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            process::process_packet(&mut st, data, sec, usec, offset);
                        }));
                        if result.is_err() {
                            st.metrics.panics_recovered += 1;
                            crate::output::log_error(
                                &format!("unhandled panic in process_packet (worker {})", ctx.id),
                                true,
                            );
                        }
                    } else {
                        st.metrics.packets_ignored += 1;
                    }
                    if let Some(started) = started {
                        st.metrics.processing_nanos += started.elapsed().as_nanos() as u64;
                        st.metrics.processing_samples += 1;
                    }

                    if drained >= HOUSEKEEPING_INTERVAL as u32 {
                        break;
                    }
                }
                // offline: end of file. live: nothing available right now.
                Ok(None) => {
                    if offline {
                        fatal = true;
                    }
                    break;
                }
                Err(e) => {
                    crate::output::log_error(&format!("capture error on worker {} ({e})", ctx.id), true);
                    if offline {
                        fatal = true;
                    }
                    break;
                }
            }
        }

        if fatal {
            break;
        }

        // Nothing to read: wait for readability (or the timeout) so shutdown is noticed fast.
        if drained == 0 {
            match poll_fd {
                Some(fd) => wait_readable(fd, poll_timeout),
                None => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }

        since_housekeeping += u64::from(drained).max(1);
        if since_housekeeping >= HOUSEKEEPING_INTERVAL || last_housekeeping.elapsed() >= HOUSEKEEPING_MAX_IDLE {
            since_housekeeping = 0;
            last_housekeeping = Instant::now();
            st.trails.refresh();
            st.sink.maybe_flush_condensed();
            // Close throttle windows on the same coarse tick.
            //
            // The clock has to differ between the two modes. Offline, `last_sec` (the packet clock)
            // is right: a replay must be deterministic and must not depend on how long it took.
            // LIVE, `last_sec` is wrong: it stops advancing the moment traffic stops, so a burst
            // that ends leaves its summary buffered until the next packet arrives — which on a
            // quiet interface may be minutes, or never before shutdown. Wall clock is what "the
            // window has closed" means for a live sensor.
            let flush_clock = if offline { st.last_sec } else { now_parts().0 };
            st.sink.flush_throttled(flush_clock);
            if let Some((received, dropped, ifdropped)) = handle.stats() {
                st.metrics.capture_received = received as u64;
                st.metrics.capture_dropped = dropped as u64;
                st.metrics.capture_ifdropped = ifdropped as u64;
            }
            publish(&ctx.slot, &mut st);
        }
    }

    // Flush the tail: condensed events are only emitted on a flush, so skipping this would
    // lose them (sensor.py does the same at the end of an offline run).
    st.sink.flush_condensed();
    st.sink.flush_throttled_all();
    if let Some((received, dropped, ifdropped)) = handle.stats() {
        st.metrics.capture_received = received as u64;
        st.metrics.capture_dropped = dropped as u64;
        st.metrics.capture_ifdropped = ifdropped as u64;
    }
    publish(&ctx.slot, &mut st);
}

fn publish(slot: &MetricsSlot, st: &mut WorkerState) {
    st.metrics.events = st.sink.events;
    st.metrics.events_written = st.sink.events_written;
    st.metrics.log_write_errors = st.sink.log_write_errors;
    let (throttled, summarized, _tracked) = st.sink.throttle_stats();
    st.metrics.events_throttled = throttled;
    st.metrics.events_summarized = summarized;
    slot.publish(&st.metrics);
}

/// Wait until `fd` is readable or `timeout_ms` elapses. Errors (including EINTR) simply return,
/// so the caller re-checks its shutdown flag.
fn wait_readable(fd: std::os::unix::io::RawFd, timeout_ms: i32) {
    let mut pollfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: `pollfd` is a single valid, initialised pollfd we own for the duration of the
    // call; `fd` is owned by the live pcap handle held by this worker.
    unsafe {
        libc::poll(&mut pollfd, 1, timeout_ms);
    }
}

/// `sec, usec = [int(_) for _ in ("%.6f" % time.time()).split('.')]`
fn now_parts() -> (u64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_micros()),
        Err(_) => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallclock_parts_are_plausible() {
        let (sec, usec) = now_parts();
        assert!(sec > 1_600_000_000);
        assert!(usec < 1_000_000);
    }
}
