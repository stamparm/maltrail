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

/// Why a worker left its capture loop.
///
/// Both variants are *expected* endings. Anything else is a `WorkerError`, and the distinction
/// is the whole point: `main` must be able to tell "this worker finished its pcap" from "this
/// worker's interface went away", because the second one means the host has stopped being
/// monitored and the process must not exit 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExit {
    /// Shutdown was requested (signal, or another worker failing) and the loop obeyed.
    Shutdown,
    /// Offline replay reached the end of its pcap file(s).
    OfflineEof,
}

/// Why a worker stopped when it should not have.
#[derive(Debug, Clone)]
pub enum WorkerError {
    /// The capture handle failed persistently. Carries the last error text for the operator.
    Capture(String),
    /// The worker thread unwound. Filled in by `main` from the join result, not returned here.
    Panic,
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::Capture(e) => write!(f, "capture failed: {e}"),
            WorkerError::Panic => write!(f, "worker thread panicked"),
        }
    }
}

/// How many consecutive capture errors, with no packet in between, before a live worker gives
/// up. A single error is often transient (an interface flap, a buffer hiccup); an unbroken run
/// of them is not, and the previous code looped on it forever, logging every time and capturing
/// nothing — a detection outage that looked like a quiet network.
const LIVE_CAPTURE_ERROR_LIMIT: u32 = 64;

/// Drive one capture handle to completion. Returns when the handle reaches EOF (offline) or
/// shutdown is requested (live); errors when capture fails persistently.
pub fn run(handle: Handle, ctx: WorkerContext) -> Result<WorkerExit, WorkerError> {
    run_all(vec![handle], ctx)
}

/// Drive several capture handles through ONE worker state, in order.
///
/// This is what `-r a.pcap,b.pcap` must do. Giving each file its own worker also gave it its own
/// `WorkerState`, so evidence split across files never accumulated: two captures that between
/// them cross a scan threshold would each stay under it and nothing would fire. An analyst
/// replaying a capture set expects one stream, and expects it to be deterministic — which a set
/// of racing per-file workers is not.
///
/// Live capture still uses one handle per worker; that is what `PACKET_FANOUT` parallelises.
pub fn run_all(handles: Vec<Handle>, ctx: WorkerContext) -> Result<WorkerExit, WorkerError> {
    let mut remaining = handles.into_iter();
    let Some(mut handle) = remaining.next() else {
        return Ok(WorkerExit::OfflineEof);
    };
    let offline = handle.is_offline();
    // Re-read per file: a capture set can mix link types (an `any`-interface capture next to an
    // Ethernet one), and resolving the second file with the first file's DLT would misparse it.
    let mut datalink = handle.datalink();
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
    let mut poll_fd = handle.selectable_fd();
    let poll_timeout = ctx.cfg.capture_timeout_ms.max(1);
    // Housekeeping runs after this many packets OR after this long, whichever comes first, so a
    // quiet interface still publishes fresh metrics instead of waiting for 1024 packets.
    let mut last_housekeeping = Instant::now();
    const HOUSEKEEPING_MAX_IDLE: std::time::Duration = std::time::Duration::from_secs(1);
    // Packet-path timing is sampled (see below); every Nth packet is measured.
    const TIMING_SAMPLE_STRIDE: u32 = 64;
    let mut timing_countdown: u32 = 1;

    // How this loop ended, decided inside it and reported to `main` on the way out.
    let mut outcome: Result<WorkerExit, WorkerError> = Ok(WorkerExit::Shutdown);
    let mut consecutive_errors: u32 = 0;

    ctx.slot.mark_alive();

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
                    // Progress: the run of errors is broken, so the limit only ever counts an
                    // UNINTERRUPTED failure streak rather than accumulating over a long uptime.
                    consecutive_errors = 0;

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
                        // Carry the SAME state into the next file rather than ending here.
                        match remaining.next() {
                            Some(next) => {
                                handle = next;
                                datalink = handle.datalink();
                                poll_fd = handle.selectable_fd();
                                continue;
                            }
                            None => {
                                outcome = Ok(WorkerExit::OfflineEof);
                                fatal = true;
                            }
                        }
                    }
                    break;
                }
                Err(e) => {
                    crate::output::log_error(&format!("capture error on worker {} ({e})", ctx.id), true);
                    if offline {
                        // A capture error is NOT a clean end of file. If it happened before a
                        // single packet was read, the capture could not be read at all, and
                        // reporting a successful replay of zero packets is the offline version
                        // of the silent blind spot Gate 1.1 fixed: the analyst sees "no
                        // detections" when the truth is "your file was never parsed".
                        //
                        // Found by the shadow harness on a `mergecap` output — libpcap refuses a
                        // pcapng whose interfaces have different link types, and the sensor
                        // replayed it to "success" with received=0.
                        //
                        // After packets HAVE been read this is a truncated tail: the events found
                        // so far are real and worth keeping, so the run still succeeds and the
                        // error stands in the log.
                        if st.metrics.packets_received == 0 {
                            outcome = Err(WorkerError::Capture(format!("{e} (no packets could be read)")));
                        } else {
                            outcome = Ok(WorkerExit::OfflineEof);
                        }
                        fatal = true;
                    } else {
                        // Live: tolerate a transient hiccup, but never spin here forever. An
                        // unbroken run of errors means the interface is gone, and a sensor that
                        // cannot capture must say so rather than quietly logging in a loop.
                        consecutive_errors += 1;
                        if consecutive_errors >= LIVE_CAPTURE_ERROR_LIMIT {
                            outcome = Err(WorkerError::Capture(format!(
                                "{consecutive_errors} consecutive capture errors, last: {e}"
                            )));
                            fatal = true;
                        }
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
            ctx.slot.heartbeat();
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
    // Marked dead AFTER the final publish, so a scrape landing in this window still sees the
    // worker's last counters rather than a half-torn-down slot.
    ctx.slot.mark_dead();
    outcome
}

fn publish(slot: &MetricsSlot, st: &mut WorkerState) {
    st.metrics.events = st.sink.events;
    st.metrics.events_written = st.sink.events_written;
    st.metrics.log_write_errors = st.sink.log_write_errors;
    let (throttled, summarized, _tracked) = st.sink.throttle_stats();
    st.metrics.events_throttled = throttled;
    st.metrics.events_summarized = summarized;
    // Every bounded map that refused a new key, in one number: an operator should not have to
    // know which structure saturated to know the sensor is degraded.
    st.metrics.state_saturations =
        st.nxdomain.saturations() + st.dns_exhaustion.saturations() + st.sink.condense_saturations;
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
