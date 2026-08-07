//! Prometheus metrics endpoint (`STATS_ADDRESS`).
//!
//! A sensor whose health you can only read from a log line it prints once an hour is not
//! operable at scale. Suricata has `stats.log` and EVE `stats` records; this exposes the same
//! information in the format monitoring systems already speak, so drops, throughput and trail
//! freshness can be alerted on instead of discovered.
//!
//! The counters and the cross-worker aggregation already existed for the metrics line — this only
//! adds an exposition format and a socket.
//!
//! Design constraints this respects:
//!
//!  * **Nothing on the packet path.** The endpoint reads the same per-worker `MetricsSlot`s the
//!    metrics line reads: one relaxed atomic load per counter, published by each worker during its
//!    own housekeeping. A scrape cannot slow down or block capture.
//!  * **No async runtime.** One thread, a blocking `TcpListener`, one response per connection.
//!  * **Bind local by default.** Metrics reveal traffic volumes and detection counts; the endpoint
//!    is opt-in and the documented address is a loopback one.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::metrics::Registry;
use crate::settings;

/// Serve until the process exits. Returns the bound address, or an error string for the caller to
/// report — a metrics endpoint that cannot bind must never be fatal to detection.
pub fn spawn(address: &str, registry: Arc<Registry>, started: std::time::Instant) -> Result<String, String> {
    let listener = TcpListener::bind(address).map_err(|e| format!("cannot bind '{address}': {e}"))?;
    let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| address.to_string());
    std::thread::Builder::new()
        .name("stats".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut s) => {
                        let body = render(&registry, started.elapsed().as_secs_f64());
                        let _ = serve(&mut s, &body);
                    }
                    // A failed accept is not worth taking the sensor down for.
                    Err(_) => continue,
                }
            }
        })
        .map_err(|e| format!("cannot start the stats thread: {e}"))?;
    Ok(bound)
}

/// One request, one response. The request line is read and discarded: this endpoint has exactly
/// one resource, and parsing more of HTTP would only add ways to get it wrong.
fn serve(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut scratch = [0u8; 1024];
    // Read whatever the client sent (bounded), so it does not see a connection reset before it
    // has finished writing its request.
    let _ = stream.read(&mut scratch);
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// The exposition text. Counter names follow the Prometheus convention (`_total` suffix on
/// monotonic counters) so they behave correctly under `rate()`.
pub fn render(registry: &Registry, uptime_seconds: f64) -> String {
    let t = registry.total();
    let mut out = String::with_capacity(4096);

    macro_rules! metric {
        ($name:expr, $kind:expr, $help:expr, $value:expr) => {{
            out.push_str(&format!("# HELP {} {}\n# TYPE {} {}\n{} {}\n", $name, $help, $name, $kind, $name, $value));
        }};
    }

    // `maltrail_up` means "this sensor is capturing", NOT "this process answered you". It used
    // to be the constant 1, which made it true even when every capture worker had died — the
    // one condition an operator most needs it to be false for. Alert on this.
    let alive = registry.workers_alive();
    metric!(
        "maltrail_up",
        "gauge",
        "1 while at least one capture worker is running; 0 means this host is NOT being monitored.",
        u8::from(alive > 0)
    );
    metric!("maltrail_workers_alive", "gauge", "Capture workers currently in their capture loop.", alive);
    metric!("maltrail_workers_total", "gauge", "Capture workers this sensor started.", registry.slots.len());
    // Version as a LABEL, which is the Prometheus convention for build info (the value is always
    // 1); emitting it as a comment line after the value would not survive relabelling.
    out.push_str("# HELP maltrail_build_info Sensor build information; the version is a label.\n");
    out.push_str("# TYPE maltrail_build_info gauge\n");
    out.push_str(&format!("maltrail_build_info{{version=\"{}\"}} 1\n", settings::VERSION));
    metric!(
        "maltrail_uptime_seconds",
        "gauge",
        "Seconds since the sensor started capturing.",
        format!("{uptime_seconds:.0}")
    );

    metric!(
        "maltrail_packets_received_total",
        "counter",
        "Packets handed to the sensor by libpcap.",
        t.packets_received
    );
    metric!(
        "maltrail_packets_processed_total",
        "counter",
        "Packets that reached the detection path.",
        t.packets_processed
    );
    metric!(
        "maltrail_packets_ignored_total",
        "counter",
        "Packets skipped (non-IP, unknown link type).",
        t.packets_ignored
    );
    metric!("maltrail_packets_malformed_total", "counter", "Packets rejected as malformed.", t.packets_malformed);
    metric!("maltrail_packets_truncated_total", "counter", "Packets too short for their headers.", t.packets_truncated);
    metric!("maltrail_packets_fragments_total", "counter", "Non-first IP fragments skipped.", t.packets_fragment);

    // The two that matter most for an alert: the kernel dropping packets means MISSED DETECTIONS,
    // silently. Nothing else in the sensor's output makes that visible in time to act on it.
    metric!(
        "maltrail_capture_dropped_total",
        "counter",
        "Packets dropped by the capture ring (missed detections).",
        t.capture_dropped
    );
    metric!(
        "maltrail_capture_ifdropped_total",
        "counter",
        "Packets dropped by the interface driver.",
        t.capture_ifdropped
    );

    metric!("maltrail_events_total", "counter", "Detections produced.", t.events);
    metric!(
        "maltrail_events_written_total",
        "counter",
        "Detections that passed the throttle and were handed to the sinks (ATTEMPTS, not proof of durability - see maltrail_local_log_errors_total).",
        t.events_written
    );
    metric!(
        "maltrail_local_log_errors_total",
        "counter",
        "Event-log open/write failures. Non-zero means detections were produced and LOST; alert on any rate.",
        t.log_write_errors
    );
    metric!(
        "maltrail_events_throttled_total",
        "counter",
        "Detections held back by the event throttle.",
        t.events_throttled
    );
    metric!(
        "maltrail_events_summarized_total",
        "counter",
        "Aggregated summary lines emitted for throttled detections.",
        t.events_summarized
    );

    // Evidence storage. The sensor never deletes an event log, so this is a real operating
    // limit: when it reaches zero, appends fail and DETECTIONS ARE LOST while the sensor still
    // looks alive. Alert on it with plenty of headroom — it is the cheapest possible warning of
    // the most expensive kind of failure. 0/absent when local storage is off (LOG_SERVER only).
    if let Some(dir) = registry.log_dir.as_deref() {
        if let Some(free) = crate::output::free_bytes(dir) {
            metric!(
                "maltrail_log_dir_free_bytes",
                "gauge",
                "Bytes available to the sensor on the filesystem holding LOG_DIR. Reaching zero \
                 means detections are being LOST; Maltrail never deletes event logs to reclaim it.",
                free
            );
        }
    }
    metric!(
        "maltrail_state_saturations_total",
        "counter",
        "Times a bounded state map refused a new key at its cap. Non-zero means heuristics are \
         narrowed (exact trail matching is unaffected); a sustained rate means the sensor is \
         under a state-exhaustion flood.",
        t.state_saturations
    );
    metric!(
        "maltrail_meta_observables_total",
        "counter",
        "Observables merged into the condensed store (LOG_DIR/meta.sqlite).",
        t.meta_flushed
    );
    metric!(
        "maltrail_meta_flush_errors_total",
        "counter",
        "Condensed-store flushes that failed. Each one loses that worker's window of \
         observables; detection and event logging are unaffected.",
        t.meta_flush_errors
    );
    metric!("maltrail_trail_lookups_total", "counter", "Trail-store lookups performed.", t.trail_lookups);
    metric!("maltrail_cache_hits_total", "counter", "Result-cache hits.", t.cache_hits);
    metric!("maltrail_cache_misses_total", "counter", "Result-cache misses.", t.cache_misses);
    metric!(
        "maltrail_panics_recovered_total",
        "counter",
        "Packets whose processing panicked and was contained.",
        t.panics_recovered
    );

    metric!("maltrail_trails", "gauge", "Trails currently loaded.", registry.trail_count.load(Ordering::Relaxed));
    metric!(
        "maltrail_trail_generation",
        "gauge",
        "Trail-store generation; increments on every reload.",
        registry.trail_generation.load(Ordering::Relaxed)
    );
    metric!(
        "maltrail_trail_reloads_total",
        "counter",
        "Successful trail reloads.",
        registry.reloads_ok.load(Ordering::Relaxed)
    );
    metric!(
        "maltrail_trail_reloads_failed_total",
        "counter",
        "Failed trail reloads.",
        registry.reloads_failed.load(Ordering::Relaxed)
    );
    metric!(
        "maltrail_trail_reloads_rejected_total",
        "counter",
        "Trail reloads that parsed but were refused for losing too much of the set; \
         the previous trails are still in use.",
        registry.reloads_rejected.load(Ordering::Relaxed)
    );

    let ns = if t.processing_samples > 0 { t.processing_nanos as f64 / t.processing_samples as f64 } else { 0.0 };
    metric!(
        "maltrail_packet_path_nanoseconds",
        "gauge",
        "Sampled mean packet-path cost per packet.",
        format!("{ns:.0}")
    );
    metric!("maltrail_workers", "gauge", "Capture workers.", registry.slots.len());

    // Per worker, so an unbalanced fanout hash is visible instead of hiding in the total.
    out.push_str("# HELP maltrail_worker_packets_total Packets processed, per worker.\n");
    out.push_str("# TYPE maltrail_worker_packets_total counter\n");
    for (i, slot) in registry.slots.iter().enumerate() {
        out.push_str(&format!(
            "maltrail_worker_packets_total{{worker=\"{i}\"}} {}\n",
            slot.snapshot().packets_processed
        ));
    }
    // Which worker died, not just how many. With PACKET_FANOUT each worker owns a slice of the
    // traffic, so one dead worker is a partial blind spot rather than a total outage.
    out.push_str("# HELP maltrail_worker_alive 1 while this worker is in its capture loop.\n");
    out.push_str("# TYPE maltrail_worker_alive gauge\n");
    for (i, slot) in registry.slots.iter().enumerate() {
        out.push_str(&format!("maltrail_worker_alive{{worker=\"{i}\"}} {}\n", u8::from(slot.is_alive())));
    }
    // A worker can hold `alive` and still be wedged inside libpcap. Staleness here is the only
    // external signal for that, so it is exported as an absolute timestamp and left for the
    // scraper to subtract (`time() - maltrail_worker_last_heartbeat_seconds > 60`).
    out.push_str("# HELP maltrail_worker_last_heartbeat_seconds Unix time of this worker's last housekeeping tick.\n");
    out.push_str("# TYPE maltrail_worker_last_heartbeat_seconds gauge\n");
    for (i, slot) in registry.slots.iter().enumerate() {
        out.push_str(&format!("maltrail_worker_last_heartbeat_seconds{{worker=\"{i}\"}} {}\n", slot.last_heartbeat()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_is_well_formed_and_scrapable() {
        let registry = Arc::new(Registry::new(2));
        registry.trail_count.store(1_505_265, Ordering::Relaxed);
        registry.trail_generation.store(3, Ordering::Relaxed);
        let text = render(&registry, 42.0);

        // Every metric must carry HELP and TYPE, or a scraper drops it silently.
        for name in [
            "maltrail_up",
            "maltrail_capture_dropped_total",
            "maltrail_events_total",
            "maltrail_trails",
            "maltrail_worker_packets_total",
        ] {
            assert!(text.contains(&format!("# HELP {name} ")), "missing HELP for {name}:\n{text}");
            assert!(text.contains(&format!("# TYPE {name} ")), "missing TYPE for {name}");
        }
        assert!(text.contains("maltrail_trails 1505265"), "{text}");
        assert!(text.contains("maltrail_workers 2"), "{text}");
        assert!(text.contains("maltrail_worker_packets_total{worker=\"1\"}"), "{text}");
        // Monotonic counters must end in _total so `rate()` works.
        for line in text.lines().filter(|l| l.starts_with("# TYPE ") && l.ends_with(" counter")) {
            let name = line.split_whitespace().nth(2).unwrap();
            assert!(name.ends_with("_total"), "counter {name} must end in _total");
        }
    }

    #[test]
    fn a_scrape_returns_the_metrics_over_http() {
        let registry = Arc::new(Registry::new(1));
        let bound = spawn("127.0.0.1:0", registry, std::time::Instant::now()).expect("bind");
        let mut stream = std::net::TcpStream::connect(&bound).expect("connect");
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("text/plain; version=0.0.4"), "{response}");
        assert!(response.contains("maltrail_up 1"), "{response}");
    }

    #[test]
    fn a_bad_address_is_reported_not_fatal() {
        let registry = Arc::new(Registry::new(1));
        assert!(spawn("300.300.300.300:1", registry, std::time::Instant::now()).is_err());
    }
}
