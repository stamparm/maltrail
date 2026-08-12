//! Per-worker state. Everything a worker touches while processing a packet lives here, so
//! the packet path never takes a lock and never shares a cache line with another worker.
//!
//! This mirrors the *process-local* globals of `sensor.py` (`_last_syn`, `_result_cache`,
//! `_connect_src_dst`, `NO_SUCH_NAME_COUNTERS`, …). The Python sensor also keeps them
//! per worker process, so heuristic state is fragmented across workers in exactly the same
//! way — with the improvement that `PACKET_FANOUT_HASH` keeps a flow on one worker.

use std::sync::Arc;

use crate::addr::Ip;
use crate::config::Config;
use crate::heuristics::dns_exhaustion::DnsExhaustion;
use crate::heuristics::nxdomain::NxCounters;
use crate::heuristics::scan::ScanState;
use crate::lru::LruMap;
use crate::meta::MetaStore;
use crate::metrics::WorkerMetrics;
use crate::output::EventSink;
use crate::packet::dlt::DltLearner;
use crate::settings::{self, Statics};
use crate::trails::TrailView;
use crate::whitelist::Whitelist;

/// `_last_syn` / `_last_udp` — the whole 5-tuple plus the second, compared by value for
/// burst suppression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FlowStamp {
    pub sec: u64,
    pub src: Ip,
    pub src_port: u16,
    pub dst: Ip,
    pub dst_port: u16,
}

pub struct WorkerState {
    pub id: usize,
    pub cfg: Arc<Config>,
    pub statics: &'static Statics,
    pub whitelist: Arc<Whitelist>,
    pub trails: TrailView,
    pub sink: EventSink,
    pub metrics: WorkerMetrics,
    pub dlt: DltLearner,

    // --- burst suppression (sensor.py globals) ---
    pub last_syn: Option<FlowStamp>,
    pub last_logged_syn: Option<FlowStamp>,
    pub last_udp: Option<FlowStamp>,
    /// Payload hash of the packet `last_udp` describes. The 5-tuple alone cannot tell two
    /// different datagrams of one socket apart, and suppressing the second silently drops a
    /// DNS query that was never parsed - see `payload_digest` in process.rs.
    pub last_udp_payload: u64,
    pub last_logged_udp: Option<FlowStamp>,

    // --- caches (core/datatype.py:LRUDict, capacity MAX_CACHE_ENTRIES) ---
    /// `_result_cache[(CACHE_TYPE.DOMAIN, query)] = False` — known-clean domains.
    pub domain_clean: LruMap<String, ()>,
    /// `_result_cache[(CACHE_TYPE.DOMAIN_WHITELISTED, query)]`
    pub domain_whitelisted: LruMap<String, bool>,
    /// `_result_cache[(CACHE_TYPE.USER_AGENT, ua)]` — `None` == cached negative.
    pub user_agent: LruMap<String, Option<String>>,
    /// `_result_cache[(CACHE_TYPE.PATH, path)]` — empty == cached negative.
    pub path_findings: LruMap<String, String>,
    /// `_result_cache[(CACHE_TYPE.POST_DATA, body)]`
    pub post_findings: LruMap<String, String>,
    /// `_result_cache[part]` — DGA entropy/consonant verdicts keyed by the bare label.
    pub dga_findings: LruMap<String, Option<String>>,
    /// `_result_cache[(CACHE_TYPE.LOCAL_PREFIX, "")]` — sticky, not part of the LRU.
    pub local_prefix_cache: Option<String>,

    // --- heuristic accumulators ---
    /// `_connect_sec` — the last second for which the sweep ran.
    pub connect_sec: u64,
    /// The second carried by the most recent packet. Used to close throttle windows on the same
    /// clock the events are stamped with, so a replay behaves exactly like live traffic.
    pub last_sec: u64,
    pub scan: ScanState,
    pub dns_exhaustion: DnsExhaustion,
    pub nxdomain: NxCounters,

    /// `LOG_DIR/meta.sqlite` — the condensed observable store (`core/meta.py`). Per worker and
    /// unsynchronised, like the Python sensor's per-process aggregate; drained on the worker's
    /// housekeeping tick. Disabled unless `USE_CONDENSED_STORAGE` is on.
    pub meta: MetaStore,
}

impl WorkerState {
    pub fn new(
        id: usize,
        cfg: Arc<Config>,
        whitelist: Arc<Whitelist>,
        trails: TrailView,
        sink: EventSink,
    ) -> WorkerState {
        let cap = settings::MAX_CACHE_ENTRIES;
        // The domain caches are the ones that thrash (a DGA flood queries a fresh name every
        // packet); the rest keep Python's size because they are keyed by far less diverse values.
        let domain_cap = cfg.domain_cache_entries;
        let meta = MetaStore::for_config(&cfg);
        WorkerState {
            id,
            cfg,
            statics: settings::statics(),
            whitelist,
            trails,
            sink,
            metrics: WorkerMetrics::default(),
            dlt: DltLearner::default(),
            last_syn: None,
            last_logged_syn: None,
            last_udp: None,
            last_udp_payload: 0,
            last_logged_udp: None,
            // Second-sighting admission: see `LruMap::insert_if_seen_before`. These two are the
            // caches a DGA flood hammers with names it never repeats, where the insert cost the
            // sensor more than recomputing the verdict.
            domain_clean: LruMap::new(domain_cap).with_admission_filter(4096),
            domain_whitelisted: LruMap::new(domain_cap).with_admission_filter(4096),
            user_agent: LruMap::new(cap),
            path_findings: LruMap::new(cap),
            post_findings: LruMap::new(cap),
            dga_findings: LruMap::new(cap),
            local_prefix_cache: None,
            connect_sec: 0,
            last_sec: 0,
            scan: ScanState::default(),
            dns_exhaustion: DnsExhaustion::default(),
            nxdomain: NxCounters::default(),
            meta,
        }
    }

    /// `sensor.py:_check_domain_whitelisted()` with its result cache.
    pub fn check_domain_whitelisted(&mut self, query: &str) -> bool {
        if let Some(v) = self.domain_whitelisted.get(query) {
            return *v;
        }
        let token = crate::whitelist::whitelist_domain_token(query);
        let result = self.whitelist.check_domain_member(token);
        self.domain_whitelisted.insert_if_seen_before_borrowed(query, result);
        result
    }

    /// `_get_local_prefix()`. The counts are maintained incrementally by `ScanState`, so this is
    /// O(distinct prefixes) instead of O(tracked source addresses) — it used to render every
    /// tracked address to a `String` once per second.
    pub fn local_prefix(&mut self) -> String {
        match self.scan.local_prefix() {
            Some(best) => {
                self.local_prefix_cache = Some(best.clone());
                best
            }
            // Python falls back to the last non-empty value it cached, then to '_'.
            None => self.local_prefix_cache.clone().unwrap_or_else(|| "_".to_string()),
        }
    }

    pub fn heuristics_enabled(&self) -> bool {
        self.cfg.use_heuristics
    }

    pub fn heuristic_enabled(&self, name: &str) -> bool {
        self.cfg.heuristic_enabled(name)
    }
}
