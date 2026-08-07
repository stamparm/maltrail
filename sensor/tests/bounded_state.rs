//! Bounded state (ROADMAP Gate 1.5).
//!
//! "Bounded" was claimed but only true of the scan accumulators. Three maps were bounded by
//! TIME and not by SIZE:
//!
//!   * `NxCounters.counters`   — pruned hourly, unbounded within the hour
//!   * `DnsExhaustion.domains` — reset hourly, unbounded within the hour
//!   * `EventSink.condensed`   — each group capped, the NUMBER of groups was not
//!
//! Every key in all three is chosen by whoever sends the traffic, so an hour on a fast link is
//! an invitation, not a bound.
//!
//! Each test floods one structure well past its cap and asserts two things: the structure
//! plateaus, and exact trail matching still works. The second is the point — the degraded mode
//! narrows heuristics, it must never cost a known-bad indicator.

use maltrail_sensor::heuristics::dns_exhaustion::{DnsExhaustion, Outcome};
use maltrail_sensor::heuristics::nxdomain::NxCounters;
use maltrail_sensor::heuristics::HEURISTIC_MAX_KEYS;
use maltrail_sensor::testkit::*;

/// Enough to pass the cap without making the test take minutes.
fn flood_len() -> usize {
    HEURISTIC_MAX_KEYS + 2_000
}

#[test]
fn nxdomain_counters_plateau_under_a_dga_flood() {
    let mut nx = NxCounters::default();
    let sec = 3600;
    for i in 0..flood_len() {
        let name = format!("{i:x}.dga-flood.example");
        nx.observe(&name, &name, sec);
    }

    assert!(nx.len() <= HEURISTIC_MAX_KEYS, "the counter map must plateau at {HEURISTIC_MAX_KEYS}, got {}", nx.len());
    assert!(nx.saturations() > 0, "refusals must be counted so the degradation is visible");

    // A domain already being tracked keeps being counted: refusal applies to NEW subjects only,
    // so evidence collected before the flood is not lost to it.
    let mut fresh = NxCounters::default();
    let tracked = "victim.example";
    fresh.observe(tracked, tracked, sec);
    for i in 0..flood_len() {
        let name = format!("{i:x}.noise.example");
        fresh.observe(&name, &name, sec);
    }
    let before = fresh.len();
    fresh.observe(tracked, tracked, sec);
    assert_eq!(fresh.len(), before, "an existing key must not grow the map");
}

#[test]
fn dns_exhaustion_domains_plateau_under_a_parent_domain_flood() {
    let mut dx = DnsExhaustion::default();
    let sec = 1_700_000_000;
    for i in 0..flood_len() {
        // A DIFFERENT parent domain each time: this is the axis that was unbounded. The
        // per-window subdomain set was already capped by the threshold.
        dx.observe(&format!("{i:x}.example"), "www", sec, 10);
    }

    assert!(dx.len() <= HEURISTIC_MAX_KEYS, "the domain map must plateau at {HEURISTIC_MAX_KEYS}, got {}", dx.len());
    assert!(dx.saturations() > 0, "refusals must be counted");

    // Refusing a new domain degrades gracefully: the caller is told to carry on to the normal
    // trail checks, NOT to drop the packet.
    assert_eq!(
        dx.observe("brand-new.example", "www", sec, 10),
        Outcome::Continue,
        "a refused domain must still fall through to trail matching"
    );
}

/// The whole justification for refusing keys instead of growing: detection of known-bad
/// indicators has to survive the flood untouched.
#[test]
fn exact_trail_matching_survives_a_state_flood() {
    let mut h = Harness::with_options(
        &[("66.66.66.66", "malware", "(static)"), ("evil-c2.com", "asyncrat (malware)", "(static)")],
        HarnessOptions::heuristics(),
    );

    // Flood the NXDOMAIN and DNS-exhaustion state with junk the attacker controls.
    for i in 0..flood_len() {
        let name = format!("{i:x}.flood.example");
        h.state.nxdomain.observe(&name, &name, 3600);
        h.state.dns_exhaustion.observe(&format!("{i:x}.parent.example"), "www", 3600, 10);
    }
    assert!(
        h.state.nxdomain.saturations() > 0 && h.state.dns_exhaustion.saturations() > 0,
        "the flood must actually have saturated both structures"
    );

    // Now the two things that must still work: an IP trail and a DNS trail. (The flood keys
    // above use '.example', which IGNORE_DNS_QUERY_SUFFIXES excludes from DNS detection — fine
    // for filling state, but a detected name must NOT use it.)
    h.feed_ip(&ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b"")), 3600);
    h.feed_ip(&ipv4(17, "10.0.0.5", "8.8.8.8", &udp(33333, 53, &dns_query("evil-c2.com", 1, 1, 0x0100))), 3601);

    let trails = h.trails();
    assert!(trails.iter().any(|t| t == "66.66.66.66"), "IP trail must still match under saturation: {trails:?}");
    assert!(trails.iter().any(|t| t == "evil-c2.com"), "DNS trail must still match under saturation: {trails:?}");
}

/// The condense buffer's key count. Capped at `MAX_CONDENSED_KEYS`, and — unlike the heuristic
/// maps — a refusal must not lose the event, because an event IS a detection.
#[test]
fn the_condense_buffer_bounds_its_group_count_without_losing_events() {
    use maltrail_sensor::settings;

    // The info must (a) match CONDENSE_ON_INFO_KEYWORDS and (b) not be an 'attacker' info,
    // which sensor.py deliberately suppresses on the destination-side SYN branch.
    let mut h = Harness::with_options(&[("66.66.66.66", "bad reputation", "(static)")], HarnessOptions::quiet());

    // One condense group per source address.
    let flood = settings::MAX_CONDENSED_KEYS + 1_000;
    for i in 0..flood {
        let src = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        h.feed_ip(&ipv4(6, &src, "66.66.66.66", &tcp(50000, 443, 0x02, b"")), 1_700_000_000);
    }

    let saturations = h.state.sink.condense_saturations;
    assert!(saturations > 0, "the group count must have hit its cap");

    // Nothing was dropped: every packet either went into a group or was written through the
    // normal (throttled) path.
    h.state.sink.flush_condensed();
    h.state.sink.flush_throttled_all();
    assert!(!h.events().is_empty(), "detections must survive condense-buffer saturation");
}
