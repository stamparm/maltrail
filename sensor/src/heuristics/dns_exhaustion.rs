//! DNS-exhaustion heuristic — the `_subdomains` / `_dns_exhausted_domains` block in
//! `sensor.py:_process_packet()`.

use crate::fasthash::{StrMap, StrSet};

use crate::settings;

struct Window {
    /// `subdomains._start` — when this domain's 60-second window opened.
    start: u64,
    subdomains: StrSet<Box<str>>,
}

#[derive(Default)]
pub struct DnsExhaustion {
    domains: StrMap<Box<str>, Window>,
    /// `_subdomains_sec` — hourly reset marker.
    hour_marker: Option<u64>,
    /// `_dns_exhausted_domains`
    exhausted: StrSet<Box<str>>,
    /// New domains refused because `HEURISTIC_MAX_KEYS` was reached.
    saturations: u64,
}

/// What the caller should do after recording a subdomain, mirroring the Python control
/// flow (which either falls through to the trail checks or returns outright).
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Below threshold: continue to the normal DNS trail checks.
    Continue,
    /// Threshold just crossed: emit one exhaustion event, then return.
    Alert,
    /// Already alerted for this domain in this window: return without logging.
    Suppress,
}

impl DnsExhaustion {
    /// `if (sec - (_subdomains_sec or 0)) > HOURLY_SECS: clear`
    pub fn maybe_hourly_reset(&mut self, sec: u64) {
        if sec.saturating_sub(self.hour_marker.unwrap_or(0)) > settings::HOURLY_SECS {
            self.domains.clear();
            self.exhausted.clear();
            self.hour_marker = Some(sec);
        }
    }

    /// New domains refused at the cap since start.
    pub fn saturations(&self) -> u64 {
        self.saturations
    }

    /// Distinct parent domains currently tracked.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    pub fn is_exhausted(&self, domain: &str) -> bool {
        self.exhausted.contains(domain)
    }

    /// Record `subdomain_part` under `domain` and report what the caller should do.
    /// `threshold` is passed in so tests can lower it, exactly like the Python test does.
    pub fn observe(&mut self, domain: &str, subdomain_part: &str, sec: u64, threshold: usize) -> Outcome {
        // NOTE: membership test, not truthiness - an existing-but-empty set (just cleared
        // at the 60s boundary) must keep its window start.
        let window = match self.domains.get_mut(domain) {
            Some(w) => w,
            None => {
                // Bounded: the hourly reset is a TIME bound, and the parent domain is chosen by
                // whoever sends the query. Refuse new domains at the cap instead of evicting
                // tracked ones, so a flood cannot push an in-progress window out of memory.
                if self.domains.len() >= super::HEURISTIC_MAX_KEYS {
                    self.saturations += 1;
                    return Outcome::Continue;
                }
                self.domains.insert(domain.into(), Window { start: sec, subdomains: StrSet::default() });
                self.domains.get_mut(domain).expect("just inserted")
            }
        };

        if sec.saturating_sub(window.start) > 60 {
            window.start = sec;
            window.subdomains.clear();
            return Outcome::Continue;
        }
        if window.subdomains.len() < threshold {
            // `contains` first: `insert(subdomain_part.into())` would build an owned copy of the
            // label on EVERY query just to throw it away as a duplicate. Real traffic queries the
            // same handful of subdomains over and over, so that was an allocation per DNS packet.
            if !window.subdomains.contains(subdomain_part) {
                window.subdomains.insert(subdomain_part.into());
            }
            return Outcome::Continue;
        }
        if !self.exhausted.contains(domain) {
            Outcome::Alert
        } else {
            Outcome::Suppress
        }
    }

    pub fn mark_exhausted(&mut self, domain: &str) {
        self.exhausted.insert(domain.into());
    }

    /// `any(_ in subdomains for _ in LOCAL_SUBDOMAIN_LOOKUPS)` — the local-resolution guard.
    pub fn has_local_lookup(&self, domain: &str) -> bool {
        let Some(window) = self.domains.get(domain) else { return false };
        settings::LOCAL_SUBDOMAIN_LOOKUPS.iter().any(|needle| window.subdomains.contains(*needle))
    }

    pub fn tracked_domains(&self) -> usize {
        self.domains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_once_over_threshold() {
        // Mirrors the retired Python suite's TestDNSExhaustion with the threshold lowered to 3.
        let mut d = DnsExhaustion::default();
        let mut alerts = 0;
        for (i, label) in ["alpha", "bravo", "charlie", "delta", "echo"].iter().enumerate() {
            match d.observe("evil.com", label, 100 + i as u64, 3) {
                Outcome::Alert => {
                    alerts += 1;
                    d.mark_exhausted("evil.com");
                }
                Outcome::Suppress => {}
                Outcome::Continue => {}
            }
        }
        assert_eq!(alerts, 1, "exactly one alert past the threshold, not one per query");
        assert!(d.is_exhausted("evil.com"));
    }

    #[test]
    fn no_alert_below_threshold() {
        let mut d = DnsExhaustion::default();
        for (i, label) in ["one", "two"].iter().enumerate() {
            assert_eq!(d.observe("evil.com", label, 100 + i as u64, 3), Outcome::Continue);
        }
    }

    #[test]
    fn window_rolls_after_sixty_seconds() {
        let mut d = DnsExhaustion::default();
        for i in 0..3 {
            d.observe("evil.com", &format!("s{i}"), 100, 3);
        }
        assert_eq!(d.observe("evil.com", "s4", 100, 3), Outcome::Alert);
        // past 60s the accumulator restarts and stops alerting
        assert_eq!(d.observe("evil.com", "s5", 200, 3), Outcome::Continue);
    }

    #[test]
    fn window_start_survives_the_roll_that_empties_the_set() {
        // The window start must be the time of the roll, NOT re-set by every later query
        // (otherwise the 60s window slides forever and exhaustion can never be detected).
        let mut d = DnsExhaustion::default();
        d.observe("evil.com", "a", 100, 3);
        d.observe("evil.com", "b", 200, 3); // 200-100 > 60 -> roll, start = 200, set empty
        d.observe("evil.com", "c", 210, 3);
        d.observe("evil.com", "d", 220, 3);
        d.observe("evil.com", "e", 230, 3); // set now holds 3 == threshold
                                            // 265 is more than 60s after the window start (200) -> the window rolls again and
                                            // no alert fires. A start that had been reset at 230 would wrongly alert here.
        assert_eq!(d.observe("evil.com", "f", 265, 3), Outcome::Continue);
        // within the window, the next query past the threshold does alert
        let mut d = DnsExhaustion::default();
        d.observe("evil.com", "a", 100, 3);
        d.observe("evil.com", "b", 200, 3);
        for (i, label) in ["c", "d", "e"].iter().enumerate() {
            d.observe("evil.com", label, 210 + i as u64, 3);
        }
        assert_eq!(d.observe("evil.com", "f", 240, 3), Outcome::Alert);
    }

    #[test]
    fn hourly_reset_clears_state() {
        let mut d = DnsExhaustion::default();
        d.maybe_hourly_reset(0);
        d.observe("evil.com", "a", 10, 3);
        assert_eq!(d.tracked_domains(), 1);
        d.maybe_hourly_reset(10_000);
        assert_eq!(d.tracked_domains(), 0);
    }

    #[test]
    fn local_lookup_guard() {
        let mut d = DnsExhaustion::default();
        d.observe("corp.example", "wpad", 10, 3);
        assert!(d.has_local_lookup("corp.example"));
        d.observe("other.example", "www", 10, 3);
        assert!(!d.has_local_lookup("other.example"));
    }
}
