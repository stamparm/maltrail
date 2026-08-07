//! The NXDOMAIN ("excessive no such domain") counters — `NO_SUCH_NAME_COUNTERS` in
//! `sensor.py`, including the hourly prune that bounds the dict.

use crate::fasthash::{StrMap, StrSet};

use crate::settings;

struct Counter {
    hour: u64,
    count: u32,
    names: StrSet<String>,
}

#[derive(Default)]
pub struct NxCounters {
    counters: StrMap<String, Counter>,
    /// New keys refused because `HEURISTIC_MAX_KEYS` was reached. Non-zero means this
    /// heuristic is running degraded and an operator should know.
    saturations: u64,
    /// `_no_such_name_hour` — the last hour bucket that was pruned.
    pruned_hour: Option<u64>,
}

/// What crossing the threshold produced.
pub enum NxAlert {
    /// A wildcard key (`*.example.com`) tripped: the trail is `(<labels>).example.com`.
    Wildcard { trail: String, names: Vec<String> },
    /// An exact name tripped: the trail is the name itself.
    Exact { trail: String },
}

impl NxCounters {
    /// Prune the previous hour's entries once per hour (bounded memory under DGA traffic).
    pub fn maybe_prune(&mut self, sec: u64) {
        let hour = sec / 3600;
        if self.pruned_hour == Some(hour) {
            return;
        }
        self.pruned_hour = Some(hour);
        self.counters.retain(|_, c| c.hour == hour);
    }

    /// Record one NXDOMAIN observation for `key` (either the full query or the `*.domain`
    /// wildcard) and report an alert when the hourly threshold is exceeded.
    ///
    /// Mirrors the Python loop exactly: a fresh key (or a key from an older hour) is reset
    /// to count 1 with an empty name set, so the very first observation never alerts.
    pub fn observe(&mut self, key: &str, query: &str, sec: u64) -> Option<NxAlert> {
        let hour = sec / 3600;
        match self.counters.get_mut(key) {
            Some(c) if c.hour == hour => {
                c.count += 1;
                c.names.insert(query.to_string());
                if c.count <= settings::NO_SUCH_NAME_PER_HOUR_THRESHOLD {
                    return None;
                }
                let alert = if let Some(suffix) = key.strip_prefix('*') {
                    // trail = "(<names with the suffix stripped>)" + suffix
                    let mut names: Vec<String> = c.names.iter().cloned().collect();
                    names.sort();
                    let joined = names.iter().map(|item| item.replace(suffix, "")).collect::<Vec<_>>().join(",");
                    NxAlert::Wildcard { trail: format!("({joined}){suffix}"), names }
                } else {
                    NxAlert::Exact { trail: key.to_string() }
                };
                // Python deletes the tracked names and the key itself after alerting.
                if let NxAlert::Wildcard { names, .. } = &alert {
                    for name in names {
                        self.counters.remove(name);
                    }
                }
                self.counters.remove(key);
                Some(alert)
            }
            _ => {
                // Bounded: the hourly prune is a TIME bound, not a memory one, and every key
                // here is a domain the sender chose. Refuse new subjects at the cap rather than
                // evicting tracked ones — see `heuristics::HEURISTIC_MAX_KEYS`.
                if self.counters.len() >= super::HEURISTIC_MAX_KEYS {
                    self.saturations += 1;
                    return None;
                }
                self.counters.insert(key.to_string(), Counter { hour, count: 1, names: StrSet::default() });
                None
            }
        }
    }

    /// New keys refused at the cap since start.
    pub fn saturations(&self) -> u64 {
        self.saturations
    }

    pub fn len(&self) -> usize {
        self.counters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    #[cfg(test)]
    pub fn keys(&self) -> Vec<String> {
        let mut k: Vec<String> = self.counters.keys().cloned().collect();
        k.sort();
        k
    }
}

/// Shannon entropy of a label, as `sensor.py` computes it (base 2, over the distinct
/// characters). Reference: https://github.com/exp0se/dga_detector
pub fn label_entropy(part: &str) -> f64 {
    if part.is_empty() {
        return 0.0;
    }
    let chars: Vec<char> = part.chars().collect();
    let len = chars.len() as f64;
    let distinct: std::collections::BTreeSet<char> = chars.iter().copied().collect();
    let mut entropy = 0.0;
    for c in distinct {
        let p = chars.iter().filter(|x| **x == c).count() as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// `sum(_ in CONSONANTS for _ in part)`
pub fn consonant_count(part: &str) -> usize {
    part.chars().filter(|c| settings::CONSONANTS.contains(*c)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_hour_entries_are_pruned() {
        // Mirrors tests/test_sensor.py:TestNXDomainCounterBounded
        let mut nx = NxCounters::default();
        const H1: u64 = 3600;
        for i in 0..5 {
            nx.maybe_prune(H1 + i);
            nx.observe(&format!("dga{i}.com"), &format!("dga{i}.com"), H1 + i);
        }
        assert_eq!(nx.len(), 5);
        nx.maybe_prune(7200);
        nx.observe("fresh.com", "fresh.com", 7200);
        assert_eq!(nx.keys(), vec!["fresh.com".to_string()]);
    }

    #[test]
    fn first_observation_never_alerts() {
        let mut nx = NxCounters::default();
        assert!(nx.observe("a.com", "a.com", 0).is_none());
    }

    #[test]
    fn exact_key_alerts_past_threshold() {
        let mut nx = NxCounters::default();
        let mut alerts = 0;
        for _ in 0..(settings::NO_SUCH_NAME_PER_HOUR_THRESHOLD + 5) {
            if let Some(NxAlert::Exact { trail }) = nx.observe("a.com", "a.com", 10) {
                assert_eq!(trail, "a.com");
                alerts += 1;
            }
        }
        assert_eq!(alerts, 1, "the key is dropped after alerting, so it fires once");
    }

    #[test]
    fn wildcard_key_builds_the_python_trail() {
        let mut nx = NxCounters::default();
        let key = "*.evil.com";
        let mut trail = None;
        for i in 0..(settings::NO_SUCH_NAME_PER_HOUR_THRESHOLD + 2) {
            if let Some(NxAlert::Wildcard { trail: t, .. }) = nx.observe(key, &format!("h{i}.evil.com"), 10) {
                trail = Some(t);
            }
        }
        let trail = trail.expect("wildcard alert");
        assert!(trail.starts_with('('), "{trail}");
        assert!(trail.ends_with(").evil.com"), "{trail}");
        assert!(trail.contains("h1,"), "{trail}");
    }

    #[test]
    fn entropy_and_consonants() {
        // sanity: a high-entropy DGA-looking label beats the 3.5 threshold
        assert!(label_entropy("xkqwzlvbnmfghjd") > settings::SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD);
        assert!(label_entropy("aaaa") < 0.001);
        assert_eq!(label_entropy(""), 0.0);
        assert_eq!(consonant_count("google"), 3);
        assert!(consonant_count("xkqwzlvbnmf") > settings::SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD);
    }
}
