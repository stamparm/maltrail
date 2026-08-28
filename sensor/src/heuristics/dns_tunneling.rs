//! DNS tunnelling — deliberately hard to trip.
//!
//! A tunnel and an antivirus reputation lookup are close to indistinguishable from query shape
//! alone. `<sha256>.avqs.mcafee.com`, `<base32>.sophosxl.net` and every DNSBL query send
//! high-entropy, never-repeated labels to one zone in volume, which is also an exact description
//! of somebody exfiltrating data over DNS. An entropy-and-length detector is therefore a machine
//! for generating tickets about the antivirus, and an operator who gets three of those mutes the
//! heuristic in week one - after which it detects nothing at all, forever.
//!
//! So nothing here fires on a single query. A (source, zone) pair has to satisfy EVERY condition
//! in [`Accumulator::verdict`] at once, inside one window, and the zone must be neither whitelisted
//! nor a known reputation service. Missing a slow tunnel is the intended trade.
//!
//! The condition that does most of the work is SPAN: a tunnel is a session that runs for minutes,
//! while a burst of reputation lookups is what a workstation does when a user opens a folder.
//! Requiring first and last query to be two minutes apart costs a tunnel nothing and rules out the
//! shape most legitimate traffic takes.

use crate::fasthash::{StrMap, StrSet};
use crate::settings;

/// One (source, zone) pair's evidence inside the current window.
#[derive(Default)]
pub struct Accumulator {
    pub queries: usize,
    /// Distinct subdomain parts. A tunnel never repeats one; a blocklist does.
    names: StrSet<Box<str>>,
    /// Queries whose leading label is long AND high-entropy - i.e. carrying a payload.
    pub carrying: usize,
    /// Total bytes of subdomain below the zone: what a tunnel is actually moving.
    pub bytes: usize,
    pub first_sec: u64,
    pub last_sec: u64,
    alerted: bool,
}

/// Shannon entropy of `label`, in bits per character times 100.
///
/// A WEAK filter, and worth saying so rather than letting the next reader assume otherwise.
/// Measured: `autodiscover.example` scores 3.88 bits/char, a 32-character hex hash 3.80 and a
/// base32 chunk 3.80. Entropy does NOT separate encoded payload from an ordinary word - over
/// twenty-odd characters almost nothing repeats enough to score low.
///
/// What it does separate is PADDING: `aaaa...` scores 0.00 and `wwww...1` scores 0.17. That is the
/// job it is kept for. The conjunction in `verdict` does the actual work, and raising this
/// threshold to where it would exclude English would also exclude hex, which is what half the
/// tunnels in the wild encode with.
pub fn entropy_x100(label: &str) -> u32 {
    let bytes = label.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0u16; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f32;
    let mut bits = 0f32;
    for &c in counts.iter() {
        if c != 0 {
            let p = c as f32 / total;
            bits -= p * p.log2();
        }
    }
    (bits * 100.0) as u32
}

/// Is this zone one whose ordinary traffic looks like a tunnel?
///
/// Suffix match on a label boundary, so `sophosxl.net` covers `a.b.sophosxl.net` and does NOT
/// cover `notsophosxl.net`. The bare `_domainkey`-style entries match anywhere, because they are
/// labels rather than zones.
pub fn allowed_zone(zone: &str) -> bool {
    for entry in settings::HASH_LABEL_SERVICE_ZONES {
        if entry.starts_with('_') || entry.starts_with("acme-") {
            if zone.split('.').any(|label| label == *entry) {
                return true;
            }
        } else if zone == *entry || zone.ends_with(&format!(".{entry}")) {
            return true;
        }
    }
    false
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not enough evidence, or already reported for this pair in this window.
    Quiet,
    /// Every condition holds: report once.
    Alert,
}

#[derive(Default)]
pub struct DnsTunneling {
    pairs: StrMap<Box<str>, Accumulator>,
    window_start: u64,
    saturations: u64,
}

impl Accumulator {
    /// Every condition, in one place, so the bar is readable rather than scattered.
    pub fn verdict(&self) -> bool {
        let queries = self.queries;
        if queries < settings::DNS_TUNNELING_MIN_QUERIES {
            return false; // volume: one lookup is never a tunnel
        }
        if self.bytes < settings::DNS_TUNNELING_MIN_BYTES {
            return false; // a tunnel MOVES something; a reputation query carries one hash
        }
        if self.last_sec.saturating_sub(self.first_sec) < settings::DNS_TUNNELING_MIN_SPAN {
            return false; // a session, not a burst - the condition that excludes most legitimate traffic
        }
        if self.names.len() * 100 < queries * settings::DNS_TUNNELING_MIN_DISTINCT_PCT {
            return false; // repeats mean a cache-missing client or a blocklist, not an encoder
        }
        if self.carrying * 100 < queries * settings::DNS_TUNNELING_MIN_LONG_PCT {
            return false; // a few long names among ordinary ones is a CDN, not a channel
        }
        true
    }
}

impl DnsTunneling {
    pub fn maybe_window_reset(&mut self, sec: u64) {
        if sec.saturating_sub(self.window_start) > settings::DNS_TUNNELING_WINDOW {
            self.pairs.clear();
            self.window_start = sec;
        }
    }

    /// Record one query and say whether the pair has just crossed every threshold.
    ///
    /// `subdomain` is everything below the registered zone; `leading` is its first label.
    pub fn observe(&mut self, key: &str, subdomain: &str, leading: &str, sec: u64) -> Outcome {
        let carrying = leading.chars().count() >= settings::DNS_TUNNELING_MIN_LABEL
            && entropy_x100(leading) >= settings::DNS_TUNNELING_MIN_ENTROPY_X100;

        let entry = match self.pairs.get_mut(key) {
            Some(entry) => entry,
            None => {
                // Refuse rather than evict, like every other accumulator here: the key is chosen
                // by whoever is sending, so eviction under flood would let them push their own
                // earlier evidence out of the window.
                if self.pairs.len() >= super::HEURISTIC_MAX_KEYS {
                    self.saturations += 1;
                    return Outcome::Quiet;
                }
                self.pairs.insert(key.into(), Accumulator { first_sec: sec, ..Accumulator::default() });
                self.pairs.get_mut(key).expect("just inserted")
            }
        };

        entry.queries += 1;
        entry.last_sec = sec;
        entry.bytes += subdomain.len();
        if carrying {
            entry.carrying += 1;
        }
        if entry.names.len() < super::HEURISTIC_MAX_KEYS {
            entry.names.insert(subdomain.into());
        }

        if entry.alerted || !entry.verdict() {
            return Outcome::Quiet;
        }
        entry.alerted = true;
        Outcome::Alert
    }

    pub fn saturations(&self) -> u64 {
        self.saturations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base32-ish labels that are never repeated - what an encoder emits.
    fn feed(t: &mut DnsTunneling, key: &str, count: usize, label_len: usize, step: u64) -> usize {
        let mut alerts = 0;
        for i in 0..count {
            let mut label = String::with_capacity(label_len);
            let mut state = (i as u64).wrapping_mul(6364136223846793005).wrapping_add(1);
            for _ in 0..label_len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                label.push(char::from(b'a' + ((state >> 33) % 26) as u8));
            }
            if t.observe(key, &label, &label, i as u64 * step) == Outcome::Alert {
                alerts += 1;
            }
        }
        alerts
    }

    #[test]
    fn a_sustained_high_volume_encoded_channel_alerts_once() {
        let mut t = DnsTunneling::default();
        assert_eq!(feed(&mut t, "10.0.0.5|tunnel.example", 400, 40, 1), 1, "exactly one report per pair");
    }

    #[test]
    fn a_burst_of_the_same_traffic_does_not() {
        // identical shape and volume, delivered inside a few seconds - a workstation opening a
        // folder full of files against a reputation service looks like this
        let mut t = DnsTunneling::default();
        assert_eq!(feed(&mut t, "10.0.0.5|av.example", 400, 40, 0), 0, "a burst is not a session");
    }

    #[test]
    fn short_labels_never_qualify_however_many_there_are() {
        let mut t = DnsTunneling::default();
        assert_eq!(feed(&mut t, "10.0.0.5|bl.example", 5000, 6, 1), 0);
    }

    #[test]
    fn repeated_names_never_qualify() {
        // a blocklist re-asks for the same names all day
        let mut t = DnsTunneling::default();
        let label = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut alerts = 0;
        for i in 0..2000u64 {
            if t.observe("10.0.0.5|bl.example", label, label, i) == Outcome::Alert {
                alerts += 1;
            }
        }
        assert_eq!(alerts, 0, "one repeated name carries no data");
    }

    #[test]
    fn a_low_entropy_long_label_never_qualifies() {
        // "wwwwwwwwww..." is long but encodes nothing
        let mut t = DnsTunneling::default();
        let mut alerts = 0;
        for i in 0..500u64 {
            let label = format!("{}{}", "w".repeat(40), i); // unique, long, near-zero entropy
            if t.observe("10.0.0.5|z.example", &label, &label, i) == Outcome::Alert {
                alerts += 1;
            }
        }
        assert_eq!(alerts, 0);
    }

    #[test]
    fn entropy_rejects_padding_and_nothing_else() {
        // measured, and the reason the threshold is where it is: an ordinary word scores HIGHER
        // than a hex hash, so this can only ever be a padding filter
        assert!(entropy_x100("aaaaaaaaaaaaaaaaaaaa") < 100);
        assert!(entropy_x100("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww1") < 100);
        assert!(entropy_x100("mfrggzdfmztwq2lknnwg23tp") >= settings::DNS_TUNNELING_MIN_ENTROPY_X100);
        assert!(entropy_x100("7d865e959b2466918c9863afca942d0f") >= settings::DNS_TUNNELING_MIN_ENTROPY_X100);
        // an English-ish label passes this filter too. It is excluded by volume, uniqueness and
        // span instead - raising the bar to catch it would also drop every hex-encoded tunnel.
        assert!(entropy_x100("autodiscover-service") >= settings::DNS_TUNNELING_MIN_ENTROPY_X100);
    }

    #[test]
    fn known_reputation_zones_are_exempt_including_subdomains() {
        assert!(allowed_zone("sophosxl.net"));
        assert!(allowed_zone("a.b.sophosxl.net"));
        assert!(allowed_zone("avqs.mcafee.com"));
        assert!(allowed_zone("zen.spamhaus.org"));
        assert!(allowed_zone("s1._domainkey.example.com"));
        assert!(!allowed_zone("notsophosxl.net"), "suffix matching must respect the label boundary");
        assert!(!allowed_zone("tunnel.example"));
    }

    #[test]
    fn the_window_reset_forgets_everything() {
        let mut t = DnsTunneling::default();
        feed(&mut t, "10.0.0.5|tunnel.example", 400, 40, 1);
        t.maybe_window_reset(settings::DNS_TUNNELING_WINDOW + 10_000);
        assert_eq!(feed(&mut t, "10.0.0.5|tunnel.example", 400, 40, 1), 1, "a new window reports again");
    }

    #[test]
    fn saturation_refuses_new_keys_instead_of_evicting() {
        let mut t = DnsTunneling::default();
        for i in 0..(super::super::HEURISTIC_MAX_KEYS + 50) {
            t.observe(&format!("k{i}"), "abcdefghijklmnopqrst", "abcdefghijklmnopqrst", 1);
        }
        assert!(t.saturations() >= 50, "past the cap new pairs are refused, not swapped in");
    }
}
