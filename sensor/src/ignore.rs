//! `core/ignore.py` — event ignore rules and `IGNORE_EVENTS_REGEX`.

use std::collections::HashSet;
use std::path::Path;

use crate::event::Event;

#[derive(Debug, Default)]
pub struct IgnoreRules {
    /// `IGNORE_EVENTS` — (src_ip, src_port, dst_ip, dst_port), `*` matching anything.
    rules: HashSet<(String, String, String, String)>,
    regex: Option<fancy_regex::Regex>,
}

impl IgnoreRules {
    /// `core/settings.py:read_ignorelist()` + `IGNORE_EVENTS_REGEX` compilation.
    pub fn load(root: &Path, user_ignorelist: Option<&Path>, events_regex: &str) -> IgnoreRules {
        let mut out = IgnoreRules::default();
        let mut files = vec![root.join("data").join("ignore_events.txt")];
        if let Some(p) = user_ignorelist {
            files.push(p.to_path_buf());
        }
        for file in files {
            out.add_file(&file);
        }

        if !events_regex.is_empty() {
            match crate::pyre::build_fancy(events_regex) {
                Ok(re) => out.regex = Some(re),
                Err(e) => {
                    // Python warns once and keeps logging rather than dropping every event.
                    crate::cprintln!(
                        "[!] invalid regular expression in option 'IGNORE_EVENTS_REGEX' ('{events_regex}'): {e}"
                    );
                }
            }
        }
        out
    }

    fn add_file(&mut self, path: &Path) {
        let Ok(data) = std::fs::read(path) else { return };
        for line in String::from_utf8_lossy(&data).lines() {
            // re.sub(r"\s+", "", line) — all whitespace removed, not just the ends
            let line: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.matches(';').count() == 3 {
                let mut it = line.split(';');
                let a = it.next().unwrap_or_default().to_string();
                let b = it.next().unwrap_or_default().to_string();
                let c = it.next().unwrap_or_default().to_string();
                let d = it.next().unwrap_or_default().to_string();
                self.rules.insert((a, b, c, d));
            }
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.regex.is_none()
    }

    /// `core/ignore.py:ignore_event()`
    pub fn ignore_event(&self, event: &Event) -> bool {
        if let Some(re) = &self.regex {
            // A regex error must never propagate out of the packet path.
            if matches!(re.is_match(&event.py_repr()), Ok(true)) {
                return true;
            }
        }
        if self.rules.is_empty() {
            return false;
        }
        let src_port = event.src_port.as_plain();
        let dst_port = event.dst_port.as_plain();
        let dst_ip = event.dst_ip.as_plain();
        for (r_src_ip, r_src_port, r_dst_ip, r_dst_port) in &self.rules {
            if r_src_ip != "*" && *r_src_ip != event.src_ip {
                continue;
            }
            if r_src_port != "*" && *r_src_port != src_port {
                continue;
            }
            if r_dst_ip != "*" && *r_dst_ip != dst_ip {
                continue;
            }
            if r_dst_port != "*" && *r_dst_port != dst_port {
                continue;
            }
            return true;
        }
        false
    }

    #[cfg(test)]
    pub fn add_rule_for_test(&mut self, rule: (&str, &str, &str, &str)) {
        self.rules.insert((rule.0.into(), rule.1.into(), rule.2.into(), rule.3.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{proto, trail_type, Event};

    fn sample() -> Event {
        Event::new(
            1,
            0,
            "192.168.0.3",
            50000u16,
            "1.2.3.4",
            22u16,
            proto::TCP,
            trail_type::IP,
            "1.2.3.4",
            "known attacker",
            "(static)",
        )
    }

    #[test]
    fn wildcard_rules() {
        let mut r = IgnoreRules::default();
        r.add_rule_for_test(("192.168.0.3", "*", "*", "*"));
        assert!(r.ignore_event(&sample()));

        let mut r = IgnoreRules::default();
        r.add_rule_for_test(("*", "*", "*", "22"));
        assert!(r.ignore_event(&sample()));

        let mut r = IgnoreRules::default();
        r.add_rule_for_test(("*", "*", "*", "23"));
        assert!(!r.ignore_event(&sample()));
    }

    #[test]
    fn regex_matches_repr() {
        let r = IgnoreRules::load(Path::new("/nonexistent"), None, "known attacker");
        assert!(r.ignore_event(&sample()));
        let r = IgnoreRules::load(Path::new("/nonexistent"), None, "sql injection|1\\.2\\.3\\.9");
        assert!(!r.ignore_event(&sample()));
    }

    #[test]
    fn invalid_regex_is_disabled_not_fatal() {
        let r = IgnoreRules::load(Path::new("/nonexistent"), None, "(unbalanced");
        assert!(!r.ignore_event(&sample()));
    }

    #[test]
    fn shipped_ignore_file_has_only_comments() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
        let r = IgnoreRules::load(&root, None, "");
        assert_eq!(r.len(), 0);
    }
}
