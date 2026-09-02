# coding: utf-8
"""Every configuration option the code reads must appear in maltrail.conf.

maltrail.conf is the file operators actually edit, and an option that exists only in the source
is an option nobody finds. Seventeen of the Rust sensor's own settings were in that state -
CAPTURE_WORKERS, the EVENT_THROTTLE_* family, CAPTURE_SNAPLEN and the rest were documented in
sensor/docs/ but absent from the config file itself, so the only way to learn they existed was to
be told. USE_CONDENSED_STORAGE was worse: read by BOTH sensors, defaulting to ON, and writing a
SQLite store, with no mention in the configuration at all.

This keeps the file honest. It is the cheap half of documentation - it cannot check that an
explanation is any good, only that the option is not missing entirely - but it is the half that
rots silently.
"""

import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Read through a variable rather than a literal (e.g. __is_allowlisted(*options), the geo home
# coordinates, the feed threshold), so no static scan can attribute them to a call site.
DYNAMIC = {"FAIL2BAN_ALLOWLIST", "BLACKLIST_ALLOWLIST", "HOME_LAT", "HOME_LON", "IP_MINIMUM_FEEDS"}

# Read only in order to tell the operator to stop using it, so it must NOT be advertised in the
# configuration file.
# Accepted by read_config() so an upgrader's existing maltrail.conf does not warn, but no longer
# documented and no longer read by anything: they configured the retired Python sensor's
# multiprocessing pool and its in-C admission prefilter, neither of which the Rust sensor has.
DEPRECATED = {"USE_MULTIPROCESSING", "DISABLE_CPU_AFFINITY", "FAST_ADMIT_ADAPTIVE",
              "FAST_ADMIT_LEVEL", "USE_CAPTURE_AFFINITY"}

OPTION = r"[A-Z][A-Z0-9_]{2,}"


def documented():
    """Option names that appear in maltrail.conf, set or commented out."""
    retval = set()
    with open(os.path.join(REPO, "maltrail.conf")) as f:
        for line in f:
            # An option line is "NAME value" or "#NAME value" - no space after the '#'. Prose
            # comments start "# Word", so this does not mistake "# TLS 1.3 encrypts..." for an
            # option called TLS, which is exactly what a looser pattern did.
            match = re.match(r"^#?(%s)(\s|$)" % OPTION, line)
            if match:
                retval.add(match.group(1))
    return retval


def read_by_python():
    sources = []
    for base, _, files in os.walk(os.path.join(REPO, "core")):
        sources += [os.path.join(base, f) for f in files if f.endswith(".py")]
    sources += [os.path.join(REPO, "server.py")]
    sources += [os.path.join(base, f) for base, _, files in os.walk(os.path.join(REPO, "feeds")) for f in files if f.endswith(".py")]
    text = ""
    for path in sources:
        with open(path, errors="replace") as f:
            text += f.read()
    return set(re.findall(r"config\.(%s)" % OPTION, text)) | \
           set(re.findall(r'getattr\(config,\s*"(%s)"' % OPTION, text))


def read_by_sensor():
    with open(os.path.join(REPO, "sensor", "src", "config.rs"), errors="replace") as f:
        text = f.read()
    retval = set()
    for pattern in (r'get_(?:str|bool|bool_opt|u64|f64)\(&raw,\s*"(%s)"' % OPTION,
                    r'raw\.get\("(%s)"\)' % OPTION,
                    r'cfg_bool\(&raw,\s*"(%s)"' % OPTION):
        retval |= set(re.findall(pattern, text))
    return retval


class TestOptionCoverage(unittest.TestCase):
    def test_every_option_the_code_reads_is_in_maltrail_conf(self):
        missing = sorted((read_by_python() | read_by_sensor()) - documented() - DEPRECATED)
        self.assertEqual(missing, [], "read by the code but absent from maltrail.conf: %s" % ", ".join(missing))

    def test_documented_defaults_match_the_sensor(self):
        """A commented "#OPTION value" line in maltrail.conf states that option's DEFAULT.

        That is the file's convention throughout (#USE_FAST_PREFILTER true, #USE_CONDENSED_STORAGE
        true, ...), and an operator reads it to learn what the sensor does when they change
        nothing. CHECK_TLS_CERTIFICATES was documented as `false` while the code defaulted to
        `true`, so the file said certificate matching was off when every deployment had it on -
        including its capture and processing cost.

        Only the options whose default is a literal in sensor/src/config.rs are compared; anything
        computed, or documented as an example rather than a default (URLs, paths), is skipped
        rather than guessed at.
        """

        conf = open(os.path.join(REPO, "maltrail.conf")).read()
        rs = open(os.path.join(REPO, "sensor", "src", "config.rs")).read()

        documented_defaults = {}
        for m in re.finditer(r"^#(%s)\s+(\S+)\s*$" % OPTION, conf, re.M):
            documented_defaults.setdefault(m.group(1), m.group(2))

        mismatches, compared = [], 0
        for option, documented in sorted(documented_defaults.items()):
            for pattern in (r'get_u64\(&raw,\s*"%s"\)\.unwrap_or\((\d[\d_]*)\)' % option,
                            r'get_bool_opt\(&raw,\s*"%s"\)\.unwrap_or\((true|false)\)' % option,
                            r'get_f64\(&raw,\s*"%s"\)\.unwrap_or\(([\d.]+)\)' % option):
                match = re.search(pattern, rs)
                if not match:
                    continue
                compared += 1
                code = match.group(1).replace("_", "")
                if documented.rstrip('.').replace("_", "").lower() != code.lower():
                    mismatches.append("%s: maltrail.conf says %s, config.rs defaults to %s"
                                      % (option, documented, match.group(1)))
                break

        # Nine options currently have a literal default on both sides. The floor is here so that a
        # rename in config.rs cannot turn this test into one that silently compares nothing.
        self.assertGreaterEqual(compared, 9, "the default-comparison found fewer options than "
                                             "expected - the config.rs patterns have probably drifted")
        self.assertEqual(mismatches, [], "documented default disagrees with the code: %s" % "; ".join(mismatches))

    def test_every_option_in_maltrail_conf_is_read_somewhere(self):
        # The other direction: an option nobody reads is a setting that silently does nothing.
        unused = sorted(documented() - read_by_python() - read_by_sensor() - DYNAMIC)
        self.assertEqual(unused, [], "in maltrail.conf but never read: %s" % ", ".join(unused))

    def test_known_config_options_covers_both_sides(self):
        """KNOWN_CONFIG_OPTIONS (core/settings.py) is what read_config() warns against.

        Drift in either direction is user-visible: an option missing from the set makes a
        legitimate config line warn on every startup, and a stale one hides a real typo.
        """
        sys.path.insert(0, REPO)
        from core.settings import KNOWN_CONFIG_OPTIONS

        undocumented = sorted(KNOWN_CONFIG_OPTIONS - documented() - read_by_python() - DEPRECATED)
        self.assertEqual(undocumented, [], "accepted by KNOWN_CONFIG_OPTIONS but neither documented nor read: %s" % ", ".join(undocumented))

        unwarned = sorted(documented() - KNOWN_CONFIG_OPTIONS)
        self.assertEqual(unwarned, [], "documented in maltrail.conf but missing from KNOWN_CONFIG_OPTIONS: %s" % ", ".join(unwarned))

    def test_the_scan_actually_finds_things(self):
        # Guard against the extraction silently matching nothing and both tests passing vacuously.
        self.assertGreater(len(read_by_python()), 30)
        self.assertGreater(len(read_by_sensor()), 30)
        self.assertGreater(len(documented()), 50)



class TestDisabledHeuristicsIsDocumented(unittest.TestCase):
    """The names DISABLED_HEURISTICS accepts live in the sensor; operators read maltrail.conf.

    The two drifted: `sensor/src/heuristics/mod.rs` has eight mutable heuristics and the shipped
    config listed six, omitting `beaconing` and `dns_tunneling` - while three lines above, the
    same file told the operator to "Mute it with: DISABLED_HEURISTICS dns_tunneling". An operator
    reading the option's own documentation could not learn that the newest heuristic was mutable,
    and a name that is not in the list is accepted silently and does nothing.
    """

    def _code_names(self):
        path = os.path.join(REPO, "sensor", "src", "heuristics", "mod.rs")
        with open(path) as f:
            src = f.read()
        block = re.search(r"pub const HEURISTIC_NAMES:[^=]*=\s*\[(.*?)\];", src, re.S)
        self.assertTrue(block, "HEURISTIC_NAMES not found - has it been renamed?")
        return sorted(re.findall(r'"([a-z_]+)"', block.group(1)))

    def _documented_names(self):
        with open(os.path.join(REPO, "maltrail.conf")) as f:
            conf = f.read()
        block = re.search(r"# Comma-separated names:(.*?)\n# Unset", conf, re.S)
        self.assertTrue(block, "the DISABLED_HEURISTICS name list is gone from maltrail.conf")
        return sorted(re.findall(r"[a-z_]{4,}", block.group(1).replace("#", " ")))

    def test_the_config_documents_every_mutable_heuristic(self):
        code, doc = self._code_names(), self._documented_names()
        self.assertTrue(code, "no heuristic names parsed from the sensor")
        self.assertEqual(doc, code,
                         "maltrail.conf's DISABLED_HEURISTICS list and HEURISTIC_NAMES disagree.\n"
                         "  documented: %s\n  in code:    %s\n"
                         "An operator cannot mute a heuristic whose name they are never told."
                         % (doc, code))

    def test_the_example_line_uses_real_names(self):
        # `#DISABLED_HEURISTICS port_scanning, dns_exhaustion` is a worked example; a name there
        # that the sensor does not know would be silently ignored if an operator uncommented it.
        with open(os.path.join(REPO, "maltrail.conf")) as f:
            conf = f.read()
        example = re.search(r"^#DISABLED_HEURISTICS (.+)$", conf, re.M)
        self.assertTrue(example, "the worked example is gone")
        used = [x.strip() for x in example.group(1).split(",") if x.strip()]
        unknown = [x for x in used if x not in self._code_names()]
        self.assertEqual(unknown, [], "maltrail.conf's example mutes %s, which the sensor does "
                                      "not know" % unknown)


if __name__ == "__main__":
    unittest.main()
