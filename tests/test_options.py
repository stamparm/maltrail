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
DEPRECATED = {"USE_MULTIPROCESSING"}

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
    sources += [os.path.join(REPO, "server.py"), os.path.join(REPO, "old", "sensor.py")]
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

    def test_the_scan_actually_finds_things(self):
        # Guard against the extraction silently matching nothing and both tests passing vacuously.
        self.assertGreater(len(read_by_python()), 30)
        self.assertGreater(len(read_by_sensor()), 30)
        self.assertGreater(len(documented()), 50)


if __name__ == "__main__":
    unittest.main()
