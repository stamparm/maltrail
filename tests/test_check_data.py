# coding: utf-8
"""Unit tests for the data/ format gate (sensor/tools/check_data.py).

Every loader for data/*.txt skips a line it cannot read, so a typo there passed CI and did nothing.
Both directions are asserted: the shipped lists pass, and each malformed form that actually reached
master (#19624) fails."""

import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import check_data as D

GOOD = {
    "worst_asns.txt": "# AS 219050\n# Reference: https://ipinfo.io/AS219050\n\n31.59.163.0/24,teraflow\n2a0f:ca80:b00b::/48,techties-as\n",
    "whitelist.txt": "# nameserver\n92.222.150.60\nexample.com\n10.0.0.0/8\n",
    "ua.txt": "FunWebProducts\n\\$({|%7B)\\w{0,}(:|%3A)\nMozilla/4.0 (compatible; MSIE 6.0)\n",
    "cdn_ranges.txt": "173.245.48.0/20\n",
    "bogon_ranges.txt": "0.0.0.0/8\n",
    "drop.txt": "1.10.16.0/20 # SBL256894\n2a06:e480::/29 # SBL1\n",
    "mass_scanner_cidr.txt": "5.63.151.0/24 # rapid7\n68.183.53.77 # driftnet.io\n",
    "public_suffix_icann.txt": "co.uk\nandøy.no\n",
    "ignore_events.txt": "# src;sport;dst;dport\n*;*;192.168.1.1;23\n",
}

BAD = [
    ("worst_asns.txt", "31.59.163.0/24, teraflow"),
    ("worst_asns.txt", "# Reference: # Reference: https://x.com/spamhaus/status/2117625871582343622"),
    ("worst_asns.txt", "# Refrence: https://ipinfo.io/AS201097"),
    ("worst_asns.txt", "31.59.163.0/24;teraflow"),
    ("worst_asns.txt", "31.59.163/24,teraflow"),
    ("whitelist.txt", "92.222.150.60   # nameserver for sci-hub.tw"),
    ("ua.txt", "(?i)a|(?i)b"),
    ("cdn_ranges.txt", "173.245.48.0"),
    ("cdn_ranges.txt", "173.245.480.0/20"),
    ("drop.txt", "1.10.16.0/40 # SBL1"),
    ("ignore_events.txt", "*;*;23"),
]


class TestCheckData(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _problems(self, files):
        for name, content in files.items():
            with open(os.path.join(self.tmp, name), "w", encoding="utf8") as f:
                f.write(content)
        return D.problems(self.tmp)

    def test_the_shipped_lists_pass(self):
        self.assertEqual(D.problems(os.path.join(ROOT, "data")), [])

    def test_well_formed_entries_pass(self):
        # the control: without it, a gate that flags everything would pass the BAD cases too
        self.assertEqual(self._problems(GOOD), [])

    def test_each_malformed_entry_fails(self):
        for name, line in BAD:
            files = dict(GOOD)
            files[name] = files[name] + line + "\n"
            found = self._problems(files)
            self.assertEqual([(_[0], _[2]) for _ in found], [(name, line.strip())], "%s: %r" % (name, line))

    def test_an_unknown_list_fails(self):
        files = dict(GOOD, **{"new_list.txt": "anything\n"})
        self.assertEqual([_[0] for _ in self._problems(files)], ["new_list.txt"])


if __name__ == "__main__":
    unittest.main()
