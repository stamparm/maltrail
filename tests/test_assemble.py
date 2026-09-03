# coding: utf-8
"""The domain-only malware list published for the DNS-filtering integrations.

Five projects that never run Maltrail consumed a derived domain list from a URL that stopped
existing when the repository hosting it was deleted: NextDNS, NoTracking, pfBlockerNG, MobSF and
MobileAudit (#19620). They cannot use trails.csv - it carries IPs, URL paths and regex trails they
would try to resolve as hostnames - so core.assemble derives a plain list of names instead, and
stamparm/trails publishes it beside the aggregate.

What has to hold is narrow but load-bearing: only names, only from the malware category, and
nothing that would poison a DNS blocklist. A regex trail like `[0-9]{2,3}\\.ru` leaking into a file
that operators feed to a resolver would block whatever it happened to match.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.assemble import malware_domains


def _trails(pairs):
    """{trail: (info, reference)} the way fetch() returns it."""
    return dict((trail, (info, "(static)")) for trail, info in pairs)


class TestMalwareDomains(unittest.TestCase):
    def test_only_the_malware_category_is_published(self):
        out = malware_domains(_trails([
            ("evil.example", "cobaltstrike (malware)"),
            ("phish.example", "gophish (malicious)"),
            ("odd.example", "pua (suspicious)"),
        ]))
        self.assertEqual(out, ["evil.example"],
                         "the list is derived from the malware trails; a (malicious) or "
                         "(suspicious) verdict must not reach a DNS blocklist")

    def test_nothing_but_hostnames_survives(self):
        out = malware_domains(_trails([
            ("good.example", "x (malware)"),
            ("1.2.3.4", "x (malware)"),                      # an IP: a resolver cannot block a name here
            ("2001:db8::1", "x (malware)"),                  # IPv6
            ("evil.example/payload.bin", "x (malware)"),     # a URL path
            (r"[0-9]{2,3}\.ru", "x (malware)"),              # a regex trail - the dangerous one
            ("1.2.3.4:8080", "x (malware)"),                 # IP:port
            ("no-dot-at-all", "x (malware)"),                # not a fully qualified name
        ]))
        self.assertEqual(out, ["good.example"],
                         "only hostnames may be published; got %r" % (out,))

    def test_sorted_deduplicated_and_lowercased(self):
        out = malware_domains(_trails([
            ("zeta.example", "x (malware)"),
            ("Alpha.Example", "x (malware)"),
            ("alpha.example", "y (malware)"),
            ("mid.example", "x (malware)"),
        ]))
        self.assertEqual(out, ["alpha.example", "mid.example", "zeta.example"])

    def test_no_malware_trails_yields_nothing(self):
        # main() turns this into a non-zero exit rather than publishing an empty blocklist, which
        # downstream would apply as "block nothing" and never notice.
        self.assertEqual(malware_domains(_trails([("x.example", "pua (suspicious)")])), [])

    def test_the_whitelist_is_applied(self):
        """A name we whitelist must not be published to the DNS filters.

        update_trails() drops whitelisted trails when it builds trails.csv, but the projects that
        aggregate this list never run it. Without the same filter here, whitelisting a false
        positive fixes our own sensors and leaves every downstream resolver still blocking it -
        which is what happened to 1rpc.io, a public RPC endpoint in the top 30k.
        """
        allowed = {"1rpc.io", "public.1rpc.io"}
        out = malware_domains(_trails([
            ("1rpc.io", "revstealer (malware)"),
            ("public.1rpc.io", "revstealer (malware)"),
            ("really-evil.example", "revstealer (malware)"),
        ]), whitelisted=lambda name: name in allowed)
        self.assertEqual(out, ["really-evil.example"],
                         "a whitelisted name reached the published blocklist: %r" % (out,))

    def test_the_real_whitelist_is_used_by_default(self):
        # No predicate passed: it must reach for the same one update_trails() uses, not publish
        # everything. 1rpc.io is in data/whitelist.txt.
        out = malware_domains(_trails([
            ("1rpc.io", "revstealer (malware)"),
            ("still-evil.example", "x (malware)"),
        ]))
        self.assertEqual(out, ["still-evil.example"],
                         "malware_domains() published a name data/whitelist.txt excludes")

    def test_a_real_looking_set_comes_through_intact(self):
        names = ["a.example", "b.co.uk", "c-d.example", "x_y.example", "deep.sub.example"]
        out = malware_domains(_trails([(n, "family (malware)") for n in names]),
                              whitelisted=lambda name: False)
        self.assertEqual(out, sorted(names))


if __name__ == "__main__":
    unittest.main()
