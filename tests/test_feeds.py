# coding: utf-8
"""A feed whose provider wants a key: skipped when none is set, fetched with it when one is.

abuse.ch put URLhaus behind an Auth-Key in October 2026; the old download answers 410 Gone. Two
things must not happen. Without a key, the feed must not be fetched and then reported among the
"dead" feeds that produced nothing - the operator has done nothing wrong. With one, the key must
reach the request and never anything that is printed.
"""

import io
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "feeds"))
sys.path.insert(0, os.path.join(REPO, "sensor", "tools"))

from core.settings import config  # noqa: E402

FIXTURE = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs)            #
#                                                              #
# Terms Of Use: https://urlhaus.abuse.ch/api/                  #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3301234","2026-10-26 12:58:04","http://1.2.3.4:41234/i","online","2026-10-26 12:58:04","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3301234/","geenensp"
"3301235","2026-10-26 12:58:05","https://evil.example/a/b.exe","offline","","malware_download","exe","https://urlhaus.abuse.ch/url/3301235/","abuse_ch"
"3301236","2026-10-26 12:58:06","ftp://not.taken.example/x","online","","malware_download","","https://urlhaus.abuse.ch/url/3301236/","abuse_ch"
"""


class UrlhausFeedTest(unittest.TestCase):
    def setUp(self):
        import urlhaus
        self.feed = urlhaus
        self.saved = (config.ABUSE_CH_AUTH_KEY, urlhaus.retrieve_content)
        self.requested = []

    def tearDown(self):
        config.ABUSE_CH_AUTH_KEY, self.feed.retrieve_content = self.saved

    def _serve(self, body):
        def fake(url, *args, **kwargs):
            self.requested.append(url)
            return body
        self.feed.retrieve_content = fake

    def test_no_key_means_no_request(self):
        self._serve(FIXTURE)
        for unset in (None, "", "   "):
            config.ABUSE_CH_AUTH_KEY = unset
            self.assertEqual(self.feed.fetch(), {})
        self.assertEqual(self.requested, [])

    def test_the_key_goes_into_the_path_and_the_urls_come_out(self):
        self._serve(FIXTURE)
        config.ABUSE_CH_AUTH_KEY = " k3y "
        trails = self.feed.fetch()
        self.assertEqual(self.requested, ["https://urlhaus-api.abuse.ch/v2/files/exports/k3y/recent.csv"])
        self.assertEqual(sorted(trails), ["1.2.3.4:41234/i", "evil.example/a/b.exe"])
        # never the row's own urlhaus_link, whatever its url column holds
        self.assertFalse([t for t in trails if "urlhaus.abuse.ch" in t], trails)
        self.assertEqual(trails["evil.example/a/b.exe"], ("malware", "abuse.ch"))

    def test_a_rejected_key_yields_nothing(self):
        self._serve('{"status":401,"message":"Invalid auth token"}')
        config.ABUSE_CH_AUTH_KEY = "bogus"
        self.assertEqual(self.feed.fetch(), {})

    def test_the_printed_url_carries_no_key(self):
        self.assertIn("<ABUSE_CH_AUTH_KEY>", self.feed.__url__)
        self.assertEqual(self.feed.__requires__, "ABUSE_CH_AUTH_KEY")


class SkippedNotDeadTest(unittest.TestCase):
    """The real update_trails(), with every feed but URLhaus disabled and no key set."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.saved = dict((k, config.get(k)) for k in (
            "TRAILS_FILE", "CUSTOM_TRAILS_DIR", "USE_FEED_UPDATES", "STATIC_TRAILS_URL", "CUSTOM_TRAILS_URL",
            "DISABLED_FEEDS", "ABUSE_CH_AUTH_KEY"))

    def tearDown(self):
        for k, v in self.saved.items():
            config[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_update_says_how_to_enable_it_and_does_not_call_it_dead(self):
        from core import update
        feeds = [f[:-3] for f in os.listdir(os.path.join(REPO, "feeds")) if f.endswith(".py") and not f.startswith("__")]
        self.assertIn("urlhaus", feeds)
        config.TRAILS_FILE = os.path.join(self.tmp, "trails.csv")
        config.CUSTOM_TRAILS_DIR = None
        config.USE_FEED_UPDATES = True
        config.STATIC_TRAILS_URL = None
        config.CUSTOM_TRAILS_URL = None
        config.DISABLED_FEEDS = ", ".join(f for f in feeds if f != "urlhaus")
        config.ABUSE_CH_AUTH_KEY = None

        out, saved = io.StringIO(), sys.stdout
        sys.stdout = out
        try:
            update.update_trails(force=True, offline=False)   # offline skips feeds entirely
        finally:
            sys.stdout = saved
        text = out.getvalue()
        self.assertIn("[i] feed skipped: 'ABUSE_CH_AUTH_KEY' is not set (a free Auth-Key from https://auth.abuse.ch/)", text)
        self.assertNotIn("no indicators from", text)
        self.assertNotIn("produced no indicators", text)
        self.assertIn("urlhaus-api.abuse.ch", text)          # it was considered at all - not vacuous


class CheckFeedsTest(unittest.TestCase):
    def setUp(self):
        self.saved = os.environ.get("ABUSE_CH_AUTH_KEY")

    def tearDown(self):
        if self.saved is None:
            os.environ.pop("ABUSE_CH_AUTH_KEY", None)
        else:
            os.environ["ABUSE_CH_AUTH_KEY"] = self.saved

    def _urlhaus(self):
        import check_feeds
        return [f for f in check_feeds._feeds() if f[0] == "urlhaus"][0]

    def test_without_a_key_it_is_not_probed(self):
        os.environ.pop("ABUSE_CH_AUTH_KEY", None)
        import check_feeds
        name, url, key = self._urlhaus()
        self.assertIsNone(key)
        self.assertEqual(check_feeds._probe((name, url, key)), (name, url, None, None))

    def test_with_a_key_it_is_probed_with_it(self):
        os.environ["ABUSE_CH_AUTH_KEY"] = "k3y"
        name, url, key = self._urlhaus()
        self.assertEqual((url, key), ("https://urlhaus-api.abuse.ch/v2/files/exports/k3y/recent.csv", "k3y"))

    def test_feeds_without_a_requirement_are_untouched(self):
        import check_feeds
        others = [f for f in check_feeds._feeds() if f[0] != "urlhaus"]
        self.assertGreater(len(others), 20)
        self.assertTrue(all(key == "" and "<" not in url for _, url, key in others))


if __name__ == "__main__":
    unittest.main()
