# coding: utf-8
"""Unit tests for core/geo.event_country() - the attack-origins map decision tree. Uses the bundled RIR
table (data/ip2cc.csv.gz), so the country codes below are real: 37.114.46.97->DE, 8.8.8.8->US, 1.1.1.1->AU,
5.5.5.5->DE, and private/loopback/domains -> None. Locks WHICH endpoint each trail type geolocates."""
import gzip
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import geo
from core import settings as S


class TestEventCountry(unittest.TestCase):
    def setUp(self):
        # sanity: the bundled table must resolve these, else the whole suite is meaningless
        if geo.ip_to_country("8.8.8.8") != "US" or geo.ip_to_country("37.114.46.97") != "DE":
            self.skipTest("bundled GeoIP table not available/expected")

    # 1. bare IP trail -> the trail IS the malicious IP, regardless of direction
    def test_ip_trail_outbound(self):
        self.assertEqual(geo.event_country("IP", "10.0.0.5", "37.114.46.97", "37.114.46.97"), "DE")

    def test_ip_trail_inbound(self):
        self.assertEqual(geo.event_country("IP", "37.114.46.97", "10.0.0.5", "37.114.46.97"), "DE")

    # 2. IPORT: "IP:port" and "IP (query)" -> leading IP
    def test_iport_colon(self):
        self.assertEqual(geo.event_country("IPORT", "10.0.0.5", "1.1.1.1", "1.1.1.1:8080"), "AU")

    def test_iport_query(self):
        self.assertEqual(geo.event_country("IPORT", "10.0.0.5", "8.8.8.8", "8.8.8.8 (evil.com)"), "US")

    # 3. URL/HTTP with an IP host -> that host IP (the reported bug: "37.114.46.97/")
    def test_url_ip_host(self):
        self.assertEqual(geo.event_country("URL", "10.0.0.5", "37.114.46.97", "37.114.46.97/"), "DE")

    # 4. URL/HTTP with a DOMAIN host -> the dst server we actually connected to (key improvement)
    def test_url_domain_host_uses_dst(self):
        self.assertEqual(geo.event_country("URL", "10.0.0.9", "5.5.5.5", "evil.com/malware.exe"), "DE")

    def test_http_domain_host_uses_dst(self):
        self.assertEqual(geo.event_country("HTTP", "10.0.0.9", "8.8.8.8", "evil.com/x"), "US")

    # 5. DNS -> None: dst is only the resolver; never plot 8.8.8.8 for a domain IOC
    def test_dns_resolver_not_plotted(self):
        self.assertIsNone(geo.event_country("DNS", "10.0.0.5", "8.8.8.8", "evil.com"))

    # 6. UA -> outbound: the C2/server the infected host contacted (dst)
    def test_ua_uses_dst(self):
        self.assertEqual(geo.event_country("UA", "10.0.0.9", "1.1.1.1", "Mozilla/evilbot"), "AU")

    # 7. inbound-attack heuristics (PATH web-scan, PORT infection) -> the SOURCE
    def test_path_scan_uses_src(self):
        self.assertEqual(geo.event_country("PATH", "37.114.46.97", "10.0.0.5", "*"), "DE")

    def test_port_infection_uses_src(self):
        self.assertEqual(geo.event_country("PORT", "1.1.1.1", "10.0.0.5", "445"), "AU")

    # 8. a digit-leading DOMAIN must NOT be mis-parsed as its leading octets
    def test_digit_leading_domain_not_misplaced(self):
        # both endpoints local + a "1.2.3.4.evil.com" domain trail -> nothing to place (proves the IP boundary)
        self.assertIsNone(geo.event_country("URL", "10.0.0.5", "10.0.0.6", "1.2.3.4.evil.com/x"))

    # 9. internal-only event -> unmapped
    def test_internal_only(self):
        self.assertIsNone(geo.event_country("IP", "10.0.0.5", "10.0.0.6", "10.0.0.6"))

    # 10. both endpoints public (transit/span) for outbound-style trail -> prefer the contacted dst
    def test_both_public_prefers_dst(self):
        self.assertEqual(geo.event_country("URL", "8.8.8.8", "5.5.5.5", "evil.com/x"), "DE")


class TestBundledTables(unittest.TestCase):
    """The seeds in data/ are what a first-run or air-gapped install geolocates with. IPv6 had no seed at all,
    so every IPv6 event was unmapped until an online update happened to succeed - and nothing said so."""

    def test_ipv6_resolves_from_the_bundled_seed(self):
        # real allocations, and their holders do not move country: Google, Cloudflare, Google-IE, RCS-RO
        for ip, cc in (("2001:4860:4860::8888", "US"), ("2606:4700::1111", "US"),
                       ("2a00:1450:4001::1", "IE"), ("2a02:2f00::1", "RO")):
            self.assertEqual(geo.ip_to_country(ip), cc, ip)

    def test_ipv6_private_and_loopback_are_unmapped(self):
        # the positive control's other half: if the table answered everything, the test above would be worthless
        for ip in ("::1", "fd00::1", "fe80::1", "::"):
            self.assertIsNone(geo.ip_to_country(ip), ip)

    def test_event_country_places_an_ipv6_trail(self):
        self.assertEqual(geo.event_country("IP", "10.0.0.5", "2606:4700::1111", "2606:4700::1111"), "US")

    def test_both_seeds_are_the_hexdelta_format(self):
        import gzip
        for path in (S.GEO_IP2CC_BUNDLED_FILE, S.GEO_IP2CC6_BUNDLED_FILE):
            with gzip.open(path, "rb") as f:
                head = f.read(64).decode("latin-1")
            self.assertTrue(head.startswith(geo.GEO_DELTA_MAGIC), path)


class TestStorageFormat(unittest.TestCase):
    """_parse() has to read both formats: a hex-delta seed, and the absolute-decimal table an existing install
    still has in USERS_DIR until its next refresh."""

    def _writer(self):
        try:
            from core.update import _write_geo   # core.update imports sqlite3 (ipcat); some builds lack _sqlite3
        except ImportError as ex:
            self.skipTest("core.update unavailable (%s)" % ex)
        return _write_geo

    def test_hexdelta_round_trip_through_the_writer(self):
        _write_geo = self._writer()
        rows = [(0, ""), (16777216, "US"), (16777472, ""), (3232235520, "HR")]
        path = os.path.join(self.tmp, "v4.csv.gz")
        _write_geo(path, rows, family=4)
        self.assertEqual(geo._parse(gzip.open(path, "rb").read().decode("latin-1")),
                         ([0, 16777216, 16777472, 3232235520], ["", "US", "", "HR"]))

    def test_hexdelta_ipv6_restores_the_low_64_bits(self):
        _write_geo = self._writer()
        start = 0x2001048604860000 << 64
        path = os.path.join(self.tmp, "v6.csv.gz")
        _write_geo(path, [(0, ""), (start, "US")], family=6)
        starts, ccs = geo._parse(gzip.open(path, "rb").read().decode("latin-1"))
        self.assertEqual((starts, ccs), ([0, start], ["", "US"]))

    def test_legacy_absolute_decimal_is_still_read(self):
        path = os.path.join(self.tmp, "legacy.csv.gz")
        with gzip.open(path, "wb") as f:
            f.write(b"0,\n167772160,US\n167772416,\n")
        self.assertEqual(geo._lookup(path, 167772165), "US")
        self.assertIsNone(geo._lookup(path, 167772500))

    def test_a_refreshed_table_is_picked_up_without_a_restart(self):
        # _load() re-stats at most once a second, so this asserts the cache expires rather than pins forever
        path = os.path.join(self.tmp, "refresh.csv.gz")
        with gzip.open(path, "wb") as f:
            f.write(b"0,\n167772160,US\n")
        self.assertEqual(geo._lookup(path, 167772165), "US")
        with gzip.open(path, "wb") as f:
            f.write(b"0,\n167772160,HR\n")
        os.utime(path, (0, 0))                       # a different mtime, without waiting a second
        geo._tables[path] = geo._tables[path][:3] + (0,)   # expire the re-stat window
        self.assertEqual(geo._lookup(path, 167772165), "HR")

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)


if __name__ == "__main__":
    unittest.main()
