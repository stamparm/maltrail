# coding: utf-8
"""Unit tests for core/geo.event_country() - the attack-origins map decision tree. Uses the bundled RIR
table (data/ip2cc.csv.gz), so the country codes below are real: 37.114.46.97->DE, 8.8.8.8->US, 1.1.1.1->AU,
5.5.5.5->DE, and private/loopback/domains -> None. Locks WHICH endpoint each trail type geolocates."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import geo


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


if __name__ == "__main__":
    unittest.main()
