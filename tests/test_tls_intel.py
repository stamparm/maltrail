# coding: utf-8
"""Battery for tls_intel: SNI, JA3/JA3S (KAT), JA4, cert CN/SAN, GREASE filtering, ALPN,
supported_versions, and malformed/fuzz robustness. stdlib unittest; Py2 + Py3."""
import hashlib
import struct
import random
import unittest

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from core import tls_intel as T

try:
    STRT = (str, unicode)
except NameError:
    STRT = (str,)


def ext(t, body):
    return struct.pack("!HH", t, len(body)) + body


def build_ch(sni="test.example.com", ciphers=(0x1301, 0x1302), with_grease=True,
             curves=(0x001d, 0x0017), ecpf=(0,), sigalgs=(0x0403, 0x0804),
             alpn=b"h2", supported_versions=None, with_record=True, legacy_ver=0x0303):
    cs = b""
    if with_grease:
        cs += struct.pack("!H", 0x0a0a)
    for c in ciphers:
        cs += struct.pack("!H", c)
    exts = b""
    if sni is not None:
        s = sni.encode()
        srv = b"\x00" + struct.pack("!H", len(s)) + s
        lst = struct.pack("!H", len(srv)) + srv
        exts += ext(0x0000, lst)
    if with_grease:
        exts += ext(0x1a1a, b"")
    if curves is not None:
        body = struct.pack("!H", 2 * len(curves)) + b"".join(struct.pack("!H", c) for c in curves)
        exts += ext(0x000a, body)
    if ecpf is not None:
        exts += ext(0x000b, struct.pack("!B", len(ecpf)) + bytes(bytearray(ecpf)))
    if sigalgs is not None:
        body = struct.pack("!H", 2 * len(sigalgs)) + b"".join(struct.pack("!H", s) for s in sigalgs)
        exts += ext(0x000d, body)
    if alpn is not None:
        a = struct.pack("B", len(alpn)) + alpn
        exts += ext(0x0010, struct.pack("!H", len(a)) + a)
    if supported_versions is not None:
        body = struct.pack("!B", 2 * len(supported_versions)) + b"".join(struct.pack("!H", v) for v in supported_versions)
        exts += ext(0x002b, body)
    body = (struct.pack("!H", legacy_ver) + b"\x11" * 32 + b"\x00"
            + struct.pack("!H", len(cs)) + cs + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    if with_record:
        return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    return hs


def build_sh(ver=0x0303, cipher=0x1301, exts_types=(0x002b,)):
    exts = b""
    for et in exts_types:
        exts += ext(et, b"\x00\x00")
    body = (struct.pack("!H", ver) + b"\x22" * 32 + b"\x00"
            + struct.pack("!H", cipher) + b"\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


class TestSNI(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(T.parse_client_hello(build_ch("evil.example.com"))["sni"], "evil.example.com")

    def test_without_record_header(self):
        self.assertEqual(T.parse_client_hello(build_ch("bare.tld", with_record=False))["sni"], "bare.tld")

    def test_no_sni(self):
        r = T.parse_client_hello(build_ch(sni=None))
        self.assertIsNone(r.get("sni"))

    def test_sni_must_be_hostname(self):
        # real-traffic finding: a malformed/partial ClientHello can decode to junk in the SNI
        # field -> we must return None, never a non-hostname string.
        self.assertIsNone(T.parse_client_hello(build_ch("not a valid host!")).get("sni"))
        self.assertEqual(T.parse_client_hello(build_ch("ok.example.com")).get("sni"), "ok.example.com")

    def test_sni_lowercased(self):
        self.assertEqual(T.parse_client_hello(build_ch("EVIL.Example.COM"))["sni"], "evil.example.com")


class TestJA3(unittest.TestCase):
    def test_ja3_string_kat(self):
        r = T.parse_client_hello(build_ch())
        # GREASE (0x0a0a cipher, 0x1a1a ext) filtered; fields: ver,ciphers,exts,curves,ecpf
        self.assertEqual(r["ja3_string"], "771,4865-4866,0-10-11-13-16,29-23,0")
        self.assertEqual(r["ja3"], hashlib.md5(r["ja3_string"].encode()).hexdigest())

    def test_grease_filtered_everywhere(self):
        r = T.parse_client_hello(build_ch(ciphers=(0x1301,), curves=(0x001d,)))
        self.assertNotIn("2570", r["ja3_string"])  # 0x0a0a == 2570 must be absent

    def test_ja3_stable(self):
        a = T.parse_client_hello(build_ch("a.com"))["ja3"]
        b = T.parse_client_hello(build_ch("b.com"))["ja3"]
        self.assertEqual(a, b)  # JA3 independent of SNI value


class TestJA3S(unittest.TestCase):
    def test_ja3s_kat(self):
        r = T.parse_server_hello(build_sh())
        self.assertEqual(r["ja3s_string"], "771,4865,43")
        self.assertEqual(r["ja3s"], hashlib.md5(r["ja3s_string"].encode()).hexdigest())


class TestJA4(unittest.TestCase):
    def test_format_tcp(self):
        r = T.parse_client_hello(build_ch(), transport="t")
        ja4 = r["ja4"]
        self.assertEqual(ja4.count("_"), 2)
        a = ja4.split("_")[0]
        self.assertTrue(a.startswith("t12d"))  # tcp, tls1.2, sni present
        self.assertTrue(a.endswith("h2"))      # ALPN first/last char

    def test_quic_transport_and_no_sni(self):
        r = T.parse_client_hello(build_ch(sni=None), transport="q")
        self.assertTrue(r["ja4"].startswith("q12i"))  # quic, no sni -> i

    def test_supported_versions_picks_13(self):
        r = T.parse_client_hello(build_ch(supported_versions=[0x0304]))
        self.assertTrue(r["ja4"].split("_")[0].startswith("t13"))


class TestJA4Edge(unittest.TestCase):
    def test_cipher_count_capped_99(self):
        many = tuple(range(0x0100, 0x0100 + 120))  # 120 ciphers (none GREASE)
        r = T.parse_client_hello(build_ch(ciphers=many))
        # ja4_a = transport(1) ver(2) sni(1) ciphercount(2) extcount(2) alpn(2)
        a = r["ja4"].split("_")[0]
        self.assertEqual(a[4:6], "99")  # cipher count capped at 99

    def test_no_alpn_is_00(self):
        r = T.parse_client_hello(build_ch(alpn=None))
        self.assertTrue(r["ja4"].split("_")[0].endswith("00"))

    def test_sslv3_version(self):
        r = T.parse_client_hello(build_ch(legacy_ver=0x0300, supported_versions=None))
        self.assertTrue(r["ja4"].split("_")[0].startswith("ts3"))

    def test_ja4_deterministic(self):
        a = T.parse_client_hello(build_ch("a.com"))["ja4"]
        b = T.parse_client_hello(build_ch("b.com"))["ja4"]
        self.assertEqual(a.split("_")[1:], b.split("_")[1:])  # hashes independent of SNI value


class TestCert(unittest.TestCase):
    def test_cn_and_san(self):
        cn = b"cert-cn.example.com"
        san = b"alt.evil.tld"
        der = (b"\x30\x82\x01\x00" + T._OID_CN + b"\x13" + struct.pack("B", len(cn)) + cn
               + T._OID_SAN + b"\x04\x10\x30\x0e" + b"\x82" + struct.pack("B", len(san)) + san)
        names = T.extract_cert_names(der)
        self.assertIn("cert-cn.example.com", names)
        self.assertIn("alt.evil.tld", names)

    def test_multiple_sans(self):
        der = T._OID_SAN + b"\x04\x20\x30\x1e"
        for d in (b"a.evil.tld", b"b.evil.tld"):
            der += b"\x82" + struct.pack("B", len(d)) + d
        names = T.extract_cert_names(der)
        self.assertIn("a.evil.tld", names)
        self.assertIn("b.evil.tld", names)

    def test_garbage_cert_returns_list(self):
        self.assertEqual(T.extract_cert_names(b"\x00" * 100), [])


class TestMalformed(unittest.TestCase):
    def test_truncated_ch(self):
        full = build_ch("trunc.example.com")
        for cut in range(0, len(full), 5):
            r = T.parse_client_hello(full[:cut])
            self.assertIsInstance(r, dict)

    def test_fuzz_never_raises(self):
        random.seed(7)
        seeds = [build_ch(), build_sh(), b"", b"\x16", b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\xff"]
        for _ in range(20000):
            if random.random() < 0.5:
                m = bytearray(random.choice(seeds) or b"\x16\x03\x01")
                for _ in range(random.randint(0, 8)):
                    if m:
                        m[random.randrange(len(m))] = random.randint(0, 255)
                if random.random() < 0.5:
                    m = m[:random.randint(0, len(m))]
                buf = bytes(m)
            else:
                buf = bytes(bytearray(random.getrandbits(8) for _ in range(random.randint(0, 60))))
            self.assertIsInstance(T.parse_client_hello(buf, "t"), dict)
            self.assertIsInstance(T.parse_server_hello(buf), dict)
            self.assertIsInstance(T.extract_cert_names(buf), list)


if __name__ == "__main__":
    unittest.main()
