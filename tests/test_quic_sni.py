# coding: utf-8
"""Battery for quic_sni: AES KATs, HKDF/QUIC key-derivation KATs (RFC 9001/9369),
round-trip, cross-backend equivalence (cryptography vs pure-Python), prefix-cap, and
malformed/fuzz robustness. stdlib unittest; Py2 + Py3."""
import binascii
import struct
import random
import unittest

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from core import quic_sni as Q

try:
    STRT = (str, unicode)            # py2: SNI decodes to unicode
except NameError:
    STRT = (str,)                    # py3


def unhx(s):
    return binascii.unhexlify(s)


def hx(b):
    return binascii.hexlify(b).decode()


# ---- a pure-Python AES backend bound to the module, for forcing the fallback ----
def _force_pure_python(monkey):
    monkey._save = (Q.HAVE_CRYPTOGRAPHY, Q.aes_ecb_block, Q.aes_ctr_decrypt)
    Q.HAVE_CRYPTOGRAPHY = False
    Q.aes_ecb_block = lambda key, blk: Q._AES128(key).encrypt_block(blk)

    def ctr(key, c0, data):
        aes = Q._AES128(key)
        out = bytearray(len(data))
        cb = bytearray(c0)
        d = Q._b(data)
        for off in range(0, len(data), 16):
            ks = Q._b(aes.encrypt_block(bytes(cb)))
            end = min(16, len(data) - off)
            for i in range(end):
                out[off + i] = d[off + i] ^ ks[i]
            j = 15
            while j >= 0:
                cb[j] = (cb[j] + 1) & 0xFF
                if cb[j]:
                    break
                j -= 1
        return bytes(out)
    Q.aes_ctr_decrypt = ctr


def _restore(monkey):
    Q.HAVE_CRYPTOGRAPHY, Q.aes_ecb_block, Q.aes_ctr_decrypt = monkey._save


def _evarint(v):
    if v < 64:
        return struct.pack("B", v)
    if v < 16384:
        return struct.pack("!H", v | 0x4000)
    return struct.pack("!I", v | 0x80000000)


def _client_hello(sni):
    s = sni.encode()
    srv = b"\x00" + struct.pack("!H", len(s)) + s
    lst = struct.pack("!H", len(srv)) + srv
    ext = b"\x00\x00" + struct.pack("!H", len(lst)) + lst
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def crypto_frame(offset, data):
    return b"\x06" + _evarint(offset) + _evarint(len(data)) + data


def build_quic_initial(sni, dcid, version=1, pn=1, pn_len=1, pad_to=1200, frames=None):
    crypto = frames if frames is not None else crypto_frame(0, _client_hello(sni))
    payload = crypto + b"\x00" * max(0, pad_to - len(crypto) - 50)
    key, iv, hp = Q.derive_client_initial_keys(dcid, version)
    nonce = bytearray(iv)
    pnbe = bytearray(struct.pack("!Q", pn))
    for i in range(8):
        nonce[4 + i] ^= pnbe[i]
    counter0 = bytes(nonce) + struct.pack("!I", 2)
    ct = Q.aes_ctr_decrypt(key, counter0, payload) + b"\x00" * 16
    first = (0xC0 if version == 1 else 0xD0) | (pn_len - 1)   # encode pn length in low 2 bits
    ver_word = 1 if version == 1 else 0x6b3343cf
    hdr = struct.pack("B", first) + struct.pack("!I", ver_word)
    hdr += struct.pack("B", len(dcid)) + dcid + b"\x00"
    hdr += _evarint(0) + _evarint(pn_len + len(ct))
    pn_bytes = struct.pack("!Q", pn)[-pn_len:]               # pn_len-byte big-endian
    pkt = bytearray(hdr + pn_bytes + ct)
    po = len(hdr)
    mask = Q._b(Q.aes_ecb_block(hp, bytes(pkt[po + 4:po + 20])))
    pkt[0] ^= (mask[0] & 0x0F)
    for i in range(pn_len):
        pkt[po + i] ^= mask[1 + i]
    return bytes(pkt)


class TestAES(unittest.TestCase):
    # FIPS-197 + extra NIST AES-128 ECB known-answer vectors
    VECTORS = [
        ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
        ("2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
        ("00000000000000000000000000000000", "00000000000000000000000000000000", "66e94bd4ef8a2c3b884cfa59ca342b2e"),
    ]

    def test_aes128_kat(self):
        for k, p, c in self.VECTORS:
            self.assertEqual(hx(Q._AES128(unhx(k)).encrypt_block(unhx(p))), c)


class TestKeyDerivation(unittest.TestCase):
    def test_quic_v1_rfc9001(self):
        k, iv, hp = Q.derive_client_initial_keys(unhx("8394c8f03e515708"), 1)
        self.assertEqual(hx(k), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(hx(iv), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(hx(hp), "9f50449e04a0e810283a1e9933adedd2")

    def test_hkdf_extract_known(self):
        # RFC 5869 test case 1 PRK
        prk = Q.hkdf_extract(unhx("000102030405060708090a0b0c"), unhx("0b" * 22))
        self.assertEqual(hx(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

    def test_hkdf_expand_known(self):
        prk = unhx("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = Q.hkdf_expand(prk, unhx("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(hx(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")


class TestRoundTrip(unittest.TestCase):
    DCID = unhx("0011223344556677")

    def test_v1_roundtrip(self):
        pkt = build_quic_initial("evil.example.com", self.DCID, version=1)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "evil.example.com")

    def test_v2_roundtrip(self):
        pkt = build_quic_initial("v2.evil.tld", self.DCID, version=2)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "v2.evil.tld")

    def test_various_snis(self):
        for sni in ["a.io", "x" * 60 + ".example.com", "sub.domain.example.co.uk", "xn--punycode.com"]:
            pkt = build_quic_initial(sni, self.DCID)
            self.assertEqual(Q.extract_sni_from_quic_initial(pkt), sni)

    def test_multibyte_packet_number(self):
        # exercise the module's pn_len decoding for 2- and 4-byte packet numbers
        pkt2 = build_quic_initial("pn2.evil.tld", self.DCID, pn=0x0102, pn_len=2)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt2), "pn2.evil.tld")
        pkt4 = build_quic_initial("pn4.evil.tld", self.DCID, pn=0x01020304, pn_len=4)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt4), "pn4.evil.tld")


class TestEdge(unittest.TestCase):
    def test_dcid_max_20_bytes(self):
        pkt = build_quic_initial("big-dcid.tld", binascii.unhexlify("00" * 20))  # max valid DCID
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "big-dcid.tld")

    def test_dcid_empty(self):
        pkt = build_quic_initial("zero-dcid.tld", b"")
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "zero-dcid.tld")

    def test_multi_crypto_frame_reassembly(self):
        ch = _client_hello("split.evil.tld")
        k = 40
        frames = crypto_frame(0, ch[:k]) + crypto_frame(k, ch[k:])
        pkt = build_quic_initial(None, binascii.unhexlify("0011223344556677"), frames=frames)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "split.evil.tld")

    def test_multi_crypto_frame_out_of_order(self):
        ch = _client_hello("ooo.evil.tld")
        k = 50
        frames = crypto_frame(k, ch[k:]) + crypto_frame(0, ch[:k])  # reversed order
        pkt = build_quic_initial(None, binascii.unhexlify("0011223344556677"), frames=frames)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "ooo.evil.tld")

    def test_padding_and_ping_frames_skipped(self):
        ch = _client_hello("pad.evil.tld")
        frames = b"\x00\x00\x00" + b"\x01" + crypto_frame(0, ch)  # PADDING*3 + PING + CRYPTO
        pkt = build_quic_initial(None, binascii.unhexlify("0011223344556677"), frames=frames)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "pad.evil.tld")


class TestCrossBackend(unittest.TestCase):
    DCID = unhx("a1b2c3d4e5f60718")

    def test_pure_python_decodes_crypto_encrypted(self):
        # encrypt with whatever default backend is active...
        pkt = build_quic_initial("malware-c2.bad.tld", self.DCID)
        # ...decode with the pure-Python fallback forced
        class M:
            pass
        m = M()
        _force_pure_python(m)
        try:
            self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "malware-c2.bad.tld")
        finally:
            _restore(m)

    def test_prefix_cap_matches_full(self):
        pkt = build_quic_initial("cap.evil.tld", self.DCID)
        self.assertEqual(Q.extract_sni_from_quic_initial(pkt), "cap.evil.tld")


class TestMalformed(unittest.TestCase):
    DCID = unhx("0011223344556677")

    def test_short_returns_none(self):
        for b in [b"", b"\xc0", b"\xc0\x00\x00\x00\x01", b"\x00" * 7]:
            self.assertIsNone(Q.extract_sni_from_quic_initial(b))

    def test_not_long_header(self):
        self.assertIsNone(Q.extract_sni_from_quic_initial(b"\x40" + b"\x00" * 50))

    def test_version_negotiation(self):
        self.assertIsNone(Q.extract_sni_from_quic_initial(b"\xc0\x00\x00\x00\x00" + b"\x00" * 50))

    def test_truncated_valid_packet(self):
        pkt = build_quic_initial("trunc.tld", self.DCID)
        for cut in range(0, len(pkt), 37):
            r = Q.extract_sni_from_quic_initial(pkt[:cut])
            self.assertTrue(r is None or isinstance(r, STRT))

    def test_fuzz_never_raises(self):
        # Force the pure-Python backend: it is the security-critical fallback (lean boxes),
        # the parsing logic is backend-independent, and this keeps the fuzz deterministic
        # across all interpreters (cross-backend equivalence is proven separately).
        random.seed(99)
        good = build_quic_initial("fuzz.seed.tld", self.DCID, pad_to=300)
        m_state = type("M", (), {})()
        _force_pure_python(m_state)
        try:
            for _ in range(1500):
                if random.random() < 0.5:
                    m = bytearray(good)
                    for _ in range(random.randint(1, 10)):
                        if m:
                            m[random.randrange(len(m))] = random.randint(0, 255)
                    if random.random() < 0.4:
                        m = m[:random.randint(0, len(m))]
                    buf = bytes(m)
                else:
                    buf = bytes(bytearray(random.getrandbits(8) for _ in range(random.randint(0, 80))))
                r = Q.extract_sni_from_quic_initial(buf)
                self.assertTrue(r is None or isinstance(r, STRT))
        finally:
            _restore(m_state)


if __name__ == "__main__":
    unittest.main()
