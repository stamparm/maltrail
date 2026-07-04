#!/usr/bin/env python3
# coding: utf-8
"""
Hardened TLS/QUIC handshake intelligence for passive sensors (Maltrail-side).

Extracts, from CLEARTEXT handshake bytes (no crypto needed) or QUIC Initial:
  * SNI            (domain on encrypted traffic)
  * JA3 / JA3S     (TLS client/server fingerprint; stdlib MD5; matches threat feeds)
  * JA4            (modern client fingerprint; QUIC-aware)
  * cert CN / SAN  (domains from the TLS1.2 server Certificate, cleartext)

SECURITY: every byte parsed here is attacker-controlled. All parsers are fully
bounds-checked and wrapped so NO exception ever escapes to the sensor loop -- a
malformed/hostile packet yields None/{} , never a crash.

stdlib only; Py2/3.  QUIC decrypt uses quic_sni (pure-Python AES fallback + optional
cryptography accel).
"""
import hashlib
import struct
import sys

try:
    from core import quic_sni                                # in-package (Maltrail)
except Exception:
    try:
        import quic_sni                                      # flat layout (standalone/tests)
    except Exception:                                        # pragma: no cover
        quic_sni = None

PY2 = sys.version_info[0] == 2
if PY2:
    def _ints(x):
        return bytearray(x)
else:
    def _ints(x):
        return x


import re as _re
# SNI = ASCII A-label host (RFC 6066): dot-separated labels of letters/digits/'-'/'_', <=253 chars.
_HOST_RE = _re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,62})\.)+[a-z0-9_](?:[a-z0-9_-]{0,62})$")


def _is_hostname(s):
    return bool(s) and bool(_HOST_RE.match(s))


class _Trunc(Exception):
    pass


class _Reader(object):
    """Bounds-checked sequential reader; raises _Trunc instead of IndexError."""
    __slots__ = ("b", "n", "p")

    def __init__(self, data):
        self.b = _ints(data)
        self.n = len(data)
        self.p = 0

    def u8(self):
        if self.p + 1 > self.n:
            raise _Trunc()
        v = self.b[self.p]
        self.p += 1
        return v

    def u16(self):
        if self.p + 2 > self.n:
            raise _Trunc()
        v = (self.b[self.p] << 8) | self.b[self.p + 1]
        self.p += 2
        return v

    def u24(self):
        if self.p + 3 > self.n:
            raise _Trunc()
        v = (self.b[self.p] << 16) | (self.b[self.p + 1] << 8) | self.b[self.p + 2]
        self.p += 3
        return v

    def take(self, k):
        if k < 0 or self.p + k > self.n:
            raise _Trunc()
        v = self.b[self.p:self.p + k]
        self.p += k
        return v

    def left(self):
        return self.n - self.p


def _is_grease(v):
    hb = (v >> 8) & 0xFF
    lb = v & 0xFF
    return hb == lb and (lb & 0x0F) == 0x0A


def _md5_12(s):
    return hashlib.md5(s.encode("ascii")).hexdigest()


def _sha256_12(s):
    return hashlib.sha256(s.encode("ascii")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# TLS ClientHello -> SNI + JA3 + JA4
# ---------------------------------------------------------------------------
def parse_client_hello(data, transport="t"):
    """data = TLS record (0x16...) OR raw handshake. transport 't'(TCP) or 'q'(QUIC).
    Returns dict or {} on any malformation (never raises)."""
    try:
        return _parse_client_hello(data, transport)
    except _Trunc:
        return {}
    except Exception:
        return {}


def _parse_client_hello(data, transport):
    r = _Reader(data)
    b = r.b
    # optional TLS record header
    if r.n >= 1 and b[0] == 0x16:
        r.take(5)
    htype = r.u8()
    if htype != 0x01:                                        # ClientHello
        return {}
    hlen = r.u24()
    end = r.p + hlen
    if end > r.n:
        end = r.n                                            # tolerate truncation; parse what we have
    legacy_ver = r.u16()
    r.take(32)                                               # random
    sid_len = r.u8(); r.take(sid_len)
    cs_len = r.u16()
    ciphers = []
    cend = r.p + cs_len
    while r.p + 2 <= cend:
        c = r.u16()
        if not _is_grease(c):
            ciphers.append(c)
    r.p = cend
    comp_len = r.u8(); r.take(comp_len)

    sni = None
    alpn0 = None
    ext_types = []
    curves = []
    ecpf = []
    sig_algs = []
    sup_vers = []
    if r.left() >= 2:
        ext_total = r.u16()
        eend = min(r.p + ext_total, r.n)
        while r.p + 4 <= eend:
            etype = r.u16()
            elen = r.u16()
            if r.p + elen > r.n:
                break
            body = bytes(bytearray(r.take(elen)))
            if not _is_grease(etype):
                ext_types.append(etype)
            if etype == 0x0000:                              # server_name
                sni = _parse_sni(body)
            elif etype == 0x000A:                            # supported_groups
                curves = _u16_list(body, skip_len2=True, drop_grease=True)
            elif etype == 0x000B:                            # ec_point_formats
                ecpf = _u8_list(body, skip_len1=True)
            elif etype == 0x000D:                            # signature_algorithms
                sig_algs = _u16_list(body, skip_len2=True, drop_grease=True)
            elif etype == 0x0010:                            # ALPN
                alpn0 = _parse_alpn_first(body)
            elif etype == 0x002B:                            # supported_versions
                sup_vers = _u8len_u16_list(body, drop_grease=True)

    out = {"sni": sni, "ciphers": ciphers, "extensions": ext_types}

    # JA3: version,ciphers,extensions,curves,ecpf
    ja3_str = "%d,%s,%s,%s,%s" % (
        legacy_ver,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in ext_types),
        "-".join(str(c) for c in curves),
        "-".join(str(c) for c in ecpf),
    )
    out["ja3_string"] = ja3_str
    out["ja3"] = _md5_12(ja3_str)

    # JA4 (client): ja4_a _ ja4_b _ ja4_c
    ver = max(sup_vers) if sup_vers else legacy_ver
    ver2 = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}.get(ver, "00")
    sni_flag = "d" if sni else "i"
    nc = min(99, len(ciphers))
    ne = min(99, len(ext_types))
    if alpn0:
        a = _ints(alpn0)                                     # ints on py2 and py3
        alpn2 = (chr(a[0]) if len(a) else "0") + (chr(a[-1]) if len(a) else "0")
    else:
        alpn2 = "00"
    ja4_a = "%s%s%s%02d%02d%s" % (transport, ver2, sni_flag, nc, ne, alpn2)
    ja4_b = _sha256_12(",".join("%04x" % c for c in sorted(ciphers)))
    # ja4_c: sorted extensions (excluding SNI 0x0000 and ALPN 0x0010) "_" sig algs in order
    exts_for_c = sorted(e for e in ext_types if e not in (0x0000, 0x0010))
    c_str = ",".join("%04x" % e for e in exts_for_c) + "_" + ",".join("%04x" % s for s in sig_algs)
    ja4_c = _sha256_12(c_str)
    out["ja4"] = "%s_%s_%s" % (ja4_a, ja4_b, ja4_c)
    return out


def _parse_sni(body):
    r = _Reader(body)
    if r.left() < 2:
        return None
    r.u16()                                                  # server_name_list length
    while r.left() >= 3:
        ntype = r.u8()
        nlen = r.u16()
        name = r.take(nlen)
        if ntype == 0x00:
            try:
                host = bytes(bytearray(name)).decode("ascii").lower()
            except Exception:
                return None
            # SNI is an ASCII A-label host (RFC 6066); reject junk from a malformed/partial CH
            return host if _is_hostname(host) else None
    return None


def _parse_alpn_first(body):
    r = _Reader(body)
    if r.left() < 2:
        return None
    r.u16()                                                  # alpn list length
    if r.left() < 1:
        return None
    plen = r.u8()
    return bytes(bytearray(r.take(plen)))


def _u16_list(body, skip_len2=False, drop_grease=False):
    r = _Reader(body)
    if skip_len2 and r.left() >= 2:
        r.u16()
    out = []
    while r.left() >= 2:
        v = r.u16()
        if drop_grease and _is_grease(v):
            continue
        out.append(v)
    return out


def _u8len_u16_list(body, drop_grease=False):
    r = _Reader(body)
    if r.left() >= 1:
        r.u8()                                               # 1-byte list length
    out = []
    while r.left() >= 2:
        v = r.u16()
        if drop_grease and _is_grease(v):
            continue
        out.append(v)
    return out


def _u8_list(body, skip_len1=False):
    r = _Reader(body)
    if skip_len1 and r.left() >= 1:
        r.u8()
    out = []
    while r.left() >= 1:
        out.append(r.u8())
    return out


# ---------------------------------------------------------------------------
# TLS ServerHello -> JA3S ; Certificate -> CN/SAN domains
# ---------------------------------------------------------------------------
def parse_server_hello(data):
    try:
        return _parse_server_hello(data)
    except _Trunc:
        return {}
    except Exception:
        return {}


def _parse_server_hello(data):
    r = _Reader(data)
    b = r.b
    if r.n >= 1 and b[0] == 0x16:
        r.take(5)
    if r.u8() != 0x02:                                       # ServerHello
        return {}
    r.u24()
    ver = r.u16()
    r.take(32)
    sid_len = r.u8(); r.take(sid_len)
    cipher = r.u16()
    r.u8()                                                   # compression method
    ext_types = []
    if r.left() >= 2:
        ext_total = r.u16()
        eend = min(r.p + ext_total, r.n)
        while r.p + 4 <= eend:
            et = r.u16(); el = r.u16(); r.take(el)
            if not _is_grease(et):
                ext_types.append(et)
    ja3s = "%d,%d,%s" % (ver, cipher, "-".join(str(e) for e in ext_types))
    return {"ja3s_string": ja3s, "ja3s": _md5_12(ja3s)}


# DER OID byte signatures
_OID_CN = b"\x06\x03\x55\x04\x03"                            # 2.5.4.3 commonName
_OID_SAN = b"\x06\x03\x55\x1d\x11"                           # 2.5.29.17 subjectAltName


def extract_cert_names(der):
    """Best-effort: pull commonName + dNSName SANs out of a DER X.509 cert without a
    full ASN.1 parser. Robust to garbage (returns []). Domains lower-cased & deduped."""
    try:
        return _extract_cert_names(der)
    except Exception:
        return []


def _extract_cert_names(der):
    data = bytearray(der)                                    # indexing yields ints on py2+py3
    names = []

    # commonName: OID then a string (PrintableString 0x13 / UTF8String 0x0c / IA5 0x16)
    i = data.find(_OID_CN)
    while i != -1:
        j = i + len(_OID_CN)
        if j + 2 <= len(data) and data[j] in (0x13, 0x0c, 0x16, 0x14):
            ln = data[j + 1]
            val = data[j + 2:j + 2 + ln]
            _add_name(names, val)
        i = data.find(_OID_CN, i + 1)

    # subjectAltName: find OID, then the GeneralNames; dNSName entries are context tag 0x82
    s = data.find(_OID_SAN)
    if s != -1:
        # scan a reasonable window after the OID for 0x82-tagged names
        window = data[s:s + 2048]
        k = 0
        wb = bytearray(window)
        while k + 2 < len(wb):
            if wb[k] == 0x82:                                # [2] dNSName, short form length
                ln = wb[k + 1]
                if ln < 0x80 and k + 2 + ln <= len(wb):
                    _add_name(names, bytes(wb[k + 2:k + 2 + ln]))
                    k += 2 + ln
                    continue
            k += 1
    # dedupe preserving order
    seen = set()
    out = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _ints_idx(data, i):
    # helper so PY2/PY3 indexing returns an int
    return i if not PY2 else i


def _add_name(names, raw):
    try:
        v = bytes(bytearray(raw)).decode("ascii").strip().lower()
    except Exception:
        return
    # plausible hostname / wildcard only
    if v and all(33 <= ord(c) <= 126 for c in v) and ("." in v):
        names.append(v)


# ---------------------------------------------------------------------------
# QUIC Initial (delegates to quic_sni; never raises)
# ---------------------------------------------------------------------------
def quic_initial_sni(udp_payload):
    if quic_sni is None:
        return None
    try:
        return quic_sni.extract_sni_from_quic_initial(udp_payload)
    except Exception:
        return None
