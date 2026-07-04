#!/usr/bin/env python3
# coding: utf-8
"""
QUIC Initial SNI extractor for passive sensors (Maltrail-side; pcapy-ng delivers the
flow-head, this parses it).  Works on ANY box:

  * FAST path  : uses the `cryptography` package's AES if it is importable.
  * FALLBACK   : a tiny pure-Python AES-128 (stdlib only) when it is not.

Both produce identical plaintext.  We are a passive observer, so we DECRYPT but do NOT
authenticate (no GCM tag / GHASH needed) -> AES-CTR is sufficient, which keeps the
stdlib fallback small and fast enough for the handful of QUIC Initial packets per flow
that a flow-cutoff actually delivers.

Public, non-secret QUIC Initial keys are derived from the client's Destination
Connection ID (RFC 9001).  HKDF runs on stdlib hashlib/hmac.

Compatible with Python 2.7 and 3.x (Maltrail constraint: single source, stdlib only).
"""
import hashlib
import hmac
import struct
import sys

import re as _re
# An SNI is an A-label host name (ASCII) per RFC 6066: letters/digits/'-'/'.', dot-separated,
# each label 1..63 chars. Used to reject junk from a truncated/edge-case ClientHello decode.
_HOST_RE = _re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,62})\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,62})$")


def _is_hostname(s):
    return bool(s) and bool(_HOST_RE.match(s))


PY2 = sys.version_info[0] == 2
if PY2:
    def _b(x):            # iterate bytes as ints
        return bytearray(x)
else:
    def _b(x):
        return x

# ---------------------------------------------------------------------------
# AES-128 block cipher (pure Python fallback) -- encrypt_block only (CTR + ECB use it)
# ---------------------------------------------------------------------------
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

# Standard AES S-box (FIPS-197). Hardcoded to avoid any generation bug.
_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


def _build_sbox():
    return


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


class _AES128(object):
    """Minimal AES-128: key expansion + single-block encrypt."""

    def __init__(self, key):
        _build_sbox()
        assert len(key) == 16
        self._rk = self._expand(bytearray(key))

    def _expand(self, key):
        sbox = _SBOX
        rk = [list(key[i:i + 4]) for i in range(0, 16, 4)]  # 4 words
        for i in range(4, 44):
            temp = list(rk[i - 1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]                  # RotWord
                temp = [sbox[b] for b in temp]              # SubWord
                temp[0] ^= _RCON[i // 4 - 1]
            rk.append([rk[i - 4][j] ^ temp[j] for j in range(4)])
        # flatten into 11 round keys of 16 bytes
        return [bytearray(b for w in rk[r * 4:r * 4 + 4] for b in w) for r in range(11)]

    def encrypt_block(self, block):
        sbox = _SBOX
        s = bytearray(block)
        rk = self._rk
        # AddRoundKey 0
        for i in range(16):
            s[i] ^= rk[0][i]
        for rnd in range(1, 10):
            # SubBytes
            for i in range(16):
                s[i] = sbox[s[i]]
            # ShiftRows
            s = bytearray((
                s[0], s[5], s[10], s[15],
                s[4], s[9], s[14], s[3],
                s[8], s[13], s[2], s[7],
                s[12], s[1], s[6], s[11],
            ))
            # MixColumns
            for c in range(4):
                o = c * 4
                a0, a1, a2, a3 = s[o], s[o + 1], s[o + 2], s[o + 3]
                s[o]     = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
                s[o + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
                s[o + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
                s[o + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
            for i in range(16):
                s[i] ^= rk[rnd][i]
        # final round (no MixColumns)
        for i in range(16):
            s[i] = sbox[s[i]]
        s = bytearray((
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ))
        for i in range(16):
            s[i] ^= rk[10][i]
        return bytes(s)


# ---------------------------------------------------------------------------
# AES backend selection: cryptography (fast) if present, else pure-Python.
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore

    HAVE_CRYPTOGRAPHY = True

    def aes_ecb_block(key, block):
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    def aes_ctr_decrypt(key, counter0, data):
        dec = Cipher(algorithms.AES(key), modes.CTR(counter0)).decryptor()
        return dec.update(data) + dec.finalize()

except Exception:                                            # pragma: no cover - exercised on lean boxes
    HAVE_CRYPTOGRAPHY = False

    def aes_ecb_block(key, block):
        return _AES128(key).encrypt_block(block)

    def aes_ctr_decrypt(key, counter0, data):
        aes = _AES128(key)
        out = bytearray(len(data))
        ctr = bytearray(counter0)
        d = _b(data)
        for off in range(0, len(data), 16):
            ks = aes.encrypt_block(bytes(ctr))
            ks = _b(ks)
            end = min(16, len(data) - off)
            for i in range(end):
                out[off + i] = d[off + i] ^ ks[i]
            # increment 128-bit counter (big-endian)
            j = 15
            while j >= 0:
                ctr[j] = (ctr[j] + 1) & 0xFF
                if ctr[j]:
                    break
                j -= 1
        return bytes(out)


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) + TLS1.3/QUIC HKDF-Expand-Label
# ---------------------------------------------------------------------------
def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + struct.pack("B", i), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack("!H", length) + struct.pack("B", len(full)) + full + b"\x00"
    return hkdf_expand(secret, info, length)


# QUIC v1 (RFC 9001) and v2 (RFC 9369) initial salts
# Hard cap on bytes decrypted per QUIC Initial: bounds per-packet CPU (DoS-safe) while
# comfortably covering a single-packet ClientHello (Initial is padded to >=1200 bytes).
MAX_INITIAL_DECRYPT = 2048

INITIAL_SALT_V1 = bytes(bytearray([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]))
INITIAL_SALT_V2 = bytes(bytearray([
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9]))


def derive_client_initial_keys(dcid, version=1):
    salt = INITIAL_SALT_V2 if version == 2 else INITIAL_SALT_V1
    if version == 2:
        klbl, ivlbl, hplbl = b"quicv2 key", b"quicv2 iv", b"quicv2 hp"
    else:
        klbl, ivlbl, hplbl = b"quic key", b"quic iv", b"quic hp"
    initial_secret = hkdf_extract(salt, dcid)
    client_secret = hkdf_expand_label(initial_secret, b"client in", 32)
    key = hkdf_expand_label(client_secret, klbl, 16)
    iv = hkdf_expand_label(client_secret, ivlbl, 12)
    hp = hkdf_expand_label(client_secret, hplbl, 16)
    return key, iv, hp


# ---------------------------------------------------------------------------
# QUIC packet parsing
# ---------------------------------------------------------------------------
def _read_varint(buf, off):
    b0 = _b(buf)[off]
    prefix = b0 >> 6
    length = 1 << prefix
    val = b0 & 0x3F
    for i in range(1, length):
        val = (val << 8) | _b(buf)[off + i]
    return val, off + length


class QuicParseError(Exception):
    pass


def extract_sni_from_quic_initial(udp_payload):
    """Given a UDP payload that is a QUIC Initial (long header), return the SNI string
    or None.  Never raises -- any malformed/hostile input yields None (passive sensor)."""
    try:
        return _extract_sni_impl(udp_payload)
    except Exception:
        return None


def _extract_sni_impl(udp_payload):
    p = _b(udp_payload)
    if len(p) < 7:
        return None
    first = p[0]
    if not (first & 0x80):
        return None                                          # not a long header
    version = struct.unpack("!I", bytes(udp_payload[1:5]))[0]
    if version == 0:
        return None                                          # version negotiation
    ver_kind = 2 if version == 0x6b3343cf else 1             # QUIC v2 (RFC 9369) else v1
    off = 5
    dcid_len = p[off]; off += 1
    dcid = bytes(udp_payload[off:off + dcid_len]); off += dcid_len
    scid_len = p[off]; off += 1
    off += scid_len
    # long header packet type must be Initial
    if ver_kind == 1:
        if (first & 0x30) != 0x00:
            return None
    else:
        if (first & 0x30) != 0x10:                            # v2 remaps Initial to 0b01
            return None
    token_len, off = _read_varint(udp_payload, off)
    off += token_len
    length, off = _read_varint(udp_payload, off)             # length of (pn + payload)
    pn_offset = off
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(p):
        raise QuicParseError("packet too short for header-protection sample")

    key, iv, hp = derive_client_initial_keys(dcid, ver_kind)

    sample = bytes(udp_payload[sample_offset:sample_offset + 16])
    mask = _b(aes_ecb_block(hp, sample))

    first_unmasked = first ^ (mask[0] & 0x0F)
    pn_len = (first_unmasked & 0x03) + 1
    pn_bytes = bytearray(udp_payload[pn_offset:pn_offset + pn_len])
    for i in range(pn_len):
        pn_bytes[i] ^= mask[1 + i]
    packet_number = 0
    for bb in pn_bytes:
        packet_number = (packet_number << 8) | bb

    payload_offset = pn_offset + pn_len
    payload_len = length - pn_len
    ciphertext = bytes(udp_payload[payload_offset:payload_offset + payload_len])
    # GCM tag is the last 16 bytes; we don't verify it (passive), just drop it
    if len(ciphertext) > 16:
        ciphertext = ciphertext[:-16]

    # nonce = iv XOR left-padded packet number; CTR start counter (GCM J0 inc) = nonce||0x00000002
    nonce = bytearray(iv)
    pn_be = struct.pack("!Q", packet_number)                 # 8 bytes
    for i in range(8):
        nonce[4 + i] ^= _b(pn_be)[i]
    counter0 = bytes(nonce) + struct.pack("!I", 2)

    # Perf + DoS-safety: the ClientHello (with SNI) sits in the first CRYPTO frame at the
    # start of the payload; the rest is PADDING. Decrypt a short prefix first and only fall
    # back to a (bounded) larger decrypt if that didn't yield an SNI. AES-CTR is seekable, so
    # a prefix decrypt is exact. We NEVER decrypt more than MAX_INITIAL_DECRYPT bytes: a single
    # QUIC Initial ClientHello fits well within that, and the cap bounds per-packet CPU so a
    # flood of hostile QUIC-ish packets cannot force unbounded pure-Python AES work.
    full = min(len(ciphertext), MAX_INITIAL_DECRYPT)
    for cap in (512, full):
        cap = min(cap, full)
        plaintext = aes_ctr_decrypt(key, counter0, ciphertext[:cap])
        crypto = _reassemble_crypto(plaintext)
        if crypto:
            sni = _client_hello_sni(crypto)
            if sni is not None:
                return sni
        if cap >= full:
            break
    return None


def _reassemble_crypto(payload):
    """Walk QUIC frames in a decrypted Initial, concatenate CRYPTO frame data by offset."""
    p = _b(payload)
    off = 0
    chunks = {}
    n = len(p)
    while off < n:
        ftype, off = _read_varint(payload, off)
        if ftype == 0x00:                                    # PADDING
            continue
        if ftype == 0x01:                                    # PING
            continue
        if ftype in (0x02, 0x03):                            # ACK
            _, off = _read_varint(payload, off)              # largest acked
            _, off = _read_varint(payload, off)              # ack delay
            rng_count, off = _read_varint(payload, off)
            _, off = _read_varint(payload, off)              # first range
            for _ in range(rng_count):
                _, off = _read_varint(payload, off)
                _, off = _read_varint(payload, off)
            if ftype == 0x03:
                for _ in range(3):
                    _, off = _read_varint(payload, off)
            continue
        if ftype == 0x06:                                    # CRYPTO
            c_off, off = _read_varint(payload, off)
            c_len, off = _read_varint(payload, off)
            chunks[c_off] = bytes(payload[off:off + c_len])
            off += c_len
            continue
        break                                                # unknown frame: stop
    if not chunks:
        return None
    out = b""
    for k in sorted(chunks):
        out += chunks[k]
    return out


def _client_hello_sni(handshake):
    """Parse a TLS ClientHello (handshake bytes) and return the first SNI host_name."""
    h = _b(handshake)
    if len(h) < 4 or h[0] != 0x01:                           # ClientHello
        return None
    pos = 4
    pos += 2 + 32                                            # legacy_version + random
    if pos >= len(h):
        return None
    sid_len = h[pos]; pos += 1 + sid_len
    if pos + 2 > len(h):
        return None
    cs_len = (h[pos] << 8) | h[pos + 1]; pos += 2 + cs_len
    if pos + 1 > len(h):
        return None
    comp_len = h[pos]; pos += 1 + comp_len
    if pos + 2 > len(h):
        return None
    ext_total = (h[pos] << 8) | h[pos + 1]; pos += 2
    end = pos + ext_total
    while pos + 4 <= end and pos + 4 <= len(h):
        etype = (h[pos] << 8) | h[pos + 1]
        elen = (h[pos + 2] << 8) | h[pos + 3]
        pos += 4
        if etype == 0x0000:                                  # server_name
            sp = pos
            sp += 2                                          # server_name_list length
            if sp + 3 > len(h):
                return None
            ntype = h[sp]; sp += 1
            nlen = (h[sp] << 8) | h[sp + 1]; sp += 2
            if ntype == 0x00 and sp + nlen <= len(h):        # bounds: don't read past a truncated CH
                try:
                    name = bytes(handshake[sp:sp + nlen]).decode("ascii")
                except Exception:
                    return None
                # Only return a real host name. A ClientHello fragmented across packets (we only
                # see one) or a decrypt edge case yields junk here -> return None rather than a
                # bogus "SNI". SNI is always an A-label (ASCII) host per RFC 6066.
                return name if _is_hostname(name) else None
        pos += elen
    return None
