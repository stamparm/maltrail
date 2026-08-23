#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Generate `sensor/tests/vectors/client_hellos.tsv`: a differential corpus of TLS ClientHello
byte strings with the SNI/JA3/JA4 that `core/tls_intel.parse_client_hello()` produces for
each. Both implementations are then held to this one file - the Rust port replays it in
`sensor/tests/vectors.rs`, the Python side re-parses it in `tests/test_tls_intel.py`.

The handcrafted half pins every branch the two embedded KATs miss: ALPN bodies cut short in
the fixed header ("no ALPN offered", parsing continues) versus protocol-name bytes overrunning
the extension body (`_Trunc` -> NO fingerprint at all - the one helper whose failure is fatal),
non-ASCII ALPN bytes landing verbatim in ja4_a via chr(), GREASE filtering sites, the 99 caps,
version mapping, and each fixed-field overrun that fails the whole parse. The random half
(seed-fixed) mutates and truncates a realistic hello so agreement is tested off the happy path.

Regenerate with:  python3 sensor/tools/gen_ja_vectors.py
"""

import random
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from core.tls_intel import parse_client_hello  # noqa: E402

SEED = 20260822


def ext(t, body):
    return struct.pack("!HH", t, len(body)) + body


def hello(exts=b"", ciphers=(0x1301, 0x1302), legacy_ver=0x0303, sid=b"",
          comp=b"\x00", ext_total=None, record=True, htype=0x01, sni_ext=None):
    """One ClientHello. `sni_ext` is spliced before `exts` when given."""
    if sni_ext is not None:
        exts = sni_ext + exts
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    body = (struct.pack("!H", legacy_ver) + b"\x11" * 32 + struct.pack("!B", len(sid)) + sid
            + struct.pack("!H", len(cs)) + cs + struct.pack("!B", len(comp)) + comp
            + struct.pack("!H", len(exts) if ext_total is None else ext_total) + exts)
    hs = bytes(bytearray([htype])) + struct.pack("!I", len(body))[1:] + body
    return (b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs) if record else hs


def sni_ext(host):
    s = host.encode("utf-8")
    srv = b"\x00" + struct.pack("!H", len(s)) + s
    return ext(0x0000, struct.pack("!H", len(srv)) + srv)


def alpn_ext(*protos):
    lst = b"".join(struct.pack("!B", len(p)) + p for p in protos)
    return ext(0x0010, struct.pack("!H", len(lst)) + lst)


GREASE_CIPHERS = (0x0A0A, 0x1A1A)
BASE_CURVES = (0x001D, 0x0017, 0x0A0A)          # x25519, secp256r1, GREASE
BASE_SIGALGS = (0x0403, 0x0804, 0x0501)
SUP_VER_TLS13 = ext(0x002B, struct.pack("!B", 4) + struct.pack("!H", 0xA0A) + struct.pack("!H", 0x0304))


def handcrafted():
    # (name, hello-bytes) pairs. Comments mark the reference behaviour being pinned.
    yield "modern_grease_h2", hello(
        exts=SUP_VER_TLS13 + alpn_ext(b"h2", b"http/1.1")
             + ext(0x000A, struct.pack("!H", 6) + b"".join(struct.pack("!H", c) for c in BASE_CURVES))
             + ext(0x000B, struct.pack("!B", 3) + b"\x00\x01\x02")
             + ext(0x000D, struct.pack("!H", 6) + b"".join(struct.pack("!H", s) for s in BASE_SIGALGS))
             + ext(0x1A1A, b""),
        ciphers=GREASE_CIPHERS + (0x1301, 0x1302, 0xC02F),
        sni_ext=sni_ext("evil.example.com"),
    )
    yield "bare_handshake_no_record", hello(record=False, sni_ext=sni_ext("bare.tld"))
    yield "no_sni", hello(alpn_ext(b"h2"))
    yield "no_alpn_extension", hello(SUP_VER_TLS13, sni_ext=sni_ext("quiet.example"))
    yield "empty_alpn_list_header_cut_short", hello(ext(0x0010, b"\x00\x00"))            # absent -> "00", parse continues
    yield "alpn_one_byte_body", hello(ext(0x0010, b"\x00"))                              # absent -> "00"
    yield "alpn_listlen_only", hello(ext(0x0010, struct.pack("!H", 0)))                  # == empty list body
    yield "alpn_plen_overruns_body", hello(ext(0x0010, b"\x00\x20\x02h"))                # _Trunc -> NO fingerprint
    yield "alpn_plen_zero", hello(alpn_ext(b""))                                         # empty name -> falsy -> "00"
    yield "alpn_nonascii_bytes_verbatim", hello(alpn_ext(b"\xffmid\x80"))                 # chr() into ja4_a unchanged
    yield "alpn_multi_first_wins", hello(alpn_ext(b"h2", b"http/1.1", b"h3"))
    yield "alpn_long_protocol", hello(alpn_ext(b"x" * 200 + b"z"))
    # elen declares 200 but only 4 body bytes exist -> loop breaks BEFORE appending the type,
    # and the curves extension behind it is never reached.
    dead_overrun = struct.pack("!HH", 0xDEAD, 200) + b"\xaa" * 4
    yield "ext_len_overrun_breaks_loop", hello(
        exts=dead_overrun + ext(0x000A, struct.pack("!H", 2) + struct.pack("!H", 0x001D)),
        sni_ext=sni_ext("cut.example"),
    )
    yield "grease_only_ciphers", hello(SUP_VER_TLS13, ciphers=GREASE_CIPHERS)             # nc=00, empty ja3 cipher field
    yield "zero_ciphers", hello(SUP_VER_TLS13, ciphers=())
    yield "many_ciphers_cap99", hello(SUP_VER_TLS13, ciphers=tuple(range(0x0100, 0x0100 + 120)))
    many_exts = b"".join(ext(t, b"") for t in range(0x0100, 0x0100 + 120))
    yield "many_extensions_cap99", hello(many_exts)
    yield "sslv3_legacy", hello(legacy_ver=0x0300, sni_ext=sni_ext("old.example"))
    yield "tls11_legacy", hello(legacy_ver=0x0302)
    yield "unknown_legacy_ver_maps_00", hello(SUP_VER_TLS13, legacy_ver=0xFE0D)
    yield "supported_versions_max_picks_13", hello(SUP_VER_TLS13)                          # GREASE 0x0a0a dropped, 0x0304 wins
    yield "curves_without_ecpf", hello(ext(0x000A, struct.pack("!H", 2) + struct.pack("!H", 0x001D)))
    yield "ecpf_without_curves", hello(ext(0x000B, struct.pack("!B", 1) + b"\x00"))
    yield "sigalgs_order_preserved", hello(ext(0x000D, struct.pack("!H", 6)
                                          + b"".join(struct.pack("!H", s) for s in (0x0804, 0x0201, 0x0403))))
    yield "duplicate_extension_both_counted", hello(ext(0x000A, struct.pack("!H", 2) + struct.pack("!H", 0x0017))
                                              + ext(0x000A, struct.pack("!H", 2) + struct.pack("!H", 0x001D)))
    yield "sni_two_names_first_taken", hello(sni_ext=_two_names())
    yield "sni_junk_not_a_hostname", hello(sni_ext=sni_ext("not a valid host!"))           # sni None -> "i" flag
    yield "sni_empty_name", hello(sni_ext=sni_ext(""))
    yield "sni_uppercased_lowered", hello(sni_ext=sni_ext("EVIL.Example.COM"))
    yield "sni_nonascii_rejected", hello(sni_ext=sni_ext("bücher.example"))
    yield "session_id_overrun_fatal", _sid_overrun()
    yield "cipher_len_overrun_fatal", _cs_overrun()
    yield "unknown_compression_method_ok", hello(comp=b"\xff")
    yield "compression_len_overrun_fatal", _comp_overrun()
    yield "ext_total_past_buffer_capped", hello(SUP_VER_TLS13, ext_total=4000)
    yield "server_hello_fed_to_client_parser", hello(b"", htype=0x02)
    yield "record_header_only", b"\x16\x03\x01\x00\x05"
    yield "empty_input", b""
    yield "single_zero_byte", b"\x00"


def _two_names():
    a, b = b"first.example", b"second.example"
    e1 = b"\x00" + struct.pack("!H", len(a)) + a
    e2 = b"\x00" + struct.pack("!H", len(b)) + b
    return ext(0x0000, struct.pack("!H", len(e1) + len(e2)) + e1 + e2)


def _sid_overrun():
    body = struct.pack("!H", 0x0303) + b"\x11" * 32 + struct.pack("!B", 200) + b"\x01\x02\x03"
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _cs_overrun():
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"
            + struct.pack("!H", 500) + b"\x13\x01")
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _comp_overrun():
    # comp_len declares 255; only 5 bytes follow before the buffer ends
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01"
            + b"\xff" + b"\xcc" * 5)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def baseline():
    """The `modern_grease_h2` bytes - the seed for the mutation half."""
    return dict(handcrafted())["modern_grease_h2"]


def mutations():
    rng = random.Random(SEED)
    base = baseline()
    out = []
    for i in range(120):
        data = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        out.append(("mutated_%03d" % i, bytes(data)))
    for i in range(40):                                   # truncations land inside every reader
        out.append(("truncated_%03d" % i, base[:rng.randint(0, len(base))]))
    for i in range(80):                                   # hostile noise, TLS-ish prefixes included
        n = rng.randint(0, 400)
        blob = bytearray(rng.randrange(256) for _ in range(n))
        if rng.random() < 0.5 and n >= 5:
            blob[0] = 0x16
            blob[1:3] = b"\x03\x01"
        elif n >= 1:
            blob[0] = 0x01
        out.append(("noise_%03d" % i, bytes(blob)))
    return out


def main():
    rows = []
    seen = set()
    for name, data in list(handcrafted()) + mutations():
        assert name not in seen, name
        seen.add(name)
        r = parse_client_hello(data)
        rows.append((name, data, r.get("sni") or "", r.get("ja3") or "", r.get("ja4") or ""))

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "vectors", "client_hellos.tsv")
    with open(out, "w") as f:
        f.write("# Generated by sensor/tools/gen_ja_vectors.py (seed %d) - do not edit by hand.\n" % SEED)
        f.write("# Columns: name <TAB> hex <TAB> sni <TAB> ja3 <TAB> ja4; empty = None.\n")
        f.write("# Golden values come from core.tls_intel.parse_client_hello itself.\n")
        for name, data, sni, ja3, ja4 in rows:
            f.write("%s\t%s\t%s\t%s\t%s\n" % (name, data.hex(), sni, ja3, ja4))
    hits = sum(1 for r in rows if r[3])
    print("%d vectors (%d parsed, %d rejected) -> %s" % (len(rows), hits, len(rows) - hits, os.path.normpath(out)))


if __name__ == "__main__":
    main()
