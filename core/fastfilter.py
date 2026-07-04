# coding: utf-8
"""
Glue for the pcapy-ng in-C prefilter (loop_filtered / loop_to_buffer).

Keeps sensor.py's change small: this module builds the IOC IP-set from Maltrail trails,
maps a pcap datalink to the IPv4 header offset, and exposes the class constants / default
admit mask. Used only when config.USE_FAST_PREFILTER is on and the installed pcapy exposes
loop_filtered (pcapy-ng-fast); otherwise the classic next() path is used unchanged.

stdlib only; Py2 + Py3.
"""
import re
import socket

# Maltrail uses pcapy-ng's built-in security classifier (loop_filtered(..., profile=PROFILE)).
PROFILE = 1   # 0 = generic; 1 = security profile

# Two separate things (must match pcapobj.cc security profile):
#  * class INDICES (0..5): what the admit-mask bits address, and the order of the per-class counts.
#  * public class IDS (100..105): the value handed to the callback's `cls` argument.
IDX_DNS, IDX_HTTP, IDX_NOISE, IDX_IPSET, IDX_HEAD, IDX_SYN = range(6)
CLS_DNS, CLS_HTTP, CLS_NOISE, CLS_IPSET, CLS_HEAD, CLS_SYN = (100 + i for i in range(6))

# default: admit everything that can produce a detection; drop only provably-inert noise.
# bits over INDICES: DNS|HTTP|IPSET|HEAD|SYN = 1|2|8|16|32 = 59 (noise index 2 NOT set)
ADMIT_DEFAULT = (1 << IDX_DNS) | (1 << IDX_HTTP) | (1 << IDX_IPSET) | (1 << IDX_HEAD) | (1 << IDX_SYN)

# Severity-aware admission tiers for overload (bits over INDICES). DNS and IPSET (confirmed
# known-bad IP) are NEVER shed -> never go blind on what matters. As load rises we drop, in
# order: SYN, then handshake HEAD, then HTTP. noise is always dropped.
ADMIT_NORMAL = ADMIT_DEFAULT                                                       # 0
ADMIT_BUSY = (1 << IDX_DNS) | (1 << IDX_HTTP) | (1 << IDX_IPSET) | (1 << IDX_HEAD)  # 1: drop SYN
ADMIT_STRAINED = (1 << IDX_DNS) | (1 << IDX_HTTP) | (1 << IDX_IPSET)               # 2: drop HEAD
ADMIT_OVERLOAD = (1 << IDX_DNS) | (1 << IDX_IPSET)                                 # 3: DNS + known-bad
_ADMIT_TIERS = (ADMIT_NORMAL, ADMIT_BUSY, ADMIT_STRAINED, ADMIT_OVERLOAD)


def admit_mask_for_load(level):
    """Pick the admit mask for a load level 0..3 (clamped). DNS and IOC are admitted at EVERY
    level (never-go-blind guarantee); higher levels progressively shed SYN, then HEAD, then DPI."""
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 0
    if level < 0:
        level = 0
    elif level >= len(_ADMIT_TIERS):
        level = len(_ADMIT_TIERS) - 1
    return _ADMIT_TIERS[level]

# a trail key that is a bare IPv4 or "IPv4:port" (addr_port form). IPv6 uses brackets -> excluded.
_IPV4_KEY = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?$")


def build_ioc_set(trail_keys):
    """From an iterable of trail keys, return the packed 4-byte network-order IPv4 set that
    loop_filtered expects (deduped). Keeps known-bad-IP packets admitted even when they'd be
    shed as bulk/QUIC noise. Domains, paths, IPv6 and IPv6:port keys are skipped."""
    seen = set()
    out = []
    for key in trail_keys:
        if not key:
            continue
        m = _IPV4_KEY.match(key)
        if not m:
            continue
        octets = m.group(1, 2, 3, 4)
        if any(int(o) > 255 for o in octets):
            continue
        ip = "%s.%s.%s.%s" % octets
        try:
            packed = socket.inet_aton(ip)
        except (socket.error, OSError):
            continue
        if packed not in seen:
            seen.add(packed)
            out.append(packed)
    return b"".join(out)


def ioc_set_from_trails(trails):
    """Convenience: build the IOC set from Maltrail's `trails` mapping (keys are indicators)."""
    try:
        keys = trails.keys()
    except AttributeError:
        keys = trails
    return build_ioc_set(keys)


def next_admit_level(level, recv_delta, drop_delta, max_level=3, hi=0.02, lo=0.002):
    """Adaptive controller: given the capture recv/drop counts seen in the last window, return
    the next severity level. Raises the level (shed more low-priority) when the libpcap ring is
    dropping (>hi), lowers it when recovered (<=lo); hysteresis between. DNS + IOC are admitted
    at EVERY level, so adapting never blinds DNS / known-bad-IP detection. max_level caps how
    aggressive shedding may get (operator bound). Pure function (no I/O) -> trivially testable."""
    try:
        max_level = max(0, min(3, int(max_level)))
        level = max(0, min(max_level, int(level)))
    except (TypeError, ValueError):
        return 0
    if recv_delta is None or recv_delta <= 0:
        return level
    ratio = float(drop_delta) / float(recv_delta)
    if ratio > hi and level < max_level:
        return level + 1
    if ratio <= lo and level > 0:
        return level - 1
    return level


_COMMON_IP_PROTO = frozenset((1, 2, 6, 17, 47, 50, 51, 58, 89, 103, 132))   # ICMP,IGMP,TCP,UDP,GRE,ESP,AH,ICMPv6,OSPF,PIM,SCTP


def _ip_header_score(b, off, n):
    """Rate the bytes at `off` as an IPv4/IPv6 header: 2 = length-consistent (strong), 1 = plausible
    (version/proto only), 0 = no. The length check (the IP header's own length field matching the
    captured remainder) is what rejects the constant false positives from L2 header bytes."""
    v = b[off] >> 4
    if v == 4 and off + 20 <= n:
        ihl = (b[off] & 0x0f) * 4
        total = (b[off + 2] << 8) | b[off + 3]
        proto = b[off + 9]
        if not (20 <= ihl <= 60 and total >= ihl and proto in _COMMON_IP_PROTO):
            return 0
        rem = n - off
        if rem >= total and rem - total <= 64:          # captured length matches IP total len (+padding)
            return 2
        return 1 if total <= 65535 else 0               # else only weakly plausible (e.g. snaplen-truncated)
    if v == 6 and off + 40 <= n:
        nexthdr = b[off + 6]
        if nexthdr not in _COMMON_IP_PROTO and nexthdr not in (0, 43, 44, 60):
            return 0
        payload = (b[off + 4] << 8) | b[off + 5]
        rem = n - off - 40
        if payload > 0 and rem >= payload and rem - payload <= 64:   # captured len matches payload len
            return 2
        return 1
    return 0


def guess_ip_offset(packet, max_off=64):
    """Heuristic IP-header offset for a datalink that is NOT in DLT_OFFSETS.

    Scans the first bytes for an IPv4/IPv6 header, validated by version + IHL + protocol AND by the
    header's own length field matching the captured remainder (so L2 header bytes that merely look
    like a version nibble are rejected). Prefers a length-consistent (strong) match; falls back to
    a merely-plausible one only if nothing strong is found. Returns the offset or None. Pair it
    with the small per-datalink learner in sensor.py (confirm across a couple of packets).
    """
    b = bytearray(packet)
    n = len(b)
    hi = min(max_off, n - 1)
    weak = None
    for off in range(0, hi + 1):
        s = _ip_header_score(b, off, n)
        if s == 2:
            return off
        if s == 1 and weak is None:
            weak = off
    return weak


def has_fast_prefilter(cap):
    """True if the installed pcapy exposes the in-C prefilter (pcapy-ng-fast)."""
    return hasattr(cap, "loop_filtered")


def _ip_at(packet, l2_base):
    """VLAN-aware: return offset of the IPv4 header (skips up to 2 802.1Q/802.1ad tags), or -1."""
    p = bytearray(packet)
    off = l2_base
    for _ in range(3):
        if off + 20 > len(p):
            return -1
        if (p[off] >> 4) == 4:
            return off
        if off >= 2 and ((p[off - 2] == 0x81 and p[off - 1] == 0x00) or (p[off - 2] == 0x88 and p[off - 1] == 0xa8)):
            off += 4
        else:
            return -1
    return -1


def head_sni(packet, l2_base):
    """For a cls==HEAD packet (TLS ClientHello on TCP, or QUIC Initial on UDP), extract the
    SNI plus the 5-tuple so the caller can feed Maltrail's _check_domain. Returns
    (sni, src_ip, src_port, dst_ip, dst_port, ip_proto) or None. Never raises (sniffer-safe)."""
    try:
        import socket as _socket
        from core import tls_intel
        try:
            from core import quic_sni
        except Exception:
            quic_sni = None

        p = bytearray(packet)
        l3 = _ip_at(p, l2_base)
        if l3 < 0:
            return None
        ihl = (p[l3] & 0x0f) * 4
        if ihl < 20 or l3 + ihl + 4 > len(p):
            return None
        proto = p[l3 + 9]
        src_ip = _socket.inet_ntoa(bytes(p[l3 + 12:l3 + 16]))
        dst_ip = _socket.inet_ntoa(bytes(p[l3 + 16:l3 + 20]))
        l4 = l3 + ihl
        sport = (p[l4] << 8) | p[l4 + 1]
        dport = (p[l4 + 2] << 8) | p[l4 + 3]

        sni = None
        if proto == 6:                                   # TCP -> TLS ClientHello
            tcphl = ((p[l4 + 12] >> 4) & 0x0f) * 4
            payload = bytes(p[l4 + tcphl:])
            info = tls_intel.parse_client_hello(payload, "t")
            sni = info.get("sni") if info else None
        elif proto == 17 and quic_sni is not None:       # UDP -> QUIC Initial
            payload = bytes(p[l4 + 8:])
            sni = quic_sni.extract_sni_from_quic_initial(payload)

        if not sni:
            return None
        return (sni, src_ip, sport, dst_ip, dport, proto)
    except Exception:
        return None
