# coding: utf-8
"""Test helper: build pcap files (and raw packets) for the pcapy-ng fast-path battery.
stdlib only; Py2/3."""
import os
import struct
import socket
import tempfile

DLT_EN10MB = 1
DLT_RAW = 12          # raw IP, no link-layer header (IP starts at offset 0)
DLT_LINUX_SLL = 113   # Linux "cooked" capture (the 'any' interface): 16-byte header
PCAP_MAGIC = 0xA1B2C3D4


def eth_vlan(vid=100, inner=0x0800, tags=1):
    # Ethernet header with one or more 802.1Q VLAN tags; IP follows at offset 14 + 4*tags.
    out = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66"   # dst+src
    for _ in range(tags):
        out += b"\x81\x00" + struct.pack("!H", vid)            # TPID + TCI per tag
    out += struct.pack("!H", inner)                            # final ethertype (0x0800)
    return out


def sll(ethertype=0x0800):
    # 16-byte LINUX_SLL cooked header: pkttype(2) arphrd(2) addrlen(2) addr(8) proto(2)
    return struct.pack("!HHH", 0, 1, 6) + b"\x11\x22\x33\x44\x55\x66\x00\x00" + struct.pack("!H", ethertype)

BAD_IPS = ["45.95.202.106", "2.200.107.168"]
BAD_DOMS = ["j0mla.sytes.net", "atacoinc8897.hopto.org"]


def eth(ethertype=0x0800):
    return b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66" + struct.pack("!H", ethertype)


def ipv4(proto, src, dst, payload, ihl=5, total_len=None):
    vihl = 0x40 | (ihl & 0x0f)
    tot = total_len if total_len is not None else (ihl * 4 + len(payload))
    return struct.pack("!BBHHHBBH4s4s", vihl, 0, tot, 0x1234, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def ipv6(proto, src, dst, payload):
    # minimal IPv6 header (40 bytes), ethertype should be 0x86DD
    return (struct.pack("!IHBB", 0x60000000, len(payload), proto, 64)
            + socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst) + payload)


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, flags, payload, doff=5):
    off = (doff & 0x0f) << 4
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, off, flags, 65535, 0, 0) + payload


def dns_query(name):
    q = b""
    for lbl in name.split("."):
        q += struct.pack("B", len(lbl)) + lbl.encode()
    q += b"\x00\x00\x01\x00\x01"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q


def tls_client_hello(sni, with_record=True):
    s = sni.encode()
    srv = b"\x00" + struct.pack("!H", len(s)) + s
    lst = struct.pack("!H", len(srv)) + srv
    ext = b"\x00\x00" + struct.pack("!H", len(lst)) + lst
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    if with_record:
        return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    return hs


# ---- convenience full-frame builders (Ethernet/IPv4) ----
def dns_packet(name, client="10.0.0.5", server="8.8.8.8", sport=12345):
    return eth() + ipv4(17, client, server, udp(sport, 53, dns_query(name)))


def tls_packet(sni, client="10.0.0.5", server="93.184.216.34", sport=40000, psh=True):
    flags = 0x18 if psh else 0x10
    return eth() + ipv4(6, client, server, tcp(sport, 443, flags, tls_client_hello(sni)))


def http_packet(host="example.com", client="10.0.0.5", server="93.184.216.34", sport=40001):
    req = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
    return eth() + ipv4(6, client, server, tcp(sport, 80, 0x18, req))


def quicish_packet(client="10.0.0.5", server="93.184.216.34", sport=40002, payload_len=1100):
    return eth() + ipv4(17, client, server, udp(sport, 443, b"\x00" * payload_len))


def ioc_packet(bad_ip, client="10.0.0.5", sport=40003, dport=4444):
    return eth() + ipv4(17, client, bad_ip, udp(sport, dport, b"\x00" * 32))


def icmp_packet(dst, client="10.0.0.5", typ=8):
    return eth() + ipv4(1, client, dst, struct.pack("!BBHHH", typ, 0, 0, 0, 1) + b"payload")


def syn_packet(dst="1.2.3.4", client="10.0.0.5", sport=40000, dport=12345):
    return eth() + ipv4(6, client, dst, tcp(sport, dport, 0x02, b""))   # pure SYN (flags==2)


def write_pcap(path, packets, linktype=DLT_EN10MB, snaplen=65535, ts=1700000000):
    with open(path, "wb") as f:
        f.write(struct.pack("!IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype))
        for i, p in enumerate(packets):
            f.write(struct.pack("!IIII", ts, i % 1000000, len(p), len(p)) + p)
    return path


def temp_pcap(packets, **kw):
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    return write_pcap(path, packets, **kw)


def write_pcap_trunc(path, records, linktype=DLT_EN10MB, snaplen=65535, ts=1700000000):
    """records = list of (wire_len, captured_bytes); writes incl_len=len(captured_bytes)
    but orig_len=wire_len, i.e. a snaplen-truncated capture."""
    with open(path, "wb") as f:
        f.write(struct.pack("!IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype))
        for i, (wire_len, data) in enumerate(records):
            f.write(struct.pack("!IIII", ts, i % 1000000, len(data), wire_len) + data)
    return path


def temp_pcap_trunc(records, **kw):
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    return write_pcap_trunc(path, records, **kw)
