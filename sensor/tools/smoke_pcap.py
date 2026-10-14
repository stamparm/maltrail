#!/usr/bin/env python3
"""Write a pcap of one DNS query per given domain, for replaying through a freshly built sensor.

    python3 sensor/tools/smoke_pcap.py out.pcap some-trail.com some-benign.com

The release replays it through each cross-built binary and refuses one that does not log the
trail. A binary that starts and prints --version can still detect nothing: the first ARMv6 build
did exactly that, because Rust's libc read libpcap's packet header with a 32-bit time_t while
libpcap had been compiled with musl's 64-bit one, so every caplen was garbage and every packet
was "ignored". Only a replay notices.
"""

import struct
import sys
import time


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def _frame(domain, ident):
    question = b"".join(bytes([len(_)]) + _.encode() for _ in domain.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    payload = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question
    udp = struct.pack(">HHHH", 40000 + ident, 53, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0, 64, 17, 0, bytes([192, 168, 1, 10]), bytes([8, 8, 8, 8]))
    ip = ip[:10] + struct.pack(">H", _checksum(ip)) + ip[12:]
    return b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00" + ip + udp


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: %s OUT.pcap DOMAIN [DOMAIN ...]" % sys.argv[0])
    now = int(time.time())
    with open(sys.argv[1], "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, domain in enumerate(sys.argv[2:]):
            frame = _frame(domain, i + 1)
            f.write(struct.pack("<IIII", now + i, 0, len(frame), len(frame)) + frame)


if __name__ == "__main__":
    main()
