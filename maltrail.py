#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import mmap
import optparse
import os
import socket
import subprocess
import stat
import struct
import sys
import tempfile
import time
import traceback

from core.blacklists import load_blacklists
from core.common import *
from core.database import *
from core.reporting import *
from core.settings import *

_buffer = None
_count = None
_multiprocessing = False
_blacklists = None

try:
    import multiprocessing

    if multiprocessing.cpu_count() > 1:
        _multiprocessing = True
except (ImportError, OSError, NotImplementedError):
    pass

try:
    import pcapy
except ImportError:
    exit("[!] please install Pcapy (e.g. '%s')" % ("sudo apt-get install python-pcapy" if not subprocess.mswindows else "https://breakingcode.wordpress.com/2012/07/16/quickpost-updated-impacketpcapy-installers-for-python-2-5-2-6-2-7/"))

try:
    import dpkt
except ImportError:
    exit("[!] please install dpkt (e.g. '%s')" % ("sudo apt-get install python-dpkt" if not subprocess.mswindows else "https://dpkt.googlecode.com/files/dpkt-1.7.win32.exe"))

def _process_packet(packet, timestamp=None):
    """
    Performs all processing on raw packets
    """

    try:
        eth_header = struct.unpack("!6s6sH", packet[:ETH_LENGTH])
        eth_protocol = socket.ntohs(eth_header[2])

        if eth_protocol == IPPROTO:  # IP
            ip_header = struct.unpack("!BBHHHBBH4s4s", packet[ETH_LENGTH:ETH_LENGTH + 20])
            ip_length = ip_header[2]
            packet = packet[:ETH_LENGTH + ip_length]  # truncate
            iph_length = (ip_header[0] & 0xF) << 2
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])

            if dst_ip in _blacklists[BLACKLIST.IP]:
                src, dst, type_, trigger, info, reference = src_ip, dst_ip, BLACKLIST.IP, dst_ip, _blacklists[BLACKLIST.IP][dst_ip][0], _blacklists[BLACKLIST.IP][dst_ip][1]
                store_db(timestamp or time.time(), src, dst, type_, trigger, info, reference)

            elif src_ip in _blacklists[BLACKLIST.IP]:
                src, dst, type_, trigger, info, reference = src_ip, dst_ip, BLACKLIST.IP, src_ip, _blacklists[BLACKLIST.IP][src_ip][0], _blacklists[BLACKLIST.IP][src_ip][1]
                store_db(timestamp or time.time(), src, dst, type_, trigger, info, reference)

            if protocol == socket.IPPROTO_TCP:
                i = iph_length + ETH_LENGTH
                tcp_header = packet[i:i + 20]
                src_port, dst_port, _, _, doff_reserved, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)
                syn = flags == 2
                tcph_length = doff_reserved >> 4
                h_size = ETH_LENGTH + iph_length + tcph_length * 4
                data = packet[h_size:]

                if dst_port == 80 and len(data) > 0:
                    index = data.find("\r\n")
                    if index >= 0:
                        line = data[:index]
                        if line.count(' ') == 2 and "HTTP/1" in line:
                            path = line.split(' ')[1]
                        else:
                            return
                    else:
                        return
                    index = data.find("\r\nHost:")
                    if index >= 0:
                        index = index + len("\r\nHost:")
                        host = data[index:data.find("\r\n", index)]
                        host = host.strip()
                    else:
                        return
                    url = "%s%s" % (host, path.rstrip('/'))
                    if url in _blacklists[BLACKLIST.URL]:
                        src, dst, type_, trigger, info, reference = src_ip, dst_ip, BLACKLIST.URL, url, _blacklists[BLACKLIST.URL][url][0], _blacklists[BLACKLIST.URL][url][1]
                        store_db(timestamp or time.time(), src, dst, type_, trigger, info, reference)

            elif protocol == socket.IPPROTO_UDP:
                i = iph_length + ETH_LENGTH
                src_port, dst_port = struct.unpack("!HH", packet[i:i + 4])
                if dst_port == 53:
                    h_size = ETH_LENGTH + iph_length + 8
                    data = packet[h_size:]

                    try:
                        dns = dpkt.dns.DNS(data)
                    except:
                        pass
                    else:
                        if dns.opcode == dpkt.dns.DNS_QUERY:
                            for query in dns.qd:
                                domain = query.name
                                parts = domain.split('.')
                                for i in xrange(0, len(parts) - 1):
                                    _ = '.'.join(parts[i:])
                                    if _ in _blacklists[BLACKLIST.DNS]:
                                        src, dst, type_, trigger, info, reference = src_ip, dst_ip, BLACKLIST.DNS, domain, _blacklists[BLACKLIST.DNS][_][0], _blacklists[BLACKLIST.DNS][_][1]
                                        store_db(timestamp or time.time(), src, dst, type_, trigger, info, reference)
                                        break
    except struct.error:
        pass

def _read_block(buffer, i):
    offset = i * BLOCK_LENGTH % BUFFER_LENGTH
    while True:
        if buffer[offset] == BLOCK_MARKER.END:
            return None
        while buffer[offset] == BLOCK_MARKER.WRITE:
            time.sleep(SHORT_SLEEP_TIME)
        buffer.seek(offset)
        buffer.write(BLOCK_MARKER.READ)
        length = struct.unpack("=H", buffer.read(2))[0]
        retval = buffer.read(length)
        if buffer[offset] == BLOCK_MARKER.READ:
            break
    buffer[offset] = BLOCK_MARKER.NOP
    return retval

def _write_block(buffer, i, block, marker=None):
    offset = i * BLOCK_LENGTH % BUFFER_LENGTH
    while buffer[offset] == BLOCK_MARKER.READ:
        time.sleep(SHORT_SLEEP_TIME)
    buffer.seek(offset)
    buffer.write(BLOCK_MARKER.WRITE + struct.pack("=H", len(block)) + block)
    buffer[offset] = marker or BLOCK_MARKER.NOP

def _worker(buffer, n):
    """
    Worker process used in multiprocessing mode
    """

    global _blacklists

    if not _blacklists:
        _blacklists = load_blacklists(verbose=False)

    offset = int(multiprocessing.current_process().name)
    mod = multiprocessing.cpu_count() - 1
    count = 0

    while True:
        try:
            if (count % mod) == offset:
                if count >= n.value:
                    time.sleep(REGULAR_SLEEP_TIME)
                    continue
                content = _read_block(buffer, count)
                if content is None:
                    break
                timestamp, packet, = struct.unpack("=I", content[:4])[0], content[4:]
                _process_packet(packet, timestamp)
            count += 1
        except KeyboardInterrupt:
            break

def _init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    global _buffer
    global _n

    if _multiprocessing:
        print ("[i] creating %d more processes (%d CPU cores detected)" % (multiprocessing.cpu_count() - 1, multiprocessing.cpu_count()))
        _buffer = mmap.mmap(-1, BUFFER_LENGTH)  # http://www.alexonlinux.com/direct-io-in-python
        _n = multiprocessing.Value('i', lock=False)

        for i in xrange(multiprocessing.cpu_count() - 1):
            process = multiprocessing.Process(target=_worker, name=str(i), args=(_buffer, _n))
            process.daemon = True
            process.start()

def process_pcap(pcapfile):
    """
    Reads .pcap file and inspects packets from it
    """

    print("[i] reading packets from '%s'..." % pcapfile)

    if not os.path.isfile(pcapfile):
        exit("[x] file '%s' does not exist" % pcapfile)
    try:
        packets = dpkt.pcap.Reader(open(pcapfile, "rb"))
    except Exception, ex:
        if "Not a pcap capture file" in traceback.format_exc():
            ex = "Not a pcap capture file"
        exit("[x] there has been a problem with reading file '%s' ('%s')" % (pcapfile, ex))

    count = 0
    try:
        for timestamp, packet in packets:
            sys.stdout.write('%s\r' % ROTATING_CHARS[count % len(ROTATING_CHARS)])
            if _multiprocessing:
                _write_block(_buffer, count, struct.pack("=I", timestamp) + packet)
                _n.value = count + 1
            else:
                _process_packet(packet, timestamp)
            count += 1
        if _multiprocessing:
            for _ in xrange(multiprocessing.cpu_count() - 1):
                _write_block(_buffer, count, "", BLOCK_MARKER.END)
                _n.value = count + 1
                count += 1
            while multiprocessing.active_children():
                time.sleep(REGULAR_SLEEP_TIME)
    except KeyboardInterrupt:
        print("\r[x] Ctrl-C pressed")

def monitor_interface(interface):
    """
    Sniffs/monitors given interface and inspects DNS packets found on it
    """

    print("[i] monitoring interface '%s'..." % interface)

    count = 0
    try:
        cap = pcapy.open_live(interface, MAX_PACKET_SIZE, True, 0)
        cap.setfilter(DEFAULT_CAPTURING_FILTER or "")
        while True:
            try:
                (header, packet) = cap.next()
                timestamp = header.getts()[0]
                if _multiprocessing:
                    _write_block(_buffer, count, struct.pack("=I", timestamp) + packet)
                    _n.value = count + 1
                else:
                    _process_packet(packet, timestamp)
                count += 1
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        print("\r[x] Ctrl-C pressed")
    except socket.error, ex:
        if "permitted" in str(ex):
            exit("\n[x] please run with sudo/Administrator privileges")
        elif "No such device" in str(ex):
            exit("\n[x] no such device '%s'" % interface)
        else:
            raise
    finally:
        if _multiprocessing:
            for _ in xrange(multiprocessing.cpu_count() - 1):
                _write_block(_buffer, count, "", BLOCK_MARKER.END)
                _n.value = count + 1
                count += 1
            while multiprocessing.active_children():
                time.sleep(REGULAR_SLEEP_TIME)
        close_db()

def main():
    global _blacklists

    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-i", dest="interface", help="listen DNS traffic on interface (e.g. eth0)")
    parser.add_option("-r", dest="pcapfile", help="read packets from (.pcap) file")
    options, _ = parser.parse_args()
    if any((options.interface, options.pcapfile)):
        if options.interface:
            if check_sudo() is False:
                exit("[x] please run with sudo/Administrator privileges")
        _blacklists = load_blacklists()
        _init_multiprocessing()
        if options.pcapfile:
            set_db(tempfile.mkstemp()[1])
            report_file = tempfile.mkstemp(prefix="%s-" % NAME.lower(), suffix=".html")[1]
            process_pcap(options.pcapfile)
            with open(report_file, "w+b") as f:
                f.write(create_report())
            os.chmod(report_file, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            print("[i] report written to '%s'" % report_file)
        elif options.interface:
            start_httpd()
            monitor_interface(options.interface)
    else:
        parser.print_help()

    os._exit(0)

if __name__ == "__main__":
    main()
