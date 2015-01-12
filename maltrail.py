#!/usr/bin/env python

from __future__ import print_function

import BaseHTTPServer
import glob
import httplib
import inspect
import logging
import mmap
import pickle
import optparse
import os
import re
import socket
import SocketServer
import sqlite3
import subprocess
import stat
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib
import urllib2
import urlparse
import zipfile
import zlib

from core.common import *
from core.database import *
from core.reporting import *
from core.settings import *

_buffer = None
_lock = None
_count = None
_multiprocessing = False

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

_blacklists = {}

def _load_blacklists(verbose=True):
    """
    Loads blacklists
    """

    global _blacklists

    if not verbose:
        def _(*args, **kwargs):
            pass
        __builtins__.original_print = __builtins__.print
        __builtins__.print = _

    _blacklists = dict((getattr(BLACKLIST, _), {}) for _ in dir(BLACKLIST) if _ == _.upper())

    if not os.path.isfile(CACHE_FILE) or (time.time() - os.stat(CACHE_FILE).st_mtime) / 3600 / 24 > FRESH_LISTS_DELTA_DAYS or os.stat(CACHE_FILE).st_size == 0:
        print("[i] %s blacklists..." % ("updating" if os.path.isfile(CACHE_FILE) else "retrieving"))

        try:
            if not os.path.isdir(STORAGE_DIRECTORY):
                os.makedirs(STORAGE_DIRECTORY, 0755)
            with open(CACHE_FILE, "w+b") as f:
                pass
        except Exception, ex:
            exit("[!] something went wrong during cache file write '%s' ('%s')" % (CACHE_FILE, ex))

        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "feeds")))
        for filename in glob.glob(os.path.join("feeds", "*.py")):
            try:
                module = __import__(os.path.basename(filename).split(".py")[0])
            except (ImportError, SyntaxError), ex:
                print("[!] something went wrong during import of feed file '%s' ('%s')" % (filename, ex))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "fetch":
                    print(" [o] '%s'" % module.__url__)
                    found = False
                    results = function()
                    if hasattr(module, "__reference__"):
                        reference_urls[module.__reference__] = module.__url__
                    for key in results:
                        if results[key]:
                            found = True
                            _blacklists[key].update(results[key])
                    if not found:
                        print("[!] something went wrong during remote data retrieval ('%s')" % module.__url__)

        try:
            with open(CACHE_FILE, "w+b") as f:
                f.write(zlib.compress(pickle.dumps(_blacklists)))
        except Exception, ex:
            print("[!] something went wrong during cache file write '%s' ('%s')" % (CACHE_FILE, ex))

    else:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "feeds")))
        for filename in glob.glob(os.path.join("feeds", "*.py")):
            try:
                module = __import__(os.path.basename(filename).split(".py")[0])
            except (ImportError, SyntaxError), ex:
                print("[!] something went wrong during import of feed file '%s' ('%s')" % (filename, ex))

            if hasattr(module, "__reference__"):
                reference_urls[module.__reference__] = module.__url__

    if not max(len(_) for _ in _blacklists.values()):
        print("[i] loading cache...")
        try:
            with open(CACHE_FILE, "rb") as f:
                _blacklists = pickle.loads(zlib.decompress(f.read()))
        except Exception, ex:
            exit("[x] something went wrong during cache file read '%s' ('%s')" % (CACHE_FILE, ex))

    for type_ in _blacklists:
        print("[i] %d blacklisted %s entries loaded" % (len(_blacklists[type_]), type_))

    if not verbose:
        __builtins__.print = __builtins__.original_print

def _process_packet(packet, timestamp=None):
    """
    Performs all processing on raw packets
    """

    try:
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        if eth_protocol == 8:  # IP
            ip_header = packet[eth_length:eth_length + 20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            if dst_ip in _blacklists[BLACKLIST.IP]:
                src, dst, type_, trigger, info, reference = src_ip, dst_ip, BLACKLIST.IP, dst_ip, _blacklists[BLACKLIST.IP][dst_ip][0], _blacklists[BLACKLIST.IP][dst_ip][1]
                store_db(timestamp or time.time(), src, dst, type_, trigger, info, reference)

            elif src_ip in _blacklists[BLACKLIST.IP]:
                src, dst, type_, trigger, info, reference = src_ip, dst_ip, BLACKLIST.IP, src_ip, _blacklists[BLACKLIST.IP][src_ip][0], _blacklists[BLACKLIST.IP][src_ip][1]
                store_db(timestamp or time.time(), src, dst, type_, trigger, info, reference)

            if protocol == socket.IPPROTO_TCP:
                i = iph_length + eth_length
                tcp_header = packet[i:i + 20]
                src_port, dst_port, _, _, doff_reserved, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)
                syn = flags == 2
                tcph_length = doff_reserved >> 4
                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size
                data = packet[h_size:]

                if dst_port == 80 and len(data) > 0:
                    index = data.find("\r\nHost:")
                    if index >= 0:
                        index = index + len("\r\nHost:")
                        host = data[index:data.find("\r\n", index)]
                        host = host.strip()
                    else:
                        return
                    line = data.split("\r\n")[0]
                    if line.count(' ') == 2 and "HTTP/1" in line:
                        path = line.split(' ')[1]
                    else:
                        return
                    url = "%s%s" % (host, path.rstrip('/'))
                    if url in _blacklists[BLACKLIST.URL]:
                        src, dst, type_, trigger, info, reference = src_ip, dst_ip, BLACKLIST.URL, url, _blacklists[BLACKLIST.URL][url][0], _blacklists[BLACKLIST.URL][url][1]
                        store_db(timestamp or time.time(), src, dst, type_, trigger, info, reference)

            elif protocol == socket.IPPROTO_UDP:
                i = iph_length + eth_length
                src_port, dst_port = struct.unpack("!HH", packet[i:i+4])
                if dst_port == 53:
                    h_size = eth_length + iph_length + 8
                    data_size = len(packet) - h_size
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

def _read_block(buffer, i, lock):
    start = i * BLOCK_LENGTH % BUFFER_LENGTH
    end = start + BLOCK_LENGTH - 1
    if buffer[end] == BLOCK_MARKER.END:
        return None
    while buffer[end] == BLOCK_MARKER.WRITE:
        time.sleep(SHORT_SLEEP_TIME)
    buffer[end] = BLOCK_MARKER.READ
    buffer.seek(start)
    retval = buffer.read(BLOCK_LENGTH)
    buffer[end] = BLOCK_MARKER.NOP
    return retval

def _write_block(buffer, i, block, lock, marker=None):
    start = i * BLOCK_LENGTH % BUFFER_LENGTH
    end = start + BLOCK_LENGTH - 1
    while buffer[end] == BLOCK_MARKER.READ:
        time.sleep(SHORT_SLEEP_TIME)
    buffer[end] = BLOCK_MARKER.WRITE
    buffer.seek(start)
    buffer.write(block)
    buffer[end] = marker or BLOCK_MARKER.NOP

def _worker(buffer, n, lock):
    """
    Worker process used in multiprocessing mode
    """

    if not _blacklists:
        _load_blacklists(verbose=False)

    offset = int(multiprocessing.current_process().name)
    mod = multiprocessing.cpu_count() - 1
    count = 0

    while True:
        try:
            if (count % mod) == offset:
                if count >= n.value:
                    time.sleep(REGULAR_SLEEP_TIME)
                    continue
                content = _read_block(buffer, count, lock)
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
    global _lock

    if _multiprocessing:
        print ("[i] creating %d more processes (%d CPU cores detected)" % (multiprocessing.cpu_count() - 1, multiprocessing.cpu_count()))
        _buffer = mmap.mmap(-1, BUFFER_LENGTH)  # http://www.alexonlinux.com/direct-io-in-python
        _lock = multiprocessing.Lock()
        _n = multiprocessing.Value('i')

        for i in xrange(multiprocessing.cpu_count() - 1):
            process = multiprocessing.Process(target=_worker, name=str(i), args=(_buffer, _n, _lock))
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
                _write_block(_buffer, count, struct.pack("=I", timestamp) + packet, _lock)
                _n.value = count + 1
            else:
                _process_packet(packet, timestamp)
            count += 1
        if _multiprocessing:
            for _ in xrange(multiprocessing.cpu_count() - 1):
                _write_block(_buffer, count, "", _lock, BLOCK_MARKER.END)
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
        cap = pcapy.open_live(interface, 65536, True, 0)
        cap.setfilter(DEFAULT_CAPTURING_FILTER or "")
        while True:
            try:
                (header, packet) = cap.next()
                timestamp = header.getts()[0]
                if _multiprocessing:
                    _write_block(_buffer, count, struct.pack("=I", timestamp) + packet, _lock)
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
                _write_block(_buffer, count, "", _lock, BLOCK_MARKER.END)
                _n.value = count + 1
                count += 1
            while multiprocessing.active_children():
                time.sleep(REGULAR_SLEEP_TIME)
        close_db()

def main():
    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-i", dest="interface", help="listen DNS traffic on interface (e.g. eth0)")
    parser.add_option("-r", dest="pcapfile", help="read packets from (.pcap) file")
    options, _ = parser.parse_args()
    if any((options.interface, options.pcapfile)):
        if options.interface:
            if check_sudo() is False:
                exit("[x] please run with sudo/Administrator privileges")
        _load_blacklists()
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
