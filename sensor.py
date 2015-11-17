#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import mmap
import optparse
import os
import re
import socket
import subprocess
import struct
import sys
import threading
import time
import traceback
import urllib
import urlparse

sys.dont_write_bytecode = True

from core.common import check_sudo
from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.enums import TRAIL
from core.log import create_log_directory
from core.log import log_event
from core.parallel import worker
from core.parallel import write_block
from core.settings import BUFFER_LENGTH
from core.settings import config
from core.settings import CONFIG_FILE
from core.settings import DEBUG
from core.settings import ETH_LENGTH
from core.settings import PPPH_LENGTH
from core.settings import IPPROTO_LUT
from core.settings import NAME
from core.settings import NO_SUCH_NAME_COUNTERS
from core.settings import NO_SUCH_NAME_PER_HOUR_THRESHOLD
from core.settings import PORT_SCANNING_THRESHOLD
from core.settings import read_config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SNAP_LEN
from core.settings import SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS
from core.settings import SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD
from core.settings import SUSPICIOUS_FILENAMES
from core.settings import SUSPICIOUS_HTTP_REQUEST_REGEX
from core.settings import SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS
from core.settings import trails
from core.settings import VERSION
from core.settings import WHITELIST
from core.update import update

_buffer = None
_cap = None
_count = 0
_multiprocessing = None
_n = None
_datalink = None
_connect_sec = 0
_connect_src_dst = {}
_connect_src_details = {}

try:
    import pcapy
except ImportError:
    if subprocess.mswindows:
        exit("[!] please install Pcapy (e.g. 'https://breakingcode.wordpress.com/?s=pcapy') and WinPcap (e.g. 'http://www.winpcap.org/install/')")
    else:
        exit("[!] please install Pcapy (e.g. 'apt-get install python-pcapy')")

def _process_packet(packet, sec, usec):
    """
    Processes single (raw) packet
    """

    global _connect_sec

    try:
        ip_offset = None

        if _datalink == pcapy.DLT_PPP:
            ppp_protocol = packet[2:4]
            if ppp_protocol == "\x00\x21":  # IP
                ip_offset = PPPH_LENGTH
        else:
            if _datalink == pcapy.DLT_LINUX_SLL:
                packet = packet[2:]

            eth_header = struct.unpack("!HH8sH", packet[:ETH_LENGTH])
            eth_protocol = socket.ntohs(eth_header[3])
            if eth_protocol == 8:  # IP
                ip_offset = ETH_LENGTH

        if ip_offset is None:
            return

        ip_header = struct.unpack("!BBHHHBBH4s4s", packet[ip_offset:ip_offset + 20])

        ip_length = ip_header[2]
        packet = packet[:ETH_LENGTH + ip_length]  # truncate
        iph_length = (ip_header[0] & 0xF) << 2
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])

        if protocol == socket.IPPROTO_TCP:  # TCP
            i = iph_length + ETH_LENGTH
            src_port, dst_port, _, _, doff_reserved, flags = struct.unpack("!HHLLBB", packet[i:i+14])

            if flags == 2:  # SYN set (only)
                if dst_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]))
                elif src_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]))

                if sec > _connect_sec:
                    for key in _connect_src_dst:
                        if len(_connect_src_dst[key]) > PORT_SCANNING_THRESHOLD:
                            for _sec, _usec, _src_port, _dst_port in _connect_src_details[key]:
                                log_event((_sec, _usec, src_ip, _src_port, dst_ip, _dst_port, "TCP", TRAIL.IP, src_ip, "potential port scanning", "(heuristic)"))

                    _connect_sec = sec
                    _connect_src_dst.clear()
                    _connect_src_details.clear()

                key = "%s:%s" % (src_ip, dst_ip)
                if key not in _connect_src_dst:
                    _connect_src_dst[key] = set()
                    _connect_src_details[key] = set()
                _connect_src_dst[key].add(dst_port)
                _connect_src_details[key].add((sec, usec, src_port, dst_port))

            if flags & 8 != 0:  # PSH set
                tcph_length = doff_reserved >> 4
                h_size = ETH_LENGTH + iph_length + (tcph_length << 2)
                data = packet[h_size:]

                if len(data) > 0 and "HTTP/" in data:
                    index = data.find("\r\n")
                    if index >= 0:
                        line = data[:index]
                        if line.count(' ') == 2 and " HTTP/" in line:
                            path = line.split(' ')[1].lower()
                        else:
                            return
                    else:
                        return

                    index = data.find("\r\nHost:")
                    if index >= 0:
                        index = index + len("\r\nHost:")
                        host = data[index:data.find("\r\n", index)]
                        host = host.strip()
                        host = re.sub(r":80\Z", "", host)
                    else:
                        return

                    url = "%s%s" % (host, path)

                    checks = [path.rstrip('/')]
                    if '?' in path:
                        checks.append(path.split('?')[0].rstrip('/'))

                    _ = os.path.splitext(checks[-1])
                    if _[1]:
                        checks.append(_[0])

                    if checks[-1].count('/') > 1:
                        checks.append(checks[-1][:checks[-1].rfind('/')])

                    for check in filter(None, checks):
                        for _ in ("", host):
                            check = "%s%s" % (_, check)
                            if check in trails:
                                parts = url.split(check)
                                other = ("(%s)" % _ if _ else _ for _ in parts)
                                trail = check.join(other)
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.HTTP, trail, trails[check][0], trails[check][1]))
                                return

                    if config.USE_HEURISTICS:
                        if any(char in path for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS):
                            for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS:
                                path = path.replace(char, urllib.quote(char))

                        if re.search(SUSPICIOUS_HTTP_REQUEST_REGEX, urllib.unquote(path)) and host not in WHITELIST:
                            trail = "%s(%s)" % (host, path)
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.HTTP, trail, "suspicious http request", "(heuristic)"))
                            return

                        if '.' in path:
                            _ = urlparse.urlparse(url)
                            filename = _.path.split('/')[-1]
                            name, extension = os.path.splitext(filename)
                            if extension and extension in SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS and '.'.join(host.split('.')[-2:]) not in WHITELIST and len(name) < 6:
                                trail = "%s(%s)" % (host, path)
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.HTTP, trail, "direct %s download (suspicious)" % extension, "(heuristic)"))
                            elif filename in SUSPICIOUS_FILENAMES:
                                trail = "%s(%s)" % (host, path)
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.HTTP, trail, "suspicious page", "(heuristic)"))

        elif protocol == socket.IPPROTO_UDP:  # UDP
            i = iph_length + ETH_LENGTH
            _ = packet[i:i + 4]
            if len(_) < 4:
                return

            src_port, dst_port = struct.unpack("!HH", _)

            if src_port != 53:
                if dst_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "UDP", TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]))
                elif src_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "UDP", TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]))

            if dst_port == 53 or src_port == 53:
                h_size = ETH_LENGTH + iph_length + 8
                data = packet[h_size:]

                # Reference: http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
                if len(data) > 6:
                    qdcount = struct.unpack("!H", data[4:6])[0]
                    if qdcount > 0:
                        offset = 12
                        query = ""

                        while len(data) > offset:
                            length = ord(data[offset])
                            if not length:
                                query = query[:-1]
                                break
                            query += data[offset + 1:offset + length + 1] + '.'
                            offset += length + 1

                        if ' ' in query or '.' not in query or query.endswith(".in-addr.arpa") or query.endswith(".local"):
                            return

                        if ord(data[2]) == 0x01:  # standard query
                            type_, class_ = struct.unpack("!HH", data[offset + 1:offset + 5])

                            # Reference: http://en.wikipedia.org/wiki/List_of_DNS_record_types
                            if type_ != 12 and class_ == 1:  # Type != PTR, Class IN
                                parts = query.split('.')

                                for i in xrange(0, len(parts)):
                                    domain = '.'.join(parts[i:])
                                    if domain in trails:
                                        if domain == query:
                                            trail = domain
                                        else:
                                            _ = ".%s" % domain
                                            trail = "(%s)%s" % (query[:-len(_)], _)

                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "UDP", TRAIL.DNS, trail, trails[domain][0], trails[domain][1]))
                                        return

                                if config.USE_HEURISTICS and len(parts[0]) > SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD and '-' not in parts[0]:
                                    trail = None

                                    if len(parts) > 2:
                                        if '.'.join(parts[-2:]) not in WHITELIST:
                                            trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                                    elif len(parts) == 2:
                                        if '.'.join(parts) not in WHITELIST:
                                            trail = "(%s).%s" % (parts[0], parts[1])
                                    else:
                                        trail = query

                                    if trail:
                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "UDP", TRAIL.DNS, trail, "long domain name (suspicious)", "(heuristic)"))

                        elif config.USE_HEURISTICS and (ord(data[2]) & 0x80) and (ord(data[3]) == 0x83):  # standard response, recursion available, no such name
                            if query not in NO_SUCH_NAME_COUNTERS or NO_SUCH_NAME_COUNTERS[query][0] != sec / 3600:
                                NO_SUCH_NAME_COUNTERS[query] = [sec / 3600, 1]
                            else:
                                NO_SUCH_NAME_COUNTERS[query][1] += 1

                                if NO_SUCH_NAME_COUNTERS[query][1] > NO_SUCH_NAME_PER_HOUR_THRESHOLD and query not in WHITELIST:
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "UDP", TRAIL.DNS, query, "excessive no such domain name (suspicious)", "(heuristic)"))

        elif protocol in IPPROTO_LUT:  # non-TCP/UDP (e.g. ICMP)
            if dst_ip in trails:
                log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]))
            elif src_ip in trails:
                log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]))

    except Exception:
        if DEBUG:
            traceback.print_exc()

def init():
    """
    Performs sensor initialization
    """

    global _cap
    global _datalink
    global _multiprocessing

    if config.USE_MULTIPROCESSING:
        try:
            import multiprocessing

            if multiprocessing.cpu_count() > 1:
                _multiprocessing = multiprocessing
        except (ImportError, OSError, NotImplementedError):
            pass

    def update_timer():
        _ = update(server=config.UPDATE_SERVER)

        if _:
            trails.clear()
            trails.update(_)
        elif not trails:
            trails.update(load_trails())

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    update_timer()

    create_log_directory()

    if check_sudo() is False:
        exit("[x] please run with sudo/Administrator privileges")

    if subprocess.mswindows and (config.MONITOR_INTERFACE or "").lower() == "any":
        exit("[x] virtual interface 'any' is not available on Windows OS")

    if config.MONITOR_INTERFACE not in pcapy.findalldevs():
        print "[x] interface '%s' not found" % config.MONITOR_INTERFACE
        exit("[!] available interfaces: '%s'" % ",".join(pcapy.findalldevs()))

    print "[i] opening interface '%s'" % config.MONITOR_INTERFACE
    try:
        _cap = pcapy.open_live(config.MONITOR_INTERFACE, SNAP_LEN, True, 0)
    except socket.error, ex:
        if "permitted" in str(ex):
            exit("\n[x] please run with sudo/Administrator privileges")
        elif "No such device" in str(ex):
            exit("\n[x] no such device '%s'" % config.MONITOR_INTERFACE)
        else:
            raise

    if config.CAPTURE_FILTER:
        print "[i] setting filter '%s'" % config.CAPTURE_FILTER
        _cap.setfilter(config.CAPTURE_FILTER)

    _datalink = _cap.datalink()
    if _datalink not in (pcapy.DLT_EN10MB, pcapy.DLT_LINUX_SLL, pcapy.DLT_PPP):
        exit("[x] datalink type '%s' not supported" % _datalink)

    if _multiprocessing:
        _init_multiprocessing()

    try:
        p = subprocess.Popen("schedtool -n -2 -M 2 -p 10 -a 0x01 %d" % os.getpid(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = p.communicate()
        if "not found" in stderr:
            print "[!] please install schedtool for better CPU scheduling (e.g. 'sudo apt-get install schedtool')"
    except:
        pass

def _init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    global _buffer
    global _n

    if _multiprocessing:
        print "[i] creating %d more processes (%d CPU cores detected)" % (_multiprocessing.cpu_count() - 1, _multiprocessing.cpu_count())
        _buffer = mmap.mmap(-1, BUFFER_LENGTH)  # http://www.alexonlinux.com/direct-io-in-python
        _n = _multiprocessing.Value('L', lock=False)

        for i in xrange(_multiprocessing.cpu_count() - 1):
            process = _multiprocessing.Process(target=worker, name=str(i), args=(_buffer, _n, i, _multiprocessing.cpu_count() - 1, _process_packet))
            process.daemon = True
            process.start()

def monitor():
    """
    Sniffs/monitors given capturing interface
    """

    def packet_handler(header, packet):
        global _count

        try:
            sec, usec = header.getts()
            if _multiprocessing:
                write_block(_buffer, _count, struct.pack("=II", sec, usec) + packet)
                _n.value = _count + 1
            else:
                _process_packet(packet, sec, usec)
            _count += 1
        except socket.timeout:
            pass

    try:
        _cap.loop(-1, packet_handler)
    except KeyboardInterrupt:
        print "\r[x] Ctrl-C pressed"
    finally:
        if _multiprocessing:
            for _ in xrange(_multiprocessing.cpu_count() - 1):
                write_block(_buffer, _n.value, "", BLOCK_MARKER.END)
                _n.value = _n.value + 1
            while _multiprocessing.active_children():
                time.sleep(REGULAR_SENSOR_SLEEP_TIME)

def main():
    print "%s (sensor) #v%s\n" % (NAME, VERSION)

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="Configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    options, _ = parser.parse_args()

    if not check_sudo():
        exit("[x] please run with sudo/Administrator privileges")

    read_config(options.config_file)

    try:
        init()
        monitor()
    except KeyboardInterrupt:
        print "\r[x] stopping (Ctrl-C pressed)"

if __name__ == "__main__":
    try:
        main()
    except Exception, ex:
        print "\r[!] Unhandled exception occurred ('%s')" % ex
        print "\r[x] Please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()

    os._exit(0)
