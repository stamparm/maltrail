#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function  # Requires: Python >= 2.6

import sys

sys.dont_write_bytecode = True

import core.versioncheck

import mmap
import optparse
import os
import re
import socket
import subprocess
import struct
import threading
import time
import traceback
import urllib
import urlparse

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
from core.settings import SUSPICIOUS_UA_LENGTH_THRESHOLD
from core.settings import SUSPICIOUS_UA_REGEX
from core.settings import trails
from core.settings import VERSION
from core.settings import WHITELIST
from core.settings import WHITELIST_HTTP_REQUEST_KEYWORDS
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

def _check_domain(query, sec, usec, src_ip, src_port, dst_ip, dst_port, proto):
    parts = query.lower().split('.')

    for i in xrange(0, len(parts)):
        domain = '.'.join(parts[i:])
        if domain in trails:
            if domain == query:
                trail = domain
            else:
                _ = ".%s" % domain
                trail = "(%s)%s" % (query[:-len(_)], _)

            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, trails[domain][0], trails[domain][1]))
            return

    if config.USE_HEURISTICS:
        if len(parts[0]) > SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD and '-' not in parts[0]:
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
                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, "long domain name (suspicious)", "(heuristic)"))

        elif "sinkhole." in query:
            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, query, "potential sinkhole domain (suspicious)", "(heuristic)"))

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

                key = "%s:%s" % (src_ip, dst_ip)
                if key not in _connect_src_dst:
                    _connect_src_dst[key] = set()
                    _connect_src_details[key] = set()
                _connect_src_dst[key].add(dst_port)
                _connect_src_details[key].add((sec, usec, src_port, dst_port))

                if sec > _connect_sec:
                    for key in _connect_src_dst:
                        if len(_connect_src_dst[key]) > PORT_SCANNING_THRESHOLD:
                            _src_ip, _dst_ip = key.split(':')
                            for _sec, _usec, _src_port, _dst_port in _connect_src_details[key]:
                                log_event((_sec, _usec, _src_ip, _src_port, _dst_ip, _dst_port, "TCP", TRAIL.IP, _src_ip, "potential port scanning", "(heuristic)"))

                    _connect_sec = sec
                    _connect_src_dst.clear()
                    _connect_src_details.clear()

            if flags & 8 != 0:  # PSH set
                tcph_length = doff_reserved >> 4
                h_size = ETH_LENGTH + iph_length + (tcph_length << 2)
                data = packet[h_size:]

                method, path = None, None
                index = data.find("\n")
                if index >= 0:
                    line = data[:index]
                    if line.count(' ') == 2 and " HTTP/" in line:
                        method = line.split(' ')[0].upper()
                        path = line.split(' ')[1].lower()

                if method and path:
                    index = data.find("\r\nHost:")
                    if index >= 0:
                        index = index + len("\r\nHost:")
                        host = data[index:data.find("\r\n", index)]
                        host = host.strip()
                        host = re.sub(r":80\Z", "", host)
                    else:
                        host = dst_ip
                        if config.USE_MISSING_HOST:
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.HTTP, "%s%s" % (host, path), "suspicious http request (missing host header)", "(heuristic)"))

                    if "://" in path:
                        url = path.split("://", 1)[1]

                        if '/' not in url:
                            url = "%s/" % url

                        host, path = url.split('/', 1)
                        host = re.sub(r":80\Z", "", host)
                        path = "/%s" % path
                        proxy_domain = host.split(':')[0]
                        _check_domain(proxy_domain, sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP")
                    elif method == "CONNECT":
                        if '/' in path:
                            host, path = path.split('/', 1)
                            path = "/%s" % path
                        else:
                            host, path = path, '/'
                        host = re.sub(r":80\Z", "", host)
                        url = "%s%s" % (host, path)
                        proxy_domain = host.split(':')[0]
                        _check_domain(proxy_domain, sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP")
                    else:
                        url = "%s%s" % (host, path)

                    user_agent = None
                    index = data.find("\r\nUser-Agent:")
                    if index >= 0:
                        index = index + len("\r\nUser-Agent:")
                        user_agent = urllib.unquote(data[index:data.find("\r\n", index)]).strip()

                    if config.USE_HEURISTICS:
                        found = False
                        if user_agent:
                            if re.search(SUSPICIOUS_UA_REGEX, user_agent):
                                found = True
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.UA, user_agent.replace('(', "&#40;").replace(')', "&#41;"), "suspicious user agent", "(heuristic)"))

                        if not found and config.USE_SHORT_OR_MISSING_USER_AGENT:
                            if user_agent is None:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.HTTP, url, "suspicious http request (missing user agent header)", "(heuristic)"))
                            elif len(user_agent) < SUSPICIOUS_UA_LENGTH_THRESHOLD:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.UA, user_agent, "suspicious user agent (too short)", "(heuristic)"))

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
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.URL, trail, trails[check][0], trails[check][1]))
                                return

                    if config.USE_HEURISTICS:
                        if any(char in path for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS):
                            for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS:
                                path = path.replace(char, urllib.quote(char))

                        if host not in WHITELIST and not any(_ in path for _ in WHITELIST_HTTP_REQUEST_KEYWORDS) and re.search(SUSPICIOUS_HTTP_REQUEST_REGEX, urllib.unquote(path)):
                            trail = "%s(%s)" % (host, path)
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.URL, trail, "suspicious http request", "(heuristic)"))
                            return

                        if '.' in path:
                            _ = urlparse.urlparse("http://%s" % url)  # dummy scheme
                            filename = _.path.split('/')[-1]
                            name, extension = os.path.splitext(filename)
                            if extension and extension in SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS and '.'.join(host.split('.')[-2:]) not in WHITELIST and not _.query and len(name) < 10:
                                trail = "%s(%s)" % (host, path)
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.URL, trail, "direct %s download (suspicious)" % extension, "(heuristic)"))
                            elif filename in SUSPICIOUS_FILENAMES:
                                trail = "%s(%s)" % (host, path)
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "TCP", TRAIL.URL, trail, "suspicious page", "(heuristic)"))

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
                                _check_domain(query, sec, usec, src_ip, src_port, dst_ip, dst_port, "UDP")

                        elif config.USE_HEURISTICS and (ord(data[2]) & 0x80) and (ord(data[3]) == 0x83):  # standard response, recursion available, no such name
                            if query not in NO_SUCH_NAME_COUNTERS or NO_SUCH_NAME_COUNTERS[query][0] != sec / 3600:
                                NO_SUCH_NAME_COUNTERS[query] = [sec / 3600, 1]
                            else:
                                NO_SUCH_NAME_COUNTERS[query][1] += 1

                                if NO_SUCH_NAME_COUNTERS[query][1] > NO_SUCH_NAME_PER_HOUR_THRESHOLD and query not in WHITELIST and '.'.join(query.split('.')[-2:]) not in WHITELIST:
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, "UDP", TRAIL.DNS, query, "excessive no such domain name (suspicious)", "(heuristic)"))

        elif protocol in IPPROTO_LUT:  # non-TCP/UDP (e.g. ICMP)
            if protocol == socket.IPPROTO_ICMP:
                i = iph_length + ETH_LENGTH
                if packet[i] != 8:  # Echo request
                    return

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
        exit("[!] please run with sudo/Administrator privileges")

    if (config.MONITOR_INTERFACE or "").lower() == "any":
        if subprocess.mswindows:
            exit("[!] virtual interface 'any' is not available on Windows OS")
        else:
            print("[!] in case of any problems with packet capture on virtual interface 'any', please put all monitoring interfaces to promiscuous mode manually (e.g. 'sudo ifconfig eth0 promisc')")

    if config.MONITOR_INTERFACE not in pcapy.findalldevs():
        print("[!] interface '%s' not found" % config.MONITOR_INTERFACE)
        exit("[x] available interfaces: '%s'" % ",".join(pcapy.findalldevs()))

    print("[i] opening interface '%s'" % config.MONITOR_INTERFACE)
    try:
        _cap = pcapy.open_live(config.MONITOR_INTERFACE, SNAP_LEN, True, 0)
    except (socket.error, pcapy.PcapError):
        if "permitted" in str(sys.exc_info()[1]):
            exit("[!] please run with sudo/Administrator privileges")
        elif "No such device" in str(sys.exc_info()[1]):
            exit("[!] no such device '%s'" % config.MONITOR_INTERFACE)
        else:
            raise

    if config.LOG_SERVER and not len(config.LOG_SERVER.split(':')) == 2:
        exit("[!] invalid configuration value for 'LOG_SERVER' ('%s')" % config.LOG_SERVER)

    if config.CAPTURE_FILTER:
        print("[i] setting filter '%s'" % config.CAPTURE_FILTER)
        _cap.setfilter(config.CAPTURE_FILTER)

    _datalink = _cap.datalink()
    if _datalink not in (pcapy.DLT_EN10MB, pcapy.DLT_LINUX_SLL, pcapy.DLT_PPP):
        exit("[!] datalink type '%s' not supported" % _datalink)

    if _multiprocessing:
        _init_multiprocessing()

    try:
        try:
            mod = int(subprocess.check_output("grep -c ^processor /proc/cpuinfo", stderr=subprocess.STDOUT, shell=True).strip())
            used = subprocess.check_output("for pid in $(ps aux | grep python | grep sensor.py | grep -E -o 'root[ ]*[0-9]*' | tr -d '[:alpha:] '); do schedtool $pid; done | grep -E -o 'AFFINITY .*' | cut -d ' ' -f 2 | grep -v 0xf", stderr=subprocess.STDOUT, shell=True).strip().split('\n')
            max_used = max(int(_, 16) for _ in used)
            affinity = max(1, (max_used << 1) % 2 ** mod)
        except:
            affinity = 1
        p = subprocess.Popen("schedtool -n -2 -M 2 -p 10 -a 0x%02x %d" % (affinity, os.getpid()), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = p.communicate()
        if "not found" in stderr:
            print("[!] please install schedtool for better CPU scheduling (e.g. 'sudo apt-get install schedtool')")
    except:
        pass

def _init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    global _buffer
    global _n

    if _multiprocessing:
        print("[i] creating %d more processes (%d CPU cores detected)" % (_multiprocessing.cpu_count() - 1, _multiprocessing.cpu_count()))
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

    print("[o] running...")

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
        print("\r[x] Ctrl-C pressed")
    finally:
        if _multiprocessing:
            for _ in xrange(_multiprocessing.cpu_count() - 1):
                write_block(_buffer, _n.value, "", BLOCK_MARKER.END)
                _n.value = _n.value + 1
            while _multiprocessing.active_children():
                time.sleep(REGULAR_SENSOR_SLEEP_TIME)

def main():
    print("%s (sensor) #v%s\n" % (NAME, VERSION))

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="Configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    options, _ = parser.parse_args()

    if not check_sudo():
        exit("[!] please run with sudo/Administrator privileges")

    read_config(options.config_file)

    try:
        init()
        monitor()
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\r[!] unhandled exception occurred ('%s')" % sys.exc_info()[1])
        print("\r[x] please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc())

    os._exit(0)
