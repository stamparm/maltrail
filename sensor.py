#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function  # Requires: Python >= 2.6

import sys

sys.dont_write_bytecode = True

import core.versioncheck

import math
import mmap
import optparse
import os
import platform
import re
import socket
import subprocess
import struct
import threading
import time
import traceback
import urllib
import urlparse

from core.attribdict import AttribDict
from core.common import check_sudo
from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.enums import PROTO
from core.enums import TRAIL
from core.log import create_log_directory
from core.log import get_error_log_handle
from core.log import log_error
from core.log import log_event
from core.parallel import worker
from core.parallel import write_block
from core.settings import check_memory
from core.settings import config
from core.settings import CAPTURE_TIMEOUT
from core.settings import CONFIG_FILE
from core.settings import DLT_OFFSETS
from core.settings import IGNORE_DNS_QUERY_SUFFIXES
from core.settings import IPPROTO_LUT
from core.settings import LOCALHOST_IP
from core.settings import MMAP_ZFILL_CHUNK_LENGTH
from core.settings import MAX_RESULT_CACHE_ENTRIES
from core.settings import NAME
from core.settings import NO_SUCH_NAME_COUNTERS
from core.settings import NO_SUCH_NAME_PER_HOUR_THRESHOLD
from core.settings import PORT_SCANNING_THRESHOLD
from core.settings import read_config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SNAP_LEN
from core.settings import SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS
from core.settings import SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD
from core.settings import SUSPICIOUS_FILENAMES
from core.settings import SUSPICIOUS_HTTP_REQUEST_REGEX
from core.settings import SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS
from core.settings import SUSPICIOUS_UA_LENGTH_THRESHOLD
from core.settings import SUSPICIOUS_UA_REGEX
from core.settings import trails
from core.settings import VERSION
from core.settings import WHITELIST
from core.settings import WHITELIST_DIRECT_DOWNLOAD_KEYWORDS
from core.settings import WHITELIST_LONG_DOMAIN_NAME_KEYWORDS
from core.settings import WHITELIST_HTTP_REQUEST_KEYWORDS
from core.settings import WHITELIST_UA_KEYWORDS
from core.update import update_ipcat
from core.update import update_trails

_buffer = None
_caps = []
_connect_sec = 0
_connect_src_dst = {}
_connect_src_details = {}
_count = 0
_locks = AttribDict()
_multiprocessing = None
_n = None
_result_cache = {}

try:
    import pcapy
except ImportError:
    if subprocess.mswindows:
        exit("[!] please install 'WinPcap' (e.g. 'http://www.winpcap.org/install/') and Pcapy (e.g. 'https://breakingcode.wordpress.com/?s=pcapy')")
    else:
        msg, _ = "[!] please install 'Pcapy'", platform.linux_distribution()[0].lower()
        for distro, install in {("fedora", "centos"): "sudo yum install pcapy", ("debian", "ubuntu"): "sudo apt-get install python-pcapy"}.items():
            if _ in distro:
                msg += " (e.g. '%s')" % install
                break
        exit(msg)

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

            if trail and not any(_ in trail for _ in WHITELIST_LONG_DOMAIN_NAME_KEYWORDS):
                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, "long domain name (suspicious)", "(heuristic)"))

        elif "sinkhole" in query:
            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, query, "potential sinkhole domain (suspicious)", "(heuristic)"))

def _process_ip(ip_data, sec, usec):
    """
    Processes single (raw) IP layer data
    """

    global _connect_sec

    try:
        if len(_result_cache) > MAX_RESULT_CACHE_ENTRIES:
            _result_cache.clear()

        if config.USE_HEURISTICS:
            if _locks.connect_sec:
                _locks.connect_sec.acquire()

            connect_sec = _connect_sec
            _connect_sec = sec

            if _locks.connect_sec:
                _locks.connect_sec.release()

            if sec > connect_sec:
                for key in _connect_src_dst:
                    if len(_connect_src_dst[key]) > PORT_SCANNING_THRESHOLD:
                        _src_ip, _dst_ip = key.split(':')
                        if _src_ip not in WHITELIST:
                            _src_ports = set(str(_[2]) for _ in _connect_src_details[key])
                            _dst_ports = set(str(_[3]) for _ in _connect_src_details[key])
                            log_event((sec, usec, _src_ip, ','.join(_src_ports), _dst_ip, ','.join(_dst_ports), PROTO.TCP, TRAIL.IP, _src_ip, "potential port scanning", "(heuristic)"))

                _connect_src_dst.clear()
                _connect_src_details.clear()

        ip_header = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])

        ip_length = ip_header[2]
        ip_data = ip_data[:ip_length]  # truncate
        iph_length = (ip_header[0] & 0xf) << 2
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])

        if protocol == socket.IPPROTO_TCP:  # TCP
            src_port, dst_port, _, _, doff_reserved, flags = struct.unpack("!HHLLBB", ip_data[iph_length:iph_length+14])

            if flags == 2:  # SYN set (only)
                if dst_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]))
                elif src_ip in trails and dst_ip != LOCALHOST_IP:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]))

                if config.USE_HEURISTICS:
                    if dst_ip != LOCALHOST_IP:
                        key = "%s:%s" % (src_ip, dst_ip)
                        if key not in _connect_src_dst:
                            _connect_src_dst[key] = set()
                            _connect_src_details[key] = set()
                        _connect_src_dst[key].add(dst_port)
                        _connect_src_details[key].add((sec, usec, src_port, dst_port))

            if flags & 8 != 0:  # PSH set
                tcph_length = doff_reserved >> 4
                h_size = iph_length + (tcph_length << 2)
                tcp_data = ip_data[h_size:]

                if src_port == 80 and tcp_data.startswith("HTTP/") and any(_ in tcp_data[:tcp_data.find("\r\n\r\n")] for _ in ("X-Sinkhole:", "Server: Apache 1.0/SinkSoft")):
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IP, src_ip, "sinkhole response (malware)", "(heuristic)"))

                method, path = None, None
                index = tcp_data.find("\n")
                if index >= 0:
                    line = tcp_data[:index]
                    if line.count(' ') == 2 and " HTTP/" in line:
                        method = line.split(' ')[0].upper()
                        path = line.split(' ')[1].lower()

                if method and path:
                    post_data = None
                    host = dst_ip
                    index = tcp_data.find("\r\nHost:")

                    if index >= 0:
                        index = index + len("\r\nHost:")
                        host = tcp_data[index:tcp_data.find("\r\n", index)]
                        host = host.strip()
                        host = re.sub(r":80\Z", "", host)
                        if dst_ip in trails and not (host[-1].isdigit() and ':' not in host):
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]))
                    elif config.USE_HEURISTICS and config.CHECK_MISSING_HOST:
                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, "%s%s" % (host, path), "suspicious http request (missing host header)", "(heuristic)"))

                    index = tcp_data.find("\r\n\r\n")
                    if index >= 0:
                        post_data = tcp_data[index:]

                    if "://" in path:
                        url = path.split("://", 1)[1]

                        if '/' not in url:
                            url = "%s/" % url

                        host, path = url.split('/', 1)
                        host = re.sub(r":80\Z", "", host)
                        path = "/%s" % path
                        proxy_domain = host.split(':')[0]
                        _check_domain(proxy_domain, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP)
                    elif method == "CONNECT":
                        if '/' in path:
                            host, path = path.split('/', 1)
                            path = "/%s" % path
                        else:
                            host, path = path, '/'
                        host = re.sub(r":80\Z", "", host)
                        url = "%s%s" % (host, path)
                        proxy_domain = host.split(':')[0]
                        _check_domain(proxy_domain, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP)
                    else:
                        url = "%s%s" % (host, path)

                    if config.USE_HEURISTICS:
                        user_agent, result = None, None
                        match = re.search("(?i)\r\nUser-Agent:([^\r\n]+)", tcp_data)
                        if match:
                            user_agent = urllib.unquote(match.group(1)).strip()

                        if user_agent:
                            result = _result_cache.get(user_agent)
                            if result is None:
                                if not any(_ in user_agent for _ in WHITELIST_UA_KEYWORDS):
                                    match = re.search(SUSPICIOUS_UA_REGEX, user_agent)
                                    if match:
                                        result = _result_cache[user_agent] = match.group(0).join(("(%s)" if _ else "%s") % _.replace('(', "\\(").replace(')', "\\)") for _ in user_agent.split(match.group(0), 1))
                                if not result:
                                    _result_cache[user_agent] = False
                            if result:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.UA, result, "suspicious user agent", "(heuristic)"))

                        if not result and config.CHECK_SHORT_OR_MISSING_USER_AGENT:
                            if user_agent is None:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, url, "suspicious http request (missing user agent header)", "(heuristic)"))
                            elif len(user_agent) < SUSPICIOUS_UA_LENGTH_THRESHOLD:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.UA, user_agent, "suspicious user agent (too short)", "(heuristic)"))

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
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, trails[check][0], trails[check][1]))
                                return

                    if config.USE_HEURISTICS:
                        if any(char in path for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS):
                            for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS:
                                path = path.replace(char, urllib.quote(char))

                        if host not in WHITELIST:
                            if not any(_ in path for _ in WHITELIST_HTTP_REQUEST_KEYWORDS):
                                result = _result_cache.get(path)
                                if result is None:
                                    result = _result_cache[path] = re.search(SUSPICIOUS_HTTP_REQUEST_REGEX, urllib.unquote(path)) is not None
                                if result:
                                    trail = "%s(%s)" % (host, path)
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "suspicious http request", "(heuristic)"))
                                    return

                            if post_data and not any(_ in post_data for _ in WHITELIST_HTTP_REQUEST_KEYWORDS):
                                result = _result_cache.get(post_data)
                                if result is None:
                                    result = _result_cache[post_data] = re.search(SUSPICIOUS_HTTP_REQUEST_REGEX, urllib.unquote(post_data)) is not None
                                if result:
                                    trail = "%s(%s \(%s %s\))" % (host, path, method, post_data.strip())
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "suspicious http request", "(heuristic)"))
                                    return

                        if '.' in path:
                            _ = urlparse.urlparse("http://%s" % url)  # dummy scheme
                            filename = _.path.split('/')[-1]
                            name, extension = os.path.splitext(filename)
                            if extension and extension in SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS and not any(_ in path for _ in WHITELIST_DIRECT_DOWNLOAD_KEYWORDS) and '.'.join(host.split('.')[-2:]) not in WHITELIST and not _.query and len(name) < 10:
                                trail = "%s(%s)" % (host, path)
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "direct %s download (suspicious)" % extension, "(heuristic)"))
                            elif filename in SUSPICIOUS_FILENAMES:
                                trail = "%s(%s)" % (host, path)
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "suspicious page", "(heuristic)"))

        elif protocol == socket.IPPROTO_UDP:  # UDP
            _ = ip_data[iph_length:iph_length + 4]
            if len(_) < 4:
                return

            src_port, dst_port = struct.unpack("!HH", _)

            if src_port != 53:
                if dst_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]))
                elif src_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]))

            if dst_port == 53 or src_port == 53:
                dns_data = ip_data[iph_length + 8:]

                # Reference: http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
                if len(dns_data) > 6:
                    qdcount = struct.unpack("!H", dns_data[4:6])[0]
                    if qdcount > 0:
                        offset = 12
                        query = ""

                        while len(dns_data) > offset:
                            length = ord(dns_data[offset])
                            if not length:
                                query = query[:-1]
                                break
                            query += dns_data[offset + 1:offset + length + 1] + '.'
                            offset += length + 1

                        if ' ' in query or '.' not in query or any(query.endswith(_) for _ in IGNORE_DNS_QUERY_SUFFIXES):
                            return

                        if ord(dns_data[2]) == 0x01:  # standard query
                            type_, class_ = struct.unpack("!HH", dns_data[offset + 1:offset + 5])

                            # Reference: http://en.wikipedia.org/wiki/List_of_DNS_record_types
                            if type_ not in (12, 28) and class_ == 1:  # Type not in (PTR, AAAA), Class IN
                                _check_domain(query, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP)

                        elif config.USE_HEURISTICS:
                            if (ord(dns_data[2]) & 0x80) and (ord(dns_data[3]) == 0x83):  # standard response, recursion available, no such name
                                parts = query.split('.')
                                if not (len(parts) > 4 and all(_.isdigit() and int(_) < 256 for _ in parts[:4])):  # generic check for DNSBL IP lookups
                                    for _ in filter(None, (query, "*.%s" % '.'.join(parts[-2:]) if query.count('.') > 1 else None)):
                                        if _ not in NO_SUCH_NAME_COUNTERS or NO_SUCH_NAME_COUNTERS[_][0] != sec / 3600:
                                            NO_SUCH_NAME_COUNTERS[_] = [sec / 3600, 1, set()]
                                        else:
                                            NO_SUCH_NAME_COUNTERS[_][1] += 1
                                            NO_SUCH_NAME_COUNTERS[_][2].add(query)

                                            if NO_SUCH_NAME_COUNTERS[_][1] > NO_SUCH_NAME_PER_HOUR_THRESHOLD and _ not in WHITELIST and '.'.join(_.split('.')[-2:]) not in WHITELIST:
                                                if _.startswith("*."):
                                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, "%s%s" % ("(%s)" % ','.join(item.replace(_[1:], "") for item in NO_SUCH_NAME_COUNTERS[_][2]), _[1:]), "excessive no such domain name (suspicious)", "(heuristic)"))
                                                    for item in NO_SUCH_NAME_COUNTERS[_][2]:
                                                        try:
                                                            del NO_SUCH_NAME_COUNTERS[item]
                                                        except KeyError:
                                                            pass
                                                else:
                                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, _, "excessive no such domain name (suspicious)", "(heuristic)"))

                                                try:
                                                    del NO_SUCH_NAME_COUNTERS[_]
                                                except KeyError:
                                                    pass

                                                break

                                    # Reference: https://github.com/exp0se/dga_detector
                                    for part in parts:
                                        if part:
                                            consonants = re.findall("(?i)[bcdfghjklmnpqrstvwxyz]", part)
                                            if len(consonants) > SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD:
                                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, query, "high consonant no such domain name (suspicious)", "(heuristic)"))
                                                break

                                            probabilities = (float(part.count(c)) / len(part) for c in set(_ for _ in part))
                                            entropy = -sum(p * math.log(p) / math.log(2.0) for p in probabilities)
                                            if entropy > SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD:
                                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, query, "high entropy no such domain name (suspicious)", "(heuristic)"))
                                                break

        elif protocol in IPPROTO_LUT:  # non-TCP/UDP (e.g. ICMP)
            if protocol == socket.IPPROTO_ICMP:
                if ord(ip_data[iph_length]) != 8:  # Non-echo request
                    return

            if dst_ip in trails:
                log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]))
            elif src_ip in trails:
                log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]))

    except struct.error:
        pass

    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()

def init():
    """
    Performs sensor initialization
    """

    global _multiprocessing

    if config.USE_MULTIPROCESSING:
        try:
            import multiprocessing

            if multiprocessing.cpu_count() > 1:
                _multiprocessing = multiprocessing
        except (ImportError, OSError, NotImplementedError):
            pass

    def update_timer():
        _ = update_trails(server=config.UPDATE_SERVER)

        update_ipcat()

        if _:
            trails.clear()
            trails.update(_)
        elif not trails:
            trails.update(load_trails())

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    create_log_directory()
    get_error_log_handle()

    check_memory()
    update_timer()

    if check_sudo() is False:
        exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)

    interfaces = set(_.strip() for _ in config.MONITOR_INTERFACE.split(','))

    if (config.MONITOR_INTERFACE or "").lower() == "any":
        if subprocess.mswindows or "any" not in pcapy.findalldevs():
            print("[x] virtual interface 'any' missing. Replacing it with all interface names")
            interfaces = pcapy.findalldevs()
        else:
            print("[?] in case of any problems with packet capture on virtual interface 'any', please put all monitoring interfaces to promiscuous mode manually (e.g. 'sudo ifconfig eth0 promisc')")

    for interface in interfaces:
        if interface.lower() != "any" and interface not in pcapy.findalldevs():
            hint = "[?] available interfaces: '%s'" % ",".join(pcapy.findalldevs())
            exit("[!] interface '%s' not found\n%s" % (interface, hint))

        print("[i] opening interface '%s'" % interface)
        try:
            _caps.append(pcapy.open_live(interface, SNAP_LEN, True, CAPTURE_TIMEOUT))
        except (socket.error, pcapy.PcapError):
            if "permitted" in str(sys.exc_info()[1]):
                exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)
            elif "No such device" in str(sys.exc_info()[1]):
                exit("[!] no such device '%s'" % interface)
            else:
                raise

    if config.LOG_SERVER and not len(config.LOG_SERVER.split(':')) == 2:
        exit("[!] invalid configuration value for 'LOG_SERVER' ('%s')" % config.LOG_SERVER)

    if config.CAPTURE_FILTER:
        print("[i] setting filter '%s'" % config.CAPTURE_FILTER)
        for _cap in _caps:
            _cap.setfilter(config.CAPTURE_FILTER)

    if _multiprocessing:
        _init_multiprocessing()

    if not subprocess.mswindows:
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
                msg, _ = "[?] please install 'schedtool' for better CPU scheduling", platform.linux_distribution()[0].lower()
                for distro, install in {("fedora", "centos"): "sudo yum install schedtool", ("debian", "ubuntu"): "sudo apt-get install schedtool"}.items():
                    if _ in distro:
                        msg += " (e.g. '%s')" % install
                        break
                print(msg)
        except:
            pass

def _init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    global _buffer
    global _n

    if _multiprocessing:
        try:
            _buffer = mmap.mmap(-1, config.CAPTURE_BUFFER)  # http://www.alexonlinux.com/direct-io-in-python

            _ = "\x00" * MMAP_ZFILL_CHUNK_LENGTH
            for i in xrange(config.CAPTURE_BUFFER / MMAP_ZFILL_CHUNK_LENGTH):
                _buffer.write(_)
            _buffer.seek(0)
        except:
            exit("[!] unable to allocate network capture buffer. Please adjust value of 'CAPTURE_BUFFER'")

        print("[i] creating %d more processes (%d CPU cores detected)" % (_multiprocessing.cpu_count() - 1, _multiprocessing.cpu_count()))
        _n = _multiprocessing.Value('L', lock=False)

        for i in xrange(_multiprocessing.cpu_count() - 1):
            process = _multiprocessing.Process(target=worker, name=str(i), args=(_buffer, _n, i, _multiprocessing.cpu_count() - 1, _process_ip))
            process.daemon = True
            process.start()

def monitor():
    """
    Sniffs/monitors given capturing interface
    """

    print("[o] running...")

    def packet_handler(datalink, header, packet):
        global _count

        ip_offset = None
        dlt_offset = DLT_OFFSETS[datalink]

        try:
            if datalink == pcapy.DLT_RAW:
                ip_offset = dlt_offset
            elif datalink == pcapy.DLT_PPP:
                if ord(packet[2]) == 0 and ord(packet[3]) == 0x21:  # IPv4
                    ip_offset = dlt_offset
            else:
                if ord(packet[dlt_offset - 2]) == 8 and ord(packet[dlt_offset - 1]) == 0:  # IPv4
                    ip_offset = dlt_offset

                elif ord(packet[dlt_offset - 2]) == 0x81 and ord(packet[dlt_offset - 1]) == 0:  # VLAN
                    if ord(packet[dlt_offset + 2]) == 8 and ord(packet[dlt_offset + 3]) == 0: # IPv4
                        ip_offset = dlt_offset + 4

        except IndexError:
            pass

        if ip_offset is None:
            return

        data = packet[ip_offset:]

        try:
            sec, usec = header.getts()
            if _multiprocessing:
                if _locks.count:
                    _locks.count.acquire()

                write_block(_buffer, _count, struct.pack("=II", sec, usec) + data)
                _count += 1
                _n.value = _count

                if _locks.count:
                    _locks.count.release()
            else:
                _process_ip(data, sec, usec)
        except socket.timeout:
            pass

    try:
        def _(_cap):
            datalink = _cap.datalink()
            while True:
                try:
                    (header, packet) = _cap.next()
                    packet_handler(datalink, header, packet)
                except (pcapy.PcapError, socket.timeout):
                    pass

        if len(_caps) > 1:
            if _multiprocessing:
                _locks.count = threading.Lock()
            _locks.connect_sec = threading.Lock()

        for _cap in _caps:
            threading.Thread(target=_, args=(_cap,)).start()

        while threading.activeCount() > 1:
            time.sleep(1)
    except SystemError, ex:
        if "error return without" in str(ex):
            print("\r[x] Ctrl-C pressed")
        else:
            raise
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
        exit("[!] please run '%s' with sudo/Administrator privileges" % __file__)

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
        msg = "\r[!] unhandled exception occurred ('%s')" % sys.exc_info()[1]
        msg += "\n[x] please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()
        log_error("\n\n%s" % msg.replace("\r", ""))

        print(msg)

    os._exit(0)
