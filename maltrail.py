#!/usr/bin/env python

from __future__ import print_function

import BaseHTTPServer
import httplib
import logging
import pickle
import optparse
import os
import re
import socket, SocketServer
import sqlite3
import subprocess
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

NAME = "MalTrail"
VERSION = "0.1l"
AUTHOR = "Miroslav Stampar (@stamparm)"
LICENSE = "Public domain (FREE)"

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.all import *
except ImportError:
    exit("[!] please install Scapy (e.g. '%s')" % ("sudo apt-get install scapy" if not subprocess.mswindows else "http://www.secdev.org/projects/scapy/doc/installation.html#windows"))

ROTATING_CHARS = ('\\', '|', '|', '/', '-')
TIMEOUT = 30
FRESH_LISTS_DELTA_DAYS = 2
DOMAINS_FILE = "domains.bin"
HISTORY_FILE = "history.bin"
OUTPUT_FORMAT = "|{0:^15s}|{1:^40s}|{2:^17s}|{3:^15s}|{4:^21s}|"
TIME_FORMAT = "%y/%m/%d %H:%M:%S"
REPORT_HEADERS = ("ip", "domain lookup", "time", "type", "reference")
HTTP_REPORTING_PORT = 8338

# Reference: http://www.scriptiny.com/2008/11/javascript-table-sorter/
HTML_OUTPUT_TEMPLATE = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>%s</title>
<style>
*{margin:0;padding:0}body{font:10px Verdana,Arial}#wrapper{width:825px;margin:50px auto}.sortable{width:823px;border:1px solid #ccc;border-bottom:none}.sortable th{padding:4px 6px 6px;background:#444;color:#fff;text-align:left;color:#ccc}.sortable td{padding:2px 4px 4px;background:#fff;border-bottom:1px solid #ccc}.sortable .head{background:#444 url(images/sort.gif) 6px center no-repeat;cursor:pointer;padding-left:18px}.sortable .desc{background:#222 url(images/desc.gif) 6px center no-repeat;cursor:pointer;padding-left:18px}.sortable .asc{background:#222 url(images/asc.gif) 6px center no-repeat;cursor:pointer;padding-left:18px}.sortable .head:hover,.sortable .desc:hover,.sortable .asc:hover{color:#fff}.sortable .even td{background:#f2f2f2}.sortable .odd td{background:#fff}
</style>
<script>
var table=function(){function e(e){this.n=e;this.t;this.b;this.r;this.d;this.p;this.w;this.a=[];this.l=0}function t(e){if(/^\d+\.\d+\.\d+\.\d+$/.test(e)){return true}else{return false}}function n(e){if(/^[\d\/]+ [\d:]+$/.test(e)){return true}else{return false}}function r(e,r){e=e.value,r=r.value;if(t(e)&&t(r)){var i=e.split(".");var s=r.split(".");e=(parseInt(i[0])<<24)+(parseInt(i[1])<<16)+(parseInt(i[2])<<8)+parseInt(i[3])>>>0;r=(parseInt(s[0])<<24)+(parseInt(s[1])<<16)+(parseInt(s[2])<<8)+parseInt(s[3])>>>0}else if(n(e)&&n(r)){e=parseInt(e.replace(/[:\/ ]/g,""));r=parseInt(r.replace(/[:\/ ]/g,""))}return e>r?1:e<r?-1:0}e.prototype.init=function(e,t){this.t=document.getElementById(e);this.b=this.t.getElementsByTagName("tbody")[0];this.r=this.b.rows;var n=this.r.length;for(var r=0;r<n;r++){if(r==0){var i=this.r[r].cells;this.w=i.length;for(var s=0;s<this.w;s++){if(i[s].className!="nosort"){i[s].className="head";i[s].onclick=new Function(this.n+".work(this.cellIndex)")}}}else{this.a[r-1]={};this.l++}}if(t!=null){var o=new Function(this.n+".work("+t+")");o()}};e.prototype.work=function(e){this.b=this.t.getElementsByTagName("tbody")[0];this.r=this.b.rows;var t=this.r[0].cells[e],n;for(n=0;n<this.l;n++){this.a[n].o=n+1;var i=this.r[n+1].cells[e].firstChild;this.a[n].value=i!=null?i.nodeValue:""}for(n=0;n<this.w;n++){var s=this.r[0].cells[n];if(s.className!="nosort"){s.className="head"}}if(this.p==e){this.a.reverse();t.className=this.d?"asc":"desc";this.d=this.d?false:true}else{this.p=e;this.a.sort(r);t.className="asc";this.d=false}var o=document.createElement("tbody");o.appendChild(this.r[0]);for(n=0;n<this.l;n++){var u=this.r[this.a[n].o-1].cloneNode(true);o.appendChild(u);u.className=n%%2==0?"even":"odd"}this.t.replaceChild(o,this.b)};return{sorter:e}}()
</script>
</head>
<body>
<div id="wrapper">
<table cellpadding="0" cellspacing="0" border="0" class="sortable" id="sorter">
%s
</table>

<form name="search" id="search" method="post" action="/">
<table style="margin:0; padding-top: 1cm;" border="0" cellpadding="2" cellspacing="2">
<tbody><tr>
<td>From:&nbsp;&nbsp;</td>
<td colspan="2"><select name="dayfrom">
<option value="">day
</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option><option value="13">13</option><option value="14">14</option><option value="15">15</option><option value="16">16</option><option value="17">17</option><option value="18">18</option><option value="19">19</option><option value="20">20</option><option value="21">21</option><option value="22">22</option><option value="23">23</option><option value="24">24</option><option value="25">25</option><option value="26">26</option><option value="27">27</option><option value="28">28</option><option value="29">29</option><option value="30">30</option><option value="31">31
</option></select>
<select name="monthfrom">
<option value="">month
</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12
</option></select>
<select name="yearfrom">
<option value="">year
</option><option value="2011">2011</option><option value="2012">2012</option><option value="2013">2013</option><option value="2014">2014
</option></select></td>
</tr>
<tr>
<td>To:&nbsp;&nbsp;</td>
<td colspan="2"><select name="dayto">
<option value="">day
</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option><option value="13">13</option><option value="14">14</option><option value="15">15</option><option value="16">16</option><option value="17">17</option><option value="18">18</option><option value="19">19</option><option value="20">20</option><option value="21">21</option><option value="22">22</option><option value="23">23</option><option value="24">24</option><option value="25">25</option><option value="26">26</option><option value="27">27</option><option value="28">28</option><option value="29">29</option><option value="30">30</option><option value="31">31

</option></select>
<select name="monthto">
<option value="">month
</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12
</option></select>
<select name="yearto">
<option value="">year
</option><option value="2011">2011</option><option value="2012">2012</option><option value="2013">2013</option><option value="2014">2014
</option></select></td>
</tr>

<tr>
<td>Domain:</td>
<td colspan="2">
<table border="0" cellpadding="0" cellspacing="0">
<tbody><tr>
    <td class="searchboxWrapper"><input name="domain" value="" type="text"></td>
    <td><input style="background: url('images/search.gif') no-repeat scroll 0 0 rgba(0, 0, 0, 0); width: 25px" value="" type="submit"></td>
</tr>
</tbody></table>
</td>
</tr>

</tbody></table>
</form>

</div>
<script type="text/javascript">
var sorter=new table.sorter("sorter");
sorter.init("sorter");
</script>
</body>
</html>
"""

HTTP_RAW_FILES = {
    "/images/asc.gif": "GIF89a\x05\x00\x03\x00\x80\x01\x00\xff\xff\xff\xff\xff\xff!\xf9\x04\x01\x00\x00\x01\x00,\x00\x00\x00\x00\x05\x00\x03\x00\x00\x02\x05L`\x07\xb8]\x00;",
    "/images/desc.gif": "GIF89a\x05\x00\x03\x00\x80\x01\x00\xff\xff\xff\xff\xff\xff!\xf9\x04\x01\x00\x00\x01\x00,\x00\x00\x00\x00\x05\x00\x03\x00\x00\x02\x05\x84\x1d\x17\x0b[\x00;",
    "/images/sort.gif": "GIF89a\x05\x00\x08\x00\x80\x01\x00\xb7\xb7\xb7\xff\xff\xff!\xf9\x04\x01\x00\x00\x01\x00,\x00\x00\x00\x00\x05\x00\x08\x00\x00\x02\x0bL`\x07\xb8\x9d\x9f\xdaR\xc8\xd4\x02\x00;",
    "/images/search.gif": "GIF89a\x18\x00\x18\x00\x80\x01\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\n\x00\x01\x00,\x00\x00\x00\x00\x18\x00\x18\x00\x00\x02@\x8c\x8f\xa9\x8b\xe0\x0c\x83\x9b4\xb6w\x81\x95\xda\xf4\x831\xd8\x97\x84\xcaC\x9eP*\x8a\x1a[\xba\x1b\xb7\x98+,\xcd8m\xed\xf6\xb9\xe3\xd5\x82\x1eX\xa5G\xa9Lf\xc5\xd2\x8fY$\"\xa5\x11*\xf4\x8a\x85\x16\x00\x00;",
}

MALWAREDOMAINLIST_URL = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
MALWAREDOMAINS_URL = "http://malwaredomains.lehigh.edu/files/domains.txt"
ZEUS_ABUSECH_URL = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
EMERGING_THREATS_URL = "https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules"

_header = None
_console_width = None
_domains = {}
_thread_data = threading.local()

def _retrieve_content(url, data=None):
    try:
        req = urllib2.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in xrange(len(url))), data, {"User-agent": NAME})
        retval = urllib2.urlopen(req, timeout=TIMEOUT).read()
    except Exception, ex:
        retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    return retval or ""

def _html_output(title, headers, rows):
    retval = "<tr>\n"
    for header in REPORT_HEADERS:
        retval += "<th>%s</th>" % header
    retval += "\n</tr>\n"
    for row in rows:
        retval += "<tr>"
        for entry in row:
            retval += "<td>%s</td>" % entry
        retval += "</tr>"
    return HTML_OUTPUT_TEMPLATE % ("%s report" % NAME, retval)

def _get_cursor():
    if not hasattr(_thread_data, "cursor"):
        _thread_data.connection = sqlite3.connect(HISTORY_FILE, isolation_level=None)
        _thread_data.cursor = _thread_data.connection.cursor()
        _thread_data.cursor.execute("CREATE TABLE IF NOT EXISTS history(ip TEXT, domain_lookup TEXT, time REAL, type TEXT, reference TEXT)")
    return _thread_data.cursor

def _store_db(ip, domain_lookup, time, type_, reference):
    _get_cursor().execute("INSERT INTO history VALUES('%s', '%s', %s, '%s', '%s')" % (ip, domain_lookup, time, type_, reference))

def _close_db():
    if hasattr(_thread_data, "cursor"):
        _thread_data.connection.commit()
        _thread_data.cursor.close()
        _thread_data.connection.close()

def _create_report(order=None, limit=None, offset=None, mintime=None, maxtime=None):
    query = "SELECT * FROM history"
    if mintime:
        query += " WHERE time >= %s" % re.sub(r"[^0-9.]", "", str(mintime))
    if maxtime:
        query += " %s time <= %s" % ("AND" if mintime else "WHERE", re.sub(r"[^0-9.]", "", str(maxtime)))
    if order:
        query += " ORDER BY time %s" % re.sub(r"[^A-Za-z]", "", order)
    if limit:
        query += " LIMIT %s" % re.sub(r"[^0-9]", "", str(limit))
    if offset:
        query += " OFFSET %s" % re.sub(r"[^0-9]", "", str(offset))
    _get_cursor().execute(query)
    rows = _get_cursor().fetchall()
    for i in xrange(len(rows)):
        rows[i] = rows[i][:2] + (time.strftime(TIME_FORMAT, time.localtime(rows[i][2])),) + rows[i][3:]
    return _html_output(NAME, REPORT_HEADERS, rows)

def _start_httpd():
    class ThreadingServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
        pass

    class ReqHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
            if path in HTTP_RAW_FILES:
                content = HTTP_RAW_FILES[path]
                length = len(content)
                self.send_response(httplib.OK)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(length))
                self.end_headers()
                self.wfile.write(content)
            elif path == '/':
                mintime, maxtime = None, None
                params = {}
                if hasattr(self, "data"):
                    params.update(urlparse.parse_qs(self.data))
                if query:
                    params.update(urlparse.parse_qs(query))
                for key in params:
                    if params[key]:
                        params[key] = params[key][-1]
                if params.get("yearfrom"):
                    mintime = time.mktime(time.strptime("%d/%02d/%02d" % (int(params.get("yearfrom")), int(params.get("monthfrom", 1)), int(params.get("dayfrom", 1))), "%Y/%m/%d"))
                if params.get("yearto"):
                    maxtime = time.mktime(time.strptime("%d/%02d/%02d" % (int(params.get("yearto")), int(params.get("monthto", 1)), int(params.get("dayto", 1))), "%Y/%m/%d"))
                content = _create_report(order=params.get("order", "DESC"), limit=params.get("limit"), offset=params.get("offset"), mintime=mintime, maxtime=maxtime)
                length = len(content)
                self.send_response(httplib.OK)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(length))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(httplib.NOT_FOUND)

        def do_POST(self):
            length = self.headers.getheader("Content-Length")
            data = self.rfile.read(int(length))
            data = urllib.unquote_plus(data)
            self.data = data
            self.do_GET()

        def log_message(self, format, *args):
            return

    server = ThreadingServer(('', HTTP_REPORTING_PORT), ReqHandler)
    print("[i] using address '%s:%d' for HTTP reporting" % ("*" if not server.server_address[0].strip("0.") else server.server_address[0], server.server_address[1]))

    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

def _check_sudo():
    check = None

    if not subprocess.mswindows:
        if getattr(os, "geteuid"):
            check = os.geteuid() == 0
    else:
        import ctypes
        check = ctypes.windll.shell32.IsUserAnAdmin()

    if check is False:
        exit("[x] please run with sudo/Administrator privileges")

def _get_console_width(default=80):
    width = None

    if os.getenv("COLUMNS", "").isdigit():
        width = int(os.getenv("COLUMNS"))
    else:
        try:
            try:
                FNULL = open(os.devnull, 'w')
            except IOError:
                FNULL = None
            process = subprocess.Popen("stty size", shell=True, stdout=subprocess.PIPE, stderr=FNULL or subprocess.PIPE)
            stdout, _ = process.communicate()
            items = stdout.split()

            if len(items) == 2 and items[1].isdigit():
                width = int(items[1])
        except OSError:
            pass

    if width is None:
        try:
            import curses
            stdscr = curses.initscr()
            _, width = stdscr.getmaxyx()
            curses.endwin()
        except:
            pass

    return width or default

def _trim_output(value):
    global _console_width

    _console_width = _console_width or _get_console_width()

    return value[:_console_width]

def _print_details(ip, domain_lookup, time, type, reference):
    global _header

    if not _header:
        _header = _trim_output(OUTPUT_FORMAT.format(*REPORT_HEADERS))
        print(" \n%s\n%s\n%s" % ("-" * len(_header), _header, "-" * len(_header)))

    print(_trim_output(OUTPUT_FORMAT.format(ip, domain_lookup, time, type, reference)))

def load_domains(bulkfile=None):
    """
    Loads suspicious/malicious domain lists
    """

    global _domains

    if bulkfile:
        if not os.path.isfile(bulkfile):
            exit("[x] file '%s' does not exist" % bulkfile)

        content = open(bulkfile, "rb").read()
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _domains[line] = ("suspicious", "custom")

    if not os.path.isfile(DOMAINS_FILE) or (time.time() - os.stat(DOMAINS_FILE).st_mtime) / 3600 / 24 > FRESH_LISTS_DELTA_DAYS:
        print("[i] %s domain lists..." % ("updating" if os.path.isfile(DOMAINS_FILE) else "retrieving"))

        print(" [o] '%s'" % MALWAREDOMAINLIST_URL)
        content = _retrieve_content(MALWAREDOMAINLIST_URL)
        if "127.0.0.1" not in content:
            print("[!] something went wrong during remote data retrieval ('%s')" % MALWAREDOMAINLIST_URL)

        for line in content.split('\n'):
            line = line.strip('\r')
            if not line or line.startswith('#'):
                continue
            items = line.split('\s+')
            if items[0] == "127.0.0.1" and items[1] != "localhost":
                _domains[items[1]] = ("malware", "MDL")

        print(" [o] '%s'" % MALWAREDOMAINS_URL)
        content = _retrieve_content(MALWAREDOMAINS_URL)
        if "safebrowsing.clients.google.com" not in content:
            print("[!] something went wrong during remote data retrieval ('%s')" % MALWAREDOMAINS_URL)

        for line in content.split('\n'):
            line = line.strip('\r')
            if not line or line.startswith('#'):
                continue
            items = line.split('\t')
            _domains[items[2]] = (items[3], items[4].split('/')[0] if '/' in items[4] else items[4])   # (type, original_reference-why_it_was_listed)

        print(" [o] '%s'" % ZEUS_ABUSECH_URL)
        content = _retrieve_content(ZEUS_ABUSECH_URL)
        if "ZeuS" not in content:
            print("[!] something went wrong during remote data retrieval ('%s')" % ZEUS_ABUSECH_URL)

        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _domains[line] = ("ZeuS", "abuse.ch")

        print(" [o] '%s'" % EMERGING_THREATS_URL)
        content = _retrieve_content(EMERGING_THREATS_URL)
        if "Emerging Threats" not in content:
            print("[!] something went wrong during remote data retrieval ('%s')" % EMERGING_THREATS_URL)

        for match in re.finditer(r"(?i)Suspicious \*?\.([^\s]+) domain", content):
            _domains[match.group(1)] = ("suspicious", "emergingthreats.net")

        for match in re.finditer(r"(?i)C2 Domain \.?([^\s\"]+)", content):
            _domains[match.group(1)] = ("C&C", "emergingthreats.net")

        try:
            with open(DOMAINS_FILE, "w+b") as f:
                f.write(zlib.compress(pickle.dumps(_domains)))
        except Exception, ex:
            print("[!] something went wrong during cache file write '%s' ('%s')" % (DOMAINS_FILE, ex))

    if not _domains:
        print("[i] loading cache...")
        try:
            with open(DOMAINS_FILE, "rb") as f:
                _domains = pickle.loads(zlib.decompress(f.read()))
        except Exception, ex:
            exit("[x] something went wrong during cache file read '%s' ('%s')" % (DOMAINS_FILE, ex))

    print("[i] %d suspicious domain names loaded" % len(_domains))

def inspect_packet(packet):
    """
    Processes packet and prints formatted result if found to be suspicious/malicious
    """

    if packet.haslayer(DNSQR) and not packet.haslayer(DNSRR):
        request = packet.getlayer(DNSQR)
        if request.qtype == 1:
            domain = request.qname.strip('.')
            parts = domain.split('.')
            for i in xrange(0, len(parts) - 1):
                _ = '.'.join(parts[i:])
                if _ in _domains:
                    ip, type_, reference = packet.getlayer(IP).src, _domains[_][0], _domains[_][1]
                    _print_details(ip, domain, time.strftime(TIME_FORMAT, time.localtime(packet.time)), type_, reference)
                    _store_db(ip, domain, packet.time, type_, reference)
                    break

def process_pcap(pcapfile):
    """
    Reads .pcap file and inspects packets from it
    """

    print("[i] reading packets from '%s'..." % pcapfile)

    if not os.path.isfile(pcapfile):
        exit("[x] file '%s' does not exist" % pcapfile)
    try:
        packets = PcapReader(pcapfile)
    except Exception, ex:
        if "Not a pcap capture file" in traceback.format_exc():
            ex = "Not a pcap capture file"
        exit("[x] there has been a problem with reading file '%s' ('%s')" % (pcapfile, ex))

    count = 0
    for packet in packets:
        count += 1
        sys.stdout.write('%s\r' % ROTATING_CHARS[count % len(ROTATING_CHARS)])
        inspect_packet(packet)
    if not _header:
        print("[i] no suspicious domain lookups found")

def monitor_interface(interface):
    """
    Sniffs/monitors given interface and inspects DNS packets found on it
    """

    print("[i] monitoring interface '%s'..." % interface)

    try:
        sniff(iface=interface if interface.lower() != "any" else None, prn=inspect_packet, filter="udp dst port 53", store=0)
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
        _close_db()

if __name__ == "__main__":
    if "--quiet" in sys.argv:
        def print(*args, **kwargs):
            pass
        print_function = print

    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("--quiet", dest="quiet", action="store_true", help="turn off program's console output")
    parser.add_option("-i", dest="interface", help="listen DNS traffic on interface (e.g. eth0)")
    parser.add_option("-r", dest="pcapfile", help="read packets from (.pcap) file")
    parser.add_option("-l", dest="bulkfile", help="load domain list from file (optional)")
    options, _ = parser.parse_args()
    if any((options.interface, options.pcapfile)):
        if options.interface:
            _check_sudo()
        _start_httpd()
        load_domains(options.bulkfile)
        if options.pcapfile:
            process_pcap(options.pcapfile)
        elif options.interface:
            monitor_interface(options.interface)
        if _header:
            print("-" * len(_header))
    else:
        parser.print_help()
