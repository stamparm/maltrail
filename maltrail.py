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
VERSION = "0.1m"
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
STORAGE_DIRECTORY = os.path.join(os.path.expanduser("~"), ".%s" % NAME.lower())
CACHE_FILE = os.path.join(STORAGE_DIRECTORY, "cache.bin")
HISTORY_FILE = os.path.join(STORAGE_DIRECTORY, "history.bin")
OUTPUT_FORMAT = "|{0:^15s}|{1:^40s}|{2:^17s}|{3:^15s}|{4:^21s}|"
TIME_FORMAT = "%d/%m/%Y %H:%M:%S"
REPORT_HEADERS = ("time", "ip", "domain lookup", "type", "reference")
HTTP_REPORTING_PORT = 8338

# Reference: http://www.scriptiny.com/2008/11/javascript-table-sorter/
HTML_OUTPUT_TEMPLATE = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>%s</title>
<style>
*{margin:0;padding:0}body{font:10px Verdana,Arial}#wrapper{width:825px;margin:50px auto}.sortable{width:823px;border:1px solid #ccc;border-bottom:none}.sortable th{padding:4px 6px 6px;background:#444;color:#fff;text-align:left;color:#ccc}.sortable td{padding:2px 4px 4px;background:#fff;border-bottom:1px solid #ccc}.sortable .head{background:#444 url(data:image/png;base64,R0lGODlhBQAIAIABALe3t////yH5BAEAAAEALAAAAAAFAAgAAAILTGAHuJ2f2lLI1AIAOw==) 6px center no-repeat;cursor:pointer;padding-left:18px}.sortable .desc{background:#222 url(data:image/png;base64,R0lGODlhBQADAIABAP///////yH5BAEAAAEALAAAAAAFAAMAAAIFhB0XC1sAOw==) 6px center no-repeat;cursor:pointer;padding-left:18px}.sortable .asc{background:#222 url(data:image/png;base64,R0lGODlhBQADAIABAP///////yH5BAEAAAEALAAAAAAFAAMAAAIFTGAHuF0AOw==) 6px center no-repeat;cursor:pointer;padding-left:18px}.sortable .head:hover,.sortable .desc:hover,.sortable .asc:hover{color:#fff}.sortable .even td{background:#f2f2f2}.sortable .odd td{background:#fff}
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
<!--filter-->
</div>
<script type="text/javascript">
var sorter=new table.sorter("sorter");
sorter.init("sorter", 0);
</script>
</body>
</html>
"""

FILTER_FORM = """
<form name="search" id="search" method="post" action="/">
<table style="margin:0; padding-top: 1cm;" border="0" cellpadding="2" cellspacing="2">
<tbody><tr>
<td>From:&nbsp;&nbsp;</td>
<td colspan="2">
<select name="dayfrom"><option value="">day</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option><option value="13">13</option><option value="14">14</option><option value="15">15</option><option value="16">16</option><option value="17">17</option><option value="18">18</option><option value="19">19</option><option value="20">20</option><option value="21">21</option><option value="22">22</option><option value="23">23</option><option value="24">24</option><option value="25">25</option><option value="26">26</option><option value="27">27</option><option value="28">28</option><option value="29">29</option><option value="30">30</option><option value="31">31</option></select>
<select name="monthfrom"><option value="">month</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option></select>
<select name="yearfrom"><option value="">year</option><option value="2011">2011</option><option value="2012">2012</option><option value="2013">2013</option><option value="2014">2014</option></select></td>
</tr>
<tr>
<td>To:&nbsp;&nbsp;</td>
<td colspan="2">
<select name="dayto"><option value="">day</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option><option value="13">13</option><option value="14">14</option><option value="15">15</option><option value="16">16</option><option value="17">17</option><option value="18">18</option><option value="19">19</option><option value="20">20</option><option value="21">21</option><option value="22">22</option><option value="23">23</option><option value="24">24</option><option value="25">25</option><option value="26">26</option><option value="27">27</option><option value="28">28</option><option value="29">29</option><option value="30">30</option><option value="31">31</option></select>
<select name="monthto"><option value="">month</option><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option></select>
<select name="yearto"><option value="">year</option><option value="2011">2011</option><option value="2012">2012</option><option value="2013">2013</option><option value="2014">2014</option></select></td>
</tr>
<tr>
<td>Domain:</td>
<td colspan="2">
<table border="0" cellpadding="0" cellspacing="0">
<tbody><tr>
<td class="searchboxWrapper"><input name="domain" value="" type="text"></td>
<td><input style="background: url('images/search.gif') no-repeat scroll 0 0 rgba(0, 0, 0, 0); width: 24px" value="" type="submit"></td>
</tr>
</tbody></table>
</td>
</tr>
</tbody></table>
</form>
"""

HTTP_RAW_FILES = {
    "/images/search.gif": 'GIF87a\x18\x00\x18\x00\xe70\x00ddf\xe6\xe6\xe6``bbbdxxz\\\\_\x9b\x9b\x9d\xe0\xe0\xe0^^`\xa9\xa9\xaahhj\x90\x90\x92\xce\xce\xcf\xde\xde\xde\xb2\xb2\xb3\xc7\xc7\xc7\xfe\xfe\xfdffhkkl\x8d\x8d\x8euuwnnp\xd1\xd1\xd2\xa5\xa5\xa6||\x80\xbe\xbe\xbf\x85\x85\x87gfk\x97\x96\x99\xb9\xb9\xba\x80\x80\x82\xb5\xb5\xb7\xda\xda\xda\xd5\xd5\xd6\xad\xad\xaf\x9e\x9e\xa0\xa6\xa6\xa8\xa1\xa1\xa3ppr\x88\x88\x8a\xb3\xb3\xb4\xf9\xf9\xfb\xe3\xe3\xe5\xdd\xdd\xdflln\xb7\xb7\xb9\x9d\x9d\x9e\x96\x96\x97WWY\xfa\xfa\xfa\xfb\xfb\xfb\xf9\xf9\xf9\xf8\xf8\xf8\xf6\xf6\xf6\xfc\xfc\xfc\xf1\xf1\xf1\xf2\xf2\xf2\xec\xec\xec\xf0\xf0\xf0\xf7\xf7\xf7\xed\xed\xed\xf4\xf4\xf4\xe5\xe5\xe5\xff\xff\xfe\xf5\xf5\xf5\xe9\xe9\xe9\xf4\xf4\xf5\xaa\xaa\xac\xe3\xe3\xe3\xeb\xeb\xeb\xef\xef\xef\xc4\xc4\xc5\xee\xee\xee\x94\x94\x96``a\xe2\xe2\xe3\xe2\xe2\xe2\xf6\xf6\xf7ssv\x99\x99\x9bdcgaac\xe4\xe4\xe4\xe4\xe4\xe5\xe8\xe8\xe8\xad\xad\xad\x8a\x8a\x8a\xea\xea\xea\xc5\xc5\xc6\xae\xae\xaf\xfc\xfc\xfbcce\xf9\xf9\xf8\xc2\xc2\xc2\xd7\xd7\xd8\x87\x87\x89\xf2\xf2\xf3\xcf\xcf\xd0\x8b\x8b\x8c\x93\x93\x94bbc\xbc\xbc\xbb\xe5\xe5\xe6\xeb\xeb\xec\xef\xef\xf0\xe8\xe8\xe9\xdb\xdb\xdczz{\xe4\xe4\xe3~~\x7f\xc3\xc3\xc4\xf5\xf5\xf4\xdd\xdd\xdd\xfd\xfe\xfeeeg\xfd\xfd\xfe\xfe\xfd\xfe\xbf\xbf\xc1\x82\x82\x84hhhiik\xfb\xfb\xfa\xf1\xf1\xf3\xf3\xf3\xf3wwx\xfd\xfd\xfd\xfe\xfe\xfe\xff\xff\xff\x80\x80\x80\x81\x81\x81\x82\x82\x82\x83\x83\x83\x84\x84\x84\x85\x85\x85\x86\x86\x86\x87\x87\x87\x88\x88\x88\x89\x89\x89\x8a\x8a\x8a\x8b\x8b\x8b\x8c\x8c\x8c\x8d\x8d\x8d\x8e\x8e\x8e\x8f\x8f\x8f\x90\x90\x90\x91\x91\x91\x92\x92\x92\x93\x93\x93\x94\x94\x94\x95\x95\x95\x96\x96\x96\x97\x97\x97\x98\x98\x98\x99\x99\x99\x9a\x9a\x9a\x9b\x9b\x9b\x9c\x9c\x9c\x9d\x9d\x9d\x9e\x9e\x9e\x9f\x9f\x9f\xa0\xa0\xa0\xa1\xa1\xa1\xa2\xa2\xa2\xa3\xa3\xa3\xa4\xa4\xa4\xa5\xa5\xa5\xa6\xa6\xa6\xa7\xa7\xa7\xa8\xa8\xa8\xa9\xa9\xa9\xaa\xaa\xaa\xab\xab\xab\xac\xac\xac\xad\xad\xad\xae\xae\xae\xaf\xaf\xaf\xb0\xb0\xb0\xb1\xb1\xb1\xb2\xb2\xb2\xb3\xb3\xb3\xb4\xb4\xb4\xb5\xb5\xb5\xb6\xb6\xb6\xb7\xb7\xb7\xb8\xb8\xb8\xb9\xb9\xb9\xba\xba\xba\xbb\xbb\xbb\xbc\xbc\xbc\xbd\xbd\xbd\xbe\xbe\xbe\xbf\xbf\xbf\xc0\xc0\xc0\xc1\xc1\xc1\xc2\xc2\xc2\xc3\xc3\xc3\xc4\xc4\xc4\xc5\xc5\xc5\xc6\xc6\xc6\xc7\xc7\xc7\xc8\xc8\xc8\xc9\xc9\xc9\xca\xca\xca\xcb\xcb\xcb\xcc\xcc\xcc\xcd\xcd\xcd\xce\xce\xce\xcf\xcf\xcf\xd0\xd0\xd0\xd1\xd1\xd1\xd2\xd2\xd2\xd3\xd3\xd3\xd4\xd4\xd4\xd5\xd5\xd5\xd6\xd6\xd6\xd7\xd7\xd7\xd8\xd8\xd8\xd9\xd9\xd9\xda\xda\xda\xdb\xdb\xdb\xdc\xdc\xdc\xdd\xdd\xdd\xde\xde\xde\xdf\xdf\xdf\xe0\xe0\xe0\xe1\xe1\xe1\xe2\xe2\xe2\xe3\xe3\xe3\xe4\xe4\xe4\xe5\xe5\xe5\xe6\xe6\xe6\xe7\xe7\xe7\xe8\xe8\xe8\xe9\xe9\xe9\xea\xea\xea\xeb\xeb\xeb\xec\xec\xec\xed\xed\xed\xee\xee\xee\xef\xef\xef\xf0\xf0\xf0\xf1\xf1\xf1\xf2\xf2\xf2\xf3\xf3\xf3\xf4\xf4\xf4\xf5\xf5\xf5\xf6\xf6\xf6\xf7\xf7\xf7\xf8\xf8\xf8\xf9\xf9\xf9\xfa\xfa\xfa\xfb\xfb\xfb\xfc\xfc\xfc\xfd\xfd\xfd\xfe\xfe\xfe\xff\xff\xff,\x00\x00\x00\x00\x18\x00\x18\x00\x00\x08\xfe\x00\xff\xfc\xf1CP`\n=`b\x08\x840\xb0\xa1\xc0\x87\x7fl<\x94\xf2a\x0c\x815\x0b\x1c,y\xe8\x07"G?}ldq\x02\x03\xc1\x86\x08\x02`8I\xa0\xb0\xa3\xc7\x81\x1d\x05l\xa9"\x04\xa2\x10\x11r\xa2\xcc\xf8\xd3\xe7\xa5@\x06[P,\xfc\xf1\xc3e\x8b-X\x1cz\x9c1\xe1E\xc7>}\x8a\xf6q9\xc2\xc3\x8c\x82\x1e\x03(\xf0\xc2\xd3e\xcf\xa9\x7f|D\x00\xe1\xf3\xcf\x03\x01-\t\x12\x9c\xdasG\x94\x16e\x1d\x08\xe8)\xb0\xa0\xda\xa2\x05\x12\x94\xed2\x80\x8e\xcb\x8e.\x05r!\x03\xb7!V3r\xd4\xfc\tr\x05"\x9a4\x7f\x0e\xe0Y\x01\x13\xa4\xcb\x14\x13\x92\xcc1\x80\xc7M\x91\x1b\x0fL\x9c\xf83b@\x82\x1e]\xed\xfe9\x12!\x83\x8a\x13\x08\x08\xb4A\xb0\x06\xc4\x11\x00\t*hPQ7p\x9f\x02\n:\x9c\tS\xc2\x05\x96 e\x14@\t\x11\xc0\x03\x9e\x07J\x1f"\x18`\'\x83\x97\x10u\xbe\x0c\x10\xb0\xa1B\x06\x1c$\xb6T\x90({`\x88\x15>\x04N\x0c\xa1\x1cC\x81\x9c\x01\x1eD\x980\xb1\xd1\xa7\x8c\x00>\xb4@d\xc0gK\x04\x00\nD\xf1\x81Ot\xd5U`\x00\x13\x08\xa0\x00\x1eQ8P\x96a\x7f\t4\x83\x08\x12\x00\xc0\xc2\x01\x04\x06\xd6\x9bC\x0c$a\xc1\x83 \x86(\xe2\x88$\x96Hb@\x00;',
}

MALWAREDOMAINLIST_URL = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
MALWAREDOMAINS_URL = "http://malwaredomains.lehigh.edu/files/domains.txt"
ZEUS_ABUSECH_URL = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
EMERGING_THREATS_URL = "https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules"

_console_width = None
_history_file = HISTORY_FILE
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
        _thread_data.connection = sqlite3.connect(_history_file, isolation_level=None)
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

def _get_time_range():
    min_, max_ = None, None
    query = "SELECT MIN(time), MAX(time) FROM history"
    _get_cursor().execute(query)
    _ = _get_cursor().fetchone()
    if _:
        min_, max_ = _
    return min_, max_

def _create_report(order=None, limit=None, offset=None, mintime=None, maxtime=None, domain=None):
    query = "SELECT * FROM history"
    if mintime:
        query += " WHERE time >= %s" % re.sub(r"[^0-9.]", "", str(mintime))
    if maxtime:
        query += " %s time <= %s" % ("AND" if mintime else "WHERE", re.sub(r"[^0-9.]", "", str(maxtime)))
    if domain:
        query += " %s domain_lookup LIKE '%%%s%%'" % ("AND" if mintime or maxtime else "WHERE", domain.replace("'", "").strip())
    if order:
        query += " ORDER BY time %s" % re.sub(r"[^A-Za-z]", "", order)
    if limit:
        query += " LIMIT %s" % re.sub(r"[^0-9]", "", str(limit))
    if offset:
        query += " OFFSET %s" % re.sub(r"[^0-9]", "", str(offset))
    _get_cursor().execute(query)
    rows = _get_cursor().fetchall()
    for i in xrange(len(rows)):
        rows[i] = (time.strftime(TIME_FORMAT, time.localtime(rows[i][2])),) + rows[i][:2] + rows[i][3:]
    return _html_output(NAME, REPORT_HEADERS, rows)

def _insert_filter(report_html):
    return report_html.replace("<!--filter-->", FILTER_FORM)

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
                min_, max_ = _get_time_range()
                if min_:
                    _ = time.localtime(min_)
                    params.setdefault("yearfrom", _.tm_year)
                    params.setdefault("monthfrom", _.tm_mon)
                    params.setdefault("dayfrom", _.tm_mday)
                if max_:
                    _ = time.localtime(max_)
                    params.setdefault("yearto", _.tm_year)
                    params.setdefault("monthto", _.tm_mon)
                    params.setdefault("dayto", _.tm_mday)
                if params.get("yearfrom"):
                    params.setdefault("monthfrom", 1)
                    params.setdefault("dayfrom", 1)
                    while True:
                        try:
                            mintime = time.mktime(time.strptime("%d/%02d/%02d" % (int(params["dayfrom"]), int(params["monthfrom"]), int(params["yearfrom"])), "%d/%m/%Y"))
                            break
                        except ValueError:
                            params["dayfrom"] = int(params["dayfrom"]) - 1
                if params.get("yearto"):
                    params.setdefault("monthto", 12)
                    params.setdefault("dayto", 31)
                    while True:
                        try:
                            maxtime = time.mktime(time.strptime("%d/%02d/%02d 23:59:59" % (int(params["dayto"]), int(params["monthto"]), int(params["yearto"])), "%d/%m/%Y %H:%M:%S"))
                            break
                        except ValueError:
                            params["dayto"] = int(params["dayto"]) - 1
                content = _create_report(order=params.get("order", "DESC"), limit=params.get("limit"), offset=params.get("offset"), mintime=mintime, maxtime=maxtime, domain=params.get("domain"))
                content = _insert_filter(content)
                for param, value in params.items():
                    content = re.sub(r"(name=\"%s\".+?<option) (value=\"%s\")" % (re.escape(param), re.escape(str(value))), r"\g<1> selected \g<2>", content)
                if params.get("domain"):
                    content = content.replace("input name=\"domain\" value=\"\"", "input name=\"domain\" value=\"%s\"" % params["domain"])
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

    if not os.path.isfile(CACHE_FILE) or (time.time() - os.stat(CACHE_FILE).st_mtime) / 3600 / 24 > FRESH_LISTS_DELTA_DAYS:
        print("[i] %s domain lists..." % ("updating" if os.path.isfile(CACHE_FILE) else "retrieving"))

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
            if not os.path.isdir(STORAGE_DIRECTORY):
                os.makedirs(STORAGE_DIRECTORY, 0755)
            with open(CACHE_FILE, "w+b") as f:
                f.write(zlib.compress(pickle.dumps(_domains)))
        except Exception, ex:
            print("[!] something went wrong during cache file write '%s' ('%s')" % (CACHE_FILE, ex))

    if not _domains:
        print("[i] loading cache...")
        try:
            with open(CACHE_FILE, "rb") as f:
                _domains = pickle.loads(zlib.decompress(f.read()))
        except Exception, ex:
            exit("[x] something went wrong during cache file read '%s' ('%s')" % (CACHE_FILE, ex))

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

def main():
    global _history_file

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
        load_domains(options.bulkfile)
        if options.pcapfile:
            _history_file = tempfile.mkstemp()[1]
            _report_file = tempfile.mkstemp(prefix="%s-" % NAME.lower(), suffix=".html")[1]
            process_pcap(options.pcapfile)
            with open(_report_file, "w+b") as f:
                f.write(_create_report())
            print("[i] report written to '%s'" % _report_file)
        elif options.interface:
            _start_httpd()
            monitor_interface(options.interface)
    else:
        parser.print_help()

if __name__ == "__main__":
    if "--quiet" in sys.argv:
        def print(*args, **kwargs):
            pass
        print_function = print

    main()