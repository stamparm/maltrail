#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os

NAME = "Maltrail"
VERSION = "0.3b"
ROTATING_CHARS = ('\\', '|', '|', '/', '-')
TIMEOUT = 30
FRESH_LISTS_DELTA_DAYS = 2
STORAGE_DIRECTORY = os.path.join(os.path.expanduser("~"), ".%s" % NAME.lower())
CACHE_FILE = os.path.join(STORAGE_DIRECTORY, "cache.bin")
HISTORY_FILE = os.path.join(STORAGE_DIRECTORY, "history.bin")
TIME_FORMAT = "%d/%m/%Y %H:%M:%S"
REPORT_HEADERS = ("time", "src", "dst", "type", "trail", "info", "reference")
HTTP_REPORTING_PORT = 8338
HISTORY_CREATE_TABLE = "CREATE TABLE IF NOT EXISTS history(time REAL, src TEXT, dst TEXT, type TEXT, trail TEXT, info TEXT, reference TEXT)"
DEFAULT_CAPTURING_FILTER = None  # DEFAULT_CAPTURING_FILTER = "tcp dst port 80 or udp dst port 53"
MAX_PACKET_SIZE = 65535
BLOCK_LENGTH = 1 + 2 + MAX_PACKET_SIZE + 4 # primitive mutex + short for packet size + max packet size + int for timestamp
BUFFER_LENGTH = 32 * 1024 * 1024 / BLOCK_LENGTH * BLOCK_LENGTH  # 32MB buffer
SHORT_SLEEP_TIME = 0.00001
REGULAR_SLEEP_TIME = 0.001
NO_BLOCK = -1
END_BLOCK = -2
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IPPROTO = 8
ETH_LENGTH = 14

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
<!--filter-->
<h2>Details:</h2>
<table cellpadding="0" cellspacing="0" border="0" class="sortable" id="sorter">
%s
</table>
</div>
<script type="text/javascript">
var sorter=new table.sorter("sorter");
sorter.init("sorter", 0);
</script>
</body>
</html>
"""

FILTER_FORM = """
<h2>Filter:</h2>
<form name="search" id="search" method="post" action="/">
<table style="margin:0; padding-bottom: 0.5cm;" border="0" cellpadding="2" cellspacing="2">
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
<td>Search:</td>
<td colspan="2">
<table border="0" cellpadding="0" cellspacing="0">
<tbody><tr>
<td class="searchboxWrapper"><input name="search" value="" type="text"></td>
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
