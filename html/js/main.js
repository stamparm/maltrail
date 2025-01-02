/*
* Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
* See the file 'LICENSE' for copying permission
*/

// globals part

var _THREATS = {};
var _SOURCES = {};
var _TOP_SOURCES = [];
var _SOURCE_EVENTS = {};
var _SEVERITY_COUNT = {};
var _TRAILS = {};
var _FLOOD_TRAILS = {};
var _HOURS = {};
var _DATASET = [];
var _TRAILS_SORTED = null;
var _DELETE_DELETE_PRESS = false;
var _MAX_EVENTS_PER_HOUR = 0;
var _MAX_SPARKLINE_PER_HOUR = 0;
var _TOTAL_EVENTS = 0;
var _USER = null;

var IP_COUNTRY = {};
var CHECK_IP = {};
var TRAIL_TYPES = {};

var CONTEXT_MENU_ROW = null;
var SPARKLINE_WIDTH = 100;
var CHART_WIDTH = screen.width - 200;
var CHART_HEIGHT = screen.height - 340;
var PIE_FONT_SIZE = 10;
var MAX_SOURCES_ITEMS = 30;
var FLOOD_TRAIL_THRESHOLD = 50;
var LONG_TRAIL_THRESHOLD = 40;
var MAX_CONDENSED_ITEMS = 100;
var HIDDEN_THREAT_COUNT = 0;
var OTHER_COLOR = "#999";
var THREAT_INFIX = "~>";
var FLOOD_THREAT_PREFIX = "...";
var DGA_THREAT_INFIX = " dga ";  // set by sensor (based on known DGAs)
var DNS_EXHAUSTION_THREAT_INFIX = " dns exhaustion ";  // set by sensor
var DATA_PARTS_DELIMITER = ", ";
var SUSPICIOUS_THREAT_INFIX = "suspicious";
var HEURISTIC_THREAT_INFIX = "heuristic";
var FLOOD_UID_SUFFIX = "F0";
var DGA_UID_SUFFIX = "D0";
var DNS_EXHAUSTION_UID_SUFFIX = "N0";
var DEFAULT_STATUS_BORDER = "1px solid #a8a8a8";
var DEFAULT_FONT_FAMILY = "Verdana, Geneva, sans-serif";
var LOG_COLUMNS = { TIME: 0, SENSOR: 1, SRC_IP: 2, SRC_PORT: 3, DST_IP: 4, DST_PORT: 5, PROTO: 6, TYPE: 7, TRAIL: 8, INFO: 9, REFERENCE: 10 };
var LOG_COLUMNS_SIZE = 0;
var DATATABLES_COLUMNS = { THREAT: 0, SENSOR: 1, EVENTS: 2, SEVERITY: 3, FIRST_SEEN: 4, LAST_SEEN: 5, SPARKLINE: 6, SRC_IP: 7, SRC_PORT: 8, DST_IP: 9, DST_PORT: 10, PROTO: 11, TYPE: 12, TRAIL: 13, INFO: 14, REFERENCE: 15, TAGS: 16 };
var PORT_NAMES = { 1: "tcpmux", 2: "nbp", 4: "echo", 6: "zip", 7: "echo", 9: "discard", 11: "systat", 13: "daytime", 15: "netstat", 17: "qotd", 18: "msp", 19: "chargen", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 39: "rlp", 42: "nameserver", 43: "whois", 49: "tacacs", 50: "re-mail-ck", 53: "dns", 57: "mtp", 65: "tacacs-ds", 67: "bootps", 68: "bootpc", 69: "tftp", 70: "gopher", 77: "rje", 79: "finger", 80: "http", 87: "link", 88: "kerberos", 95: "supdup", 98: "linuxconf", 101: "hostnames", 102: "iso-tsap", 104: "acr-nema", 105: "csnet-ns", 106: "poppassd", 107: "rtelnet", 109: "pop2", 110: "pop3", 111: "sunrpc", 113: "auth", 115: "sftp", 117: "uucp-path", 119: "nntp", 123: "ntp", 129: "pwdgen", 135: "dcom-rpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap2", 161: "snmp", 162: "snmp-trap", 163: "cmip-man", 164: "cmip-agent", 174: "mailq", 177: "xdmcp", 178: "nextstep", 179: "bgp", 191: "prospero", 194: "irc", 199: "smux", 201: "at-rtmp", 202: "at-nbp", 204: "at-echo", 206: "at-zis", 209: "qmtp", 210: "z3950", 213: "ipx", 220: "imap3", 345: "pawserv", 346: "zserv", 347: "fatserv", 369: "rpc2portmap", 370: "codaauth2", 371: "clearcase", 372: "ulistserv", 389: "ldap", 406: "imsp", 427: "svrloc", 443: "https", 444: "snpp", 445: "smb", 464: "kpasswd", 465: "urd", 487: "saft", 500: "isakmp", 502: "modbus", 512: "exec", 513: "login", 514: "shell", 515: "printer", 517: "talk", 518: "ntalk", 520: "route", 525: "timed", 526: "tempo", 530: "courier", 531: "conference", 532: "netnews", 533: "netwall", 538: "gdomap", 540: "uucp", 543: "klogin", 544: "kshell", 546: "dhcpv6-client", 547: "dhcpv6-server", 548: "afpovertcp", 549: "idfp", 554: "rtsp", 556: "remotefs", 563: "nntps", 587: "submission", 607: "nqs", 610: "npmp-local", 611: "npmp-gui", 612: "hmmp-ind", 623: "ipmi", 628: "qmqp", 631: "ipp", 636: "ldaps", 655: "tinc", 706: "silc", 749: "kerberos-adm", 750: "kerberos4", 751: "kerberos-master", 752: "passwd-server", 754: "krb-prop", 760: "krbupdate", 765: "webster", 775: "moira-db", 777: "moira-update", 779: "moira-ureg", 783: "spamd", 808: "omirr", 871: "supfilesrv", 873: "rsync", 901: "swat", 989: "ftps-data", 990: "ftps", 992: "telnets", 993: "imaps", 994: "ircs", 995: "pop3s", 1080: "socks", 1093: "proofd", 1094: "rootd", 1099: "rmiregistry", 1109: "kpop", 1127: "supfiledbg", 1178: "skkserv", 1194: "openvpn", 1210: "predict", 1214: "kazaa", 1236: "rmtcfg", 1241: "nessus", 1300: "wipld", 1313: "xtel", 1314: "xtelw", 1352: "lotusnote", 1433: "mssql", 1434: "ms-sql-m", 1524: "ingreslock", 1525: "prospero-np", 1529: "support", 1645: "datametrics", 1646: "sa-msg-port", 1649: "kermit", 1677: "groupwise", 1701: "l2f", 1723: "pptp", 1812: "radius", 1813: "radius-acct", 1863: "msnp", 1900: "upnp", 1957: "unix-status", 1958: "log-server", 1959: "remoteping", 2000: "cisco-sccp", 2003: "cfinger", 2010: "search", 2049: "nfs", 2053: "knetd", 2086: "gnunet", 2101: "rtcm-sc104", 2102: "zephyr-srv", 2103: "zephyr-clt", 2104: "zephyr-hm", 2105: "eklogin", 2111: "kx", 2119: "gsigatekeeper", 2121: "iprop", 2135: "gris", 2150: "ninstall", 2401: "cvspserver", 2430: "venus", 2431: "venus-se", 2432: "codasrv", 2433: "codasrv-se", 2583: "mon", 2600: "zebrasrv", 2601: "zebra", 2602: "ripd", 2603: "ripngd", 2604: "ospfd", 2605: "bgpd", 2606: "ospf6d", 2607: "ospfapi", 2608: "isisd", 2628: "dict", 2792: "f5-globalsite", 2811: "gsiftp", 2947: "gpsd", 2988: "afbackup", 2989: "afmbackup", 3050: "gds-db", 3128: "squid", 3130: "icpv2", 3260: "iscsi-target", 3306: "mysql", 3389: "rdesktop", 3493: "nut", 3632: "distcc", 3689: "daap", 3690: "svn", 4031: "suucp", 4094: "sysrqd", 4190: "sieve", 4224: "xtell", 4353: "f5-iquery", 4369: "epmd", 4373: "remctl", 4500: "ipsec-nat-t", 4557: "fax", 4559: "hylafax", 4569: "iax", 4600: "distmp3", 4691: "mtn", 4899: "radmin-port", 4949: "munin", 5002: "rfe", 5050: "mmcc", 5051: "enbd-cstatd", 5052: "enbd-sstatd", 5060: "sip", 5061: "sip-tls", 5151: "pcrd", 5190: "aol", 5222: "xmpp-client", 5269: "xmpp-server", 5308: "cfengine", 5351: "nat-pmp", 5353: "mdns", 5354: "noclog", 5355: "hostmon", 5357: "wsdapi", 5432: "postgresql", 5555: "rplay", 5556: "freeciv", 5631: "pc-anywhere", 5666: "nrpe", 5667: "nsca", 5672: "amqp", 5674: "mrtd", 5675: "bgpsim", 5680: "canna", 5688: "ggz", 5800: "vnc", 5900: "vnc", 5901: "vnc-1", 5902: "vnc-2", 5903: "vnc-3", 6000: "x11", 6001: "x11-1", 6002: "x11-2", 6003: "x11-3", 6004: "x11-4", 6005: "x11-5", 6006: "x11-6", 6007: "x11-7", 6346: "gnutella-svc", 6347: "gnutella-rtr", 6379: "redis", 6444: "sge-qmaster", 6445: "sge-execd", 6446: "mysql-proxy", 6514: "syslog-tls", 6566: "sane-port", 6667: "ircd", 7000: "afs3-fileserver", 7001: "afs3-callback", 7002: "afs3-prserver", 7003: "afs3-vlserver", 7004: "afs3-kaserver", 7005: "afs3-volser", 7006: "afs3-errors", 7007: "afs3-bos", 7008: "afs3-update", 7009: "afs3-rmtsys", 7100: "font-service", 7547: "cwmp", 8021: "zope-ftp", 8080: "http-alt", 8081: "tproxy", 8088: "omniorb", 8118: "privoxy", 8338: "maltrail", 8339: "tsusen", 8443: "https-alt", 8990: "clc-build-daemon", 9098: "xinetd", 9101: "bacula-dir", 9102: "bacula-fd", 9103: "bacula-sd", 9200: "wap-wsp", 9359: "mandelspawn", 9418: "git", 9667: "xmms2", 9673: "zope", 10000: "webmin", 10050: "zabbix-agent", 10051: "zabbix-trapper", 10080: "amanda", 10081: "kamanda", 10082: "amandaidx", 10083: "amidxtape", 10809: "nbd", 11112: "dicom", 11201: "smsqp", 11211: "memcached", 11371: "hkp", 13720: "bprd", 13721: "bpdbm", 13722: "bpjava-msvc", 13724: "vnetd", 13782: "bpcd", 13783: "vopied", 15345: "xpilot", 17001: "sgi-cmsd", 17002: "sgi-crsd", 17003: "sgi-gcd", 17004: "sgi-cad", 17185: "vxworks", 17500: "db-lsp", 20011: "isdnlog", 20012: "vboxd", 22125: "dcap", 22128: "gsidcap", 22273: "wnn6", 24554: "binkp", 27017: "mongo", 27374: "asp", 30865: "csync2", 53413: "netis", 57000: "dircproxy", 60177: "tfido", 60179: "fido" };
var SEARCH_TIP_TIMER = 0;
var DRAW_SPARKLINES_TIMER = 0;
var PAPAPARSE_COMPLETE_TIMER = 0;
var REPORT_URL = "http://23.254.203.53/report.php"  // NOTE: Right click / Report false positive
var SEARCH_TIP_URL = "https://searx.baczek.me/search?q=${query}"

//var SEARCH_TIP_URL = "https://www.searchencrypt.com/search/?q=%22${query}%22";        // Reference: https://kinsta.com/blog/alternative-search-engines/
//var SEARCH_TIP_URL = "https://duckduckgo.com/?q=${query}";
//var SEARCH_TIP_URL = "https://www.google.com/cse?cx=011750002002865445766%3Ay5klxdomj78&ie=UTF-8&q=${query}";
var DAY_SUFFIXES = { 1: "st", 2: "nd", 3: "rd" };
var DOT_COLUMNS = [ LOG_COLUMNS.SENSOR, LOG_COLUMNS.SRC_PORT, LOG_COLUMNS.SRC_IP, LOG_COLUMNS.DST_IP, LOG_COLUMNS.DST_PORT, LOG_COLUMNS.TRAIL, LOG_COLUMNS.PROTO ];
var DATA_CONDENSING_COLUMNS = [ LOG_COLUMNS.SRC_PORT, LOG_COLUMNS.DST_IP, LOG_COLUMNS.DST_PORT, LOG_COLUMNS.PROTO ];
var SPARKLINE_COLOR = "#ff0000";
var NONCE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
var NONCE_LENGTH = 12;
var CHUNK_SIZE = 20 * 1024 * 1024;  // 20MB
var CTRL_CLICK_PRESSED = false;
var CTRL_DATES = [];
var PREFERRED_TRAIL_COLORS = { DNS: "#3366cc", IP: "#dc3912", URL: "#ffad33", UA: "#9900cc" };
var SEVERITY = { LOW: 1, MEDIUM: 2, HIGH: 3 };
var SEVERITY_COLORS = { 1: "#8ba8c0", 2: "#f0ad4e", 3: "#d9534f"};
var CHART_TOOLTIP_FORMAT = "<%= datasetLabel %>: <%= value %>";
var INFO_SEVERITY_KEYWORDS = { "malware": SEVERITY.HIGH, "adversary": SEVERITY.HIGH, "ransomware": SEVERITY.HIGH, "reputation": SEVERITY.LOW, "attacker": SEVERITY.LOW, "spammer": SEVERITY.LOW, "compromised": SEVERITY.LOW, "crawler": SEVERITY.LOW, "scanning": SEVERITY.LOW }
var STORAGE_KEY_ACTIVE_STATUS_BUTTON = "STORAGE_KEY_ACTIVE_STATUS_BUTTON";
var STORAGE_KEY_EDIT_ALIASES = "STORAGE_KEY_EDIT_ALIASES";
var STORAGE_KEY_HIDDEN_THREATS = "STORAGE_KEY_HIDDEN_THREATS";
var COMMA_ENCODE_TRAIL_TYPES = { UA: true, URL: true};
var TOOLTIP_FOLDING_REGEX = /([^\s]{60})/g;
var REPLACE_SINGLE_CLOUD_WITH_BRACES = false;
var IP_ALIASES = {};
var DEMO = false;

$("body").loader("show");
$("#graph_close").on("click", graphClose);
$("#spanToggleHeatmap").on("click", toggleHeatmap);
$("#logo").on("click", resetView);

for (var column in LOG_COLUMNS) if (LOG_COLUMNS.hasOwnProperty(column)) LOG_COLUMNS_SIZE++;

var _ = {};
for (var i = 0; i < DATA_CONDENSING_COLUMNS.length; i++) {
    _[DATA_CONDENSING_COLUMNS[i]] = true;
}
DATA_CONDENSING_COLUMNS = _;

window.onkeydown = function(event) {
    CTRL_DATES.length = 0;
    CTRL_CLICK_PRESSED = event.ctrlKey;
};

window.onkeyup = function(event) {
    CTRL_CLICK_PRESSED = false;
};

// Retrieve (and parse) log data
$(document).ready(function() {
    $("#noscript").remove();
    // assign buttons
    $("#btnDrawThreats").on("click", function() {
        drawInfo("Threats");
    });
    $("#btnDrawEvents").on("click", function() {
        drawInfo("Events");
    });
    $("#btnDrawSeverity").on("click", function() {
        drawInfo("Severity");
    });
    $("#btnDrawSources").on("click", function() {
        drawInfo("Sources");
    });
    $("#btnDrawTrails").on("click", function() {
        drawInfo("Trails");
    });

    // Reference: http://tosbourn.com/a-fix-for-window-location-origin-in-internet-explorer/
    if (!window.location.origin)
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port: '');

    DEMO = !window.location.origin.startsWith('http') || (window.location.origin == "https://maltraildemo.github.io");

    if (!DEMO) {
        initCalHeatmap();
        initDialogs();
    }

    Papa.SCRIPT_PATH = "/js/papaparse.min.js"
    Papa.RemoteChunkSize = CHUNK_SIZE; // 10 MB (per one chunk request)

    Chart.defaults.global.tooltipFontFamily = DEFAULT_FONT_FAMILY;
    Chart.defaults.global.tooltipTitleFontFamily = DEFAULT_FONT_FAMILY;
    Chart.defaults.global.scaleLabel = "<%=numberWithCommas(value)%>";
    Chart.defaults.global.scaleFontFamily = DEFAULT_FONT_FAMILY;
    Chart.defaults.global.animationSteps = 10;

    $("#header_container").sticky({ topSpacing: 0 });
    $("#graph_close").css("left", CHART_WIDTH / 2 - 11)

    init(location.origin + "/events?date=" + formatDate(new Date()), new Date());

    // Reference: https://stackoverflow.com/a/20471268
    $(document).bind("mousedown", function (e) {
        if (!$(e.target).parents(".custom-menu").length > 0) {
            $(".custom-menu").hide(100);
        }
    });

    $(".custom-menu li").click(function() {
        var table = $("#details").dataTable();
        var hidden_threats = $.jStorage.get(STORAGE_KEY_HIDDEN_THREATS, {});
        var threat = $(CONTEXT_MENU_ROW).find("td:first").text();

        switch ($(this).attr("data-action")) {
            case "hide_threat":
                hidden_threats[threat] = true;
                HIDDEN_THREAT_COUNT += 1;
                $.jStorage.set(STORAGE_KEY_HIDDEN_THREATS, hidden_threats);
                table.api().row(CONTEXT_MENU_ROW).remove().draw();
                break;
            case "report_false_positive":
                $.ajax({
                    type: "POST",
                    url: REPORT_URL,
                    data: $(CONTEXT_MENU_ROW).find("td").map(function() { return $(this).text(); }).get().join('|'),
                    success: function(result) { alertify.success("Threat successfully reported to developers"); }
                })
                break;
        }

        $(".custom-menu").hide(100);
    });
});

function initDialogs() {
    var options = {
        autoOpen: false,
        resizable: false,
        //autoResize: true,
        width: "auto",
        modal: true,
        buttons: {
            Cancel: function() {
                $(this).dialog("close");
            },
            "Log In": function() {
                var SHA256 = new Hashes.SHA256;
                var nonce = generateNonce();

                $.ajax({
                    type: "POST",
                    url: "login",
                    dataType: "text",
                    data: "username=" + $(this).find("#username")[0].value.trim() + "&hash=" + SHA256.hex(SHA256.hex($(this).find("#password")[0].value.trim()) + nonce) + "&nonce=" + nonce,
                    cache: false,
                    beforeSend: function() {
                        $("input").prop("disabled", true);
                        $(".ui-dialog-buttonpane button").button("disable");
                    },
                    complete: function(response) {
                        $("input").prop("disabled", false);
                        $(".ui-dialog-buttonpane button").button("enable");
                        if(response.status === 401) {
                            alertify.error("Wrong username and/or password");
                            $("#login_dialog input").val("");
                            $("#login_dialog").effect("highlight", { color: 'red' }, 500);
                            $("#username").focus();
                        }
                        else if (response.status === 0) {
                            alertify.error("Network connection issue");
                        }
                        else {
                            window.location.href = "/";
                        }
                    }
                });
            }
        },
        close: function(event, ui) {
            $(this).dialog('destroy').remove();
        }
    };

    $("#login_link").click(function() {
        $("body").loader("hide");
        if ($("#login_dialog").length === 0)
            $('<div id="login_dialog" background-color: red" title="Authentication"><table><tbody><tr><td style="display: inline-block !important">Username:</td><td style="display: inline-block !important"><input id="username" name="username"></td></tr><tr><td style="display: inline-block !important">Password:</td><td style="display: inline-block !important"><input id="password" name="password" type="password" autocomplete="off"></td></tr></tbody></table></div>').appendTo('body').dialog(options);
        $("#login_dialog input").val("");
        $("#login_dialog").dialog("open")
        .keyup(function(e) {
            // Reference: http://stackoverflow.com/questions/868889/submit-jquery-ui-dialog-on-enter
            if (e.keyCode === $.ui.keyCode.ENTER) {
                $(this).parent().find('.ui-dialog-buttonpane button:last').click();
                return false;
            }
        });
    });
}

$(window).resize(function() {
    $("#login_dialog").dialog("option", "position", {my: "center", at: "center", of: window});
});

function checkAuthentication() {
    $.ajax({
        type: "GET",
        url: "whoami",
        dataType: "text",
        cache: false,
        complete: function(response) {
            if(response.status === 404) {
                document.title = "Maltrail";
                document.body.hidden = true;
                throw new Error("Maltrail should be accessed ONLY at its server instance's address (e.g. http://127.0.0.1:8338)");
            }
            else if ((response.status === 200) && (typeof response.responseText !== "undefined") && (response.responseText.length > 0)) {
                _USER = response.responseText;
                if (_USER !== '?') {
                    $("#login_link").html("Log Out (" + _USER + ")");
                    $("#login_link").off("click");
                    $("#login_link").click(function() {
                        window.location.href = "logout";
                    });
                }
                else {
                    $("#login_link").html("");
                }

                if (window.location.search) {
                    var refresh = window.location.search.match(/refresh=(\d+)/);
                    if ((refresh !== null) && (parseInt(refresh[1]) > 0)) {
                        setTimeout(function(){
                            window.location.reload(true);
                        }, 1000 * parseInt(refresh[1]));
                    }
                }
            }
            else if (window.location.origin.startsWith('http')) {
                _USER = "";
                document.title = "Maltrail (unauthorized)";
                setTimeout(function() {
                    $("#login_link").click();
                }, 1000);
            }
        }
    });
}

function toggleHeatmap() {
    if ($("#heatmap_container").is(":visible"))
        $("#heatmap_container").hide();
    else {
        $("#heatmap_container").removeClass("hidden").show();
        $(".graph-legend").attr("width", 14);  // dirty patch for ugly legend width (missing one pixel)
        scrollTo("#header_container-sticky-wrapper");
    }
}

function graphClose() {
    $("#chart_area").empty();
    resetStatusButtons();
}

function initCalHeatmap() {
    var start = new Date();
    //start.setYear(start.getYear() - 1);
    start.setDate(start.getDate() - 90);
    var cal = new CalHeatMap();

    try {
        cal.init({
            domain: "month",
            subdomain: "day",
            itemSelector: "#cal-heatmap",
            range: 4,
            cellSize: 13,
            legendCellSize: 13,
            legendHorizontalPosition: "right",
            legendVerticalPosition: "center",
            legendOrientation: "vertical",
            maxDate: new Date(),
            itemName: ["event", "events"],
            domainLabelFormat: "%Y-%m",
            legend: [ 500, 1000, 5000, 10000 ],  // more than 4 will make it unusable (>last are not colorized)
            legendMargin: [ 0, 0, 0, 20 ],
            label: {
                    position: "bottom"
            },
            data: window.location.origin + "/counts?from={{d:start}}&to={{d:end}}",
            highlight: [ "now" ],
            subDomainTitleFormat: {
                empty: "No events on {date}",
                filled: "~{count} (total) events on {date}"
            },
            start: start,
            onClick: function(date, nb) {
                this.highlight(date);
                if (!CTRL_CLICK_PRESSED) {
                    this.highlight(date);
                    query(date);
                }
                else {
                    CTRL_DATES.push(date);
                    this.highlight(CTRL_DATES);
                    if (CTRL_DATES.length === 2)
                        query(date, CTRL_DATES[0]);
                }
            }
        });
    }
    catch(err) {
    }
    finally {
        $("#heatmap-previous").on("click", function() {
            cal.previous();
        });

        $("#heatmap-next").on("click", function() {
            cal.next();
        });
    }
}

function charTrim(str, chr) {
    while (str.substr(0, 1) === chr)
        str = str.substr(1);
    while (str.substr(str.length - 1) === chr)
        str = str.substr(0, str.length - 1);
    return str;
}

// Reference: http://stackoverflow.com/questions/2901102/how-to-print-a-number-with-commas-as-thousands-separators-in-javascript
function numberWithCommas(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Reference: http://en.wikipedia.org/wiki/Private_network
function isLocalAddress(ip) {
    if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127."))
        return true;
    else if (ip.startsWith("172.")) {
        var _ = parseInt(ip.split(".")[1]);
        return ((_ >= 16) && (_ <= 31));
    }
    else if (ip === "::1")
        return true;
    else
        return false;
}

// Reference: https://www.w3resource.com/javascript-exercises/javascript-array-exercise-4.php
var last = function(array, n) {
    if (array == null)
        return void 0;

    if (n == null)
        return array[array.length - 1];

    return array.slice(Math.max(array.length - n, 0));
};

var entityMap = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': '&quot;',
    "'": '&#39;',
    "/": '&#x2F;'
};

// Reference: http://stackoverflow.com/a/12034334
function escapeHtml(string) {
    return String(string).replace(/[&<>"'\/]/g, function (s) {
        return entityMap[s];
    });
}

// Reference: http://24ways.org/2010/calculating-color-contrast/
function getContrast50(hexcolor) {
    return (parseInt(hexcolor, 16) > 0xffffff / 2) ? "black": "white";
}

// Reference: http://stackoverflow.com/questions/340209/generate-colors-between-red-and-green-for-a-power-meter
function getPercentageColor(percentage) {
    var power = percentage / 100.0;

    if ((0 <= power) && (power < 0.5)) {
        green = 1.0;
        red = 2 * power;
    }
    if ((0.5 <= power) && (power <= 1)) {
        red = 1.0;
        green = 1.0 - 2 * (power - 0.5);
    }
    red = Math.round(red * 255);
    green = Math.round(green * 255);

    return "#" + pad(red.toString(16), 2) + pad(green.toString(16), 2) + "00";
}

function getContrastYIQ(hexcolor){
    if (hexcolor.charAt(0) === "#")
        hexcolor = hexcolor.slice(1);

    var r = parseInt(hexcolor.substr(0, 2), 16);
    var g = parseInt(hexcolor.substr(2, 2), 16);
    var b = parseInt(hexcolor.substr(4, 2), 16);
    var yiq = ((r * 299) + (g * 587) + (b * 114)) / 1000;

    return (yiq >= 128) ? "black" : "white";
}

function getTagHtml(tag) {
    var retval = "";

    if (tag.length > 0) {
        var color = getHashColor(tag);
        retval = String.prototype.concat.apply("", ['<span class="tag ', getContrastYIQ(color), '-label-text" style="background-color: ', color, '">', tag, '</span>']);
    }

    return retval;
}

function getHashColor(value) {
    return "#" + pad(value.hashCode().toString(16), 6).substring(0, 6);
}

// Reference: http://stackoverflow.com/a/6969486
function escapeRegExp(str) {
    return str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, "\\$&");
}

function getThreatUID(threat) {  // e.g. 192.168.0.1~>shv4.no-ip.biz
    if (threat.startsWith(FLOOD_THREAT_PREFIX))
        return pad(threat.hashCode().toString(16), 6).substr(0, 6) + FLOOD_UID_SUFFIX;
    else if (threat.indexOf(DGA_THREAT_INFIX) > -1)
        return pad(threat.hashCode().toString(16), 6).substr(0, 6) + DGA_UID_SUFFIX;
    else if (threat.indexOf(DNS_EXHAUSTION_THREAT_INFIX) > -1)
        return pad(threat.hashCode().toString(16), 6).substr(0, 6) + DNS_EXHAUSTION_UID_SUFFIX;
    else
        return pad(threat.hashCode().toString(16), 8);
}

function resetView() {
    var table = $("#details").dataTable();

    $("body").loader("show");

    $("#main_container").toggleClass("hidden", true);
    $("#heatmap_container").hide();
    $("#calendar_container").hide();

    table.fnFilter("");
    graphClose();

    window.location.href = window.location.href;
}

function init(url, from, to) {
    var csv = "";

    document.title = "Maltrail (loading...)";
    $("body").loader("show");
    $("#main_container").toggleClass("hidden", true);
    $("#heatmap_container").hide();
    $("#calendar_container").hide();

    $(".alertify-log").remove();

    _THREATS = {};
    _SOURCES = {};
    _SOURCE_EVENTS = {};
    _TRAILS = {};
    _FLOOD_TRAILS = {};
    _HOURS = {};
    _SEVERITY_COUNT = {}
    TRAIL_TYPES = {};

    _DATASET.length = 0;
    _TOTAL_EVENTS = 0;
    _CHUNK_COUNT = 0;

    for (var severity in SEVERITY)
        _SEVERITY_COUNT[SEVERITY[severity]] = 0;

    if (DEMO) {
        $(".bottom").html($(".bottom").html().replace(/ \(.+\)/, ""));

        csv = getDemoCSV();

        $("#login_link").toggleClass("hidden", true);
        $("#login_splitter").toggleClass("hidden", true);
    }
    else {
        $("#login_link").toggleClass("hidden", false);
        $("#login_splitter").toggleClass("hidden", false);

        $.ajax({
            type: "GET",
            url: "ping",
            dataType: "text",
            cache: false,
            complete: function(response) {
                if ((typeof response.responseText === "undefined") || (response.responseText.length === 0))
                    alertify.error("No connection to the server");
                else
                    checkAuthentication();
            }
        });
    }

    Papa.parse(DEMO ? csv : url, {
        download: !DEMO,
        delimiter: ' ',
        //newline: '\n',
        worker: !DEMO,
        skipEmptyLines: true,
        chunk: function(results) {
            var title = document.title.replace(/\s?\.\s?/g, '.');
            var parts = title.split('.');
            var total = results.data.length;
            var _ = _CHUNK_COUNT % parts.length;
            var trailSources = { };

            if (_ < parts.length - 1)
                parts[_] += " ";
            else
                parts[_] = " " + parts[_];

            document.title = parts.join('.');
            _CHUNK_COUNT += 1;

            for (var i = 0; i < total; i++) {
                var data = results.data[i];

                if (data.length !== LOG_COLUMNS_SIZE)
                    continue;

                var trail = data[LOG_COLUMNS.TRAIL];
                var type = data[LOG_COLUMNS.TYPE];

                if (type.match(/^[A-Z]+$/) === null)
                    continue;

                if (!(type in TRAIL_TYPES))
                    TRAIL_TYPES[type] = PREFERRED_TRAIL_COLORS[type] || getHashColor(type);

                if (type in COMMA_ENCODE_TRAIL_TYPES)
                    trail = trail.replace(/\,/g, "&#44;");

                trail = data[LOG_COLUMNS.TRAIL] = trail.replace(/\\\(/g, "&#40;").replace(/\\\)/g, "&#41;")
                var _ = trail.replace(/\([^)]+\)/g, "");

                if (!(_ in trailSources))
                    trailSources[_] = {};

                trailSources[_][data[LOG_COLUMNS.SRC_IP]] = true;

                _ +=  " (" + type + ")";
                if (!(_ in _TRAILS))
                    _TRAILS[_] = 1;
                else
                    _TRAILS[_] += 1;
            }

            for (var _ in trailSources) {
                if (Object.size(trailSources[_]) > FLOOD_TRAIL_THRESHOLD)
                    _FLOOD_TRAILS[charTrim(_, '.')] = true;
            }

            for (var i = 0; i < results.data.length; i++) {
                var threat_text, threat_data, match, _;
                var data = results.data[i]

                if (data.length !== LOG_COLUMNS_SIZE)
                    continue;

                var time = data[LOG_COLUMNS.TIME];
                var src_ip = data[LOG_COLUMNS.SRC_IP];
                var type = data[LOG_COLUMNS.TYPE];
                var info = data[LOG_COLUMNS.INFO];
                var reference = data[LOG_COLUMNS.REFERENCE];

                if (type.match(/^[A-Z]+$/) === null)
                    continue;

                _ = data[LOG_COLUMNS.TRAIL];
                _ = charTrim(charTrim(_.replace(/\([^)]+\)/g, ""), ' '), '.');

                var flood = _ in _FLOOD_TRAILS;
                var dga = info.indexOf(DGA_THREAT_INFIX) > -1;
                var dns_exhaustion = info.indexOf(DNS_EXHAUSTION_THREAT_INFIX) > -1;
                var heuristic = reference.indexOf(HEURISTIC_THREAT_INFIX) > -1;

                if (dns_exhaustion)
                    threat_text = info + THREAT_INFIX + _;
                else if (flood)
                    threat_text = FLOOD_THREAT_PREFIX + THREAT_INFIX + _;
                else if (dga)
                    threat_text = src_ip + THREAT_INFIX + info;
                else if (heuristic)
                    threat_text = src_ip + THREAT_INFIX + _ + info;
                else
                    threat_text = src_ip + THREAT_INFIX + _;

                _TOTAL_EVENTS += 1;

                if (!(threat_text in _THREATS))
                    threat_data = _THREATS[threat_text] = [1, [time], time, time, data];  // count, times, minTime, maxTime, (threat)data
                else {
                    match = time.match(/ (\d+:\d+)/);

                    threat_data = _THREATS[threat_text];
                    threat_data[0] += 1;

                    if (match !== null)
                        reduced = time.match(/ (\d+:\d+)/)[1];
                    else
                        reduced = time;

                    if (reduced != last(threat_data[1]))
                        threat_data[1].push(reduced);

                    if (time < threat_data[2])
                        threat_data[2] = time;
                    else if (time > threat_data[3])
                        threat_data[3] = time;
                }

                _ = threat_data[4];

                for (var j = 0; j < DOT_COLUMNS.length; j++) {
                    var column = DOT_COLUMNS[j];
                    var condensed = (column in DATA_CONDENSING_COLUMNS) && data[column].contains(',');
                    if (condensed || (data[column] !== _[column])) {
                        if (typeof _[column] === "string") {
                            var original = _[column];
                            _[column] = {};

                            if (condensed) {
                                var parts = original.split(',');
                                for (var k = 0; k < Math.min(parts.length, MAX_CONDENSED_ITEMS); k++) {
                                    _[column][parts[k]] = true;
                                }

                                if (parts.length > MAX_CONDENSED_ITEMS)
                                    _[column]["..."] = true;
                            }
                            else
                                _[column][original] = true;
                        }

                        if (typeof data[column] === "string") {
                            if (condensed) {
                                var parts = data[column].split(',');

                                for (var k = 0; k < parts.length; k++) {
                                    if (Object.keys(_[column]).length >= MAX_CONDENSED_ITEMS)
                                        _[column]["..."] = true;
                                    else
                                        _[column][parts[k]] = true;
                                }
                            }
                            else {
                                if (Object.keys(_[column]).length < MAX_CONDENSED_ITEMS)
                                    _[column][data[column]] = true;
                                else
                                    _[column]["..."] = true;
                            }
                        }
                    }
                }

                if (!(src_ip in _SOURCES))
                    _SOURCES[src_ip] = 1;
                else
                    _SOURCES[src_ip] += 1;

                if (!(src_ip in _SOURCE_EVENTS)) {
                    _SOURCE_EVENTS[src_ip] = {};

                    for (var key in TRAIL_TYPES)
                        _SOURCE_EVENTS[src_ip][key] = 0;
                }
                _SOURCE_EVENTS[src_ip][type] += 1;

                match = time.match(/(\d{4})-(\d{2})-(\d{2})\ (\d{2}):(\d{2}):(\d{2})/);

                if (match !== null) {
                    var date = new Date(parseInt(match[1]), parseInt(match[2]) - 1, parseInt(match[3]), parseInt(match[4]), parseInt(match[5]), parseInt(match[6]));
                    var hour = Math.floor(date.getTime() / 60 / 60 / 1000);

                    if (!(hour in _HOURS)) {
                        _HOURS[hour] = {};

                        for (var item in TRAIL_TYPES)
                            _HOURS[hour][item] = 0;
                    }

                    _HOURS[hour][type] += 1;

                    if (!(threat_text in _HOURS[hour]))
                        _HOURS[hour][threat_text] = 0;

                    _HOURS[hour][threat_text] += 1;
                }
            }
        },
        complete: function() {
            clearTimeout(PAPAPARSE_COMPLETE_TIMER);
            PAPAPARSE_COMPLETE_TIMER = setTimeout(function() {
                var hidden_threats = $.jStorage.get(STORAGE_KEY_HIDDEN_THREATS, {});

                // threat sensor first_time last_time count src_ip src_port dst_ip dst_port proto type trail info reference tags
                for (var threat_text in _THREATS) {
                    var threatUID = getThreatUID(threat_text);
                    var threat_data = _THREATS[threat_text];
                    var count = threat_data[0];
                    var times = threat_data[1];
                    var minTime = threat_data[2];
                    var maxTime = threat_data[3];
                    var sparkline_data = [];
                    var data = threat_data[4];
                    var row = [];
                    var severity = SEVERITY.MEDIUM;

                    var stored_locally = $.jStorage.get(threatUID);
                    var tagData = "";

                    if (threatUID in hidden_threats) {
                        HIDDEN_THREAT_COUNT += 1;
                        continue;
                    }

                    if (stored_locally !== null)
                        tagData = stored_locally.tagData;

                    for (var i = 0; i < DOT_COLUMNS.length; i++) {
                        var column = DOT_COLUMNS[i];

                        if (typeof data[column] !== "string") {
                            var _ = [];

                            for (var entry in data[column]) {
                                if ((column === LOG_COLUMNS.TRAIL) && (data[LOG_COLUMNS.TYPE] === "IP") && (entry.indexOf('(') === -1))
                                    continue;
                                _.push(entry.replace(DATA_PARTS_DELIMITER, DATA_PARTS_DELIMITER.replace(" ", "")));
                            }

                            if ((column === LOG_COLUMNS.SRC_PORT) || (column === LOG_COLUMNS.DST_PORT))
                                _.sort(function(a, b) {
                                    a = parseInt(a);
                                    b = parseInt(b);
                                    return a < b ? -1 : (a > b ? 1 : 0);
                                });
                            else if ((column === LOG_COLUMNS.SRC_IP) || (column === LOG_COLUMNS.DST_IP))
                                _.sort(function(a, b) {
                                    a = _ipSortingValue(a);
                                    b = _ipSortingValue(b);
                                    return a < b ? -1 : (a > b ? 1 : 0);
                                });
                            else
                                _.sort();

                            data[column] = _.join(DATA_PARTS_DELIMITER);
                        }
                    }

                    var min_ = null;
                    var max_ = null;
                    var _ = [];

                    for (var hour in _HOURS) {
                        if (min_ === null)
                            min_ = hour;
                        else
                            min_ = Math.min(min_, hour);

                        if (max_ === null)
                            max_ = hour;
                        else
                            max_ = Math.max(max_, hour);
                    }

                    if ((min_ !== null) && (max_ !== null)) {
                        var ms = 60 * 60 * 1000;
                        min_ = dayStart(min_ * ms) / ms;
                        max_ = dayEnd(max_ * ms) / ms;

                        for (var hour = min_; hour <= max_; hour++) {
                            if (!(hour in _HOURS))
                                _HOURS[hour] = {};
                        }
                    }

                    for (var hour in _HOURS)
                        _.push([hour >>> 0, _HOURS[hour][threat_text]]);

                    _.sort(function(a, b) {
                        a = a[0];
                        b = b[0];

                        return a < b ? -1 : (a > b ? 1 : 0);
                    });

                    for (var i = 0; i < 24; i++)
                        sparkline_data.push(0);

                    var total_days = Math.round(_.length / 24);
                    for (var i = 0; i < _.length; i++) {
                        sparkline_data[Math.floor(i / total_days)] += (_[i][1] | 0);
                        //_MAX_SPARKLINE_PER_HOUR = Math.max(_MAX_SPARKLINE_PER_HOUR, _[i][1] | 0);
                    }

                    if (data[LOG_COLUMNS.REFERENCE].contains("(custom)"))
                        severity = SEVERITY.HIGH;
                    else if (data[LOG_COLUMNS.REFERENCE].contains("(remote custom)"))
                        severity = SEVERITY.HIGH;
                    else if (data[LOG_COLUMNS.INFO].contains("potential malware site"))
                        severity = SEVERITY.MEDIUM;
                    else if (data[LOG_COLUMNS.REFERENCE].contains("malwaredomainlist"))
                        severity = SEVERITY.HIGH;
                    else if (data[LOG_COLUMNS.INFO].contains("malware distribution"))
                        severity = SEVERITY.MEDIUM;
                    else if (data[LOG_COLUMNS.INFO].contains("mass scanner"))
                        severity = SEVERITY.LOW;
                    else {
                        for (var keyword in INFO_SEVERITY_KEYWORDS)
                            if (data[LOG_COLUMNS.INFO].contains(keyword)) {
                                severity = INFO_SEVERITY_KEYWORDS[keyword];
                                break;
                            }
                    }

                    _SEVERITY_COUNT[severity] += 1;

                    row = [threatUID, data[LOG_COLUMNS.SENSOR], [count, times], severity, minTime, maxTime, sparkline_data.join(","), data[LOG_COLUMNS.SRC_IP], data[LOG_COLUMNS.SRC_PORT], data[LOG_COLUMNS.DST_IP], data[LOG_COLUMNS.DST_PORT], data[LOG_COLUMNS.PROTO], data[LOG_COLUMNS.TYPE], data[LOG_COLUMNS.TRAIL], data[LOG_COLUMNS.INFO], data[LOG_COLUMNS.REFERENCE], tagData];

                    _DATASET.push(row);
                }

                if (DEMO) {
                    alertify.log("Showing demo data");

                    document.title = "Maltrail (demo)";
                    $("#period_label").html("(demo)");
                }
                else {
                    if (_DATASET.length > 0)
                        alertify.success("Processed " + numberWithCommas(_TOTAL_EVENTS) + " events");
                    else
                        alertify.log("No events found");

                    var period = "";

                    if (typeof from !== "undefined") {
                        period += formatDate(from);
                        if (typeof to !== "undefined")
                            period += "_" + formatDate(to);
                    }

                    if (document.title.indexOf("unauthorized") === -1)
                        document.title = "Maltrail (" + period + ")";

                    scrollTo("#main_container");

                    var _ = moment(dayStart(from)).from(dayStart(new Date()));
                    if (_.indexOf("seconds") != -1)
                        _ = "today";

                    $("#period_label").html("<b>" + period + "</b> (" + _ + ")");
                }

                if (HIDDEN_THREAT_COUNT > 0)
                    alertify.log(HIDDEN_THREAT_COUNT + " threats are hidden in details table");

                try {
                    initDetails();
                    initVisual();
                }
                catch(err) {
                    alert(err);
                }

                $("#main_container").toggleClass("hidden", false);
                $("#main_container").children().toggleClass("hidden", false);  // Reference: http://stackoverflow.com/a/4740050
                $(".dynamicsparkline").parent().children().toggleClass("hidden", false);

                $.sparkline_display_visible();

                $("#chart_area").empty();

                if (jQuery.isEmptyObject(_HOURS))
                    $("li.status-button").css("cursor", "default");
                else
                    $("li.status-button").css("cursor", "pointer");

                if ($.jStorage.get(STORAGE_KEY_ACTIVE_STATUS_BUTTON) !== null)
                    drawInfo($.jStorage.get(STORAGE_KEY_ACTIVE_STATUS_BUTTON))
                else
                    resetStatusButtons();

                $("#calendar_container").show();
                $("#header_container").show();
                $("body").loader("hide");
            }, 500);
        }
    });
}

function resetStatusButtons() {
    $.jStorage.deleteKey(STORAGE_KEY_ACTIVE_STATUS_BUTTON);
    $("li.status-button").each(function() {
        $(this).css("text-shadow", "-1px -1px 0 rgba(0, 0, 0, 0.50), -1px 1px 0 rgba(0, 0, 0, 0.50), 1px 1px 0 rgba(0, 0, 0, 0.50), 1px -1px 0 rgba(0, 0, 0, 0.50)");
        $(this).css("border", "3px solid rgba(0, 0, 0, 0.50)");
    });
    $("#graph_close").hide();
}

function scrollTo(id) {
    if ($(id).length > 0)
        $("html, body").animate({
            scrollTop: $(id).offset().top
        }, 300);
}

function addrToInt(value) {
    var _ = value.split('.');
    return (_[0] << 24) + (_[1] << 16) + (_[2] << 8) + _[3];
}

function makeMask(bits) {
    return 0xffffffff ^ (1 << 32 - bits) - 1;
}

function netmaskValidate(netmask) {
    var match = netmask.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/);
    return match !== null;
}

function searchTipToTab(query) {
    var win = window.open(SEARCH_TIP_URL.replace("${query}", query), '_blank');

    // Reference: http://stackoverflow.com/a/19851803
    if(win) {
        // Browser has allowed it to be opened
        win.focus();
    } else {
        // Broswer has blocked it
        alert('Please allow popups for this site');
    }
}

function tagInputKeyUp(event, forcedelete) {
    var table, position;
    var tagData = null;
    var newTag = event.target.value;

    if (event.target.parentNode === null)
        return;

    if ((typeof forcedelete !== "undefined") || (event.keyCode === 8)) {  // appendFilter or Delete
        if ((typeof newTag === "undefined") || (newTag.length === 0)) {
            if ((event.keyCode === 8) && (_DELETE_DELETE_PRESS !== true)) {
                _DELETE_DELETE_PRESS = true;
                return;
            }
            table = $("#details").dataTable();
            position = table.fnGetPosition(event.target.parentNode);
            tagData = table.fnGetData(event.target.parentNode);

            if (tagData.length > 0) {
                if (event.target.classList.contains("tag-input")) {
                    var i = tagData.lastIndexOf('|');
                    if (i > 0)
                        tagData = tagData.substring(0, i);
                    else
                        tagData = "";
                }
                else if (event.target.classList.contains("tag")) {
                    var tag = event.target.innerHTML;
                    var regex = new RegExp("(^|\\|)" + escapeRegExp(tag) + "($|\\|)");
                    tagData = charTrim(tagData.replace(regex, '|'), '|');
                }
            }
        }
    }
    else if ((typeof event.keyCode === "undefined") || (event.keyCode === 13)) {  // blur or Enter
        if (newTag.length > 0) {
            table = $("#details").dataTable();
            newTag = newTag.replace(/[^a-zA-Z0-9_]/g, "");
            position = table.fnGetPosition(event.target.parentNode);
            tagData = table.fnGetData(event.target.parentNode);

            if (!(new RegExp("(^|\\|)" + escapeRegExp(newTag) + "($|\\|)").test(tagData)))
                tagData = tagData + '|' + newTag;
            //$(event.target).before(getTagHtml(newTag));
            //newTag = "";
        }
    }

    _DELETE_DELETE_PRESS = false;

    if (tagData !== null) {
        var api = table.api();
        var threat = table.fnGetData(position[0], DATATABLES_COLUMNS.THREAT);
        var row = api.row(position[0]);
        var data = row.data();

        $.jStorage.set(threat, { tagData: tagData });

        data[DATATABLES_COLUMNS.TAGS] = tagData;

        try {                           // dirty patch for #14900 (reproducible on Chromium - blur being thrown after the Enter has been processed)
            row.invalidate();
        }
        catch(err) {
        }

        api.draw(false);
    }
}

function stopPropagation(event) {
    if (event.stopPropagation) {
        event.stopPropagation();   // W3C model
    } else {
        event.cancelBubble = true; // IE model
    }
}

function _sort(obj) {
    var tuples = [];

    for (var key in obj) {
        if (typeof obj[key] !== "function")
            tuples.push([key, obj[key]]);
    }

    tuples.sort(function(a, b) {
        a = a[1];
        b = b[1];
        return a > b ? -1 : (a < b ? 1 : 0);
    });

    return tuples;
}

function _ipSortingValue(a) {
    var x = "";
    var match = a.match(/\d+\.\d+\.\d+\.\d+/);
    if (match !== null) {
        var m = match[0].split(".");

        for (var i = 0; i < m.length; i++) {
            var item = m[i];

            if(item.length === 1) {
                x += "00" + item;
            } else if(item.length === 2) {
                x += "0" + item;
            } else {
                x += item;
            }
        }
    }

    return x;
}

function _ipCompareValues(a, b) {
    // Reference: http://stackoverflow.com/a/949970
    return _ipSortingValue(a) - _ipSortingValue(b);
}

function copyEllipsisToClipboard(event) {
    if (event.button === 0) {  // left mouse button
        var target = $(event.target);
        var text = target.parent().title || '';
        var html = target.parent().html() || '';
        var left = html.search(/^<[^>]*ellipsis/) !== -1;
        var common = html.replace(/<span class="(ipcat|hidden)">[^<]+<\/span>/g, "").replace(/<[^>]+>/g, "");
        if (!text) {
            var tooltip = $(".ui-tooltip");
            if (tooltip.length > 0) {
                text = tooltip.text();

                if (common) {
                    var _ = text.split(DATA_PARTS_DELIMITER);
                    for (var i = 0; i < _.length; i++) {
                        if (left)
                            _[i] += common;
                        else {
                            if (!common.endsWith(' '))
                                _[i] = common + _[i];
                        }
                    }
                    text = _.join(DATA_PARTS_DELIMITER);
                }
            }
            tooltip.remove();
        }
        window.prompt("Copy details to clipboard (press Ctrl+C)", text);
    }
}

function copyEventsToClipboard(event) {
    var target = $(event.target);
    var text = target.parent().find("span").text();
    window.prompt("Copy details to clipboard (press Ctrl+C)", text);
}

function appendFilter(filter, event, istag) {
    try {
        var table = $("#details").dataTable();
        var currentFilter = table.api().search();

        // Reference: http://stackoverflow.com/a/3076685
        if (typeof event !== "undefined") {
            stopPropagation(event);

            if (event.button === 0) {  // left mouse button
                if (!(new RegExp("\\b" + escapeRegExp(filter) + "\\b").test(currentFilter))) {
                    currentFilter = currentFilter + " " + filter;
                    table.fnFilter(currentFilter.trim());
                    // table.DataTable().columns(11).search(currentFilter.trim()).draw();
                }
            }
            else if ((istag === true) && (event.button === 1)) {  // middle mouse button
                tagInputKeyUp(event, true);
                event.preventDefault();
            }
        }
        else {
            if (!(new RegExp("\\b" + escapeRegExp(filter) + "\\b").test(currentFilter))) {
                currentFilter = currentFilter + " " + filter;
                table.fnFilter(currentFilter.trim());
            }
        }

        $(".searchtip").remove();
        clearTimeout(SEARCH_TIP_TIMER);
        $(".ui-tooltip").remove();
        $(".custom-menu").hide();
        $('#details_filter label input').get(0).scrollLeft = $('#details_filter label input').get(0).scrollWidth;
        //$('#details_filter label input').get(0).focus();
    }
    catch(err) {
    }
}

// DataTables part
function initDetails() {
    var details = $("#details").dataTable( {
        bDestroy: true,
        bAutoWidth: false,
        bStateSave: true,
        data: _DATASET,
        columns: [
            { "title": "threat", "type": "threat", "class": "center" },
            { "title": "sensor", "class": "center" },
            { "title": "events", "type": "events", "class": "right" },
            { "title": "severity", "type": "severity", "class": "center" },
            { "title": "first_seen", "class": "center", "sType": "date-custom" },
            { "title": "last_seen", "class": "center", "sType": "date-custom" },
            { "title": "sparkline", "type": "sparkline", "class": "center" },
            { "title": "src_ip", "type": "ip-address", "class": "right" },
            { "title": "src_port", "type": "port", "class": "center" },
            { "title": "dst_ip", "type": "ip-address", "class": "right" },
            { "title": "dst_port", "type": "port", "class": "center" },
            { "title": "proto", "class": "center" },
            { "title": "type", "class": "center" },
            { "title": "trail", "class": "trail" },
            { "title": "info" },
            { "title": "reference" },
            { "title": "tags" }
        ],
        search: {
            caseInsensitive: false
        },
        iDisplayLength: 25,
        aLengthMenu: [ [10, 25, 50, 100, 200], [10, 25, 50, 100, 200] ],
        aaSorting: [ [DATATABLES_COLUMNS.LAST_SEEN, 'desc'] ],
        bDeferRender: true,
        searchDelay: 500,
        columnDefs: [
            {
                orderData: [DATATABLES_COLUMNS.SPARKLINE, DATATABLES_COLUMNS.SEVERITY, DATATABLES_COLUMNS.SRC_IP, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.SPARKLINE
            },
            {
                orderData: [DATATABLES_COLUMNS.SENSOR, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.SENSOR
            },
            {
                orderData: [DATATABLES_COLUMNS.SEVERITY, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.SEVERITY
            },
            {
                orderData: [DATATABLES_COLUMNS.INFO, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.INFO
            },
            {
                orderData: [DATATABLES_COLUMNS.REFERENCE, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.REFERENCE
            },
            {
                orderData: [DATATABLES_COLUMNS.SRC_IP, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.SRC_IP
            },
            {
                orderData: [DATATABLES_COLUMNS.DST_IP, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.DST_IP
            },
            {
                orderData: [DATATABLES_COLUMNS.TYPE, DATATABLES_COLUMNS.EVENTS], targets: DATATABLES_COLUMNS.TYPE
            },
            {
                orderSequence: [ "desc", "asc" ],
                targets: [ DATATABLES_COLUMNS.EVENTS, DATATABLES_COLUMNS.SEVERITY, DATATABLES_COLUMNS.LAST_SEEN, DATATABLES_COLUMNS.SPARKLINE ]
            },
//             {
//                 orderable: false,
//                 targets: DATATABLES_COLUMNS.SPARKLINE
//             },
            {
                render: function (data, type, row) {
                    var name = "";
                    if (data === SEVERITY.LOW)
                        name = "low"
                    else if (data === SEVERITY.HIGH)
                        name = "high"
                    else if (data === SEVERITY.MEDIUM)
                        name = "medium";
                    var retval = "<span class='severity' style='background-color: " + SEVERITY_COLORS[data] + "' value='" + data + "'>" + name + "</span>"
                    return retval;
                },
                targets: DATATABLES_COLUMNS.SEVERITY
            },
            {
                render: function (data, type, row) {
                    if (data.indexOf(',') > -1) {
                        var parts = data.split(DATA_PARTS_DELIMITER);
                        for (var i = 0; i < parts.length; i++) {
                            if (parts[i] in PORT_NAMES)
                                parts[i] = parts[i] + " (" + PORT_NAMES[parts[i]] + ")";
                        }
                        data = "<span title='" + parts.join(DATA_PARTS_DELIMITER) + "' class='ellipsis'></span>";
                    }
                    else {
                        if (data in PORT_NAMES)
                            data = data + " (" + PORT_NAMES[data] + ")";
                    }
                    return data;
                },
                targets: [ DATATABLES_COLUMNS.SRC_PORT, DATATABLES_COLUMNS.DST_PORT ]
            },
            {
                render: function (data, type, row) {
                    if (data.indexOf(',') > -1)
                        data = "<span title='" + data + "' class='ellipsis'></span>";
                    else if (data in IP_ALIASES) {
                        data = "<span class='ipcat'>" + IP_ALIASES[data] + "</span>" + data;
                    }
                    else {
                        var stored = $.jStorage.get(STORAGE_KEY_EDIT_ALIASES);
                        if (stored !== null) {
                            if (data in stored)
                                data = "<span class='ipcat'>" + stored[data] + "</span>" + data;
                        }
                    }
                    return data;
                },
                targets: [ DATATABLES_COLUMNS.SRC_IP, DATATABLES_COLUMNS.DST_IP ]
            },
            {
                render: function (data, type, row) {
                    if (data.indexOf(',') > -1)
                        data = "<span title='" + data + "' class='ellipsis'></span>" + "<span class='hidden'>" + data + "</span>";
                    return data;
                },
                targets: [ DATATABLES_COLUMNS.SENSOR, DATATABLES_COLUMNS.PROTO ]
            },
            {
                render: function (data, type, row) {
                    var info = row[DATATABLES_COLUMNS.INFO];

                    data = data.replace(/</g, "&lt;").replace(/>/g, "&gt;");

                    if ((data.indexOf(',') > -1) || (data.replace(/&#\d+;/g, "|").length > LONG_TRAIL_THRESHOLD)) {
                        var common = "";
                        var title = "";
                        var left = false;

                        if ((data.indexOf('(') > -1) && (data.indexOf(')') > -1)) {
                            var parts = data.split(DATA_PARTS_DELIMITER);
                            for (var i = 0; i < parts.length; i++) {
                                var index = parts[i].indexOf('(');
                                if (index > -1) {
                                    if (index === 0)
                                        left = true;
                                    common = parts[i].replace(/\(.+\)/g, "");
                                    break;
                                }
                            }
                        }

                        var parts = data.split(DATA_PARTS_DELIMITER);
                        for (var i = 0; i < parts.length; i++)
                            parts[i] = parts[i].replace(common, "").replace(/[()]/g, "");  // replace only first occurrence

                        title = parts.join(DATA_PARTS_DELIMITER);

//                        title = data.replace(common, "").replace(/[()]/g, "");
//                        title = data.split(common).join("").replace(/[()]/g, "");

                        if (common.startsWith('.'))
                            title = title.split(common.substr(1)).join("");

                        try {
                            title = decodeURIComponent(title);
                        }
                        catch(err) {
                        }
                        finally {
                            title = title.replace(/"/g, '%22');
                        }

                        // Reference: https://stackoverflow.com/questions/3340802/add-line-break-within-tooltips
                        title = title.replace(TOOLTIP_FOLDING_REGEX, "$1&#10;");

                        common = '<span class="trail-text">' + common + '</span>';

                        if (left)
                            data = "<span title=\"" + title + "\" class='ellipsis'></span>" + common;
                        else
                            data = common + "<span title=\"" + title + "\" class='ellipsis'></span>";
                    }
                    else {
                        if (REPLACE_SINGLE_CLOUD_WITH_BRACES)
                            data = data.replace('(', '{').replace(')', '}');

                        if (info.contains("sinkholed"))
                            data = data.replace('(', '').replace(')', '');

                        data = '<span class="trail-text">' + data + '</span>';
                    }

                    return data;
                },
                targets: [ DATATABLES_COLUMNS.TRAIL ]
            },
            {
                render: function ( data, type, row ) {
                    return '<div class="event-data">' + data[0] + '</div><span class="hidden">' + data[1].join(DATA_PARTS_DELIMITER) + '</span>';
                },
                targets: DATATABLES_COLUMNS.EVENTS
            },
            {
                render: function ( data, type, row ) {
                    var color = data in TRAIL_TYPES ? TRAIL_TYPES[data] : getHashColor(data);
                    return '<span class="label-type white-label-text" style="background-color: ' + color + '">' + data + '</span>';
                },
                targets: DATATABLES_COLUMNS.TYPE
            },
            {
                render: function (data, type, row) {
                    var parts = data.split(' ');
                    if (parts.length > 1) {
                        var day = parts[0].split('-')[2];
                        var dayint = parseInt(day);
                        var suffix = (dayint > 10 && dayint < 20) ? "th" : DAY_SUFFIXES[dayint % 10] || "th";
                        return "<div title='" + data + "'><span class='time-day'>" + day + "<sup>" + suffix + "</sup></span> " + parts[1].split('.')[0] + "</div>";
                    }
                    else
                        return data;
                },
                targets: [ DATATABLES_COLUMNS.FIRST_SEEN, DATATABLES_COLUMNS.LAST_SEEN ]
            },
            {
                render: function (data, type, row) {
                    var value = 0;
                    var items = data.split(",");
                    for (var i = 0; i < items.length; i++)
                        if (items[i] !== "0")
                            value += 1;
                    return "<div class='sparkline hidden' value='" + value + "'>" + data + "</div>";
                },
                targets: DATATABLES_COLUMNS.SPARKLINE
            },
            {
                render: function (data, type, row) {
                    return '<div class="label-type ' + getContrastYIQ(data.substring(0, 6)) + '-label-text" style="background-color: #' + data.substring(0, 6) + '">' + data + '</div>';
                },
                targets: DATATABLES_COLUMNS.THREAT
            },
            {
                render: function (data, type, row) {
                    if (data.contains('(+')) {
                        var duplicates = data.match(/ \((\+\d+)\)$/);
                        if (duplicates !== null) {
                            data = data.replace(duplicates[0], "");
                            return ((data.substr(0, 1) != '(') ? '<i>' + data + '</i>': data) + '<span class="duplicates">' + duplicates[1] + '</span>';
                        }

                        duplicates = data.match(/ \(\+(.+)\)$/);
                        if (duplicates !== null) {
                            var items = duplicates[1].split(',');
                            data = data.replace(duplicates[0], "");
                            return ((data.substr(0, 1) != '(') ? '<i>' + data + '</i>': data) + '<span title="' + duplicates[1].replace(/,([^ ])/g, ", $1") + '" class="duplicates">+' + items.length + '</span>' + '<span class="searchable">' + duplicates[1] + "</span>";
                        }
                    }
                    return (data.substr(0, 1) != '(') ? '<i>' + data + '</i>': data;
                },
                targets: DATATABLES_COLUMNS.REFERENCE
            },
            {
                render: function (data, type, row) {
                    var retval = "";
                    var tags = data.split('|');
                    for (var index in tags) {
                        var tag = tags[index];
                        if ((typeof tag !== "function") && (tag.length > 0)) {
                            retval += getTagHtml(tag);
                        }
                    }
                    retval += "<input class='tag-input' type='text'>";
                    return retval;
                },
                targets: DATATABLES_COLUMNS.TAGS
            },
            {
               width: "1%",
               targets: [ DATATABLES_COLUMNS.THREAT, DATATABLES_COLUMNS.SENSOR, DATATABLES_COLUMNS.EVENTS, DATATABLES_COLUMNS.SEVERITY, DATATABLES_COLUMNS.FIRST_SEEN, DATATABLES_COLUMNS.LAST_SEEN, DATATABLES_COLUMNS.SPARKLINE, DATATABLES_COLUMNS.SRC_IP, DATATABLES_COLUMNS.SRC_PORT, DATATABLES_COLUMNS.DST_IP, DATATABLES_COLUMNS.DST_PORT, DATATABLES_COLUMNS.PROTO, DATATABLES_COLUMNS.TYPE ]
            }
        ],
        oLanguage: {
            sLengthMenu: "_MENU_ threats per page",  // Reference: http://www.sprymedia.co.uk/dataTables/example_language.html
            sZeroRecords: "No matching threats found",
            sInfo: "Showing _START_ to _END_ of <span class='details_total'>_TOTAL_</span> threats",
            sInfoEmpty: "Showing 0 to 0 of <span class='details_total'>0</span> total threats",
            sInfoFiltered: "(<span style='color: red'>filtered</span> from _MAX_ total threats)",
            sSearchPlaceholder: "Filter",
            sSearch: ""
        },
        dom: 'T<"clear">lfrtip',
        tableTools: {
            aButtons: [
                {
                    sExtends: "text",
                    sButtonText: "Clear",
                    fnClick: function (nButton, oConfig, oFlash) {
                        var table = $("#details").dataTable();
                        var settings = table.fnSettings();
                        table.fnFilter("");
//                         if ((settings._iDisplayLength > 0) && (settings._iDisplayLength < 30))
//                             $("html, body").animate({ scrollTop: $(document).height() }, "slow");
                    }
                },
                "print",
                {
                    sExtends: "collection",
                    sButtonText: "Tools",
                    aButtons: [
                        {
                            sExtends: "text",
                            sButtonText: "Edit custom IP aliases",
                            fnClick: function ( nButton, oConfig, oFlash ) {
                                function _initAliases() {
                                    $('#table_aliases').editableTableWidget();
                                    $('#table_aliases td').on('change', function(event, newValue) {
                                        if (event.target.cellIndex === 0)
                                            return (newValue.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) !== null);
                                    });
                                };

                                var html = '<table id="table_aliases" class="dataTable"><thead><tr class="ui-widget-header"><th>IP</th><th>Alias</th></tr></thead><tbody>';
                                var stored = $.jStorage.get(STORAGE_KEY_EDIT_ALIASES);
                                if (stored !== null) {
                                    $.each( stored, function( ip, alias ) {
                                        html += '<tr class="alias"><td>' + ip + '</td><td>' + alias + '</td></tr>'
                                    });
                                }
                                html += '</tbody></table>'

                                $('<div id="dialog-aliases" title="Aliases"></div>').appendTo('body')
                                .html(html)
                                .dialog({
                                    resizable: false,
                                    width: "auto",
                                    height: "auto",
                                    modal: true,
                                    buttons: {
                                        Add: function() {
                                            $('#table_aliases tr:last').after('<tr class="alias"><td>&nbsp;</td><td>&nbsp;</td></tr>');
                                            _initAliases();
                                            $("#table_aliases tr:last td:first").focus().click();
                                        },
                                        Done: function() {
                                            $(this).dialog("close");
                                            $('#dialog-aliases').remove();
                                            window.location.reload(false);
                                        }
                                    },
                                    open: function(event, ui) {
                                        _initAliases();
                                    },
                                    close: function(event, ui) {
                                        var result = {};
                                        $(this).find(".alias").each(function() {
                                            var ip = $(this).find("td").eq(0).text();
                                            var alias = $(this).find("td").eq(1).text();
                                            if ($.trim(ip) && $.trim(alias))
                                                result[ip] = alias;
                                        });
                                        $.jStorage.set(STORAGE_KEY_EDIT_ALIASES, result);

                                        $(this).dialog("destroy").remove();
                                    }
                                });
                            }
                        },
                        {
                            sExtends: "text",
                            sButtonText: "Flush local storage",
                            fnClick: function ( nButton, oConfig, oFlash ) {
                                $('<div id="dialog-confirm" title="Flush local storage?"></div>').appendTo('body')
                                .html('<p><span class="ui-icon ui-icon-alert" style="float:left; margin:0 7px 20px 0;"></span>These items will be permanently deleted and<br>won\'t be recoverable. Are you sure?</p>')
                                .dialog({
                                    resizable: false,
                                    width: "auto",
                                    height: "auto",
                                    modal: true,
                                    buttons: {
                                        Cancel: function() {
                                            $(this).dialog("close");
                                        },
                                        "Delete all items": function() {
                                            $(this).dialog("close");
                                            $.jStorage.flush();
                                            location.reload();
                                        }
                                    },
                                    close: function(event, ui) {
                                        $(this).dialog('destroy').remove();
                                    }
                                });
                            }
                        }
                    ]
                }
            ]
        },
        fnStateSaveParams: function (oSettings, oData) {
            oData.start = 0;
        },
        fnDrawCallback: function(oSettings) {
            $(".ui-tooltip").remove();
            $(".custom-menu").hide();
            clearTimeout(DRAW_SPARKLINES_TIMER);
            $(".sparkline:contains(',')").sparkline('html', { type: 'bar', barWidth: 2, barColor: SPARKLINE_COLOR, disableInteraction: false, tooltipClassname: "sparkline-tooltip" }); //, chartRangeMin: 0, chartRangeMax: _MAX_SPARKLINE_PER_HOUR });

            $(".tag-input").keyup(function(event) {
                tagInputKeyUp(event);
            }).blur(function(event) {
                tagInputKeyUp(event);
            });

            try {
                var sparklines = $(".sparkline");
                (function drawSparklines() {
                        var hidden = sparklines.filter(".hidden");
                        hidden.filter(':lt(10)').removeClass("hidden");
                        $.sparkline_display_visible();
                        if (hidden.length) {
                            DRAW_SPARKLINES_TIMER = setTimeout(drawSparklines, 100);
                        }
                    }
                )();
            }
            catch(err) {
            }
        },
        fnRowCallback: function(nRow, aData, iDisplayIndex, iDisplayIndexFull) {
            function nslookup(event, ui) {
                var elem = $(this);
                var html = elem.parent().html();
                var match = html.match(/\d+\.\d+\.\d+\.\d+/) || html.match(/[\w:]*:[\w:]*:[\w:]*/);

                if (match !== null) {
                    var ip = match[0];

                    $.ajax("https://stat.ripe.net/data/dns-chain/data.json?resource=" + ip, { dataType:"jsonp", ip: ip})
                    .done(function(json) {
                        var _ = json.data.reverse_nodes[this.ip];
                        if ((typeof _ === "undefined") || (_.length === 0) || (_ === "localhost")) {
                            _ = "-";
                        }
                        _ = String(_);
                        if (_.length > 40) {
                            _ = _.substring(0, 40) + "<br>" + _.substring(40);
                        }
                        var msg = "<p><b>" + _ + "</b></p>";
                        ui.tooltip.find(".ui-tooltip-content").html(msg + "please wait...");

                        $.ajax("https://stat.ripe.net/data/whois/data.json?resource=" + ip, { dataType:"jsonp", ip: ip, msg: msg })
                        .done(function(json) {
                            // Reference: http://bugs.jqueryui.com/ticket/8740#comment:21
                            var found = null;
                            var msg = "";

                            if (json.data.records !== undefined)
                                for (var i = json.data.records.length - 1; i >= 0 ; i--) {
                                    if ((json.data.records[i][0].key.toLowerCase().indexOf("inetnum") != -1) || (json.data.records[i][0].key.toLowerCase().indexOf("netrange") != -1)){
                                        found = i;
                                        break;
                                    }
                                }

                            if (found !== null) {
                                for (var j = 0; j < json.data.records[found].length; j++) {
                                    msg += json.data.records[found][j].key + ": " + json.data.records[found][j].value;
                                    msg += "<br>";
                                }
                                msg = msg.replace(/(-\+)+/g, "--").replace(/(-\+)+/g, "--");
                            }

                            ui.tooltip.find(".ui-tooltip-content").html(this.msg + msg);
                        });
                    });
                }
            }

            $('[title]', nRow).tooltip();

            $.each([DATATABLES_COLUMNS.TRAIL], function(index, value) {
                var cell = $('td:eq(' + value + ')', nRow);

                if (cell === null)
                    return false;

                var html = cell.html();

                if (html === null)
                    return false;

                if (html.indexOf('ipcat') > -1)
                    return false;

                var match = html.match(/\d+\.\d+\.\d+\.\d+/);
                if (match === null)
                    return false;

                var interval = null;
                var img = "";
                var ip = match[0];

                if (!DEMO && !isLocalAddress(ip)) {
                    if (!(ip in CHECK_IP)) {
                        CHECK_IP[ip] = null;
                        $.ajax("/check_ip?address=" + ip, { dataType: "jsonp", ip: ip, cell: cell })
                        .done(function(json) {
                            var span_ip = $(json.ipcat.length > 0 ? "<span class='ipcat'></span>" : "<span class='ipcat hidden'></span>").html(json.ipcat);
                            CHECK_IP[this.ip] = json;
                            this.cell.append(span_ip);
                            if (json.worst_asns === "true")
                                this.cell.append($("<span class='worst_asns' title='malicious ASN'></span>").tooltip());
                        });
                    }
                    else if (CHECK_IP[ip] !== null) {
                        var json = CHECK_IP[ip];
                        var span_ip = $(json.ipcat.length > 0 ? "<span class='ipcat'></span>" : "<span class='ipcat hidden'></span>").html(json.ipcat);
                        cell.append(span_ip);
                        if (json.worst_asns === "true")
                            cell.append($("<span class='worst_asns' title='malicious ASN'></span>").tooltip());
                    }
                    else {
                        interval = setInterval(function(ip, cell) {
                            if (typeof cell === "undefined")
                                clearInterval(interval);
                            else {
                                html = cell.html();
                                if (CHECK_IP[ip] !== null) {
                                    if (html.indexOf("ipcat") === -1) {
                                        var json = CHECK_IP[ip];
                                        var span_ip = $(json.ipcat.length > 0 ? "<span class='ipcat'></span>" : "<span class='ipcat hidden'></span>").html(json.ipcat);
                                        cell.append(span_ip);
                                        if (json.worst_asns === "true")
                                            cell.append($("<span class='worst_asns' title='malicious ASN'></span>").tooltip());
                                    }
                                    clearInterval(interval);
                                }
                            }
                        }, 500, ip, cell);
                    }
                }
            });

            $.each([DATATABLES_COLUMNS.SRC_IP, DATATABLES_COLUMNS.DST_IP], function(index, value) {
                var cell = $('td:eq(' + value + ')', nRow);

                if (cell === null)
                    return false;

                var html = cell.html();

                if (html === null)
                    return false;

                if ((html.indexOf('flag') > -1) || (html.indexOf('lan') > -1) || (html.indexOf(',') > -1) || (html.indexOf('ellipsis') > -1))
                    return false;

                var match = html.match(/\d+\.\d+\.\d+\.\d+/) || html.match(/[\w:]*:[\w:]*:[\w:]*/);
                if (match === null)
                    return false;

                var interval = null;
                var img = "";
                var ip = match[0];
                var options = { content: "please wait...", open: nslookup, position: { my: "left center", at: "right+10 top-50" } };

                if (!isLocalAddress(ip)) {
                    if (!(ip in IP_COUNTRY)) {
                        IP_COUNTRY[ip] = null;
                        $.ajax("https://stat.ripe.net/data/geoloc/data.json?resource=" + ip, { dataType:"jsonp", ip: ip, html: html, cell: cell })
                        .done(function(json) {
                            var span_ip = $("<span title=''/>").html(this.html + " ");
                            var country = null;

                            try {
                                country = json.data.located_resources[0].locations[0].country.toLowerCase().split('-')[0];
                            }
                            catch(err) {
                                try {
                                    country = json.data.located_resources[0].location.toLowerCase().split('-')[0];
                                }
                                catch(err) {
                                }
                            }

                            if ((country !== null) && (country !== "ano")) {
                                IP_COUNTRY[this.ip] = country;
                                img = '<img src="images/blank.gif" class="flag flag-' + IP_COUNTRY[this.ip] + '" title="' + IP_COUNTRY[this.ip].toUpperCase() + '">';
                            }
                            else {
                                IP_COUNTRY[this.ip] = "unknown";
                                img = '<img src="images/blank.gif" class="flag flag-unknown" title="UNKNOWN">';
                            }

                            span_ip.tooltip(options);
                            this.cell.html("").append(span_ip).append($(img).tooltip());
                        });
                    }
                    else if (IP_COUNTRY[ip] !== null) {
                        img = ' <img src="images/blank.gif" class="flag flag-' + IP_COUNTRY[ip] + '" title="' + IP_COUNTRY[ip].toUpperCase() + '">';

                        var span_ip = $("<span title=''/>").html(html + " ");
                        span_ip.tooltip(options);

                        if (typeof cell !== "undefined")
                            cell.html("").append(span_ip).append($(img).tooltip());
                    }
                    else {
                        interval = setInterval(function(ip, cell) {
                            if (typeof cell === "undefined")
                                clearInterval(interval);
                            else {
                                html = cell.html();
                                if (typeof html === "undefined")
                                    clearInterval(interval);
                                else if (IP_COUNTRY[ip] !== null) {
                                    if (html.indexOf("flag-") === -1) {
                                        img = ' <img src="images/blank.gif" class="flag flag-' + IP_COUNTRY[ip] + '" title="' + IP_COUNTRY[ip].toUpperCase() + '">';

                                        var span_ip = $("<span title=''/>").html(html + " ");
                                        span_ip.tooltip(options);

                                        cell.html("").append(span_ip).append($(img).tooltip());
                                    }
                                    clearInterval(interval);
                                }
                            }
                        }, 1000, ip, cell);
                    }
                }
                else {
                    img = '<img src="images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">';
                    cell.html(html + " ").append($(img).tooltip());
                }
            });
        }
    });

    $(details).find("thead").addClass("noselect");

    details.off("mouseenter");  // clear previous
    details.on("mouseenter", ".trail-text", function(event) {
        var cell = event.target;
        if (event.target.classList.contains("trail-text")) {
            clearTimeout(SEARCH_TIP_TIMER);
            SEARCH_TIP_TIMER = setTimeout(function(cell, event) {
                if ((event.buttons === 0) && ($(".ui-tooltip").length === 0)) {
                    var query = cell[0].innerHTML.replace(/<span class="ipcat.+span>/g, "").replace(/<[^>]+>/g, "").replace(/[\d.]+ \(([^)]+)\)/, "$1").replace(/[()]/g, "").replace(/^www\./g, "").replace(/:\d+$/, "").replace(/^([^\/]*\.[^\/]*)\/.+/, "$1").trim();
                    $(".searchtip").remove();
                    $("body").append(
                        $('<div class="ui-tooltip searchtip"><div><img src="images/newtab.png" style="cursor: pointer" title="open in new tab"><img src="images/close.png" style="cursor: pointer; width: 16px; height: 16px" title="close"></div><iframe src="' + SEARCH_TIP_URL.replace("${query}", query) + '"></iframe><div>')
                        .css('position', 'absolute')
                        .show()
                        .position({ my: "right+10 top-200", of: event })
                        .on("mouseleave", function(){
                            $(".searchtip").remove();
                        })
                    );
                    $(".searchtip img[title='open in new tab']").on("click", function() { searchTipToTab(query); });
                    $(".searchtip img[title='close']").on("click", function() { $(".searchtip").remove(); });
                }
            }, 2000, $(this), event);

            $(cell).on("mouseleave", function(mouseenter) {
                clearTimeout(SEARCH_TIP_TIMER);
            });
        }
    });

    details.off("click", ".trail");
    details.on("click", ".trail", function(event) {
        clearTimeout(SEARCH_TIP_TIMER);
    });

    details.off("dblclick");  // clear previous
    details.on("dblclick", "td", function (){
        var table = $("#details").dataTable();
        var filter = "";

        if ($(this).find(".info-input").length > 0)
            filter = $(this).find(".info-input")[0].value;
        else if ($(this).find(".time-day").length > 0)
            filter = $(this).find("div")[0].lastChild.textContent;
        else if ($(this).find(".trail-text").length > 0)
            filter = $(this).find(".trail-text")[0].lastChild.textContent.replace(/\([^)]+\)/g, "");
        else if ($(this).find(".duplicates").length > 0)
            filter = this.innerHTML.replace(/<span.+/g, " ").replace(/<.+?>/g, " ");
        else if (this.innerHTML.indexOf("ellipsis") > -1) {
            match = this.innerHTML.match(/title=["']([^"']+)/);
            if (match !== null)
                filter = match[1].replace(/,\ /g, " ");
            else {
                var tooltip = $(".ui-tooltip");
                if (tooltip.length > 0)
                    filter = tooltip.html().replace(/,\ /g, " ");
            }
        }
        else {
            filter = this.innerHTML.replace(/<span class="ipcat">.+?<\/span>/g, "").replace(/<.+?>/g, " ");
        }

        filter = filter.replace(/\s+/g, " ").trim();
        filter = $('<div/>').html(filter).text();
        appendFilter(filter);
    });

    details.off("mouseup");  // clear previous
    details.on("mouseup", "td", function (event) {
        if (event.button === 0) {  // left mouse button
            if (event.target.classList.contains("tag"))
                appendFilter(event.target.innerHTML, event, true);
            else if (event.target.classList.toString().startsWith("severity"))
                appendFilter(event.target.innerHTML, event);
            else if (event.target.classList.contains("label-type"))
                appendFilter(event.target.innerHTML, event);
        }
        else if (event.button === 1) {  // middle mouse button
            if (event.target.classList.contains("tag"))
                appendFilter(event.target.innerHTML, event, true);
        }
        else if (event.button === 2) {  // right mouse button/click
            stopPropagation(event);
        }
    });

    details.on("mouseup", ".event-data", copyEventsToClipboard);
    details.on("mouseup", ".ellipsis", copyEllipsisToClipboard);

    details.off("contextmenu");  // clear previous
    details.on("contextmenu", "td", function (event) {
        event.preventDefault();

        $(".ui-tooltip").remove();
        CONTEXT_MENU_ROW = $(event.target).closest("tr");

        // Show contextmenu
        $(".custom-menu").finish().toggle(100).

        // In the right position (the mouse)
        css({
            top: event.pageY + "px",
            left: event.pageX + "px"
        });
    });
}

function generateNonce() {
    var retval = "";

    for(var i = 0; i < NONCE_LENGTH; i++)
        retval += NONCE_ALPHABET.charAt(Math.floor(Math.random() * NONCE_ALPHABET.length));

    return retval;
}

String.prototype.hashCode = function() {
    return murmurhash3_32_gc(this, 13);
};


// Reference: http://stackoverflow.com/a/1026087
String.prototype.capitalizeFirstLetter = function() {
    return this.charAt(0).toUpperCase() + this.slice(1);
};

// Reference: http://stackoverflow.com/a/12710609
Array.prototype.insert = function (index, item) {
  this.splice(index, 0, item);
};

Array.prototype.clean = function(deleteValue) {
    for (var i = 0; i < this.length; i++) {
        if (this[i] === deleteValue) {
            this.splice(i, 1);
            i--;
        }
    }
    return this;
};

if (typeof String.prototype.startsWith !== "function") {
    String.prototype.startsWith = function (str){
        return this.indexOf(str) === 0;
    };
}

if (typeof String.prototype.contains !== "function") {
    String.prototype.contains = function (str){
        return this.indexOf(str) !== -1;
    };
}

// Reference: http://stackoverflow.com/a/2548133
if (typeof String.prototype.endsWith !== "function") {
    String.prototype.endsWith = function(suffix) {
        return this.indexOf(suffix, this.length - suffix.length) !== -1;
    };
}

// Reference: http://stackoverflow.com/a/6700
Object.size = function(obj) {
    var size = 0, key;
    for (key in obj) {
        if (obj.hasOwnProperty(key))
            size++;
    }
    return size;
};

jQuery.fn.dataTableExt.afnFiltering.push(
    function(settings, data, dataIndex) {
        return true;
    }
);

jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    // Reference: http://cdn.datatables.net/plug-ins/3cfcc339e89/sorting/date-euro.js
    "date-custom-pre": function ( a ) {
        var x;
        if ( $.trim(a) !== '' ) {
            // extract timestamp from "<div title='yyyy-mm-dd hh:mm:ss.ususus'><span class='time-day'>dd<sup>th</sup></span> hh:mm:ss</div>"
            var frTimestamp = $.trim(a).split("'")[1];

            var frDatea = frTimestamp.split(' ');
            var frTimea = frDatea[1].split('.')[0].split(':');
            var frUseca = frDatea[1].split('.')[1];
            var frDatea2 = frDatea[0].split('-');

            x = (frDatea2[0] + frDatea2[1] + frDatea2[2] + frTimea[0] + frTimea[1] + frTimea[2] + frUseca) * 1;
        }
        else {
            x = Infinity;
        }
        return x;
    },
    "date-custom-asc": function ( a, b ) {
        return a - b;
    },
    "date-custom-desc": function ( a, b ) {
        return b - a;
    }
});

jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    // Reference: https://cdn.datatables.net/plug-ins/3cfcc339e89/sorting/ip-address.js
    "ip-address-pre": function (a) {
        return _ipSortingValue(a);
    },

    "ip-address-asc": function ( a, b ) {
        return ((a < b) ? -1 : ((a > b) ? 1 : 0));
    },

    "ip-address-desc": function ( a, b ) {
        return ((a < b) ? 1 : ((a > b) ? -1 : 0));
    }
});

jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    "events-pre": function (a) {
        return parseInt(a.replace(/<[^>]+>/g, ""));
    },

    "events-asc": function ( a, b ) {
        return ((a < b) ? -1 : ((a > b) ? 1 : 0));
    },

    "events-desc": function ( a, b ) {
        return ((a < b) ? 1 : ((a > b) ? -1 : 0));
    }
});

jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    "severity-pre": function (a) {
        var x = 0;
        var match = a.match(/value=["'](\d+)/);

        if (match !== null) {
            x = parseInt(match[1]);
        }

        return x;
    },

    "severity-asc": function ( a, b ) {
        return ((a < b) ? -1 : ((a > b) ? 1 : 0));
    },

    "severity-desc": function ( a, b ) {
        return ((a < b) ? 1 : ((a > b) ? -1 : 0));
    }
});

jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    // Reference: https://cdn.datatables.net/plug-ins/3cfcc339e89/sorting/ip-address.js
    "sparkline-pre": function ( a ) {
        return parseInt($(a).attr("value"));
    },

    "sparkline-asc": function ( a, b ) {
        return ((a < b) ? -1 : ((a > b) ? 1 : 0));
    },

    "sparkline-desc": function ( a, b ) {
        return ((a < b) ? 1 : ((a > b) ? -1 : 0));
    }
});

jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    // Reference: https://cdn.datatables.net/plug-ins/3cfcc339e89/sorting/ip-address.js
    "port-pre": function ( a ) {
        var x = 0;
        var match = a.match(/\d+/);

        if (match !== null)
            x = parseInt(match[0]);

        return x;
    },

    "port-asc": function ( a, b ) {
        return ((a < b) ? -1 : ((a > b) ? 1 : 0));
    },

    "port-desc": function ( a, b ) {
        return ((a < b) ? 1 : ((a > b) ? -1 : 0));
    }
});

jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    "threat-pre": function ( a ) {
        var x = "";
        var match = a.match(/([0-9a-fA-F]{8})/);

        if (match !== null)
            //x = parseInt(match[1], 16);
            x = match[1];

        return x;
    },

    "threat-asc": function ( a, b ) {
        return ((a < b) ? -1 : ((a > b) ? 1 : 0));
    },

    "threat-desc": function ( a, b ) {
        return ((a < b) ? 1 : ((a > b) ? -1 : 0));
    }
});

function setChartScale(options, maxValue) {
    if (maxValue > 0) {
        stepValue = Math.pow(10, Math.floor(Math.log(maxValue) / Math.LN10));
        options.scaleOverride = true;
        options.scaleStartValue = 0;
        while ((stepValue > 0) && (stepValue === Math.floor(stepValue))) {
            options.scaleStepWidth = stepValue;
            options.scaleSteps = Math.ceil(maxValue / stepValue);
            if ((options.scaleSteps >= 5) || (stepValue === 1))
                break;
            else
                stepValue = stepValue / 2;
        }
    }
}

function drawInfo(type) {
    //var color = $("#" + type.toLowerCase() + "_count").parent()[0].style["background-color"];
    //$("li.status-button").css("opacity", "0.6");
    $("#chart_area").empty();

    if (jQuery.isEmptyObject(_HOURS))
        return;

    if ($("#" + type.toLowerCase() + "_count").parent()[0].style.border.contains("white")) {
        resetStatusButtons();
        return;
    }

    resetStatusButtons();

    $("#" + type.toLowerCase() + "_count").parent().css("text-shadow", "none");
    $("#" + type.toLowerCase() + "_count").parent().css("border", "3px solid white");

    $("#graph_close").removeClass("hidden").show();

    $.jStorage.set(STORAGE_KEY_ACTIVE_STATUS_BUTTON, type);

    if (type === "Events") {
        var ticks = {};
        var labels = [];
        var first = true;
        var datasets = [];
        var total_days = Math.round(Object.size(_HOURS) / 24);

        for (var type in TRAIL_TYPES) {
            var _ = [];

            ticks[type] = [];

            for (var hour in _HOURS)
                _.push([hour >>> 0, _HOURS[hour][type]]);

            _.sort(function(a, b) {
                a = a[0];
                b = b[0];

                return a < b ? -1 : (a > b ? 1 : 0);
            });

            for (var i = 0; i < _.length; i++) {
                var date = new Date(_[i][0] * 60 * 60 * 1000);
                if (first) {
                    if (i % total_days === 0) {
                        var label = "";
                        if (total_days > 2) {
                            label += pad(date.getFullYear(), 4) + "-" + pad(date.getMonth(), 2) + "-" + pad(date.getDate(), 2) + " ";
                        }
                        label += pad(date.getHours(), 2) + "h";
                        labels.push(label);
                    }
                    else
                        labels.push("");
                }

                ticks[type].push(_[i][1] | 0);
            }

            for (var i = ticks[type].length - 1; i >= 0; i--) {
                if (ticks[type][i] === 0)
                    ticks[type][i] = null;
                else
                    break;
            }

            first = false;

            datasets.push(
                {
                    label: type,
                    strokeColor: TRAIL_TYPES[type],
                    pointColor: TRAIL_TYPES[type],
                    pointHighlightFill: "#fff",
                    data: ticks[type]
                }
            );
        }

        var data = {
            labels: labels,
            datasets: datasets
        };
        var options = {
            //scaleGridLineColor: "#abb2b4",
            scaleShowVerticalLines: false,
            scaleShowHorizontalLines: false, // because StackedBar doesn't show them properly
            datasetFill: false,
            bezierCurve: false,
            pointDotRadius: Math.max(1, 5 - total_days),
            //scaleShowGridLines: false
            //tooltipTemplate: "<%if (label){%><%=label.replace(/[^0-9]/, '')%>:00h-<%=label.replace(/[^0-9]/, '')%>:59h: <%}%><%= value %> events",
            tooltipTemplate: CHART_TOOLTIP_FORMAT,
            multiTooltipTemplate: CHART_TOOLTIP_FORMAT,  // Reference: http://stackoverflow.com/a/24622442
            pointHitDetectionRadius: 5
        };

        //setChartScale(options, _MAX_EVENTS_PER_HOUR);

        var ctx = $('<canvas id="chart_canvas" width="' + CHART_WIDTH + '" height="' + CHART_HEIGHT + '"></canvas>').appendTo('#chart_area')[0].getContext("2d");
        var chart = new Chart(ctx);
        var line = chart.Line(data, options);

        chart.canvas.onclick = function(evt) {
            var activePoints = line.getPointsAtEvent(evt);

            if (activePoints.length > 0) {
                var filter = '" ' + activePoints[0].label.replace(/[^0-9]/g, "") + ':"';
                var table = $("#details").dataTable();

                table.fnFilter(filter);
                scrollTo("#details");
            }
        };
    }
    else if (type === "Trails") {
        var data = [];
        var other = 0;
        var _ = {};

        for (var type in TRAIL_TYPES)
            _[type] = [];

        var threshold = 0;
        for (var i = 0; i < _TRAILS_SORTED.length; i++)
            threshold += _TRAILS_SORTED[i][1];

        threshold = threshold / 100;

        for (var i = 0; i < _TRAILS_SORTED.length; i++) {
            var item = _TRAILS_SORTED[i];

            if (item[1] >= threshold) {
                var match = item[0].match(/(.*?)\ \(([^)]+)\)/);
                var type = match[2];
                var count = item[1];

                data.push({value: count, label: item[0], color: type in TRAIL_TYPES ? TRAIL_TYPES[type] : getHashColor(type)});
            }
            else
                other += item[1];
        }

        if (other > 0)
            data.push({ value: other, label: "Other (<1%)", color: OTHER_COLOR });

        var pie = new d3pie("chart_area", {
            header: {
                title: {
                    fontSize: 1,
                    font: DEFAULT_FONT_FAMILY
                },
                subtitle: {
                    color: "#999999",
                    fontSize: 1,
                    font: DEFAULT_FONT_FAMILY
                },
                titleSubtitlePadding: 0
            },
            footer: {
                color: "#999999",
                fontSize: 1,
                font: DEFAULT_FONT_FAMILY,
                location: "bottom-left"
            },
            size: {
                canvasHeight: CHART_HEIGHT,
                canvasWidth: CHART_WIDTH
            },
            data: {
                content: data
            },
            labels: {
                inner: {
                    hideWhenLessThanPercentage: 101
                },
                mainLabel: {
                    font: DEFAULT_FONT_FAMILY,
                    fontSize: PIE_FONT_SIZE
                },
                percentage: {
                    color: "#ffffff",
                    font: DEFAULT_FONT_FAMILY,
                    decimalPlaces: 0
                },
                value: {
                    color: "#adadad",
                    font: DEFAULT_FONT_FAMILY,
                    fontSize: PIE_FONT_SIZE
                },
                lines: {
                    enabled: true
                }
            },
            tooltips: {
                enabled: true,
                type: "placeholder",
                string: "{label}: {value}, {percentage}%",
                styles: {
                    font: DEFAULT_FONT_FAMILY
                }
            },
            effects: {
                load: {
                    speed: 500
                },
                pullOutSegmentOnClick: {
                    effect: "none"
                }
            },
            misc: {
                gradient: {
                    enabled: true,
                    percentage: 100
                }
            },
            callbacks: {
                onClickSegment: function(a) {
                    var filter = a.data.label.replace(/\(([A-Z]+)\)/g, "$1");

                    if (!filter.startsWith("Other")) {
                        var table = $("#details").dataTable();

                        table.fnFilter(filter);
                        scrollTo("#details");
                    }
                }
            }
        });
    }
    else if (type === "Sources") {
        var labels = [];
        var values = [];
        var maxValue = 0;
        var datasets = {};
        var options = {
            scaleShowVerticalLines: false,
            scaleShowHorizontalLines: false,
            tooltipTemplate: CHART_TOOLTIP_FORMAT,
            multiTooltipTemplate: CHART_TOOLTIP_FORMAT  // Reference: http://stackoverflow.com/a/24622442
        };

        for (var key in TRAIL_TYPES)
            datasets[key] = { fillColor: TRAIL_TYPES[key], label: key, data: [] };

        for (var i = 0; i < _TOP_SOURCES.length; i++) {
            labels.push(_TOP_SOURCES[i][0]);
            maxValue = Math.max(_TOP_SOURCES[i][1], maxValue);

            for (var key in TRAIL_TYPES)
                datasets[key].data.push(_SOURCE_EVENTS[_TOP_SOURCES[i][0]][key]);
        }

        _ = [];
        for (var key in TRAIL_TYPES) {
            _.insert(0, datasets[key]); // StackedBar is drawing from last to first (for some strange reason)
        }

        var data = {
            labels: labels,
            datasets: _
        };

        var ctx = $('<canvas id="chart_canvas" width="' + CHART_WIDTH + '" height="' + CHART_HEIGHT + '"></canvas>').appendTo('#chart_area')[0].getContext("2d");
        var chart = new Chart(ctx);
        var bar = chart.StackedBar(data, options);

        chart.canvas.onclick = function(evt) {
            var activeBars = bar.getBarsAtEvent(evt);

            if (activeBars.length > 0) {
                var filter = activeBars[0].label;

                if (filter.toLowerCase() != "other") {
                    var table = $("#details").dataTable();

                    table.fnFilter(filter);
                    scrollTo("#details");
                }
            }
        };
    }
    else if (type === "Severity") {
        var data = [];

        for (var severity in _SEVERITY_COUNT) {
            var count = _SEVERITY_COUNT[severity];
            var color = SEVERITY_COLORS[severity];
            var label = "";
            for (var key in SEVERITY)
                if (SEVERITY[key] == severity)
                    label = key.toLowerCase();
            data.push({value: count, label: label, color: color})
        }

        var pie = new d3pie("chart_area", {
            "header": {
                "title": {
                    "fontSize": 1,
                    "font": DEFAULT_FONT_FAMILY
                },
                "subtitle": {
                    "color": "#999999",
                    "fontSize": 1,
                    "font": DEFAULT_FONT_FAMILY
                },
                "titleSubtitlePadding": 0
            },
            "footer": {
                "color": "#999999",
                "fontSize": 1,
                "font": DEFAULT_FONT_FAMILY,
                "location": "bottom-left"
            },
            "size": {
                "canvasHeight": CHART_HEIGHT,
                "canvasWidth": CHART_WIDTH
            },
            "data": {
                "content": data
            },
            "labels": {
                "inner": {
                    "hideWhenLessThanPercentage": 101
                },
                "mainLabel": {
                    "font": DEFAULT_FONT_FAMILY,
                    "fontSize": PIE_FONT_SIZE
                },
                "percentage": {
                    "color": "#ffffff",
                    "font": DEFAULT_FONT_FAMILY,
                    "decimalPlaces": 0
                },
                "value": {
                    "color": "#adadad",
                    "font": DEFAULT_FONT_FAMILY,
                    "fontSize": PIE_FONT_SIZE
                },
                "lines": {
                    "enabled": true
                }
            },
            "tooltips": {
                "enabled": true,
                "type": "placeholder",
                "string": "{label}: {value}, {percentage}%",
                "styles": {
                    "font": DEFAULT_FONT_FAMILY
                }
            },
            "effects": {
                "load": {
                    "speed": 500
                },
                "pullOutSegmentOnClick": {
                    "effect": "none"
                }
            },
            "misc": {
                "gradient": {
                    "enabled": true,
                    "percentage": 100
                }
            },
            "callbacks": {
                onClickSegment: function(a) {
                    var filter = a.data.label;
                    var table = $("#details").dataTable();

                    table.fnFilter(filter);
                    scrollTo("#details");
                }
            }
        });
    }
    else if (type === "Threats") {
        var data = [];
        var threshold = 0;
        for (var i = 0; i < _THREATS_SORTED.length; i++)
            threshold += _THREATS_SORTED[i][1];

        threshold = threshold / 100;

        var other = 0;
        for (var i = 0; i < _THREATS_SORTED.length; i++) {
            var item = _THREATS_SORTED[i];

            if (item[1] >= threshold) {
                //var threat = item[0];
                var threat = item[0].replace(/\ \([^)]+\)/g, "");
                var count = item[1];
                var color = "#" + threat.substr(0, 6);

                data.push({value: count, label: threat, color: color})
            }
            else
                other += item[1];
        }

        if (other > 0)
            data.push({value: other, label: "Other (<1%)", color: OTHER_COLOR})

        var pie = new d3pie("chart_area", {
            "header": {
                "title": {
                    "fontSize": 1,
                    "font": DEFAULT_FONT_FAMILY
                },
                "subtitle": {
                    "color": "#999999",
                    "fontSize": 1,
                    "font": DEFAULT_FONT_FAMILY
                },
                "titleSubtitlePadding": 0
            },
            "footer": {
                "color": "#999999",
                "fontSize": 1,
                "font": DEFAULT_FONT_FAMILY,
                "location": "bottom-left"
            },
            "size": {
                "canvasHeight": CHART_HEIGHT,
                "canvasWidth": CHART_WIDTH
            },
            "data": {
                "content": data
            },
            "labels": {
                "inner": {
                    "hideWhenLessThanPercentage": 101
                },
                "mainLabel": {
                    "font": DEFAULT_FONT_FAMILY,
                    "fontSize": PIE_FONT_SIZE
                },
                "percentage": {
                    "color": "#ffffff",
                    "font": DEFAULT_FONT_FAMILY,
                    "decimalPlaces": 0
                },
                "value": {
                    "color": "#adadad",
                    "font": DEFAULT_FONT_FAMILY,
                    "fontSize": PIE_FONT_SIZE
                },
                "lines": {
                    "enabled": true
                }
            },
            "tooltips": {
                "enabled": true,
                "type": "placeholder",
                "string": "{label}: {value}, {percentage}%",
                "styles": {
                    "font": DEFAULT_FONT_FAMILY
                }
            },
            "effects": {
                "load": {
                    "speed": 500
                },
                "pullOutSegmentOnClick": {
                    "effect": "none"
                }
            },
            "misc": {
                "gradient": {
                    "enabled": true,
                    "percentage": 100
                }
            },
            "callbacks": {
                onClickSegment: function(a) {
                    var filter = a.data.label.substr(0, 8);

                    if (!filter.startsWith("Other")) {
                        var table = $("#details").dataTable();

                        table.fnFilter(filter);
                        scrollTo("#details");
                    }
                }
            }
        });
    }
}

function initVisual() {
    var sparklines = {}
    var min_ = null;
    var max_ = null;
    var sliceColors = [];
    var total = {};
    var data = [];
    var other = 0;
    var severityMax = null;
    var severityMaxName = null;
    var severitySum = 0;

    _MAX_EVENTS_PER_HOUR = 0;
    _TRAILS_SORTED = _sort(_TRAILS);

    for (var type in TRAIL_TYPES) {
        sparklines[type] = [];
        total[type] = 0;
    }

    // Severity sparkline
    for (var severity in _SEVERITY_COUNT) {
        if (_SEVERITY_COUNT[severity] * severity > severityMax) {
            severityMax = _SEVERITY_COUNT[severity] * severity;
            for (var key in SEVERITY)
                if (SEVERITY[key] == severity)
                    severityMaxName = key.toLowerCase();
        }
        severitySum += _SEVERITY_COUNT[severity];
        data.push(_SEVERITY_COUNT[severity]);
        sliceColors.push(SEVERITY_COLORS[severity])
    }

    if (severitySum === 0) {
        data = [1];
        sliceColors = [OTHER_COLOR];
    }

    total["Severity"] = severityMaxName;

    var options = { type: 'pie', sliceColors: sliceColors, minSpotColor: "", maxSpotColor: "", spotColor: "", highlightSpotColor: "", highlightLineColor: "", tooltipClassname: "", width: '30', height: '30', offset: -90, disableInteraction: true };

    $("#severity_sparkline").sparkline(data, options);


    // Trails sparkline
    var threshold = 0;
    for (var i = 0; i < _TRAILS_SORTED.length; i++)
        threshold += _TRAILS_SORTED[i][1];

    threshold = threshold / 100;
    options.sliceColors = [];
    data = [];

    for (var i = 0; i < _TRAILS_SORTED.length; i++) {
        if (_TRAILS_SORTED[i][1] >= threshold) {
            var type = _TRAILS_SORTED[i][0].match(/\(([A-Z]+)\)/)[1];
            data.push(_TRAILS_SORTED[i][1]);
            options.sliceColors.push(type in TRAIL_TYPES ? TRAIL_TYPES[type] : getHashColor(type));
        }
        else
            other += _TRAILS_SORTED[i][1];
    }

    if (other > 0) {
        data.push(other);
        options.sliceColors.push(OTHER_COLOR);
    }

    if (data.length === 0) {
        data.push(1);
        options.sliceColors.push(OTHER_COLOR);
    }

    total["Trails"] = _TRAILS_SORTED.length;

    $("#trails_sparkline").sparkline(data, options);

    // Threats sparkline
    var _ = {};
    for (var threat in _THREATS) {
        var threatUID = getThreatUID(threat);
        var count = _THREATS[threat][0];
        var type = _THREATS[threat][4][LOG_COLUMNS.TYPE];
        total[type] += count;
        _[threatUID] = count;
    }

    _THREATS_SORTED = _sort(_);
    var other = 0;

    data = [];
    options.sliceColors = [];

    var threshold = 0;
    for (var i = 0; i < _THREATS_SORTED.length; i++)
        threshold += _THREATS_SORTED[i][1];

    threshold = threshold / 100;

    for (var i = 0; i < _THREATS_SORTED.length; i++) {
        if (_THREATS_SORTED[i][1] >= threshold) {
            data.push(_THREATS_SORTED[i][1]);
            options.sliceColors.push("#" + _THREATS_SORTED[i][0].substr(0, 6));
        }
        else
            other += _THREATS_SORTED[i][1];
    }

    if (other > 0) {
        data.push(other);
        options.sliceColors.push(OTHER_COLOR);
    }

    if (data.length === 0) {
        data.push(1);
        options.sliceColors.push(OTHER_COLOR);
    }

    total["Threats"] = _THREATS_SORTED.length;
    $("#threats_sparkline").sparkline(data, options);

    // Events sparklines
    for (var hour in _HOURS) {
        if (min_ === null)
            min_ = hour;
        else
            min_ = Math.min(min_, hour);

        if (max_ === null)
            max_ = hour;
        else
            max_ = Math.max(max_, hour);
    }

    if ((min_ !== null) && (max_ !== null)) {
        var ms = 60 * 60 * 1000;
        min_ = dayStart(min_ * ms) / ms;
        max_ = dayEnd(max_ * ms) / ms;

        for (var hour = min_; hour <= max_; hour++) {
            if (!(hour in _HOURS)) {
                for (var key in sparklines)
                    sparklines[key].push(0);

                _HOURS[hour] = {};
                for (var type in TRAIL_TYPES)
                    _HOURS[hour][type] = 0;
            }
            else
                for (var key in sparklines) {
                    _MAX_EVENTS_PER_HOUR = Math.max(_MAX_EVENTS_PER_HOUR, _HOURS[hour][key] | 0);
                    sparklines[key].push(_HOURS[hour][key] | 0);
                }
        }

        for (var key in sparklines) {
            for (var i = sparklines[key].length - 1; i >= 0; i--) {
                if (sparklines[key][i] === 0)
                    sparklines[key][i] = null;
                else
                    break;
            }
        }
    }
    else {
        for (var key in sparklines) {
            sparklines[key].push(0);
            sparklines[key].push(0);
        }
    }

    // Sources sparkline
    _ = [];
    _TOP_SOURCES = [];
    total["Sources"] = Object.size(_SOURCES);

    sorted = _sort(_SOURCES);
    other = 0;

    var top = {};
    var ips = [];
    var zero = [];
    other_events = {};

    for (var key in TRAIL_TYPES) {
        zero.push(0);
        other_events[key] = 0;
    }

    for (var i = 0; i < sorted.length; i++) {
        if (i < MAX_SOURCES_ITEMS) {
            top[sorted[i][0]] = sorted[i][1];
            ips.push(sorted[i][0]);
        }
        else {
            for (var key in TRAIL_TYPES)
                other_events[key] += _SOURCE_EVENTS[sorted[i][0]][key];
            other += sorted[i][1];
        }
    }

    ips.sort(_ipCompareValues);
    _ = [zero];

    for (var i = 0; i < ips.length; i++) {
        var _type_counts = [];

        for (var key in TRAIL_TYPES)
            _type_counts.push(_SOURCE_EVENTS[ips[i]][key] | 0);

        _.push(_type_counts);
        _TOP_SOURCES.push([ips[i], _type_counts]);
    }

    if (other > 0) {
        var _other_counts = [];

        for (var key in TRAIL_TYPES)
            _other_counts.push(other_events[key] | 0);

        _.push(_other_counts);
        _TOP_SOURCES.push(["Other", other]);
        _SOURCE_EVENTS["Other"] = other_events;
    }

    _.push(zero);  // because of 0 value display problem

    var barWidth = Math.min(6, Math.max(2, Math.floor((SPARKLINE_WIDTH / (_.length + 2)) - 1)));

    var barColors = [];
    for (var key in TRAIL_TYPES)
        barColors.push(TRAIL_TYPES[key]);

    $('#sources_sparkline').sparkline(_, { width: SPARKLINE_WIDTH, height: '30', type: 'bar', barColor: '#ffffff', barWidth: barWidth, disableInteraction: true, zeroColor: "rgba(0, 0, 0, 0)", stackedBarColor: barColors});

    var options = { fillColor: false, minSpotColor: "", maxSpotColor: "", spotColor: "", highlightSpotColor: "", highlightLineColor: "", tooltipClassname: "", chartRangeMin: 0, chartRangeMax: _MAX_EVENTS_PER_HOUR, width: SPARKLINE_WIDTH, height: '30', lineWidth: 2 };

    total["Events"] = 0;

    var found = false;
    for (var key in total) {
        if (key.toUpperCase() === key) {
            options.lineColor = TRAIL_TYPES[key];
            $('#events_sparkline').sparkline(sparklines[key], options);
            options.composite = true;
            total["Events"] += total[key];
            found = true;
        }
    }

    if (!found) {
        $('#events_sparkline').sparkline([], options);
    }
    else {
        options.lineColor = "rgba(255, 255, 255, 0.25)";
        options.lineWidth = 1;
        $('#events_sparkline').sparkline([0, 0], options);
    }

    sum = 0;
    $("[id$=_count]").each(function() {
        sum += parseInt(total[$(this).attr("id").replace(/_count/, "").capitalizeFirstLetter()]) | 0;
    });

    for (var key in total)
        $("#" + key.toLowerCase() + "_count").html((sum > 0) ? numberWithCommas(total[key]) : '-')
}

function timestamp(str){
    return new Date(str).getTime();
}

function pad(n, width, z) {
    z = z || '0';
    n = n + '';

    return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
}

function formatDate(value) {
    return value.getFullYear() + "-" + pad(value.getMonth() + 1, 2) + "-" + pad(value.getDate(), 2);
};

function parseDate(value) {
    var retval = new Date(0);
    var match = value.match(/(\d{4})-(\d{2})-(\d{2})/);

    if (match !== null)
        retval = new Date(match[1], match[2] - 1, match[3]);

    return retval;
};

function getParameterByName(name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");

    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(location.search);

    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function dayStart(tick_seconds) {
    var value = new Date(tick_seconds);

    value.setHours(0);
    value.setMinutes(0);
    value.setSeconds(0);
    value.setMilliseconds(0);

    return Math.floor(value.getTime());
}

function dayEnd(tick_seconds) {
    var value = new Date(tick_seconds);

    value.setHours(23);
    value.setMinutes(59);
    value.setSeconds(59);
    value.setMilliseconds(999);

    return Math.floor(value.getTime());
}

$(document).keyup(function(e){
    var key = e.which || e.keyCode;

    if (key === 37) {        // left
        $("#details_previous").click();
    }
    else if (key === 39) {    // right
        $("#details_next").click();
    }
});

$(document).ready(function() {
    var from = dayStart(new Date().getTime());
    var to = dayStart(new Date().getTime());

    if (getParameterByName("from"))
        from = dayStart(parseDate(getParameterByName("from")));
    if (getParameterByName("to"))
        to = dayStart(parseDate(getParameterByName("to")));
});

function query(date1, date2) {
    if (date2 === undefined) {
        var url = location.origin + "/events?date=" + formatDate(date1);

        init(url, date1);
    }
    else {
        var d1, d2;
        if (date1 < date2) {
            d1 = date1; d2 = date2;
        }
        else {
            d1 = date2; d2 = date1;
        }
        var url = location.origin + "/events?date=" + formatDate(d1) + "_" + formatDate(d2);

        init(url, d1, d2);
    }
}

