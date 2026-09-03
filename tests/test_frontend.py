# coding: utf-8
"""The dashboard's table markup has to agree with the code that fills it.

The grid's columns live in html/index.html, the cells that fill them live in html/js/main.js, and
nothing connects the two but the fact that a person kept them in step. Add a column and forget the
matching cell and every row is silently shifted one column to the left from that point on - a
table that still renders, still sorts, and shows every value under the wrong heading. The
empty-state row is worse, because its colspan is a number that has to be counted by hand.

None of that is caught by a JS syntax check, and it is not worth a browser. The correspondence is
plain text in two files: read both and compare.

Adding the 'proto' column for #19569 needed exactly these three edits (header, cell, colspan), so
this file exists to make the fourth one impossible to forget.
"""

import json
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(REPO, "html", "index.html")
MAIN_JS = os.path.join(REPO, "html", "js", "main.js")

# Columns whose header is not a sortable field and whose cell carries no data-l label: the
# sparkline canvas and the per-threat tag editor.
UNLABELLED = {"sparkline", "tags"}


def _read(path):
    with open(path, "rb") as f:
        return f.read().decode("utf8")


def _severity_js(js):
    """The severityOf() implementation, evaluable by node on its own.

    Takes the whole block from the policy comment through the function, because severityOf() now
    depends on SEVERITY_FALLBACK and the compiled-regex IIFE above it. Under node there is no
    `document`, so the IIFE falls back to the shipped regex - which is what these tests then
    exercise, and why _the_fallback_matches_the_shipped_regex is worth its own test.
    """

    found = re.search(r"  // Severity is a POLICY.*?\n  \}\n", js, re.S)
    assert found, "could not find severityOf() and its policy block in main.js"
    return found.group(0)


class TestGridColumns(unittest.TestCase):
    def setUp(self):
        self.html = _read(INDEX)
        self.js = _read(MAIN_JS)
        grid = re.search(r"<table id=\"grid\">.*?</thead>", self.html, re.S)
        self.assertTrue(grid, "html/index.html no longer contains the #grid table header")
        self.headers = re.findall(r"<th[^>]*>([^<]*)</th>", grid.group(0))

    def test_every_column_has_a_cell(self):
        # The row template is one long concatenation of '<td ... data-l="name">' fragments.
        cells = re.findall(r"<td[^>]*data-l=\"([^\"]+)\"", self.js)
        expected = [h for h in self.headers if h not in UNLABELLED]
        self.assertEqual(
            expected, [c for c in cells if c in expected],
            "the grid's columns and the cells rendered for them are out of step - "
            "headers: %s, cells: %s" % (expected, cells))

    def test_no_orphan_cells(self):
        cells = [c for c in re.findall(r"<td[^>]*data-l=\"([^\"]+)\"", self.js)]
        for cell in cells:
            self.assertIn(cell, self.headers,
                          "row cell data-l=%r has no column heading in index.html" % cell)

    def test_empty_state_spans_every_column(self):
        spans = [int(n) for n in re.findall(r"colspan=\"(\d+)\" class=\"emptystate\"", self.js)]
        self.assertTrue(spans, "the empty-state row lost its colspan")
        for span in spans:
            self.assertEqual(len(self.headers), span,
                             "empty-state colspan is %d but the table has %d columns"
                             % (span, len(self.headers)))

    def test_sortable_columns_are_sortable(self):
        # data-key is what the sort comparator reads off a threat object: 'sev', 'count' and the
        # ip keys have their own branches, everything else falls through to a[k] and so must be a
        # field the aggregator actually sets.
        keys = re.findall(r"<th[^>]*data-key=\"([a-z]+)\"", self.html)
        built = re.search(r"t = \{ key: ttext,(.*?)\};", self.js, re.S)
        self.assertTrue(built, "could not find the threat object literal in main.js")
        fields = set(re.findall(r"(\w+):", built.group(1))) | {"sev", "count", "first", "uid"}
        for key in keys:
            self.assertIn(key, fields, "column data-key=%r is not a field of a threat" % key)


class TestSeverity(unittest.TestCase):
    """How an event is ranked in the queue.

    The sensor's own '(suspicious)' verdicts (long domain above all, and the HTTP request
    signatures) are guesses nothing corroborated, so they rank LOW - while everything a feed
    listed keeps the legacy Maltrail severity it has always had.

    A guess never reaches HIGH. Two of them are concrete enough for MEDIUM - an
    architecture-tagged dropper URL, and one host spraying 445 across the network - but the rest
    stay at LOW, which is where noisy output belongs.
    """

    # info, ref, expected severity (3 high / 2 medium / 1 low)
    CASES = (
        ("long domain (suspicious)", "(heuristic)", 1),
        ("potential periodic beaconing (suspicious)", "(heuristic)", 1),
        ("potential sql injection (suspicious)", "(heuristic)", 1),
        ("excessive no such domain (suspicious)", "(heuristic)", 1),
        ("sinkhole response (malware)", "(heuristic)", 3),        # a heuristic, but a confirmed one
        # #19622: the "malware" in this made it HIGH, level with a proven C2 callback. It is a
        # guess about a URL shape, so it is capped at MEDIUM - and must not fall to LOW either.
        ("potential iot-malware download (suspicious)", "(heuristic)", 2),
        # #19621 gave the counting heuristics the class marker the others always had. Severity
        # must not move because of that: an infection sweep stays MEDIUM, scanning stays LOW.
        ("potential infection (suspicious)", "(heuristic)", 2),
        ("potential infection", "(heuristic)", 2),                # pre-#19621 logs still rank the same
        ("potential port scanning (suspicious)", "(heuristic)", 1),
        ("potential web scanning (suspicious)", "(heuristic)", 1),
        ("potential udp scanning (suspicious)", "(heuristic)", 1),
        ("potential port scanning", "(heuristic)", 1),
        ("ipinfo (suspicious)", "(static)", 2),                   # a feed said so: legacy MEDIUM
        ("pua (suspicious)", "(static)", 2),
        ("cobaltstrike (malware)", "(feed)", 3),
        ("gophish (malicious)", "(feed)", 2),
        ("mass scanner", "(static)", 1),
        ("anything at all", "(custom)", 3),
    )

    def setUp(self):
        self.js = _read(MAIN_JS)

    def test_severity_of_real_events(self):
        node = None
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                node = candidate
                break
        if not node:
            raise unittest.SkipTest("needs node to evaluate severityOf()")
        script = _severity_js(self.js) + """
var cases = %s;
cases.forEach(function (c) {
  var got = severityOf(c[0], c[1]);
  if (got !== c[2]) console.log("FAIL " + JSON.stringify(c) + " -> " + got);
});
console.log("OK");
""" % json.dumps([list(c) for c in self.CASES])
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())


class TestThreatClassIcon(unittest.TestCase):
    """Every event must show its threat class, including the ones whose info never carried it.

    Static trail files get "<filename> (<category>)" from their path and the heuristics all end in
    "(suspicious)", but the feeds never adopted the convention: openphish has read "phishing" since
    2015 and urlhaus "malware" since 2018. Those rows rendered with no class icon at all (#19621).

    The strings are matched by other people's tooling, so classOf() infers the class instead of
    rewriting them - and SEVERITY MUST NOT MOVE as a result, which is what the second half of this
    pins. "known attacker" in particular has to stay LOW.
    """

    # info -> the class icon it must resolve to (None = deliberately none)
    ICON_CASES = (
        ("malware", "malware"),                             # urlhaus, viriback, cybercrimetracker, ...
        ("potential malware site", "malware"),
        ("phishing", "malicious"),                          # openphish
        ("known attacker", "suspicious"),
        ("bad reputation", "suspicious"),
        ("bad reputation (tor node)", "suspicious"),
        ("spammer", "suspicious"),
        ("crawler", "suspicious"),
        ("cobaltstrike (malware)", "malware"),              # already marked: unchanged
        ("gophish (malicious)", "malicious"),
        ("potential port scanning (suspicious)", "suspicious"),
        ("mass scanner", None),                             # not a threat class, so no icon
    )

    # info, ref -> severity that must be EXACTLY what it was before the icons existed
    SEVERITY_UNCHANGED = (
        ("malware", "abuse.ch", 3),
        ("known attacker", "x", 1),                         # must stay LOW
        ("bad reputation", "x", 1),
        ("bad reputation (tor node)", "x", 1),
        ("spammer", "x", 1),
        ("crawler", "x", 1),
        ("phishing", "x", 2),                               # unchanged, as before
        ("potential malware site", "x", 2),
    )

    def setUp(self):
        self.js = _read(MAIN_JS)
        self.node = None
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                self.node = candidate
                break
        if not self.node:
            self.skipTest("needs node to evaluate classOf()")

    def _run(self, extra, cases):
        import subprocess
        icons = re.search(r"var CLASS_ICON = \{.*?\n  \};", self.js, re.S)
        table = re.search(r"var UNMARKED_INFO_CLASS = \[.*?\];", self.js, re.S)
        fn = re.search(r"function classOf\(info\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(icons and table and fn,
                        "could not find CLASS_ICON / UNMARKED_INFO_CLASS / classOf() in main.js")
        script = ("var _lucideTag = '';\n" + icons.group(0) + "\n" + table.group(0) + "\n"
                  + fn.group(0) + "\n" + extra % json.dumps([list(c) for c in cases]))
        out = subprocess.check_output([self.node, "-e", script], stderr=subprocess.STDOUT)
        return out.decode("utf8", "replace").strip()

    def test_every_info_resolves_to_its_class(self):
        out = self._run("""
var cases = %s;
cases.forEach(function (c) {
  var got = classOf(c[0]);
  if (got !== c[1]) console.log("FAIL " + JSON.stringify(c[0]) + " -> " + got);
});
console.log("OK");
""", [(a, b) for a, b in self.ICON_CASES])
        self.assertEqual("OK", out, out)

    def test_a_trailing_qualifier_is_not_eaten(self):
        # The row strips the trailing parenthetical only when it IS the class. Stripping whichever
        # parenthetical happened to be last would render "bad reputation (tor node)" as
        # "bad reputation" and lose which kind of node it was.
        row = re.search(r"var ic = classOf\(t\.info\), desc = (.*?);", self.js)
        self.assertTrue(row, "could not find the info cell in main.js")
        self.assertIn("malware|malicious|suspicious", row.group(1),
                      "the info cell strips any trailing parenthetical again, so a qualifier like "
                      "'bad reputation (tor node)' loses it")

    def test_no_severity_moved(self):
        import subprocess
        script = (_severity_js(self.js) + """
var cases = %s;
cases.forEach(function (c) {
  var got = severityOf(c[0], c[1]);
  if (got !== c[2]) console.log("FAIL " + JSON.stringify(c) + " -> " + got);
});
console.log("OK");
""" % json.dumps([list(c) for c in self.SEVERITY_UNCHANGED]))
        out = subprocess.check_output([self.node, "-e", script], stderr=subprocess.STDOUT)
        self.assertEqual("OK", out.decode("utf8", "replace").strip(),
                         out.decode("utf8", "replace").strip())


class TestParseEvents(unittest.TestCase):
    """main.js must read an event log in either format (issue #19130, LOCAL_LOG_FORMAT).

    The browser parses the log itself - /events streams the raw bytes - so the frontend is one of
    the readers that has to know both. A single .log file can hold BOTH: flipping the option and
    restarting mid-day appends JSON after the text already written that morning.
    """

    TEXT = '"2026-01-01 10:00:03.123456" box 10.0.0.8 6666 5.5.5.5 80 TCP IP 5.5.5.5 "malware (test)" (static)'
    JSON = ('{"timestamp": 1767261603, "time": "2026-01-01 10:00:03.123456", "sensor": "box", '
            '"severity": "medium", "src_ip": "10.0.0.8", "src_port": 6666, "dst_ip": "5.5.5.5", '
            '"dst_port": 80, "proto": "TCP", "type": "IP", "trail": "5.5.5.5", "info": "malware (test)", '
            '"reference": "(static)"}')

    def setUp(self):
        self.js = _read(MAIN_JS)

    def _node(self):
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                return candidate
        raise unittest.SkipTest("needs node to evaluate parseEvents()")

    def _run(self, text):
        node = self._node()
        fields = re.search(r"var EVENT_FIELDS = \[.*?\];", self.js, re.S)
        row_fn = re.search(r"function jsonEventRow\(line\) \{.*?\n  \}", self.js, re.S)
        parse_fn = re.search(r"function parseEvents\(text\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(fields and row_fn and parse_fn, "could not find parseEvents() in main.js")
        # a stand-in for PapaParse: the delimiter is a space and quoting follows safe_value()
        shim = """
var window = { Papa: { parse: function (text, opts) {
  var out = [], lines = text.split("\\n");
  lines.forEach(function (line) {
    if (opts.skipEmptyLines && !line) return;
    var row = [], cur = "", q = false, i;
    for (i = 0; i < line.length; i++) {
      var ch = line[i];
      if (q) {
        if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; }
        else cur += ch;
      } else if (ch === '"') q = true;
      else if (ch === " ") { row.push(cur); cur = ""; }
      else cur += ch;
    }
    row.push(cur);
    out.push(row);
  });
  return { data: out };
} } };
"""
        script = shim + fields.group(0) + "\n" + row_fn.group(0) + "\n" + parse_fn.group(0) + """
console.log(JSON.stringify(parseEvents(%s)));
""" % json.dumps(text)
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        return json.loads(out.strip())

    def test_both_formats_produce_the_same_row(self):
        from_text = self._run(self.TEXT)
        from_json = self._run(self.JSON)
        self.assertEqual(len(from_text), 1)
        self.assertEqual(from_text, from_json, "a JSON line must aggregate exactly like a text one")
        # the indices aggregateRows() uses
        self.assertEqual(from_text[0][2], "10.0.0.8")
        self.assertEqual(from_text[0][7], "IP")
        self.assertEqual(from_text[0][8], "5.5.5.5")
        self.assertEqual(from_text[0][9], "malware (test)")

    def test_a_file_holding_both_formats_reads_completely(self):
        # the option changed and the sensor restarted mid-day
        rows = self._run("\n".join([self.TEXT, self.JSON, self.TEXT, self.JSON, self.JSON]))
        self.assertEqual(len(rows), 5, "a mixed file must not lose lines from either format")
        self.assertTrue(all(r[2] == "10.0.0.8" for r in rows))

    def test_ports_arrive_as_strings(self):
        # JSON writes a port as a number; the aggregator indexes rows as text throughout
        self.assertEqual(self._run(self.JSON)[0][3], "6666")

    def test_junk_lines_are_dropped_not_half_parsed(self):
        rows = self._run("\n".join(["{not json", self.JSON, '{"timestamp": 1}']))
        self.assertEqual(len(rows), 1, "only the complete event survives")

    def test_empty_input(self):
        self.assertEqual(self._run(""), [])


class TestDateRange(unittest.TestCase):
    """Multi-day selection (issue #4, open since 2015).

    /events has always understood "START_END"; only the UI was single-day. The date arithmetic is
    what actually breaks here - month ends, leap days, year boundaries and DST - so it is tested
    rather than eyeballed.
    """

    def setUp(self):
        self.js = _read(MAIN_JS)

    def _eval(self, expr):
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                node = candidate
                break
        else:
            raise unittest.SkipTest("needs node")
        pieces = []
        for pattern in (r"var RANGE_RE = /.*?/;",
                        r"function rangeParts\(s\) \{.*?\}",
                        r"function isRange\(s\) \{.*?\}",
                        r"function daySpan\(a, b\) \{.*?\}",
                        r"function addDays\(ds, n\) \{.*?\n  \}"):
            m = re.search(pattern, self.js, re.S)
            self.assertTrue(m, "could not find %s in main.js" % pattern)
            pieces.append(m.group(0))
        script = "function pad2(n){return (n<10?'0':'')+n;}\n" + "\n".join(pieces) + "\nconsole.log(JSON.stringify(%s));" % expr
        import subprocess
        return json.loads(subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode())

    def test_a_range_is_told_apart_from_a_day(self):
        self.assertEqual(self._eval('rangeParts("2026-01-01_2026-01-07")'), ["2026-01-01", "2026-01-07"])
        self.assertIsNone(self._eval('rangeParts("2026-01-01")'))
        self.assertFalse(self._eval('isRange("2026-01-01")'))
        self.assertFalse(self._eval('isRange("")'))

    def test_day_spans_are_inclusive(self):
        self.assertEqual(self._eval('daySpan("2026-01-01", "2026-01-01")'), 1)
        self.assertEqual(self._eval('daySpan("2026-01-01", "2026-01-07")'), 7)
        # across a month end, a year end and a leap day
        self.assertEqual(self._eval('daySpan("2026-01-30", "2026-02-02")'), 4)
        self.assertEqual(self._eval('daySpan("2025-12-30", "2026-01-02")'), 4)
        self.assertEqual(self._eval('daySpan("2024-02-28", "2024-03-01")'), 3)

    def test_stepping_days_crosses_boundaries(self):
        self.assertEqual(self._eval('addDays("2026-01-31", 1)'), "2026-02-01")
        self.assertEqual(self._eval('addDays("2026-01-01", -1)'), "2025-12-31")
        self.assertEqual(self._eval('addDays("2024-02-28", 1)'), "2024-02-29", "2024 is a leap year")
        self.assertEqual(self._eval('addDays("2023-02-28", 1)'), "2023-03-01")
        self.assertEqual(self._eval('addDays("2026-01-01", 0)'), "2026-01-01")

    def test_a_window_steps_by_its_own_length(self):
        # what prev/next must do with a 7-day range on screen: show the PREVIOUS seven days
        span = self._eval('daySpan("2026-01-08", "2026-01-14")')
        self.assertEqual(span, 7)
        self.assertEqual(self._eval('addDays("2026-01-08", -1 * 7)'), "2026-01-01")
        self.assertEqual(self._eval('addDays("2026-01-14", -1 * 7)'), "2026-01-07")

    def test_dst_does_not_shift_a_day(self):
        # local-midnight arithmetic must not lose or gain a day across a DST transition
        self.assertEqual(self._eval('addDays("2026-03-28", 1)'), "2026-03-29")
        self.assertEqual(self._eval('addDays("2026-03-29", 1)'), "2026-03-30")
        self.assertEqual(self._eval('daySpan("2026-03-27", "2026-03-31")'), 5)


class TestFamily(unittest.TestCase):
    """family: pulls a campaign back together.

    Feeds ship a big dump split into interlock / interlock-1 / interlock-2 - one incident under
    three names, 13% of the trail set on a normal box. The shard suffix is 1-2 digits, so a name
    that ends in a longer number (a CVE) has to survive intact.
    """

    CASES = (
        ("interlock-1 (malware)", "interlock"),
        ("interlock-2 (malware)", "interlock"),
        ("interlock (malware)", "interlock"),
        ("ek clearfake-1 (malicious)", "ek clearfake"),
        ("apt gamaredon-1 (malware)", "apt gamaredon"),
        ("cobaltstrike-2 (malware)", "cobaltstrike"),
        ("apt unc6691-1 (malware)", "apt unc6691"),      # digits in the name itself stay
        ("lummac2 (malware)", "lummac2"),
        ("cve-2021-44228 (malware)", "cve-2021-44228"),  # not a shard suffix
        ("long domain (suspicious)", "long domain"),
        ("mass scanner", "mass scanner"),                # no class marker at all
    )

    def setUp(self):
        self.js = _read(MAIN_JS)

    def test_family_of_real_info_fields(self):
        node = None
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                node = candidate
                break
        if not node:
            raise unittest.SkipTest("needs node to evaluate familyOf()")
        fn = re.search(r"var _famCache = .*?function familyOf\(info\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(fn, "could not find familyOf() in main.js")
        script = fn.group(0) + """
var cases = %s;
cases.forEach(function (c) {
  var got = familyOf(c[0]);
  if (got !== c[1]) console.log("FAIL " + JSON.stringify(c[0]) + " -> " + JSON.stringify(got));
});
console.log("OK");
""" % json.dumps([list(c) for c in self.CASES])
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())

    def test_family_token_filters_rows(self):
        # the wiring, not just the helper: run the real query matcher over threat objects
        node = None
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                node = candidate
                break
        if not node:
            raise unittest.SkipTest("needs node to evaluate matchPos()")
        # _lc ... matchPos is one contiguous block in main.js; take it whole rather than stitching
        start, end = self.js.find("function _lc(x)"), self.js.find("function matchToken(")
        self.assertTrue(0 < start < end, "the query-matching block moved in main.js")
        script = """
var state = { triage: {} };
function setList() { return []; } function displayPortSet() { return []; }
function tagsOf() { return []; } function getNote() { return ""; }
function portDir() { return null; } function hay(t) { return (t.info + " " + t.trail).toLowerCase(); }
""" + self.js[start:end] + """
var shard1 = { info: "interlock-1 (malware)", trail: "a.example" },
    shard2 = { info: "interlock-2 (malware)", trail: "b.example" },
    other  = { info: "cobaltstrike-1 (malware)", trail: "c.example" };
function want(ok, why) { if (!ok) console.log("FAIL " + why); }
want(matchPos(shard1, "family:interlock"), "family:interlock misses interlock-1");
want(matchPos(shard2, "family:interlock"), "family:interlock misses interlock-2");
want(!matchPos(other, "family:interlock"), "family:interlock matches an unrelated family");
want(!matchPos(shard2, "info:interlock-1"), "info: should still be the exact-ish field");
console.log("OK");
"""
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())


class TestChartLayout(unittest.TestCase):
    """The drill-down chart has to use the panel it is given.

    `main` lost its centered 1500px column, so the canvas's old hard 980px cap left the chart in the
    left third of a wide screen with dead space beside it - and the donut, positioned off the canvas
    HEIGHT (cx = h/2 + 6), sat against the left edge on top of that.
    """

    def setUp(self):
        self.js = _read(MAIN_JS)

    def test_canvas_is_sized_from_the_panel(self):
        fn = re.search(r"function showChart\(type\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(fn, "could not find showChart() in main.js")
        self.assertIn("area.clientWidth", fn.group(0), "showChart no longer measures the panel")
        self.assertNotIn("Math.min(980", fn.group(0), "the fixed 980px canvas cap is back")

    def test_open_chart_follows_a_window_resize(self):
        self.assertIn('window.addEventListener("resize"', self.js,
                      "nothing re-sizes the open chart when the window changes")

    def test_donut_and_legend_are_centred(self):
        node = None
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                node = candidate
                break
        if not node:
            raise unittest.SkipTest("needs node to evaluate donutPlacement()")
        fn = re.search(r"function donutPlacement\(ctx, cv, slices, R, fs\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(fn, "could not find donutPlacement() in main.js")
        script = fn.group(0) + """
var ctx = { font: "", measureText: function (s) { return { width: s.length * 7 }; } };
var slices = [];
for (var i = 0; i < 10; i++) slices.push({ k: "threat" + i, v: 100 - i });
[[1900, 184], [980, 109], [420, 90]].forEach(function (c) {
  var cv = { _w: c[0], _h: 400 }, R = c[1], p = donutPlacement(ctx, cv, slices, R);
  var lw = p.cols * p.colw - 26, block = R * 2 + 26 + lw;
  var left = p.cx - R, right = cv._w - (p.lx + lw);
  if (block + 12 <= cv._w) {                      // room to centre it
    if (Math.abs(left - right) > 1.5) console.log("FAIL w=" + c[0] + " not centred: " + left + " vs " + right);
  } else if (Math.abs(left - 6) > 0.5) {          // too wide: pinned to the left margin, not off-canvas
    console.log("FAIL w=" + c[0] + " not clamped to the margin (" + left + ")");
  }
  if (p.lx <= p.cx + R) console.log("FAIL w=" + c[0] + " legend overlaps the disc");
  if (p.cols * p.rows < Math.min(slices.length, 11)) console.log("FAIL w=" + c[0] + " legend drops rows");
});
// a wide panel splits ten entries into two columns; a narrow one keeps a single column
if (donutPlacement(ctx, { _w: 1900, _h: 400 }, slices, 184).cols !== 2) console.log("FAIL wide panel kept one legend column");
if (donutPlacement(ctx, { _w: 900, _h: 300 }, slices, 134).cols !== 1) console.log("FAIL narrow panel split the legend");
console.log("OK");
"""
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())


class TestChartAxis(unittest.TestCase):
    """The y axis of a count chart: integer steps, no repeated label, and it must be drawn at all.

    The line chart labelled five fixed gridlines with round(max * g / 4), so a peak of 2 came out as
    "0 1 1 2 2" (#19570), and both bar charts drew the gridlines with no labels whatsoever (#19571).
    """

    def setUp(self):
        self.js = _read(MAIN_JS)

    def test_every_count_chart_labels_its_gridlines(self):
        for fn in ("drawLines", "drawBars", "drawInteractiveBars"):
            body = re.search(r"function %s\(.*?\n  \}\n" % fn, self.js, re.S)
            self.assertTrue(body, "could not find %s() in main.js" % fn)
            self.assertIn("axisTicks(", body.group(0),
                          "%s() no longer derives its y axis from axisTicks()" % fn)
            self.assertIn("fillText(fmtN(v)", body.group(0),
                          "%s() draws gridlines without labelling them" % fn)
            # the rounded-quarters axis, which labelled different gridlines with the same number
            self.assertNotIn("Math.round(max", body.group(0),
                             "%s() is rounding a fraction of the peak into a label again" % fn)

    def test_axis_ticks_are_whole_and_distinct(self):
        # Run the real function, not a paraphrase of it: pull its source out of main.js and evaluate.
        node = None
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                node = candidate
                break
        if not node:
            raise unittest.SkipTest("needs node to evaluate axisTicks()")
        fn = re.search(r"function axisTicks\(max\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(fn, "could not find axisTicks() in main.js")
        script = fn.group(0) + """
var peaks = [0,1,2,3,4,5,6,7,8,9,10,11,13,17,23,43,99,100,101,250,999,1000,4321,99999,1234567];
peaks.forEach(function (p) {
  var t = axisTicks(p), labels = t.map(String);
  function die(why) { console.log("FAIL peak=" + p + " ticks=" + t.join(",") + " " + why); }
  if (t.length < 2) die("fewer than two gridlines");
  if (t[0] !== 0) die("does not start at zero");
  if (labels.length !== labels.filter(function (v, i) { return labels.indexOf(v) === i; }).length) die("repeated label");
  t.forEach(function (v, i) {
    if (v !== Math.round(v)) die("fractional tick");
    if (i && v <= t[i - 1]) die("not ascending");
  });
  if (t[t.length - 1] < p) die("top of scale below the peak");
  if (t.length > 7) die("too many gridlines");
});
console.log("OK");
"""
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())


class TestDrawerFields(unittest.TestCase):
    """Every field of an event line should be reachable in the detail panel (#19569)."""

    def setUp(self):
        self.js = _read(MAIN_JS)
        drawer = re.search(r"function openDrawer\(t\) \{.*?\n  \}\n", self.js, re.S)
        self.assertTrue(drawer, "could not find openDrawer() in main.js")
        self.drawer = drawer.group(0)

    def test_the_whole_tag_set_is_editable_here(self):
        # The row shows two tags and hides the rest behind "+N", so this is the only place a third
        # tag can be removed (#19568).
        self.assertIn('id="dwr_tags"', self.drawer, "the detail panel lost its tag section")
        self.assertIn('id="dwr_tagadd"', self.drawer, "the detail panel lost its tag input")
        self.assertIn("data-rm=", self.js, "drawer tags are no longer removable")

    def test_sections_cover_the_event_tuple(self):
        for section in ("sources", "destinations", "destination ports", "source ports", "protocols", "raw events"):
            self.assertIn(section + " \\u00b7 ", self.drawer,
                          "the detail panel no longer has a %r section" % section)



class TestServedAssets(unittest.TestCase):
    """Every asset the frontend asks for exists, and every file in html/ is asked for.

    Both halves have already been wrong. A jQuery UI theme and nine pre-v3 icons - 27 files - sat
    in html/images/ for seven weeks after the rewrite stopped referencing them, and the only reason
    anyone noticed is that someone read the directory. The mirror failure is worse: a renamed or
    deleted asset makes the live dashboard 404, and nothing in the suite would have said so
    because no test ever compared the references against the directory.

    Verifying it by hand meant serving html/ and reading an access log, which is why it happened
    once and never again. It is plain text on both sides: read the references, read the directory.
    """

    HTML_DIR = os.path.join(REPO, "html")

    # Files in html/ that nothing references, on purpose. Each entry needs a reason, and an entry
    # without one is an orphan wearing a disguise.
    UNREFERENCED_BY_DESIGN = {
        "index.html": "the entry point itself; the server serves it for /",
        "favicon.ico": "browsers request /favicon.ico whether or not the markup mentions it",
        "robots.txt": "fetched by crawlers, and named in CONTENT_EXTENSIONS_EXCLUSIONS for exactly that",
        "README.txt": "documents the directory; .txt is in DISABLED_CONTENT_EXTENSIONS, so it is not servable",
        "images/logo.xcf": "editable source of mlogo.png, not a served asset",
    }

    # Where a reference to a file under html/ can legitimately come from.
    SOURCES = (
        "html/index.html",
        "html/css/main.css",
        "html/js/main.js",
        "html/js/demo.js",
        "html/js/worldmap.js",
        "html/js/thirdparty.min.js",
        "core/httpd.py",   # _logo() renders <img src="images/mlogo.png">, _assetver() stats js/main.js and css/main.css
    )

    # Only directory-prefixed paths count as references. Everything the frontend and the server
    # actually ask for is written that way ("css/main.css", "images/mlogo.png"), and a bare
    # "main.js" would otherwise match the several comments that name the legacy files by filename.
    ASSET_RE = re.compile(r"""["'(]\s*/?((?:images|js|css)/[A-Za-z0-9._/-]+)""")

    def _referenced(self):
        found = {}
        for source in self.SOURCES:
            body = _read(os.path.join(REPO, source))
            for ref in self.ASSET_RE.findall(body):
                ref = ref.split("?")[0].split("#")[0].strip()
                if not ref or ref.startswith(("http:", "https:", "//", "data:")):
                    continue
                found.setdefault(ref.lstrip("/"), source)
        return found

    def _shipped(self):
        out = set()
        for root, _, names in os.walk(self.HTML_DIR):
            for name in names:
                out.add(os.path.relpath(os.path.join(root, name), self.HTML_DIR).replace(os.sep, "/"))
        return out

    def test_every_referenced_asset_exists(self):
        # The zero-404 check: a reference the dashboard makes must resolve to a file on disk.
        missing = []
        for ref, source in sorted(self._referenced().items()):
            if not os.path.isfile(os.path.join(self.HTML_DIR, ref)):
                missing.append("%s references html/%s, which does not exist" % (source, ref))
        self.assertEqual(missing, [], "the dashboard would 404: %s" % "; ".join(missing))

    def test_no_orphan_assets(self):
        # And the mirror: a file in html/ that nothing references is dead weight being served.
        referenced = self._referenced()
        orphans = sorted(f for f in self._shipped()
                         if f not in referenced and f not in self.UNREFERENCED_BY_DESIGN)
        self.assertEqual(orphans, [],
                         "nothing references these files under html/ - delete them, or add them to "
                         "UNREFERENCED_BY_DESIGN with the reason they stay: %s" % ", ".join(orphans))

    def test_the_allowlist_has_no_stale_entries(self):
        # An allowlist that outlives its files is how the next 27 orphans get in unnoticed.
        shipped = self._shipped()
        stale = sorted(f for f in self.UNREFERENCED_BY_DESIGN if f not in shipped)
        self.assertEqual(stale, [], "UNREFERENCED_BY_DESIGN names files that are gone: %s" % ", ".join(stale))


class TestNoEvalInServedScripts(unittest.TestCase):
    """The CSP's script-src does not allow 'unsafe-eval', so nothing served may need it.

    Dropping that keyword only holds while the frontend stays free of dynamic code evaluation.
    If someone adds an eval() the page breaks under the shipped policy, and the tempting fix is to
    widen the policy again - quietly giving back the injection protection it exists for. This
    fails first, and names the file.
    """

    PATTERNS = (
        r"\beval\s*\(",
        r"\bnew\s+Function\s*\(",
        r"\bset(?:Timeout|Interval)\s*\(\s*[\'\"]",
    )

    def test_no_dynamic_code_evaluation(self):
        offenders = []
        js_dir = os.path.join(REPO, "html", "js")
        for name in sorted(os.listdir(js_dir)):
            if not name.endswith(".js"):
                continue
            with open(os.path.join(js_dir, name), encoding="utf-8", errors="replace") as f:
                body = f.read()
            for pattern in self.PATTERNS:
                if re.search(pattern, body):
                    offenders.append("%s matches %s" % (name, pattern))
        self.assertEqual(offenders, [], "a served script uses dynamic code evaluation, which the "
                                        "shipped CSP forbids: %s" % "; ".join(offenders))

class TestRiskScoreMemo(unittest.TestCase):
    """riskOf() is memoized; the memo must not change a single score or the order they produce.

    It is called from inside the grid's sort comparator, twice per comparison, so it is cached on
    the threat - keyed on `count`, the only input that can still move after a threat is built. If
    that key were ever wrong the grid would silently rank threats by a stale score: still sorted,
    still plausible, quietly putting the wrong thing at the top. So this compares the memoized
    function against the original formula, including across a count change.
    """

    def _node(self):
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                return candidate
        raise unittest.SkipTest("needs node to evaluate riskOf()")

    def test_memo_matches_the_plain_formula(self):
        node = self._node()
        js = _read(MAIN_JS)
        hot = re.search(r"var RISK_HOT = /.*?/;", js, re.S)
        noise = re.search(r"var RISK_NOISE = /.*?/;", js, re.S)
        fn = re.search(r"function riskOf\(t\) \{.*?\n  \}", js, re.S)
        self.assertTrue(hot and noise and fn, "could not find riskOf() in main.js")
        script = hot.group(0) + "\n" + noise.group(0) + "\n" + fn.group(0) + """
// the pre-memo implementation, verbatim, as the reference
function reference(t) {
  var s = (t.sev || 1) * 1000;
  var hay = (("" + (t.type || "")) + " " + (t.info || "") + " " + (t.trail || "")).toLowerCase();
  if (RISK_HOT.test(hay)) s += 400;
  if (RISK_NOISE.test(hay)) s -= 250;
  s += Math.min(90, Math.log(1 + (t.count || 1)) * 15);
  return s;
}
var TYPES = ["DNS", "IP", "URL", "UA", "HTTP", "JA3"];
var INFOS = ["asyncrat (malware)", "mass scanner (suspicious)", "ipinfo (suspicious)",
             "cobalt strike beacon", "crawler reputation", "phish kit", "", "unknown thing"];
var TRAILS = ["evil.ru", "1.2.3.4", "ransomware.example/gate.php", "sinkhole.test", "x"];
var bad = [];
var all = [];
for (var s = 1; s <= 3; s++)
  for (var ti = 0; ti < TYPES.length; ti++)
    for (var ii = 0; ii < INFOS.length; ii++)
      for (var tr = 0; tr < TRAILS.length; tr++)
        for (var c = 0; c < 4; c++) {
          var count = [0, 1, 37, 900000][c];
          all.push({ sev: s, type: TYPES[ti], info: INFOS[ii], trail: TRAILS[tr], count: count });
        }
all.forEach(function (t) {
  var want = reference(t);
  if (riskOf(t) !== want) bad.push("first call " + JSON.stringify(t) + " " + riskOf(t) + " != " + want);
  if (riskOf(t) !== want) bad.push("memo hit differs " + JSON.stringify(t));
  // the memo is keyed on count: moving it must re-derive, not serve the stale score
  t.count = t.count + 11;
  var want2 = reference(t);
  if (riskOf(t) !== want2) bad.push("after count change " + JSON.stringify(t) + " " + riskOf(t) + " != " + want2);
});
// and the ORDER the comparator produces must be identical either way
var a = all.slice(), b = all.slice();
a.sort(function (x, y) { var c = riskOf(x) - riskOf(y); if (c === 0) c = y.count - x.count; return c; });
b.sort(function (x, y) { var c = reference(x) - reference(y); if (c === 0) c = y.count - x.count; return c; });
for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) { bad.push("order diverges at " + i); break; }
console.log(bad.length ? bad.slice(0, 5).join(" | ") : "OK");
"""
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())


class TestViewCacheInvalidation(unittest.TestCase):
    """The grid's filtered/sorted list is cached; the exclusion list is what makes that safe.

    Every persisted preference bumps a counter that drops the cache, EXCEPT the keys named in
    LS_NOT_A_FILTER. That list is a promise: "writing this can never change which rows are
    shown". Adding a key that CAN change it would leave the grid showing rows that no longer
    match - not an error, just wrong data on screen - so the list is pinned here and a new
    entry has to be argued for in this test rather than slipped in.
    """

    ALLOWED = {"mt_ripe", "mt_prefs"}

    def test_only_non_filtering_keys_skip_invalidation(self):
        js = _read(MAIN_JS)
        m = re.search(r"var LS_NOT_A_FILTER = \{([^}]*)\};", js)
        self.assertTrue(m, "LS_NOT_A_FILTER is gone from main.js - is the grid view still cached?")
        keys = set(re.findall(r'"([^"]+)"', m.group(1)))
        self.assertEqual(self.ALLOWED, keys,
                         "LS_NOT_A_FILTER changed. A key listed here is exempt from invalidating "
                         "the cached grid view, so it must be one that cannot affect which rows "
                         "match. Update ALLOWED here only after checking that.")

    def test_the_grid_view_is_actually_invalidated_somewhere(self):
        js = _read(MAIN_JS)
        self.assertIn("_viewVer++", js, "nothing bumps the grid-view cache counter any more")
        self.assertRegex(js, r"state\.all = d\.threats;[^\n]*_viewVer\+\+",
                         "a new aggregate must drop the cached grid view, or live updates would "
                         "keep rendering the previous load's rows")

class TestZoomSafeFullHeightOverlays(unittest.TestCase):
    """The text-size control zooms the root element, so `vh` is not the viewport.

    applyScale() sets document.documentElement.style.zoom. A `vh` length does NOT account for that
    zoom, so a full-height fixed panel sized with 100vh comes out wrong at every step except 1.0:
    the detail drawer rendered 86px short of the screen at the smallest text size, and 1200px tall
    in an 857px viewport at the largest - putting its own action buttons off the bottom of the
    screen with no way to reach them. A fixed element pinned top AND bottom resolves against the
    viewport at any zoom, which is what it uses now.
    """

    def setUp(self):
        with open(os.path.join(REPO, "html", "css", "main.css"), encoding="utf-8") as f:
            self.css = f.read()
        self.js = _read(MAIN_JS)

    def test_the_scale_control_still_zooms_the_root(self):
        # If this ever stops being true, the rule below can be relaxed - but not before.
        self.assertRegex(self.js, r"documentElement\.style\.zoom",
                         "applyScale no longer zooms the root; re-check whether full-height "
                         "overlays still need to avoid vh units")

    def test_drawer_is_not_sized_in_viewport_units(self):
        m = re.search(r"^\.drawer\{([^}]*)\}", self.css, re.M | re.S)
        self.assertTrue(m, "could not find the .drawer rule in main.css")
        rule = m.group(1)
        self.assertNotRegex(
            rule, r"height:\s*\d+(?:\.\d+)?d?vh",
            "the detail drawer is sized with a viewport-height unit again. The text-size control "
            "zooms the root element, and vh ignores zoom - so the panel renders short when text is "
            "made smaller and runs off the bottom of the screen when it is made larger. Pin it "
            "with top:0;bottom:0 instead.")
        self.assertIn("bottom:0", rule,
                      "the drawer must be pinned to the bottom of the viewport, not given a height")

    def test_drawer_body_does_not_chain_its_scroll(self):
        m = re.search(r"^\.dwr-body\{([^}]*)\}", self.css, re.M | re.S)
        self.assertTrue(m, "could not find the .dwr-body rule in main.css")
        self.assertIn(
            "overscroll-behavior:contain", m.group(1).replace(" ", ""),
            "the drawer's scrolling body must contain its overscroll. Without it, wheeling past "
            "the end of the panel scrolls the grid BEHIND the modal - measured at 600px - so "
            "closing the drawer drops the analyst somewhere else in the table.")

class TestIpSortKeyMemo(unittest.TestCase):
    """ipKey() is memoized, and the memo must not reorder anything.

    It is called from inside the grid's sort comparator, so sorting by source or destination ran
    it millions of times - a regex match, two array allocations and a per-octet concat apiece. That
    one column took 780ms while every other took under 100. A wrong cache here would not error; it
    would put addresses in the wrong order, which is the kind of thing nobody notices.
    """

    def _node(self):
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                return candidate
        raise unittest.SkipTest("needs node to evaluate ipKey()")

    def test_memo_matches_the_plain_implementation(self):
        node = self._node()
        js = _read(MAIN_JS)
        fn = re.search(r"var _ipkCache = new Map\(\);\s*function ipKey\(s\) \{.*?\n  \}", js, re.S)
        self.assertTrue(fn, "could not find the memoized ipKey() in main.js")
        script = fn.group(0) + """
function reference(s) {
  return ((s || "").match(/\\d+/g) || []).map(function (n) { return ("00" + n).slice(-3); }).join(".");
}
var CASES = ["10.0.0.1", "10.0.0.2", "9.9.9.9", "192.168.1.1", "8.8.8.8", "255.255.255.255",
             "0.0.0.0", "1.2.3.4", "", null, undefined, "not-an-ip", "2001:db8::1",
             "1.2.3.4/24", "10.0.0.1 (rdns)", "  ", "999.999.999.999"];
var bad = [];
CASES.forEach(function (c) {
  var want = reference(c);
  if (ipKey(c) !== want) bad.push("miss " + JSON.stringify(c) + " " + ipKey(c) + " != " + want);
  if (ipKey(c) !== want) bad.push("hit  " + JSON.stringify(c) + " differs on the cached call");
});
// ordering must be identical to the unmemoized version over a shuffled address space
var ips = [];
for (var a = 0; a < 12; a++) for (var b = 0; b < 12; b++) ips.push(a + "." + b + "." + (b * 7 % 256) + "." + (a * 13 % 256));
ips.push("8.8.8.8", "10.0.0.1", "", "x");
var m = ips.slice().sort(function (x, y) { var p = ipKey(x), q = ipKey(y); return p < q ? -1 : p > q ? 1 : 0; });
var r = ips.slice().sort(function (x, y) { var p = reference(x), q = reference(y); return p < q ? -1 : p > q ? 1 : 0; });
for (var i = 0; i < m.length; i++) if (m[i] !== r[i]) { bad.push("order diverges at " + i); break; }
console.log(bad.length ? bad.slice(0, 4).join(" | ") : "OK");
"""
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())


class TestDrawerOpensPromptly(unittest.TestCase):
    """What makes the detail panel feel slow is the gap before it starts moving, not its frame rate.

    Two things closed that gap and both are easy to undo by accident. The panel's sections skip
    layout until scrolled into view - two of them ("sources", "raw events") were 1,485 of its 1,699
    nodes, and laying them out before the first animated frame cost 56ms. And the slide is started
    BEFORE the sparkline/focus/enrichment tail, which used to run first and delay it further.
    """

    def setUp(self):
        with open(os.path.join(REPO, "html", "css", "main.css"), encoding="utf-8") as f:
            self.css = f.read()
        self.js = _read(MAIN_JS)

    def test_drawer_sections_skip_offscreen_layout(self):
        m = re.search(r"^\.dwr-sec\{([^}]*)\}", self.css, re.M)
        self.assertTrue(m, "could not find the .dwr-sec rule in main.css")
        rule = m.group(1).replace(" ", "")
        self.assertIn("content-visibility:auto", rule,
                      "the drawer's sections no longer skip layout while off-screen; opening the "
                      "panel goes back to laying out ~1700 nodes before it can start moving")
        self.assertIn("contain-intrinsic-size", rule,
                      "content-visibility:auto without contain-intrinsic-size gives the drawer a "
                      "meaningless scrollbar length until each section has been seen once")

    def test_the_slide_starts_before_the_tail_work(self):
        body = re.search(r"function openDrawer\(t\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(body, "could not find openDrawer() in main.js")
        body = body.group(0)
        start = body.index('classList.add("open")')
        # Only calls that actually run on open - a .focus() inside a click handler defined earlier
        # in the same function is a closure, not work done while the panel is opening.
        for name in ("enrichDrawerIPs()", "drawDwrSpark(", "_cl.focus()"):
            self.assertGreater(
                body.index(name), start,
                "%s runs before the drawer is told to slide. That work does not affect the first "
                "frame of the animation, and doing it first is what put ~45ms between the click "
                "and any movement." % name)

    def test_a_closed_drawer_leaves_the_tab_order(self):
        self.assertRegex(self.js, r"inert = true",
                         "a closed drawer is only translated off-screen, so without inert the "
                         "next Tab walks through a panel the user cannot see")

class TestProgressiveLoadIsRateLimited(unittest.TestCase):
    """Streaming a day repainted the grid ~12 times, each one re-filtering and re-sorting every
    threat, sometimes tens of milliseconds apart - quicker than anyone can read a table, so the
    work bought nothing. A floor on how OFTEN a repaint may happen took a busy day from ~1360ms to
    ~940ms to fully load.

    The first repaint is deliberately exempt: it is the one the user is waiting on, and an earlier
    version that made it wait too traded away time-to-first-rows to buy the rest.
    """

    def setUp(self):
        self.js = _read(MAIN_JS)

    def test_there_is_a_floor_on_repaint_frequency(self):
        self.assertRegex(self.js, r"var RENDER_MIN_MS = \d+",
                         "the progressive-load repaint rate floor is gone; a busy day goes back to "
                         "re-filtering and re-sorting every threat a dozen times while loading")

    def test_the_first_repaint_is_not_delayed_by_it(self):
        m = re.search(r"if \(agg && seen - lastRender >= RENDER_EVERY[^{]*\{", self.js, re.S)
        self.assertTrue(m, "could not find the progressive-render gate in main.js")
        self.assertIn("lastRenderT === 0", m.group(0),
                      "the first progressive repaint must be exempt from the rate floor - it is the "
                      "one the user is waiting on, and delaying it regressed time-to-first-rows")

class TestGridSortEquivalence(unittest.TestCase):
    """The grid sorts by computing each row's key once and sorting a permutation, instead of
    deriving keys inside the comparator (about two million times per sort).

    The failure mode is silent: a decorate/undecorate that gets ties or direction wrong still
    returns a sorted-looking table, just with rows in the wrong places. So the SHIPPED block is
    extracted and run against the direct comparator it replaced, over a population built to be
    full of ties.

    Deterministic on purpose. The equivalent check driven through a browser cannot be: the
    aggregate itself depends on how the event stream happens to be chunked, so the same build
    disagrees with itself run to run.
    """

    def _node(self):
        for candidate in ("node", "nodejs"):
            if any(os.access(os.path.join(d, candidate), os.X_OK)
                   for d in os.environ.get("PATH", "").split(os.pathsep) if d):
                return candidate
        raise unittest.SkipTest("needs node to evaluate the sort")

    def test_it_orders_exactly_as_the_direct_comparator_did(self):
        node = self._node()
        js = _read(MAIN_JS)
        block = re.search(r"var n = filtered\.length, i;.*?for \(i = 0; i < n; i\+\+\) list\[i\] = filtered\[idx\[i\]\];",
                          js, re.S)
        self.assertTrue(block, "could not find the grid's sort block in main.js")
        risk = re.search(r"var RISK_HOT = /.*?/;\n\s*var RISK_NOISE = /.*?/;\n.*?function riskOf\(t\) \{.*?\n  \}", js, re.S)
        ipk = re.search(r"var _ipkCache = new Map\(\);\s*function ipKey\(s\) \{.*?\n  \}", js, re.S)
        self.assertTrue(risk and ipk, "could not find riskOf()/ipKey() in main.js")

        script = risk.group(0) + "\n" + ipk.group(0) + """
function shipped(filtered, k, dir) {
""" + block.group(0) + """
  return list;
}
function reference(filtered, k, dir) {
  var list = filtered.slice();
  list.sort(function (a, b) {
    var c;
    if (k === "sev") c = riskOf(a) - riskOf(b);
    else if (k === "count") c = a.count - b.count;
    else if (k === "dport") c = (parseInt(a.dport, 10) || 0) - (parseInt(b.dport, 10) || 0);
    else if (k === "src" || k === "dst") { var ak = ipKey(a[k]), bk = ipKey(b[k]); c = ak < bk ? -1 : ak > bk ? 1 : 0; }
    else { var av = (a[k] || "") + "", bv = (b[k] || "") + ""; c = av < bv ? -1 : av > bv ? 1 : 0; }
    if (c === 0) c = b.count - a.count;
    return c * dir;
  });
  return list;
}
var TYPES = ['DNS','IP','URL','UA','','HTTP'], rows = [];
for (var i = 0; i < 4000; i++) rows.push({
  uid: 'u' + (i % 7 === 0 ? 1 : i), uidc: 'c' + i,
  sensor: ['a','b','','c'][i % 4],
  src: ['10.0.0.1','9.9.9.9','192.168.1.254','','8.8.8.8','10.0.0.10'][i % 6],
  dst: ['1.2.3.4','255.255.255.255','','10.0.0.2'][i % 4],
  dport: ['53','443','','80','1'][i % 5],
  proto: ['TCP','UDP',''][i % 3], type: TYPES[i % TYPES.length],
  trail: ['a.com','b.ru','','zz.top','a.com'][i % 5],
  info: ['x (malware)','scanner (suspicious)','','cobalt beacon'][i % 4],
  first: ['2026-01-01 00:00:00','2026-01-01 00:00:00','2026-06-06 12:00:00',''][i % 4],
  ref: '(static)', sev: 1 + (i % 3), count: [1,1,1,2,37,900000][i % 6]
});
var COLS = ['uid','sensor','count','sev','src','dst','dport','proto','type','trail','info','first'];
var bad = [];
COLS.forEach(function (k) { [1, -1].forEach(function (dir) {
  var a = shipped(rows, k, dir).map(function (r) { return r.uidc; }).join(',');
  var b = reference(rows, k, dir).map(function (r) { return r.uidc; }).join(',');
  if (a !== b) bad.push(k + ' dir=' + dir);
}); });
console.log(bad.length ? 'DIVERGES: ' + bad.join(', ') : 'OK');
"""
        import subprocess
        out = subprocess.check_output([node, "-e", script], stderr=subprocess.STDOUT).decode("utf8", "replace")
        self.assertEqual("OK", out.strip(), out.strip())


class TestSeverityFilterIsSeparate(unittest.TestCase):
    """The severity buttons are the most-clicked filter on the page, and severity is a single
    integer compare on a field that never changes after a threat is built. It is applied to a
    cached result of the expensive chain (whitelist probe, chip tokens, compiled query) rather
    than re-running that chain over every threat.
    """

    def test_the_expensive_chain_is_cached_without_severity(self):
        js = _read(MAIN_JS)
        m = re.search(r"var bsig = _viewVer.*?state\._vbSig = bsig", js, re.S)
        self.assertTrue(m, "the base filter cache (everything except severity) is gone")
        self.assertNotIn("state.sev", m.group(0),
                         "severity is back inside the cached filter key, so clicking a severity "
                         "button re-runs the whole filter chain over every threat again")


class TestTrailTypesReachTheTable(unittest.TestCase):
    """Every trail type the sensors emit must satisfy main.js's type test.

    aggregateRows() drops a row whose field 7 is not a trail type - that is what keeps a shifted
    or truncated line out of the aggregate. The test was `/^[A-Z]+$/`, letters only, while the
    sensor emits TRAIL::JA3 and TRAIL::JA4. Those carry a digit, so every TLS-fingerprint
    detection was discarded in silence: no error, no count, simply missing from the table, the
    type breakdown and the charts. Found by building the public demo and searching it for "ja3".

    Text comparison, like the rest of this file: the emitted names are in the sources and the
    test is in main.js, and nothing but this keeps them in step.
    """

    def _emitted_types(self):
        names = set()
        for root, _dirs, files in os.walk(os.path.join(REPO, "sensor", "src")):
            for name in files:
                if name.endswith(".rs"):
                    with open(os.path.join(root, name), encoding="utf8", errors="replace") as f:
                        names.update(re.findall(r"TRAIL::([A-Z0-9]+)", f.read()))
        for name in ("log.py", "httpd.py", "testing.py", "enums.py"):
            path = os.path.join(REPO, "core", name)
            if os.path.isfile(path):
                with open(path, encoding="utf8", errors="replace") as f:
                    names.update(re.findall(r"TRAIL\.([A-Z0-9]+)", f.read()))
        return names

    def _type_tests(self):
        with open(os.path.join(REPO, "html", "js", "main.js"), encoding="utf8") as f:
            return re.findall(r"/\^\[([A-Z0-9-]+)\]\+\$/\.test\((?:row\[7\]|type)\)", f.read())

    def test_the_type_test_accepts_every_emitted_type(self):
        emitted = self._emitted_types()
        self.assertTrue(emitted, "no TRAIL:: / TRAIL. names found - has the enum been renamed?")

        patterns = self._type_tests()
        self.assertTrue(patterns, "main.js no longer tests field 7 against a character class; "
                                  "if the guard moved, move this test with it")

        for cls in patterns:
            rx = re.compile(r"^[%s]+$" % cls)
            rejected = sorted(t for t in emitted if not rx.match(t))
            self.assertEqual(rejected, [],
                             "main.js drops trail type(s) %s with /^[%s]+$/ - the sensor emits "
                             "them, so those detections never appear in the dashboard"
                             % (rejected, cls))

    def test_the_guard_still_rejects_a_non_type(self):
        # It must keep doing its job: a shifted line whose field 7 is an address or a lowercase
        # word has to stay out of the aggregate.
        for cls in self._type_tests():
            rx = re.compile(r"^[%s]+$" % cls)
            for junk in ("10.0.0.5", "dns", "", "UDP DNS", "evil.com", '"quoted"'):
                self.assertIsNone(rx.match(junk),
                                  "/^[%s]+$/ accepts %r, which is not a trail type" % (cls, junk))


class TestDemoAddressesAreNotRealPeoples(unittest.TestCase):
    """html/js/demo.js is published on the public web, so its addresses must name nobody.

    The demo shipped `2a03:2880:f12d:83:face:b00c::1` - Meta Platforms Ireland - labelled
    "cobalt strike beacon (malware)" 22 times, and a live Tor exit node labelled "wannacry".
    Separately, the capture it was built from was taken ISP-side, so the "monitored" hosts were
    public 2.200.x.x subscribers: 64% of events showed a public SOURCE, and Google's own addresses
    appeared as hosts inside the network being monitored.

    Both are checkable without a geo database, because every address here should be one of three
    things: RFC 1918 for our own hosts, RFC 5737 / RFC 3849 documentation space for the external
    party, or a well-known public resolver.
    """

    RESOLVERS = ("8.8.8.8", "8.8.4.4", "9.9.9.9", "1.1.1.1", "1.0.0.1")

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, REPO)
        from core import logfmt
        cls.FI = dict((name, i) for i, name in enumerate(logfmt.FIELDS))
        path = os.path.join(REPO, "html", "js", "demo.js")
        if not os.path.isfile(path):
            raise unittest.SkipTest("demo.js is not present")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        cls.rows = []
        for chunk in re.findall(r"'((?:[^'\\]|\\.)*)\\n'", text):
            line = chunk.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
            fields = logfmt.fields(line)
            if fields:
                cls.rows.append(fields)
        # A skipped or empty-corpus assertion proves nothing, so insist the fixture really parsed.
        assert len(cls.rows) > 500, "only %d event(s) parsed out of demo.js" % len(cls.rows)

    @staticmethod
    def _is_private(a):
        return bool(re.match(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|169\.254\.)", a)
                    or re.match(r"^(?:fe80:|f[cd]|::1$)", a, re.I)
                    or re.match(r"^2001:db8:", a, re.I))

    @staticmethod
    def _is_doc(a):
        return bool(re.match(r"^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)", a)
                    or re.match(r"^2001:db8:", a, re.I))

    @staticmethod
    def _addresses(value):
        for part in value.split(","):
            part = part.strip()
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", part):
                yield part
            elif ":" in part and re.match(r"^[0-9a-f:]+$", part, re.I):
                yield part

    def _our_side(self, row):
        """Field holding the MONITORED host - core/geo.py:event_country owns this decision."""
        FI = self.FI
        if row[FI["src_port"]] == "53":                                 # a resolver answering us
            return FI["dst_ip"]
        if row[FI["type"]] in ("PATH", "PORT"):                         # inbound heuristics
            return FI["dst_ip"]
        if row[FI["type"]] == "IP" and row[FI["trail"]] == row[FI["src_ip"]]:   # a scan, trail IS the source
            return FI["dst_ip"]
        return FI["src_ip"]                                             # outbound: our host is the source

    def _demo_geo(self):
        """The getDemoGeo() table, read out of demo.js without a JS engine."""
        with open(os.path.join(REPO, "html", "js", "demo.js"), encoding="utf-8") as f:
            text = f.read()
        if "function getDemoGeo()" not in text:
            self.fail("demo.js has no getDemoGeo() table - re-run sensor/tools/gen_demo_js.py")
        block = text[text.index("function getDemoGeo()"):]
        return dict(re.findall(r'"([^"]+)":\s*"([A-Z]{2})"', block))

    def test_our_own_hosts_are_never_public(self):
        offenders = []
        for row in self.rows:
            for address in self._addresses(row[self._our_side(row)]):
                if not self._is_private(address):
                    offenders.append((address, row[self.FI["info"]]))
        self.assertEqual(offenders[:6], [],
                         "%d event(s) in demo.js put a public address in the MONITORED host's "
                         "position, so the demo reads as though we monitored somebody else's "
                         "network rather than a LAN: %s" % (len(offenders), offenders[:6]))

    def test_every_country_code_is_the_real_one(self):
        """getDemoGeo() must agree with core.geo, entry for entry.

        The dashboard used to fabricate a country by hashing the address into a 20-entry list,
        which published 8.8.8.8 as Sweden and 8.8.4.4 as IRAN. A demo may invent hosts; it may not
        invent facts about hosts that exist.
        """
        from core.geo import ip_to_country
        table = self._demo_geo()
        self.assertGreater(len(table), 50, "getDemoGeo() is missing or nearly empty")
        wrong = [(ip, cc, ip_to_country(ip)) for ip, cc in sorted(table.items())
                 if ip_to_country(ip) != cc]
        self.assertEqual(wrong[:6], [],
                         "%d address(es) in getDemoGeo() disagree with core.geo, so the demo "
                         "states a country the RIR tables do not: %s" % (len(wrong), wrong[:6]))

    def test_an_address_with_a_real_country_is_never_left_out(self):
        # The other half: a real address missing from the table shows no flag, which is a silent
        # hole rather than a lie, but it also means the map under-reports. Regenerate the table.
        from core.geo import ip_to_country
        table = self._demo_geo()
        missing = {}
        for row in self.rows:
            for field in ("src_ip", "dst_ip", "trail"):
                for address in self._addresses(row[self.FI[field]]):
                    if ip_to_country(address) and address not in table:
                        missing[address] = ip_to_country(address)
        self.assertEqual(missing, {},
                         "%d address(es) have a real country but are absent from getDemoGeo(): "
                         "%s. Re-run sensor/tools/gen_demo_js.py."
                         % (len(missing), sorted(missing.items())[:6]))

    def test_the_dashboard_does_not_invent_a_country_or_an_asn(self):
        with open(MAIN_JS, encoding="utf-8") as f:
            js = f.read()
        self.assertNotIn("DEMO_CC", js,
                         "main.js still carries the hashed country list. Hashing an address into "
                         "a country list is what put Google in Iran; read getDemoGeo() instead.")
        self.assertNotIn("Example Networks", js,
                         "main.js still fabricates an ASN holder. No ASN table ships with the "
                         "demo, so a real address would be given a made-up network.")
        body = js[js.index("function demoCC("):]
        self.assertIn("DEMO_GEO", body[:200],
                      "demoCC() no longer reads the generated table, so the map and the table "
                      "flags can disagree - or be invented again.")

    def test_the_map_does_not_geolocate_only_the_source(self):
        # demoGeo() used to take the first public SOURCE, which is right only for an inbound
        # attack. With the monitored hosts correctly private it maps nothing at all, so the world
        # map in the published demo renders blank.
        with open(MAIN_JS, encoding="utf-8") as f:
            js = f.read()
        body = js[js.index("function demoGeo()"):]
        body = body[:body.index("\n  }")]
        self.assertIn("dstS", body,
                      "demoGeo() no longer looks at the destination set. It must mirror "
                      "core/geo.py:event_country and plot the EXTERNAL party, which for an "
                      "outbound detection is the destination - geolocating only sources maps "
                      "nothing once the monitored hosts are private.")


class TestDemoOffersNothingItCannotDo(unittest.TestCase):
    """A demo build has no server, so it must not present server-only controls.

    Offering them is worse than hiding them: the login button opened a password prompt that posted
    to nowhere, and the day picker's heat grid comes from /counts, so the demo was fabricating a
    density per day from a hash of the date - decorative numbers for days holding no events, on a
    build that cannot navigate to them anyway.
    """

    @classmethod
    def setUpClass(cls):
        with open(MAIN_JS, encoding="utf-8") as f:
            cls.js = f.read()

    def test_the_login_button_is_hidden(self):
        # It has to happen on the DEMO branch of boot(): checkAuth() is only called on the server
        # path, so a guard inside checkAuth() would never run.
        demo_branch = self.js[self.js.index('document.title = "Maltrail (demo)";'):]
        demo_branch = demo_branch[:demo_branch.index("} else {")]
        self.assertIn("login_link", demo_branch,
                      "the demo build no longer hides #login_link, so it shows a Log in button "
                      "that opens a password prompt posting to a server that does not exist")

    def test_no_day_densities_are_invented(self):
        body = self.js[self.js.index("function fetchCounts("):]
        body = body[:body.index("\n  function ")]
        self.assertIn("if (DEMO) return;", body,
                      "fetchCounts() fabricates per-day event counts again. /counts is a server "
                      "capability; a demo holding one day must not invent densities for the rest.")
        self.assertNotIn("murmur3", body,
                         "fetchCounts() is hashing the date into an event count again")

    def test_the_day_picker_does_not_open(self):
        for name in ("function openDatePicker(", "function pickDay("):
            body = self.js[self.js.index(name):]
            body = body[:body.index("\n  function ")]
            self.assertIn("if (DEMO) return;", body,
                          "%s no longer refuses to run in a demo build, so the day picker opens "
                          "onto an empty heat grid" % name.replace("function ", "").rstrip("("))
            self.assertNotIn("&& !DEMO", body,
                             "%s bypasses the disabled-control check for demo builds again"
                             % name.replace("function ", "").rstrip("("))

    def test_the_demo_day_is_derived_not_hardcoded(self):
        """demoCSV() must find the demo's day in the data, not carry a copy of it.

        It used to replace a literal "2024-01-11" with today. Nothing tied that literal to what
        demo.js actually held, so regenerating the demo on any other day made the replace match
        nothing - silently freezing every timestamp at a date years in the past.
        """
        body = self.js[self.js.index("  function demoCSV() {"):]
        body = body[:body.index("\n  }") + 4]
        self.assertNotRegex(body, r"\d{4}-\d{2}-\d{2}",
                            "demoCSV() hardcodes a date again. Derive the day from the events so "
                            "a regenerated demo.js cannot silently keep stale timestamps.")
        self.assertIn("todayStr()", body, "demoCSV() no longer rebases the demo onto today")

    def test_the_shipped_robots_txt_still_blocks_indexing(self):
        # Deliberately the opposite of the public demo's, which ships none. A real deployment's
        # dashboard is private and must not be indexed; maltraildemo's build.sh skips this file.
        path = os.path.join(REPO, "html", "robots.txt")
        if not os.path.isfile(path):
            self.skipTest("html/robots.txt is not present")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("Disallow: /", text,
                      "html/robots.txt no longer blocks crawlers. A deployment's dashboard is "
                      "private; it is the public demo that wants indexing, and that build drops "
                      "this file rather than shipping a permissive one.")


if __name__ == "__main__":
    unittest.main()
