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
    """

    # info, ref, expected severity (3 high / 2 medium / 1 low)
    CASES = (
        ("long domain (suspicious)", "(heuristic)", 1),
        ("potential periodic beaconing (suspicious)", "(heuristic)", 1),
        ("potential sql injection (suspicious)", "(heuristic)", 1),
        ("excessive no such domain (suspicious)", "(heuristic)", 1),
        ("sinkhole response (malware)", "(heuristic)", 3),        # a heuristic, but a confirmed one
        ("potential infection", "(heuristic)", 2),                # no class marker: legacy default
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
        keywords = re.search(r"var INFO_SEVERITY_KEYWORDS = \[.*?\];", self.js, re.S)
        fn = re.search(r"function severityOf\(info, ref\) \{.*?\n  \}", self.js, re.S)
        self.assertTrue(keywords and fn, "could not find severityOf() in main.js")
        script = keywords.group(0) + "\n" + fn.group(0) + """
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

class TestGridSortComparator(unittest.TestCase):
    """The grid's sort picks its comparator once per sort rather than re-testing the column on
    every comparison (about two million of them on a busy day, which also kept the one comparator
    polymorphic). That turned one shared tiebreak into one per branch - and a branch that loses its
    tiebreak does not error, it just orders equal-key rows differently, which nobody would notice.
    """

    def setUp(self):
        self.js = _read(MAIN_JS)
        m = re.search(r"var cmp;\n(.*?)\n    list\.sort\(cmp\);", self.js, re.S)
        self.assertTrue(m, "could not find the grid's comparator selection in main.js")
        self.block = m.group(1)

    def test_every_branch_keeps_the_count_tiebreak(self):
        branches = self.block.count("cmp = function")
        ties = self.block.count("if (c === 0) c = b.count - a.count;")
        self.assertGreaterEqual(branches, 5, "expected one comparator per sortable column kind")
        self.assertEqual(branches, ties,
                         "%d comparator branches but %d count tiebreaks - a column whose branch "
                         "lost the tiebreak silently orders equal-key rows differently"
                         % (branches, ties))

    def test_every_branch_applies_the_direction(self):
        branches = self.block.count("cmp = function")
        self.assertEqual(branches, self.block.count("return c * dir;"),
                         "a comparator branch does not apply the sort direction, so that column "
                         "would ignore ascending/descending")


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

if __name__ == "__main__":
    unittest.main()
