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

if __name__ == "__main__":
    unittest.main()
