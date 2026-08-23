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
