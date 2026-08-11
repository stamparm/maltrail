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


class TestDrawerFields(unittest.TestCase):
    """Every field of an event line should be reachable in the detail panel (#19569)."""

    def setUp(self):
        self.js = _read(MAIN_JS)
        drawer = re.search(r"function openDrawer\(t\) \{.*?\n  \}\n", self.js, re.S)
        self.assertTrue(drawer, "could not find openDrawer() in main.js")
        self.drawer = drawer.group(0)

    def test_sections_cover_the_event_tuple(self):
        for section in ("sources", "destinations", "destination ports", "source ports", "protocols", "raw events"):
            self.assertIn(section + " \\u00b7 ", self.drawer,
                          "the detail panel no longer has a %r section" % section)


if __name__ == "__main__":
    unittest.main()
