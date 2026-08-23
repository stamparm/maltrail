# coding: utf-8
"""Unit tests for core/colorized (the --console colouring).

The trail type is picked out of the event line by a regex, and it used to be `[A-Z]+` - which
matches "JA" of "JA3" and leaves the digit outside the colour run, so the two TLS fingerprint
types could not be coloured at all, no matter what the colour table said.
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.colorized import ColorizedStream
from core.enums import BACKGROUND

EVENT = ('"2026-01-01 00:00:00.000000" sensor 10.0.0.5 5000 1.2.3.4 443 TCP %s '
         'trail "some info (malware)" (feed)\n')


def _colorize(line):
    sink = io.StringIO()
    ColorizedStream(sink).write(line)
    return sink.getvalue()


class TestTypeColors(unittest.TestCase):
    def test_every_trail_type_is_coloured(self):
        for trail_type, color in (("DNS", BACKGROUND.BLUE), ("IP", BACKGROUND.RED),
                                  ("CERT", BACKGROUND.OLIVE), ("JA3", BACKGROUND.LIGHT_MAGENTA),
                                  ("JA4", BACKGROUND.LIGHT_MAGENTA)):
            out = _colorize(EVENT % trail_type)
            self.assertIn("TCP %s%s" % (color, trail_type), out,
                          "%s is not coloured: %r" % (trail_type, out))

    def test_unknown_type_still_renders(self):
        out = _colorize(EVENT % "NEWTYPE")
        self.assertIn("NEWTYPE", out)


if __name__ == "__main__":
    unittest.main()
