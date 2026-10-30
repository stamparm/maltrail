# coding: utf-8
"""Runs the doctests embedded in the core modules as part of the suite. Several core helpers document
their contract with >>> examples (addr parsing, LRUDict eviction, trail (de)serialization, ...); those
examples were never executed by the test run, so they could silently drift from the code. This wires
them in (py2/py3), turning that documentation into enforced tests."""
import os
import sys
import doctest
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.addr
import core.common
import core.datatype
import core.log
import core.trailsbin
import core.trailsdict

_MODULES = (core.addr, core.common, core.datatype, core.log, core.trailsbin, core.trailsdict)


def load_tests(loader, tests, ignore):
    for mod in _MODULES:
        tests.addTests(doctest.DocTestSuite(mod))
    return tests


if __name__ == "__main__":
    # explicit runner (load_tests is honored by unittest.main via the __main__ module loader)
    suite = unittest.TestSuite()
    for mod in _MODULES:
        suite.addTests(doctest.DocTestSuite(mod))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
