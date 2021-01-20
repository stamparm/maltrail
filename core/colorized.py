#!/usr/bin/env python

import os
import re
import sys

from enums import COLOR
from enums import SEVERITY

IS_TTY = hasattr(sys.stdout, "fileno") and os.isatty(sys.stdout.fileno())

class ColorizedStream:
    def __init__(self, original):
        self._original = original
        self._log_colors = {'i': COLOR.LIGHT_BLUE, '!': COLOR.LIGHT_YELLOW, 'x': COLOR.BOLD_LIGHT_RED, '?': COLOR.LIGHT_YELLOW, 'o': COLOR.BOLD_WHITE, '+': COLOR.BOLD_LIGHT_GREEN}
        self._severity_colors = {SEVERITY.LOW: COLOR.BOLD_LIGHT_CYAN, SEVERITY.MEDIUM: COLOR.BOLD_LIGHT_YELLOW, SEVERITY.HIGH: COLOR.BOLD_LIGHT_RED}

    def write(self, text):
        match = re.search(r"\A(\s*)\[(.)\]", text)
        if match and match.group(2) in self._log_colors:
            text = text.replace(match.group(0), "%s[%s%s%s]" % (match.group(1), self._log_colors[match.group(2)], match.group(2), COLOR.RESET), 1)

        if "Maltrail (" in text:
            text = re.sub(r"\((\w+)\)", "(%s\g<1>%s)" % (COLOR.BOLD_LIGHT_GREEN, COLOR.RESET), text)

        if "Usage: " in text:
            text = re.sub(r"(.*Usage: )(.+)", r"\g<1>%s\g<2>%s" % (COLOR.BOLD_WHITE, COLOR.RESET), text)

        for match in re.finditer(r"[^\w]'([^']+)'", text):  # single-quoted
            text = re.sub("'%s'" % match.group(1), r"'%s%s%s'" % (COLOR.LIGHT_GRAY, match.group(1), COLOR.RESET), text)

        self._original.write("%s" % text)

    def flush(self):
        self._original.flush()

def init_output():
    if IS_TTY:
        sys.stderr = ColorizedStream(sys.stderr)
        sys.stdout = ColorizedStream(sys.stdout)
