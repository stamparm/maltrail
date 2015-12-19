#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/Neo23x0/Loki/master/iocs/otx-c2-iocs.txt"
__check__ = "zapto"
__info__ = "malware"
__reference__ = "otx.alienvault.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or ';' not in line:
                continue
            items = line.split(';')
            if re.search(r"\d+\.\d+\.\d+\.\d+", items[0]):
                continue
            info = __info__
            for _ in ("bedep", "sofacy", "red october", "aaeh", "flame", "gauss", "stuxnet", "el machete", "deep panda", "buhtrap", "dridex", "volatile cedar", "cryptofortress", "equationdrug", "skype worm", "bandachor", "signed pos", "fessleak", "desert falcons", "carbanak", "angler", "neutrino", "symmi", "filmkan", "ctb-locker", "asprox", "regin", "wintti", "plugx", "xlscmd", "hellsing", "dyre", "trapwot", "rig", "torrentlocker", "the naikon", "triplenine", "shell crew", "cmstar", "teslacrypt", "nitlovepos", "darpapox", "poseidon", "moose", "sandworm", "evilgrab", "elastic botnet", "rsa ir", "lotus blossom", "nuclear", "pushdo", "grabit", "gamapos", "andromeda", "black vine", "kriptovor", "babar", "windigo", "potao express", "sakula", "the equation", "cleaver", "armageddon", "group-3390", "poison ivy", "darkhotel", "dragonok", "anunak", "destover", "pony", "wirelurker", "retefe", "the masked", "rocket kitten", "keyraider", "kazy", "escelar", "turla", "plugx", "zeuscart", "shade encryptor", "pkybot", "word intruder", "camerashy", "arid viper", "gaza cybergang", "steamstealers", "elf.billgates"):
                if re.search(r"(?i)\b%s\b" % _, items[1]):
                    info = "%s (malware)" % _
                    break
            retval[items[0]] = (info, __reference__)

    return retval
