#!/usr/bin/env python2

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/otx-c2-iocs.txt"
__check__ = "zapto"
__reference__ = "otx.alienvault.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or ';' not in line or "packetstormsecurity" in line:
                continue
            items = line.split(';')
            if re.search(r"\d+\.\d+\.\d+\.\d+", items[0]):
                continue
            for _ in ('aaeh', 'andromeda', 'anunak', 'arid viper', 'armageddon', 'asprox', 'azorult', 'babar', 'bandachor', 'bedep', 'black vine', 'buhtrap', 'camerashy', 'carbanak', 'cleaver', 'cmstar', 'cryptofortress', 'ctb-locker', 'darkhotel', 'darpapox', 'deep panda', 'desert falcons', 'destover', 'dragonok', 'dyre', 'el machete', 'elastic botnet', 'elf.billgates', 'equationdrug', 'escelar', 'evilgrab', 'fessleak', 'filmkan', 'flame', 'gamapos', 'gauss', 'gaza cybergang', 'grabit', 'group-3390', 'hellsing', 'kazy', 'keyraider', 'kriptovor', 'locky', 'lotus blossom', 'moose', 'neutrino', 'nitlovepos', 'nuclear', 'pkybot', 'plugx', 'poison ivy', 'pony', 'poseidon', 'potao express', 'pushdo', 'ramnit', 'red october', 'regin', 'retefe', 'rocket kitten', 'rsa ir', 'sakula', 'sandworm', 'shade encryptor', 'shell crew', 'signed pos', 'skype worm', 'steamstealers', 'stuxnet', 'symmi', 'teslacrypt', 'the equation', 'the masked', 'the naikon', 'torrentlocker', 'trapwot', 'triplenine', 'turla', 'volatile cedar', 'windigo', 'wintti', 'wirelurker', 'word intruder', 'xlscmd', 'zeuscart'):
                if re.search(r"(?i)\b%s\b" % _, items[1]):
                    info = "%s (malware)" % _
                    retval[items[0]] = (info, __reference__)
                    break

    return retval
