#!/bin/sh
# RAM-safe unit-test runner for Maltrail (Py2 + Py3).
#
# Each test file is run in its own interpreter under a hard address-space cap (ulimit -v) and a
# wall-clock timeout: Python 2 + the optional `cryptography` accel can balloon RSS and OOM the host,
# so NEVER run these uncapped. Usage: tests/run.sh [python2|python3 ...]   (default: both if present)

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
MEM_KB=1200000          # ~1.2 GB address-space cap per interpreter
TIMEOUT=300             # seconds per test file

TESTS="test_addr test_fastfilter test_quic_sni test_tls_intel test_sensor test_fanout"

if [ "$#" -gt 0 ]; then
    PYS="$*"
else
    PYS=""
    for p in python2 python3; do command -v "$p" >/dev/null 2>&1 && PYS="$PYS $p"; done
fi

rc=0
for py in $PYS; do
    echo "============================================================"
    echo "== $($py --version 2>&1)"
    echo "============================================================"
    for t in $TESTS; do
        printf '%-18s ' "$t"
        out=$( (ulimit -v "$MEM_KB"; timeout "$TIMEOUT" "$py" "$HERE/$t.py" 2>&1) )
        if printf '%s' "$out" | grep -qE '^OK( \(skipped=[0-9]+\))?$'; then
            ran=$(printf '%s' "$out" | grep -oE 'Ran [0-9]+ tests' | head -1)
            echo "PASS ($ran)"
        else
            echo "FAIL"
            printf '%s\n' "$out" | tail -20
            rc=1
        fi
    done
done
exit $rc
