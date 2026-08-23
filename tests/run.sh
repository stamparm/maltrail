#!/bin/sh
# RAM-safe unit-test runner for Maltrail.
#
# Each test file is run in its own interpreter under a hard address-space cap (ulimit -v) and a
# wall-clock timeout: the optional `cryptography` accel can balloon RSS and OOM the host, so NEVER
# run these uncapped. Usage: tests/run.sh [python3 ...]   (default: python3)
#
# Python 2 is no longer supported: the vendored `six`/`odict` shims and every PY2 branch were
# removed in 3.0, and the current sensor is Rust. Running the suite under python2 would only
# report syntax errors for Python 3 code.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
MEM_KB=1200000          # ~1.2 GB address-space cap per interpreter
TIMEOUT=300             # seconds per test file

TESTS="test_addr test_common test_datatype test_ignore test_config test_trailsdict test_fastfilter test_quic_sni test_tls_intel test_sensor test_fanout test_httpd test_log_condense test_logd test_meta test_geo test_reference test_doctests test_enums test_parallel test_options test_doctor test_confidence test_index test_adversarial test_frontend test_update test_debug_artifacts test_check_trails test_detect_test test_smoke test_alert"

# A test file that is not in TESTS is not run by this script or by CI, and nothing else would ever
# say so - it just sits there passing locally and covering nothing. Fail instead.
missing=""
for f in "$HERE"/test_*.py; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .py)
    case " $TESTS " in *" $name "*) ;; *) missing="$missing $name" ;; esac
done
if [ -n "$missing" ]; then
    echo "[!] test file(s) not listed in TESTS (tests/run.sh):$missing"
    exit 1
fi

if [ "$#" -gt 0 ]; then
    PYS="$*"
else
    PYS=""
    for p in python3; do command -v "$p" >/dev/null 2>&1 && PYS="$PYS $p"; done
fi

rc=0
skipped=""
for py in $PYS; do
    echo "============================================================"
    echo "== $($py --version 2>&1)"
    echo "============================================================"
    # single-source py2/py3 guard: every core module + entrypoint must PARSE on this interpreter, even
    # ones no test imports (a py3-only construct in such a module ships silently and breaks that runtime)
    printf '%-18s ' "compile-all"
    cout=$( (ulimit -v "$MEM_KB"; timeout "$TIMEOUT" "$py" - "$HERE/.." <<'PYEOF' 2>&1
import sys, os, glob, py_compile
root = sys.argv[1]; bad = 0
files = glob.glob(os.path.join(root, "core", "*.py")) + \
        [os.path.join(root, f) for f in ("old/sensor.py", "server.py") if os.path.isfile(os.path.join(root, f))]
for f in files:
    try:
        py_compile.compile(f, doraise=True)
    except Exception as e:
        print("FAIL %s: %s" % (f, e)); bad += 1
print("OK %d modules" % len(files) if not bad else "%d FAILURES" % bad)
PYEOF
) )
    if printf '%s' "$cout" | grep -qE '^OK [0-9]+ modules$'; then
        echo "PASS ($cout)"
    else
        echo "FAIL"; printf '%s\n' "$cout" | tail -20; rc=1
    fi
    for t in $TESTS; do
        printf '%-18s ' "$t"
        out=$( (ulimit -v "$MEM_KB"; timeout "$TIMEOUT" "$py" "$HERE/$t.py" 2>&1) )
        if printf '%s' "$out" | grep -qE '^OK( \(skipped=[0-9]+\))?$'; then
            ran=$(printf '%s' "$out" | grep -oE 'Ran [0-9]+ tests' | head -1)
            echo "PASS ($ran)"
        elif printf '%s' "$out" | grep -qE "No module named 'pcapy'|please install 'pcapy"; then
            # These exercise the OLD (Python) sensor, which needs pcapy-ng. It is not a
            # dependency of the current sensor or of the server, so a contributor without
            # libpcap headers must not see a wall of tracebacks. CI installs it, so this
            # SKIP never masks a regression there — see .github/workflows/ci.yml.
            echo "SKIP (needs pcapy-ng: pip install -r old/requirements.txt)"
            skipped="$skipped $t"
        else
            echo "FAIL"
            printf '%s\n' "$out" | tail -20
            rc=1
        fi
    done
done

if [ -n "$skipped" ]; then
    echo
    echo "[!] SKIPPED (pcapy-ng not installed):$skipped"
    echo "[?] these cover the old Python sensor in old/; install with: pip install -r old/requirements.txt"
fi

# Frontend guard: a syntax typo in the dashboard JS ships silently and breaks the WHOLE UI (no Python
# test can catch it). If a JS engine is available, syntax-check the hand-written frontend files. Skips
# cleanly (not a failure) when neither node nor a fallback is installed, and never checks minified vendor code.
JS_ENGINE=""
for e in node nodejs; do command -v "$e" >/dev/null 2>&1 && { JS_ENGINE="$e"; break; }; done
echo "============================================================"
echo "== frontend JS syntax"
echo "============================================================"
if [ -n "$JS_ENGINE" ]; then
    for f in "$HERE/../html/js/main.js" "$HERE/../html/js/demo.js"; do
        [ -f "$f" ] || continue
        name=$(basename "$f")
        printf '%-18s ' "$name"
        if err=$("$JS_ENGINE" --check "$f" 2>&1); then
            echo "PASS (syntax)"
        else
            echo "FAIL"
            printf '%s\n' "$err" | tail -20
            rc=1
        fi
    done
else
    echo "(skipped: no node/nodejs found)"
fi

exit $rc
