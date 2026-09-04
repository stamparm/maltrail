#!/bin/sh
# Build the sensor for Windows and RUN it, on Linux, through Wine.
#
# Why this exists
# ---------------
# The Windows sensor was released on the strength of `cargo check`. Nothing had executed it,
# because executing it looked impossible: wpcap is a load-time dependency, wpcap.dll ships with
# the Npcap driver, and Npcap's free edition installs interactively - so no hosted Windows runner
# can have it. That was true and it was also the wrong conclusion. Three things get around it:
#
#   * mingw-w64 cross-compiles the binary on Linux (no MSVC, no Windows host).
#   * Npcap's installer is an NSIS archive, so 7z extracts wpcap.dll and Packet.dll from it
#     without installing or running anything. Those are userspace libraries; only CAPTURE needs
#     the kernel driver, and offline pcap replay does not capture.
#   * Wine runs the resulting PE.
#
# What it proves, and what it does not
# ------------------------------------
# Proves: the Windows binary starts, parses the shipped configuration, passes its own -T
# self-test, runs its whole unit suite, and produces byte-identical detections to the Linux
# binary over the entire pcap corpus.
#
# Does NOT prove: live capture on Windows. That needs the Npcap kernel driver and a real Windows
# machine. Nothing here pretends otherwise.
#
# Running it found four real bugs that a build could not have: a dropped drive letter in every
# absolute config path, an interpreter search that could never find python.exe, a log directory
# the server and sensor disagreed about, and a disk-space check that never ran.
#
# Prerequisites (the workflow installs them; see .github/workflows/ci.yml)
#   x86_64-w64-mingw32-gcc   wine   7z   curl   rustup target add x86_64-pc-windows-gnu
#
# Usage: sh sensor/tools/check_windows.sh [--work DIR]

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGET=x86_64-pc-windows-gnu
WORK=${MALTRAIL_WIN_WORK:-${TMPDIR:-/tmp}/maltrail-windows-check}
NPCAP_VERSION=${NPCAP_VERSION:-1.79}

while [ $# -gt 0 ]; do
    case "$1" in
        --work) WORK=$2; shift 2 ;;
        *) echo "[!] unknown argument: $1" >&2; exit 2 ;;
    esac
done

missing=
for tool in x86_64-w64-mingw32-gcc wine 7z curl cargo; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    echo "[!] missing:$missing" >&2
    echo "    on Debian/Ubuntu: apt-get install gcc-mingw-w64-x86-64 wine64 p7zip-full" >&2
    exit 2
fi
rustup target list --installed 2>/dev/null | grep -qx "$TARGET" || {
    echo "[!] rustup target add $TARGET" >&2; exit 2; }

mkdir -p "$WORK"

# Never leave a wineserver (or a half-started sensor) behind, on any exit path.
cleanup() {
    status=$?
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "${WINEPREFIX:-}" ]; then
        wineserver -k 2>/dev/null || true
    fi
    exit $status
}
trap cleanup EXIT INT TERM

# --- the Npcap userspace libraries, out of the installer, without installing it ---------------
# The x64 pair lives under $SYSDIR in the NSIS layout. The directory literally called "x64" holds
# the 32-bit build and the archive root holds the ARM64 one, which is worth stating because
# picking either produces a "wpcap.dll not found" that names the right file.
DLLDIR=$WORK/npcap
if [ ! -f "$DLLDIR/wpcap.dll" ]; then
    echo "== extracting Npcap $NPCAP_VERSION userspace libraries =="
    mkdir -p "$DLLDIR"
    curl -sSfL -o "$WORK/npcap.exe" "https://npcap.com/dist/npcap-$NPCAP_VERSION.exe"
    7z x -y -o"$WORK/npcap-unpacked" "$WORK/npcap.exe" >/dev/null
    for name in wpcap Packet; do
        src="$WORK/npcap-unpacked/\$SYSDIR/Npcap/$name.dll"
        test -f "$src" || { echo "[!] $name.dll is not where it was expected in the installer" >&2; exit 1; }
        file "$src" | grep -q 'x86-64' || { echo "[!] $src is not the x86-64 build" >&2; exit 1; }
        cp "$src" "$DLLDIR/$name.dll"
    done
fi

# --- the import library to link against --------------------------------------------------------
SDK=$WORK/npcap-sdk
if [ ! -f "$SDK/Lib/x64/wpcap.lib" ]; then
    echo "== fetching the Npcap SDK =="
    curl -sSfL -o "$WORK/npcap-sdk.zip" https://npcap.com/dist/npcap-sdk-1.13.zip
    7z x -y -o"$SDK" "$WORK/npcap-sdk.zip" >/dev/null
fi

# --- a Wine prefix of our own, so nothing touches the user's ~/.wine ---------------------------
WINEPREFIX=$WORK/wineprefix
export WINEPREFIX
export WINEDEBUG=${WINEDEBUG:--all}
# Native only: Wine ships a builtin wpcap, and it does not implement pcap_open_dead - which the
# sensor calls to compile its capture filter, so -T aborts against the builtin.
export WINEDLLOVERRIDES="wpcap,packet=n"
if [ ! -d "$WINEPREFIX/drive_c" ]; then
    echo "== creating a Wine prefix =="
    wineboot -i >/dev/null 2>&1 || true
    # wineboot returns before the prefix is fully populated.
    i=0
    while [ ! -d "$WINEPREFIX/drive_c/windows/system32" ] && [ "$i" -lt 30 ]; do
        i=$((i + 1)); sleep 1
    done
fi
test -d "$WINEPREFIX/drive_c/windows/system32" || { echo "[!] Wine prefix was not created" >&2; exit 1; }
cp "$DLLDIR/wpcap.dll" "$DLLDIR/Packet.dll" "$WINEPREFIX/drive_c/windows/system32/"

# --- a Windows Python, so the trail updater's interpreter search is exercised ------------------
# The embeddable build is a zip, not an installer. Without it the two interpreter-discovery tests
# fail for want of an interpreter - which is exactly how the bug where the search could never
# find python.exe stayed invisible.
PY_VERSION=${PY_VERSION:-3.12.8}
if [ ! -f "$WINEPREFIX/drive_c/python/python.exe" ]; then
    echo "== unpacking an embeddable Python $PY_VERSION =="
    curl -sSfL -o "$WORK/python-embed.zip" \
        "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-embed-amd64.zip"
    mkdir -p "$WINEPREFIX/drive_c/python"
    7z x -y -o"$WINEPREFIX/drive_c/python" "$WORK/python-embed.zip" >/dev/null
fi
# The embeddable build runs isolated, so PYTHONPATH is ignored and `._pth` IS sys.path. The repo
# has to be on it for `import core` to resolve when the server is started below.
for pth in "$WINEPREFIX"/drive_c/python/python*._pth; do
    test -f "$pth" || continue
    grep -qxF "Z:$ROOT" "$pth" || printf 'Z:%s\n' "$ROOT" >> "$pth"
done
WINEPATH='C:\python'
export WINEPATH

# --- build both binaries -----------------------------------------------------------------------
echo "== building for $TARGET =="
LIBPCAP_LIBDIR=$SDK/Lib/x64
export LIBPCAP_LIBDIR
CARGO_TERM_COLOR=never
export CARGO_TERM_COLOR
cargo build --release --manifest-path "$ROOT/sensor/Cargo.toml" --target "$TARGET" --bin maltrail-sensor
WIN_BIN=$ROOT/sensor/target/$TARGET/release/maltrail-sensor.exe
test -f "$WIN_BIN" || { echo "[!] no Windows binary" >&2; exit 1; }
file "$WIN_BIN" | grep -q 'PE32+' || { echo "[!] not a 64-bit PE: $(file -b "$WIN_BIN")" >&2; exit 1; }

echo "== building the native comparison binary =="
cargo build --release --manifest-path "$ROOT/sensor/Cargo.toml" --bin maltrail-sensor
NATIVE_BIN=$ROOT/sensor/target/release/maltrail-sensor

# --- it starts, and reports itself -------------------------------------------------------------
echo "== the Windows binary runs =="
wine "$WIN_BIN" --version
wine "$WIN_BIN" --help >/dev/null

# --- its own unit suite, executed as Windows code ----------------------------------------------
echo "== the Windows unit suite =="
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER
cargo test --release --manifest-path "$ROOT/sensor/Cargo.toml" --target "$TARGET" --lib

# --- the self-test against the shipped configuration -------------------------------------------
echo "== -T against the shipped maltrail.conf =="
CASE=$WORK/case
rm -rf "$CASE"; mkdir -p "$CASE/logs"
printf 'evil.example,"malware (test)","(static)"\n1.2.3.4,"malware (test)","(static)"\n' > "$CASE/trails.csv"
# SENSOR_NAME is pinned so the comparison below is about detections, not about the fact that
# Windows reports its host name in upper case.
make_conf() {
    sed -e 's|^HTTP_ADDRESS.*|HTTP_ADDRESS 127.0.0.1|' "$ROOT/maltrail.conf" > "$2"
    printf '\nDISABLE_TRAIL_UPDATES true\nSENSOR_NAME mt-crossplatform\nTRAILS_FILE %s%s/trails.csv\nLOG_DIR %s%s/logs\n' \
        "$1" "$CASE" "$1" "$CASE" >> "$2"
}
make_conf "" "$CASE/native.conf"
make_conf "Z:" "$CASE/windows.conf"
wine "$WIN_BIN" -c "Z:$CASE/windows.conf" -T

# --- the whole corpus, both binaries, byte-compared --------------------------------------------
echo "== pcap corpus: Windows vs native =="
CORPUS=$ROOT/sensor/tests/corpus
make_conf "" "$CASE/native-corpus.conf"
make_conf "Z:" "$CASE/windows-corpus.conf"
sed -i "s|^TRAILS_FILE .*|TRAILS_FILE $CORPUS/trails.csv|" "$CASE/native-corpus.conf"
sed -i "s|^TRAILS_FILE .*|TRAILS_FILE Z:$CORPUS/trails.csv|" "$CASE/windows-corpus.conf"

same=0; differ=0; events=0
for pcap in "$CORPUS"/*.pcap; do
    name=$(basename "$pcap" .pcap)
    rm -rf "$CASE/logs"; mkdir -p "$CASE/logs"
    # --console writes events to STDERR. Discarding it made an earlier version of this report "42
    # identical" with zero events on both sides - a comparison that could only ever agree.
    "$NATIVE_BIN" -r "$pcap" -c "$CASE/native-corpus.conf" --console --offline -q 2>&1 \
        | grep '^"' | sort > "$CASE/native.txt" || true
    rm -rf "$CASE/logs"; mkdir -p "$CASE/logs"
    wine "$WIN_BIN" -r "Z:$pcap" -c "Z:$CASE/windows-corpus.conf" --console --offline -q 2>&1 \
        | grep '^"' | sort > "$CASE/windows.txt" || true
    n=$(wc -l < "$CASE/native.txt")
    events=$((events + n))
    if cmp -s "$CASE/native.txt" "$CASE/windows.txt"; then
        same=$((same + 1))
    else
        differ=$((differ + 1))
        echo "[!] $name: native=$n windows=$(wc -l < "$CASE/windows.txt")"
        diff "$CASE/native.txt" "$CASE/windows.txt" | head -6 | sed 's/^/      /'
    fi
done

echo "== corpus: $same identical, $differ different, $events detections =="
if [ "$events" -eq 0 ]; then
    echo "[!] nothing was detected on either side, so this comparison proves nothing" >&2
    exit 1
fi
if [ "$differ" -ne 0 ]; then
    echo "[!] the Windows sensor does not agree with the native one" >&2
    exit 1
fi
# --- the server, on Windows Python -------------------------------------------------------------
# The other half of a deployment. It is pure Python with IS_WIN branches, which is an argument
# that it works rather than evidence, and this is the evidence. Its stdio is deliberately NOT
# redirected: the embeddable interpreter fails to initialise its standard streams under Wine when
# stdout is a file, with "OSError: [WinError 6] Invalid handle" and no Python frame.
echo "== the server answers /ping on Windows Python =="
PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()")
SRVDIR=$WORK/server
rm -rf "$SRVDIR"; mkdir -p "$SRVDIR/logs"
printf 'evil.example,"malware (test)","(static)"\n' > "$SRVDIR/trails.csv"
sed -e 's|^HTTP_ADDRESS.*|HTTP_ADDRESS 127.0.0.1|' -e "s|^HTTP_PORT.*|HTTP_PORT $PORT|" \
    "$ROOT/maltrail.conf" > "$SRVDIR/s.conf"
printf '\nUSE_SERVER_UPDATE_TRAILS false\nTRAILS_FILE Z:%s/trails.csv\nLOG_DIR Z:%s/logs\n' \
    "$SRVDIR" "$SRVDIR" >> "$SRVDIR/s.conf"

( cd "$ROOT" && wine 'C:\python\python.exe' server.py -c "Z:$SRVDIR/s.conf" ) &
SERVER_PID=$!
answered=no
i=0
while [ "$i" -lt 30 ]; do
    i=$((i + 1))
    sleep 2
    if python3 -c "
import sys, urllib.request
try:
    body = urllib.request.urlopen('http://127.0.0.1:$PORT/ping', timeout=2).read().strip()
except Exception:
    sys.exit(1)
sys.exit(0 if body == b'pong' else 1)
" 2>/dev/null; then
        answered=yes
        break
    fi
done
kill "$SERVER_PID" 2>/dev/null || true
SERVER_PID=
if [ "$answered" != yes ]; then
    echo "[!] the server never answered /ping on port $PORT under Windows Python" >&2
    exit 1
fi
echo "[i] /ping answered on port $PORT"

echo "== all checks passed =="
