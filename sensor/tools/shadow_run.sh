#!/bin/bash
# Shadow test on REAL traffic (ROADMAP Gate 2.3), without waiting a week.
#
# The shadow gate asks one question: does the OLD sensor detect anything the NEW one does not?
# Answering it needs traffic nobody hand-wrote. This captures live traffic while driving an
# adversarial workload, then replays that ONE capture through BOTH sensors and diffs the results.
#
# Replaying a single capture beats running both sensors live: two AF_PACKET sockets see slightly
# different packets and drop differently, so a difference could be the network rather than the
# sensor. One capture gives both sensors byte-identical input, and the pcap is kept as evidence.
#
#   sudo -v                                   # capture needs CAP_NET_RAW; see below
#   bash sensor/tools/shadow_run.sh --seconds 600
#
# Everything except the capture runs unprivileged. The generator never connects to malicious
# infrastructure — see the SAFETY note in adversarial_traffic.py.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

SECONDS_TO_RUN=300
IFACE=any
OUT=""
EXTRA_GEN=""
EXISTING_PCAP=""

while [ $# -gt 0 ]; do
    case "$1" in
        --seconds) SECONDS_TO_RUN="$2"; shift 2 ;;
        --interface) IFACE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --pcap) EXISTING_PCAP="$2"; shift 2 ;;
        --no-dns) EXTRA_GEN="$EXTRA_GEN --no-dns"; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "[!] unknown option '$1'"; exit 2 ;;
    esac
done

OUT=${OUT:-$(mktemp -d /tmp/maltrail-shadow-XXXXXX)}
mkdir -p "$OUT/new" "$OUT/old"
PCAP="$OUT/traffic.pcap"
TRAILS_SRC="${MALTRAIL_TRAILS:-$HOME/.maltrail/trails.csv}"

echo "== Maltrail shadow test =="
echo "[i] output directory: $OUT"

if [ ! -f "$TRAILS_SRC" ]; then
    echo "[!] no trail set at '$TRAILS_SRC'; run the sensor once first"
    exit 1
fi
# One snapshot, used by BOTH sensors: a trail update landing mid-run would otherwise give the
# two sensors different indicator sets and make every difference meaningless.
cp "$TRAILS_SRC" "$OUT/trails.csv"
echo "[i] trail snapshot: $(wc -l < "$OUT/trails.csv") rows"

SENSOR_BIN="$ROOT/sensor/target/release/maltrail-sensor"
if [ ! -x "$SENSOR_BIN" ]; then
    echo "[!] build the sensor first: cargo build --release --manifest-path sensor/Cargo.toml"
    exit 1
fi

# ---------------------------------------------------------------------------- capture
# --pcap re-analyses a capture taken earlier: no privileges, no traffic, same comparison. Useful
# for re-running the diff after a sensor change against the exact bytes that found something.
if [ -n "$EXISTING_PCAP" ]; then
    cp "$EXISTING_PCAP" "$PCAP"
    echo "[i] using existing capture: $EXISTING_PCAP ($(du -h "$PCAP" | cut -f1))"
else
CAP=""
if [ -x /usr/bin/dumpcap ] && /usr/bin/dumpcap -D >/dev/null 2>&1; then
    CAP="/usr/bin/dumpcap -i $IFACE -w $PCAP -q"
elif tcpdump -i "$IFACE" -c 1 -w /dev/null >/dev/null 2>&1; then
    CAP="tcpdump -i $IFACE -w $PCAP -U -s 0"
elif sudo -n true 2>/dev/null; then
    CAP="sudo tcpdump -i $IFACE -w $PCAP -U -s 0"
else
    cat <<EOF
[!] no way to capture unprivileged. Pick ONE, then re-run this script:

      sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap     # once, then never again
      sudo -v                                                        # cache sudo for this run

EOF
    exit 1
fi

echo "[i] capturing on '$IFACE' for ${SECONDS_TO_RUN}s: $CAP"
$CAP >"$OUT/capture.log" 2>&1 &
CAP_PID=$!
sleep 2
if ! kill -0 "$CAP_PID" 2>/dev/null; then
    echo "[!] capture died immediately:"; cat "$OUT/capture.log"; exit 1
fi

# ---------------------------------------------------------------------------- traffic
python3 "$HERE/adversarial_traffic.py" --seconds "$SECONDS_TO_RUN" --trails "$OUT/trails.csv" $EXTRA_GEN \
    2>&1 | tee "$OUT/traffic.log" | grep -E "^\[i\] (done|sampled|local|[0-9])"

sleep 2
kill -INT "$CAP_PID" 2>/dev/null
wait "$CAP_PID" 2>/dev/null
sync

if [ ! -s "$PCAP" ]; then
    echo "[!] capture produced nothing:"; cat "$OUT/capture.log"; exit 1
fi
echo "[i] captured $(du -h "$PCAP" | cut -f1) -> $PCAP"
fi

# ---------------------------------------------------------------------------- replay both
# Same config for both, apart from LOG_DIR. Trail updating is off on both sides so the snapshot
# above is what each of them detects with.
write_conf() {   # $1 = log dir, $2 = output path
    cat > "$2" <<EOF
MONITOR_INTERFACE any
CAPTURE_BUFFER 10%
PROCESS_COUNT 1
UPDATE_PERIOD 999999999
USE_FEED_UPDATES false
DISABLE_CHECK_SUDO true
DISABLE_TRAIL_UPDATES true
USE_HEURISTICS true
CHECK_MISSING_HOST true
CHECK_HOST_DOMAINS true
USE_CONDENSED_STORAGE false
SENSOR_NAME shadow
SCAN_WINDOW 30
EVENT_THROTTLE_MODE off
LOG_DIR $1
TRAILS_FILE $OUT/trails.csv
EOF
}

# Each sensor gets its own trails.csv copy: sensor.py writes a .bin sidecar next to it.
cp "$OUT/trails.csv" "$OUT/trails-old.csv"
write_conf "$OUT/new" "$OUT/new.conf"
write_conf "$OUT/old" "$OUT/old.conf"
sed -i "s|^TRAILS_FILE .*|TRAILS_FILE $OUT/trails-old.csv|" "$OUT/old.conf"

echo "[i] replaying through the new sensor..."
"$SENSOR_BIN" -r "$PCAP" -c "$OUT/new.conf" -q --offline >"$OUT/new.log" 2>&1
echo "[i]   exit $?"

echo "[i] replaying through the old sensor (old/sensor.py)..."
python3 "$ROOT/old/sensor.py" -r "$PCAP" -c "$OUT/old.conf" --offline >"$OUT/old.log" 2>&1
echo "[i]   exit $?"

# ---------------------------------------------------------------------------- compare
echo
python3 "$HERE/shadow_diff.py" --new "$OUT/new" --old "$OUT/old" --all --json "$OUT/report.json"
STATUS=$?
echo
echo "[i] artifacts kept in $OUT (pcap, both LOG_DIRs, report.json)"
exit $STATUS
