#!/bin/sh
# Everything that must pass before the Rust sensor is considered good.
#
#   sh sensor/tools/check.sh
#
# Run from the repository root. Nothing here needs root; the live-capture and PACKET_FANOUT
# proof is separate and needs privileges:
#   sudo python3 sensor/tools/fanout_check.py --interface <iface> --workers 4
set -e

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

# Check the toolchain BEFORE doing five minutes of work that ends in `rustfmt: command not
# found`. A distribution Rust package often splits these out (openSUSE puts rustfmt in `rustup`
# or `cargo1.NN`), so "I installed Rust" does not mean these exist — and the bare shell error
# names the command without saying it is optional, which package provides it, or that the
# thousands of lines of passing output above it are unaffected.
missing=""
for tool in cargo rustfmt python3; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
# clippy is a cargo subcommand rather than a binary on PATH.
cargo clippy --version >/dev/null 2>&1 || missing="$missing cargo-clippy"
if [ -n "$missing" ]; then
    echo "[!] this gate needs:$missing"
    echo "[?] with rustup:   rustup component add rustfmt clippy"
    echo "[?] openSUSE/SLES: sudo zypper install rustup && rustup default stable"
    echo "[?] Debian/Ubuntu: sudo apt-get install rustfmt cargo clippy python3"
    echo "[i] none of this is needed to BUILD or RUN the sensor — 'cargo build --release' is enough."
    exit 1
fi

echo "== generated files are in sync with core/settings.py =="
# BEFORE regenerating, not after: this gate exists to catch a constant that was changed in
# core/settings.py without regenerating, and regenerating first would silently repair the drift
# instead of reporting it. The Python sensor reads those constants at runtime while the Rust one
# compiles them in, so a mismatch makes the two sensors disagree in a way the parity harness
# structurally cannot see (it compares two sensors that are each internally consistent).
cargo test --manifest-path sensor/Cargo.toml --release --test generated

echo "== regenerate the Python-derived constants and vectors =="
python3 sensor/tools/gen_settings.py
python3 sensor/tools/gen_vectors.py
python3 sensor/tools/gen_corpus.py
# The generator emits valid but unformatted Rust (one long line per table), so format just that
# file before the repository-wide formatting check below.
rustfmt --edition 2021 --config-path sensor/rustfmt.toml sensor/src/settings_gen.rs

echo "== formatting =="
cargo fmt --manifest-path sensor/Cargo.toml --check

echo "== clippy =="
cargo clippy --manifest-path sensor/Cargo.toml --all-targets -- -D warnings

echo "== tests, DEBUG profile (overflow checks ON) =="
# Debug first, and not optional: integer overflow panics only in debug, so a release-only test run
# cannot see it. The fuzz parsers exist to prove the packet path never panics on arbitrary input,
# and that proof is worthless in a profile where the check is compiled out. A real overflow in
# dns::question_type_class shipped unnoticed for exactly this reason.
cargo test --manifest-path sensor/Cargo.toml

echo "== tests, RELEASE profile (what actually ships) =="
cargo test --manifest-path sensor/Cargo.toml --release

echo "== build the release binary =="
cargo build --manifest-path sensor/Cargo.toml --release

echo "== differential parity against sensor.py =="
python3 sensor/tools/parity.py
python3 sensor/tools/parity.py --timestamps pcap

echo "== differential parity against sensor.py, using the REAL trail set =="
# The fixture corpus above uses 30 hand-written trails, which cannot exercise anything that
# depends on real trail data (a domain whose parent is also a trail, a trail that only exists in a
# feed, a 1.5M-row store). This step samples the operator's actual trails.csv, synthesizes the
# traffic each sampled trail should trip, and runs BOTH sensors over it. Skipped when the host has
# no trails file yet.
REAL_TRAILS="${MALTRAIL_TRAILS:-$HOME/.maltrail/trails.csv}"
if [ -f "$REAL_TRAILS" ]; then
    REAL_CORPUS="$(mktemp -d)"
    python3 sensor/tools/gen_corpus.py --from-trails "$REAL_TRAILS" --out "$REAL_CORPUS" --per-bucket 25
    python3 sensor/tools/parity.py --corpus "$REAL_CORPUS" --timeout 600
    rm -rf "$REAL_CORPUS"
else
    echo "[skip] no '$REAL_TRAILS'; run the sensor once (or set MALTRAIL_TRAILS) to enable this step"
fi

echo "== all checks passed =="
