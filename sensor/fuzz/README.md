# Fuzzing the Rust sensor

Two layers:

1. **Always-on, stable Rust.** `cargo test --test fuzz_parsers` runs a deterministic fuzzer
   (~200k inputs: random bytes, patterned bytes, and mutations of valid packets) against every
   parser and against the whole packet path. It is part of the normal test run, so the
   "never panic on arbitrary input" property is checked on every build.

2. **Coverage-guided, nightly.** The targets here use `libfuzzer-sys` via `cargo-fuzz`.

```bash
cargo install cargo-fuzz                 # once
rustup toolchain install nightly         # once

cd sensor
cargo +nightly fuzz list
cargo +nightly fuzz run packet   -- -max_total_time=300
cargo +nightly fuzz run dns      -- -max_total_time=300
cargo +nightly fuzz run http     -- -max_total_time=300
cargo +nightly fuzz run tls      -- -max_total_time=300
cargo +nightly fuzz run quic     -- -max_total_time=300
cargo +nightly fuzz run process  -- -max_total_time=600
```

Seed the corpora from the replay corpus for a much faster start:

```bash
python3 tools/gen_corpus.py
mkdir -p fuzz/corpus/process
cp tests/corpus/*.pcap fuzz/corpus/process/     # libFuzzer treats each file as one input
```

A crash is written to `fuzz/artifacts/<target>/`. Reproduce with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

Any crash is a bug: the sensor must treat every byte sequence as untrusted input and drop it,
never abort. `src/worker.rs` additionally wraps each packet in `catch_unwind` as a last-resort
net (mirroring `sensor.py`'s blanket `except Exception`), but that net must stay unused.
