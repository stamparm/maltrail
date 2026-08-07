# `old/` — the previous, Python sensor

`sensor.py` was Maltrail's sensor until the Rust sensor in [`../sensor/`](../sensor/)
replaced it. It is **not deleted, and should not be** — it has three jobs left:

1. **The differential oracle.** The sensor's parity harness replays a corpus through *both* sensors
   and requires byte-identical events. That test only exists while this file does. It is the reason
   the port can claim parity rather than assert it.
2. **The reference implementation.** Every Rust module names the Python function it was ported from.
   When a detection's exact behaviour is in question, this is the answer.
3. **A fallback.** It still works. `maltrail-sensor-old.service` runs it.

## Running it

```bash
sudo python3 old/sensor.py                 # live capture
python3 old/sensor.py -r capture.pcap --offline
```

It imports `core.*` from the repository root and works from any directory.

## Running both side by side

Give each sensor its own `LOG_DIR` and its own copy of `TRAILS_FILE` (the Python sensor writes a
`.bin` sidecar next to it and the two must not race), then compare the event logs:

```bash
python3 sensor/tools/parity.py                 # the automated version of exactly that
```

## What is gone

* **Plugins (`-p`).** Removed from both sensors and the `plugins/` directory deleted. The hook took
  a Python callable per event, which no longer has a home in a Rust sensor, and there was no
  evidence of use.

## What only this sensor still does

Nothing, as of 3.0: the condensed observable store (`meta.sqlite`, `USE_CONDENSED_STORAGE`) was
the last feature only this sensor wrote, and the Rust sensor now writes it in the same format
(`sensor/docs/ROADMAP.md` §4.1). This sensor remains the reference implementation and the oracle
`sensor/tools/parity.py` replays against, which is reason enough to keep it.
