# Maltrail unit tests

Self-contained `unittest` suites for Maltrail's core logic. Pure stdlib (the optional
`cryptography` module is used only as an accelerator and is auto-skipped if absent), Python 2 and 3.

## Running

```sh
tests/run.sh                 # both python2 and python3 if present
tests/run.sh python3         # one interpreter
python3 tests/test_addr.py   # a single suite, verbose
```

`run.sh` runs each file in its own interpreter under a hard address-space cap (`ulimit -v`) and a
timeout. **Always run capped** — Python 2 with `cryptography` loaded can balloon RSS and OOM the host.

## What's covered

| File                | Module                | What it checks |
|---------------------|-----------------------|----------------|
| `test_addr.py`      | `core/addr.py`        | IPv4/IPv6 int conversions, masks, compression, ranges, host:port parsing |
| `test_fastfilter.py`| `core/fastfilter.py`  | IOC-set building, severity admission tiers, the adaptive controller, and the DLT-offset heuristic |
| `test_quic_sni.py`  | `core/quic_sni.py`    | QUIC Initial decryption (RFC 9001 KAT), HKDF, SNI extraction, malformed-input safety |
| `test_tls_intel.py` | `core/tls_intel.py`   | TLS ClientHello SNI, JA3/JA3S/JA4 fingerprints, cert names, fuzz-safety |
| `test_sensor.py`    | `sensor.py`           | The real detection path — `_check_domain` and `_process_packet` raising DNS / IP / IP:port / UDP trails — plus the DLT-offset learner |

`_pcapgen.py` is a small packet builder (Ethernet/SLL/VLAN/IPv4/IPv6/TCP/UDP) shared by the
packet-level suites.
