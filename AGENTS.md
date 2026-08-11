# Working on Maltrail

Notes for anyone — human or agent — picking this repository up. Not style rules; the things that
cost real time here when you get them wrong.

## The one failure mode that matters

Maltrail's characteristic bug is **"looks fine, detects nothing"**. It has shipped in every form:
a feed that returns an empty list, a trails file that never gets built, a `cap_add` that grants
nothing, a healthcheck that asks the wrong question, a bind mount nobody can write, an option that
exists only in the source. Every one of these installed cleanly, started, served a UI, and detected
nothing — for months, with nobody noticing.

So: **a change is not done until you have watched it work.** Not read the diff, not reasoned about
it — run it and look. Every fix in the recent history came with an empirical check, and several
"obviously correct" fixes were wrong when actually run. Two examples worth internalising:

* A `/blacklist` fix "verified" by seeing no IPs in the response — the server had failed to start.
  The output was empty because *nothing was running*.
* A benchmark reporting 1 ns/packet, because the sensor under test had exited immediately.

When you assert something, assert against a positive control too: if the test cannot fail, it is
not a test.

## Layout

| path | what |
| --- | --- |
| `server.py`, `core/` | the server: HTTP UI, event intake (UDP 8337), trail updating |
| `sensor/` | the Rust sensor (`src/`), its docs (`docs/`), tools (`tools/`) |
| `old/` | the retired Python sensor — a test oracle for parity runs, not a supported path |
| `html/` | the dashboard (vanilla JS, no build step; `main.js` is hand-written) |
| `trails/static/`, `trails/feeds/` | the indicator lists and the feed fetchers |
| `tests/` | Python tests + `tests/install/` (the installer harness) |
| `docker/` | image, compose, entrypoint, and the entrypoint's tests |
| `install.sh` | the `curl \| sh` installer |

## Gates, and what they cost

Run what your change touches. CI runs everything on push; do not re-run the full set locally for a
one-line change (that habit cost ~20 minutes per push and was called out, twice).

```bash
bash tests/run.sh python3            # server suite: ~26 files, 311 tests, ~2 min
bash sensor/tools/check.sh           # sensor gate: fmt, clippy -D warnings, 385 tests, ~3 min
cargo test -q --manifest-path sensor/Cargo.toml --lib      # the fast inner loop, ~1 s
bash tests/install/run.sh debian     # ONE distribution, 37 s
bash tests/install/run.sh            # all five, 2m36s
bash docker/tests/entrypoint_test.sh # container entrypoint contract, ~1 min
```

`tests/run.sh` refuses to start if a `tests/test_*.py` file is missing from its `TESTS` list — a
test that is not listed is not run by CI either, and it will sit there passing locally and covering
nothing.

## Floors, and where they are enforced

* **Rust 1.74** — openSUSE Leap 15 / SLE 15 ship exactly that. `msrv` job in CI. Crates declaring
  `edition = "2024"` cannot be parsed by cargo 1.74; several Dependabot PRs died on this.
* **Python 3.6** — the stock `python3` of RHEL 8, CentOS 7, Leap 15, Amazon Linux 2. CI job `floor`
  runs the whole suite *and builds a trail set* in `python:3.6-slim`. It was 3.7 for one call
  (`str.isascii()`), which killed the trail update on all of those distributions.
* **glibc 2.28** — release binaries build inside AlmaLinux 8, and the release refuses to publish a
  binary needing anything newer. Built on the runner they did not start on Debian 12, Leap 15.6,
  RHEL 8 or 9.

## Working the issue tracker

The pattern that has worked: pick one issue, fix it properly, prove it empirically, add a guard so
the class cannot recur silently, then close with a short human comment — `done - <commit-sha>` plus
two or three sentences in plain language. Not a changelog entry, not a lecture.

Long-open issues are usually open because the *actual* objection was never answered. #19053 sat for
three years with "just whitelist it" as the advice, while the reporter kept saying that a whitelist
also suppresses future detections. Read the thread to the end before writing code.

## Commits

* Explain **why**, and what you measured. Numbers, error strings, before/after — the commit is
  where the next person learns what was actually wrong.
* **No `Co-Authored-By: Claude` trailer.** Ever.
* Do not credit security reporters unless asked to.
* If you push and then need to change the message: `git commit --amend` + `--force-with-lease`.

## Gotchas that have cost hours here

* **`git clean -fd` on a user's tree deletes their custom trails.** `trails/custom/*.txt` are
  untracked by design. `install.sh` therefore never runs `git clean`.
* **`safe.directory` is "protected configuration"** — git ignores it from `GIT_CONFIG_*` env vars
  and `-c` on purpose. It has to be a real config file.
* **Docker's `cap_add` does nothing for a non-root `USER`**: the capability lands in the bounding
  set, ambient stays empty, and only a process that starts as root can raise it.
* **A bind mount keeps the host's ownership**, replacing whatever the image prepared.
* **`HEALTHCHECK` does not go through `ENTRYPOINT`.**
* **Compose resolves relative bind-mount paths against the compose file's directory**, not the
  shell's.
* **libpcap has two SONAMEs**: `libpcap.so.1` (RHEL/Fedora/SUSE) and `libpcap.so.0.8`
  (Debian/Ubuntu). Same ABI. The loader's error reads as if the library were absent.
* **Do not copy the working tree in tests** — `sensor/target` is ~14 GB. Use a shallow clone. That
  single mistake was 10 of the 12 minutes the installer harness used to take.
* **The frontend has no build step and no framework.** `html/index.html` declares the columns,
  `html/js/main.js` fills them, and nothing but a person keeps them in step —
  `tests/test_frontend.py` exists because of that.
* **Chromium can render the dashboard headless** for real assertions:
  `chromium --headless --dump-dom`, with a probe script injected into a *copy* of `index.html`.
  Note it cannot read `file://` under snap confinement — serve the directory over HTTP.

## Editing files

Prefer exact-string replacement. Index arithmetic on file contents (`s.index(...)` and slicing) has
silently deleted 178 lines of README here. When a patch grows past two or three hunks, rewrite the
section in one shot instead of stacking patches — patch-on-patch is where hunks get lost and
variables end up undefined.
