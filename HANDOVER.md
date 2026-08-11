# Handover

State of play as of **2026-08-11**, master at `170c40d9`. Read `AGENTS.md` first — it has the
working conventions and the traps. This file is what is *in flight* and what was *decided*.

## Where things stand

**3.1.1 is released** (`52b2872e`, tag `3.1.1`): binaries for x86_64 and aarch64,
`ghcr.io/stamparm/maltrail:3.1.1` + `:latest`, provenance attested, gate green. The published
x86_64 binary was checked after the fact rather than trusted: checksum matches, highest glibc
symbol required is **2.28**, `--version` says `#v3.1.1`. That was the point of the release — the
3.1 artefacts needed 2.39 and did not exec on RHEL 8/9, Debian 12 or Leap 15.6, and `install.sh`
downloads the latest release. Open issues: **79**, down from 97.

Master has no unreleased changes beyond documentation.

Everything below is on master, green in CI (`sensor`, `msrv`, `floor`, `server` ×3, `version`,
`docker`, `installer`, `audit`).

## Landed since 3.1, and why it matters

| what | why it was not cosmetic |
| --- | --- |
| `install.sh` + 5-distribution harness | there was no supported one-command install at all |
| Release binaries built on glibc **2.28** | the published ones did not `exec` on Debian 12, Leap 15.6, RHEL 8/9 |
| **Python 3.6** support restored | one `str.isascii()` call left RHEL 8 / CentOS 7 / Leap 15 / AL2 with an empty trail set |
| Docker entrypoint (`docker/entrypoint.sh`) | bind mounts were unwritable; `cap_add` granted the sensor nothing; compose did not start |
| Sensor trail updates with a relative `-c` | `chdir("")` → "unable to run python3.12" → empty trail set on every Docker and tarball install |
| `cleared.txt` (#19053) | a flagged host could only be removed from `/blacklist` by whitelisting it forever |
| `proto` column + panel fields (#19569), tag editing (#19568), chart axis (#19570/#19571) | dashboard regressions from the v3 rewrite |

## Next, in the order I would do it

1. **The trails split** (agreed in principle, not started). See below. The gate is the licence
   audit, not code.
2. `#19595` — wiki page for the config options. Left open on purpose: the wiki is a separate repo,
   so it is a deliverable, not a code change.
3. Whatever the 3.1.1 release surfaces. It is the first version whose binaries start on the
   enterprise distributions *and* the first the README tells people to install with one command,
   so the installer is about to meet many more environments than the five in the harness.

**Done, 11 Aug 2026** (was 1 and 2 here): 3.1.1 tagged and published, and the README quick start
now leads with `curl … | sudo sh` (`170c40d9`), with build-from-source moved under its own heading
and the same pointer added to `sensor/docs/INSTALL.md`. Advertising the one-liner was deliberately
held until the tag existed, because before it the installer fetched binaries that could not exec.

## Decisions already made (do not relitigate without a reason)

* **The installer clones with git, it does not ship a release bundle.** The trail lists live *in*
  the repository, so a clone brings current detection content with the code and an upgrade is a
  fetch. A bundle would be new release machinery for something git already does.
* **`install.sh` stays at the repository root.** Run from inside an existing checkout it installs
  *that* tree in place and never touches its git state; `--prefix`/`--repo` asks for a managed copy.
  Uninstall only removes a tree the installer created (recorded in `/var/lib/maltrail/installed-prefix`).
* **The container drops privileges in the entrypoint rather than via `USER`.** That is the only way
  to reconcile a bind mount's ownership, and the only way `cap_add` can reach a non-root process.
* **Configuration lives in `/etc/maltrail.conf`** for installer-managed deployments, so a
  `git reset --hard` on upgrade cannot eat it. A later duplicate key wins, so the installer appends
  its block rather than rewriting the operator's lines.
* **Log pruning was rejected.** This is an IDS; the event log is evidence.
* **`feodotracker` was dropped**; `sslblcert` (SHA-1 C2 certificate fingerprints, `CERT` trail type)
  was added and is rated *suspicious*, not malware, to keep the false-positive cost down.

## The trails split — agreed direction, not started

The numbers that decided it: **97% of all commits touch `trails/static`** (8,664 of 8,925; 94% in
the last 90 days), the top eight files alone account for ~1.8 GB of history, and static trails are
frozen per revision — so updating detection means pulling code.

Shape agreed:

* content moves to its own repository; **do not rewrite this repository's history** (forks, clones
  and every SHA in an issue comment would break). Freeze in place: stop adding, let it stop growing.
* the new repository needs an anti-growth policy from day one — current set in git, versioned
  snapshots as release assets, or periodic orphan-branch rotation. Daily commits of 3,000 text files
  is the same ledger in a new suit.
* clients pull an aggregate. `UPDATE_SERVER` already exists and does exactly this, so the client
  work is caching, verification and provenance — not plumbing.
* **the blocker is licensing, not engineering**: redistributing an aggregate is a different act from
  each user fetching a feed. That audit — 43 feeds, one line each: licence, redistribution y/n,
  attribution — is the gate. Feeds that say no stay client-side (`USE_FEED_UPDATES` already toggles
  this).
* keep a bootstrap snapshot for air-gapped installs, preserve per-trail provenance (the UI cites a
  trail's source), and let sensors pin a version so a bad publish is not instantly global.

Side benefit worth more than the bandwidth: a dated trail history gives *first-seen* per indicator
across the whole corpus, which is what `meta.sqlite` retro-hunt wants and what few aggregators
publish well.

## Known gaps, honestly

* **Alpine/musl**: no prebuilt sensor. The installer detects it, says so, and points at building
  from source. A musl target with static libpcap would fix it; not started.
* **BSD**: unsupported and untestable in containers (they share the Linux kernel). Would need a CI
  VM, `rc.d` scripts, and a FreeBSD sensor target.
* **`systemctl enable --now` is not covered by the harness** — systemd does not run in a plain
  container. Units are rendered and checked; starting them is not exercised.
* **`/trails` serves custom trail names unauthenticated.** The smaller sibling of this was fixed for
  `/check`; the larger question was flagged for a deliberate decision and is still open.
* **134 static trails contain underscores** and are unreachable through `VALID_DNS_NAME_REGEX`.
  `sensor/tools/check_trails.py` reports them; fixing means changing matching behaviour.
* **`PACKET_FANOUT_EBPF`** (source-affine fanout) would remove the scan-heuristic dilution at high
  worker counts. Demoted to an optimisation — exact trail detection is identical at every worker
  count; only the source-counting heuristics dilute (91% / 86% / 65% survive at 2 / 4 / 8 workers).

## Standing instructions from the maintainer

* No `Co-Authored-By` trailers. No reporter credits unless asked.
* Contacting real infrastructure (DNS, IPs, live C2) during testing is authorised.
* Do not moralise about how security reports are handled.
* Do not waste the maintainer's time: run the gates your change touches, not all of them; iterate on
  one environment, not five. If something is going to take 20 minutes, say so before starting it.
* **Never sit and poll.** No `gh run watch`, no `sleep` loops waiting on CI, no re-running locally
  what CI already ran on that commit. Start the slow thing, do the next piece of work, and if only
  background verification is left, say it is still running and stop. Waiting is not progress — a
  release turn was burned on exactly this. `tests/install/run.sh` across all five distributions
  takes 20+ minutes on a cold cache (openSUSE is the slow one) and the `installer` CI job already
  covers it; the useful local check on a published binary is checksum + `objdump -T | grep GLIBC`
  + `--version`, which takes seconds.
