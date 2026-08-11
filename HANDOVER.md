# Handover

State of play as of **2026-08-11**, master at `37c455c4`. Read `AGENTS.md` first — it has the
working conventions and the traps. This file is what is *in flight* and what was *decided*.

## Where things stand

**3.1 is released** (binaries + `ghcr.io/stamparm/maltrail:3.1` + `:latest`, provenance attested).
Master carries an **unreleased 3.1.1** worth of fixes — see the top of `CHANGELOG`. Open issues:
**79**, down from 97.

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

1. **Tag 3.1.1.** The installer currently downloads 3.1 binaries, which are the glibc-2.39 ones that
   do not start on half the enterprise distributions. Everything needed for the tag is on master;
   the release workflow now builds against 2.28 and refuses anything newer. **Verify the published
   artefact before announcing:** `MALTRAIL_TEST_SENSOR=<downloaded binary> bash tests/install/run.sh`.
2. **README: advertise the one-liner.** Deliberately not done yet — pointing people at
   `curl … | sh` while it fetches binaries that cannot run would be worse than not having it.
   Do it immediately after step 1.
3. **The trails split** (agreed in principle, not started). See below.
4. `#19595` — wiki page for the config options. Left open on purpose: the wiki is a separate repo,
   so it is a deliverable, not a code change.

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
