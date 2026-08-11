# Docker

```bash
docker compose -f docker/docker-compose.yml up -d
```

That builds one image containing both the server and the sensor, and starts both.
The reporting interface is on <http://localhost:8338>.

To build the image by hand, **from the repository root** — the Dockerfile needs the whole tree:

```bash
docker build -f docker/Dockerfile -t maltrail .
```

## What runs

| service | command | notes |
| --- | --- | --- |
| `server` | `python3 server.py` | reporting UI on 8338/tcp, event intake on 8337/udp |
| `sensor` | `maltrail-sensor` | `network_mode: host`, `NET_RAW` + `NET_ADMIN` — **not** privileged |

The sensor uses the host network namespace deliberately: inside the default bridge it would only
ever see container traffic. It does not run as `privileged`; packet capture needs exactly two
capabilities and it gets exactly those two.

## Configuration and data

`maltrail.conf` is bind-mounted read-only from the repository root — edit it there and restart.
Two named volumes hold state that must survive a rebuild:

* `maltrail-logs` → `/var/log/maltrail` (events)
* `maltrail-state` → `/var/lib/maltrail` (the trail set)

Point `TRAILS_FILE` at `/var/lib/maltrail/trails.csv` so the trail set is not rebuilt on every
container start.

### Bind mounts and the unprivileged user

Both processes run as **uid/gid 10001** by default, not root — but a bind mount keeps the *host*
directory's ownership, which replaces whatever the image prepared. So `-v ./logs:/var/log/maltrail`
with `./logs` owned by your login user used to leave the container unable to create the day's log
file, and because the log file is only opened when the first event arrives, the container started,
served its UI, and persisted nothing.

Nothing needs doing about that now. `docker/entrypoint.sh` runs as root for a few milliseconds,
works out which uid can write the log and state directories, and drops to it before the sensor or
the server starts:

| what it finds | what it does |
| --- | --- |
| a named volume, or nothing mounted | runs as 10001, the image's own user |
| a bind mount owned by uid 1000 | **runs as 1000** — your files stay yours |
| a bind mount owned by `root:1000`, group-writable | keeps uid 10001, takes gid 1000 |
| a root-owned bind mount | takes ownership of that one directory, runs as 10001 |
| `PUID` / `PGID` set | uses exactly those, whatever the directory says |
| `--user` given, directory not writable | refuses to start and says which directory and why |

So `docker run -v $PWD/logs:/var/log/maltrail ...` works with no `chown` on the host, and the
events it writes belong to you rather than to a system uid you have to `sudo` past to read.

Two consequences worth knowing:

* the image has no `USER`, so **`docker exec` lands you as root**. Use `docker exec -u maltrail`
  (or `-u 1000`) if you want a shell as the user the processes actually run as.
* `--user` disables the adaptation entirely — with no root there is nothing to adapt with. The
  container then checks the directories and fails loudly rather than starting half-working.

`docker/tests/entrypoint_test.sh` asserts every row of that table against a real daemon, and runs
in CI.

## Trails are not baked into the image

Earlier versions ran the updater at build time and a cron job inside the container. Neither is done
now: baking ~2 million indicators into an image makes it large and stale the moment it is published,
and cron inside a container is a second process to supervise for no benefit. Both the server and the
sensor refresh trails themselves at startup and every `UPDATE_PERIOD`.

## Server only, receiving from remote sensors

```bash
docker run -d --name maltrail-server \
  -p 8338:8338/tcp -p 8337:8337/udp \
  -v /etc/maltrail.conf:/opt/maltrail/maltrail.conf:ro \
  -v maltrail-logs:/var/log/maltrail \
  -v maltrail-state:/var/lib/maltrail \
  maltrail:latest
```

That is the image's default command, so nothing needs overriding — and no capabilities: a server
captures nothing, so it needs neither `NET_RAW` nor `NET_ADMIN`. The built-in healthcheck asks the
server's own `/ping`, so it passes without them.

## Sensor only, against an existing server

```bash
docker run -d --name maltrail-sensor \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v /etc/maltrail.conf:/opt/maltrail/maltrail.conf:ro \
  -v maltrail-state:/var/lib/maltrail \
  maltrail:latest maltrail-sensor
```

Set `LOG_SERVER` in that config to the address of the server's 8337/udp port.

## Checking a deployment

```bash
docker compose -f docker/docker-compose.yml run --rm sensor maltrail-sensor -T
```

`-T` validates the configuration, trails, whitelist, log directory, capture filter and privileges,
then exits non-zero if the sensor would not work.

## Security posture

Both processes run as the unprivileged user `maltrail` (uid 10001 by default), matching the
systemd units. Neither needs root: the sensor gets `CAP_NET_RAW` and `CAP_NET_ADMIN`, and the
server binds only unprivileged ports. The compose file is **not** `privileged`.

Only `docker/entrypoint.sh` runs as uid 0, and only until it has decided which uid to use; it
`exec`s the real command through `setpriv`, so there is no root process left in the container.
That is also what makes `cap_add` work at all: Docker puts a requested capability in the
*bounding* set and leaves the *ambient* set empty, and an ambient capability can only be raised by
a process that starts as root. With `USER maltrail` baked into the image, `--cap-add NET_RAW` gave
the sensor `CapEff: 0000000000000000` and its capture socket failed with `EPERM`. It now gets
`CapEff: 0000000000003000` as uid 10001 — and only the sensor does; the server keeps none.

The image's own `HEALTHCHECK` asks the **server** whether it is serving, because the image's
default command is `server.py`: it fetches `/ping` and expects `pong`. The compose file's sensor
service overrides it with `maltrail-sensor -T`, so an unhealthy sensor is one that has genuinely
lost the ability to detect — bad configuration, unreadable trails, an unwritable log directory —
rather than one whose PID 1 merely still exists. `start-period` covers the first trail build.

A `HEALTHCHECK` does not go through `ENTRYPOINT`, so that override invokes the entrypoint
explicitly; otherwise `-T` would run as root, and root can write any log directory, which is one
of the things the check exists to catch.

Published images are multi-arch (`linux/amd64`, `linux/arm64`) and carry a build-provenance
attestation, so you can confirm one was built by the release workflow from this repository:

```bash
gh attestation verify oci://ghcr.io/stamparm/maltrail:3.0 --repo stamparm/maltrail
```
