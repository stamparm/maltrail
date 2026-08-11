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

Both processes run as **uid/gid 10001**, not root. Named volumes (the default above) are fine:
Docker initialises a new named volume from the image, ownership included, so the directories are
already writable.

A **bind mount is not** — it keeps the host directory's ownership, which replaces the one the
image prepared. A directory owned by your login user leaves the container unable to create the
day's log file, and because `server.py` only opens that file when the first event arrives, the
container starts, serves the UI, and silently fails to persist anything.

Pick one:

```bash
# 1. give the host directory to the container's user (simplest)
sudo chown 10001:10001 ./logs

# 2. or build the image to run as the user that already owns it
docker build --build-arg MALTRAIL_UID=$(id -u) --build-arg MALTRAIL_GID=$(id -g) \
             -f docker/Dockerfile -t maltrail:latest .

# 3. or use a named volume and read events out with `docker cp` / a sidecar
```

`maltrail-sensor -T` reports this directly — `log directory: '...' is NOT writable as uid 10001`
— so run it against a new deployment before trusting it.

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

The image runs as the unprivileged user `maltrail` (uid 10001), matching the systemd units.
Neither process needs root: the sensor gets `CAP_NET_RAW` and `CAP_NET_ADMIN` through `cap_add`
rather than by being root, and the server binds only unprivileged ports. The compose file is
**not** `privileged`.

`HEALTHCHECK` runs `maltrail-sensor -T`, so an unhealthy container is one that has genuinely lost
the ability to detect — bad configuration, unreadable trails, an unwritable log directory — rather
than one whose PID 1 merely still exists. `start-period` covers the first trail build.

Published images are multi-arch (`linux/amd64`, `linux/arm64`) and carry a build-provenance
attestation, so you can confirm one was built by the release workflow from this repository:

```bash
gh attestation verify oci://ghcr.io/stamparm/maltrail:3.0 --repo stamparm/maltrail
```
