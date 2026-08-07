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

## Trails are not baked into the image

Earlier versions ran the updater at build time and a cron job inside the container. Neither is done
now: baking ~2 million indicators into an image makes it large and stale the moment it is published,
and cron inside a container is a second process to supervise for no benefit. Both the server and the
sensor refresh trails themselves at startup and every `UPDATE_PERIOD`.

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
