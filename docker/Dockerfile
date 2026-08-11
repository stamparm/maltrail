# Maltrail — server and sensor in one image.
#
# Build from the REPOSITORY ROOT (the build context must contain the whole tree):
#
#     docker build -f docker/Dockerfile -t maltrail .
#
# or just use docker/docker-compose.yml, which sets the context correctly.

# ---------------------------------------------------------------------------------------
# Stage 1: build the sensor
# ---------------------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS sensor-build

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Manifests first, so a source-only change does not re-download and rebuild every dependency.
COPY sensor/Cargo.toml sensor/Cargo.lock ./sensor/
RUN mkdir -p sensor/src && echo 'fn main() {}' > sensor/src/main.rs && \
    echo '' > sensor/src/lib.rs && \
    cargo build --release --manifest-path sensor/Cargo.toml 2>/dev/null || true

COPY sensor/ ./sensor/
# The build script generates nothing, but `touch` defeats the stale-fingerprint cache above.
RUN touch sensor/src/main.rs sensor/src/lib.rs && \
    cargo build --release --manifest-path sensor/Cargo.toml && \
    strip sensor/target/release/maltrail-sensor

# ---------------------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# libpcap runtime only (not -dev: nothing compiles here), and tini so signals reach the process.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 tini && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/maltrail

COPY . /opt/maltrail/
COPY --from=sensor-build /build/sensor/target/release/maltrail-sensor /usr/local/bin/maltrail-sensor

# Server: 8338/tcp reporting UI, 8337/udp event intake from remote sensors.
EXPOSE 8338/tcp
EXPOSE 8337/udp

# Run unprivileged, matching the systemd units. Neither process needs root: the sensor wants
# CAP_NET_RAW/CAP_NET_ADMIN (granted by cap_add, not by being root) and the server binds only
# unprivileged ports. A packet parser running as uid 0 is a needless escalation path, and "it is
# only a container" is not an argument — user namespaces are off by default in most deployments,
# so root here is root on the host if anything escapes.
#
# The uid is only the DEFAULT: docker/entrypoint.sh runs as root just long enough to work out
# which uid can write the log and state directories, and drops to it before exec'ing anything.
# That is what makes a bind mount owned by an ordinary host user work without `sudo chown` on the
# host first (issue #19596). Setting it at build time is still honoured and still supported.
#
# HOME is set because the default TRAILS_FILE is ~/.maltrail/trails.csv, and this user has no
# home outside the state volume.
ARG MALTRAIL_UID=10001
ARG MALTRAIL_GID=10001
RUN groupadd --system --gid ${MALTRAIL_GID} maltrail && \
    useradd --system --uid ${MALTRAIL_UID} --gid ${MALTRAIL_GID} --no-create-home --shell /usr/sbin/nologin maltrail && \
    mkdir -p /var/log/maltrail /var/lib/maltrail && \
    chown -R maltrail:maltrail /var/log/maltrail /var/lib/maltrail
ENV HOME=/var/lib/maltrail

# VOLUME must come AFTER the chown above. Docker snapshots the image content of a path at the
# moment VOLUME is declared, and discards anything a later layer does to it — declaring these
# earlier meant the ownership fix never reached the volume and the unprivileged user could not
# write its own log or state directory. Verified by running the image, not by reading the docs.
#
# Trails are NOT baked into the image: downloading them at build time produces a large image
# full of indicators that are stale the moment it is published. Both processes refresh them at
# startup and every UPDATE_PERIOD into the state volume.
VOLUME ["/var/log/maltrail", "/var/lib/maltrail"]

# No `USER maltrail` here on purpose. The entrypoint below is what drops privileges, because a
# uid fixed at build time cannot be reconciled with a bind mount whose ownership only exists at
# `docker run` time. `--user` is still respected: with one set, the entrypoint has no root to
# adapt with, so it verifies the directories are writable and fails loudly if they are not.
COPY docker/entrypoint.sh /usr/local/bin/maltrail-entrypoint
RUN chmod 0755 /usr/local/bin/maltrail-entrypoint

# Liveness for the process this image actually starts. CMD below is `server.py`, so the default
# healthcheck asks the SERVER whether it is serving: /ping is unauthenticated and answers "pong".
#
# It used to run `maltrail-sensor -T`, which is the wrong question to ask a server container:
# unless the configuration happens to set DISABLE_CHECK_SUDO, `-T` fails on a missing CAP_NET_RAW
# that a server neither has nor needs, so a working server-only deployment reported itself
# unhealthy (issue #19596, measured: exit 1 on that check alone). A healthcheck that cannot pass
# in a correct configuration is worse than none — it trains people to ignore health.
#
# A sensor container overrides this; see docker-compose.yml, which sets `-T` for that service.
# start-period covers the first trail build, which takes a minute or so on a cold volume.
HEALTHCHECK --interval=60s --timeout=30s --start-period=180s --retries=3 \
    CMD ["python3", "-c", "import os,sys,urllib.request; port=os.environ.get('MALTRAIL_HTTP_PORT','8338'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/ping' % port, timeout=10).read().strip() == b'pong' else 1)"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/maltrail-entrypoint"]
CMD ["python3", "server.py"]
