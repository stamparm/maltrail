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

# Run unprivileged, matching the systemd units. The container needed no root even before this:
# the sensor wants CAP_NET_RAW/CAP_NET_ADMIN (granted by cap_add, not by being root) and the
# server binds only unprivileged ports. A packet parser running as uid 0 is a needless
# escalation path, and "it is only a container" is not an argument — user namespaces are off by
# default in most deployments, so root here is root on the host if anything escapes.
#
# HOME is set because the default TRAILS_FILE is ~/.maltrail/trails.csv, and this user has no
# home outside the state volume.
RUN groupadd --system --gid 10001 maltrail && \
    useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin maltrail && \
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

USER maltrail

# Liveness that means something. `-T` validates the configuration, trails, whitelist, log
# directory and capture filter and exits non-zero if the deployment would not work — so an
# unhealthy container is one that has actually stopped being able to detect, rather than one
# whose PID 1 happens to still exist. start-period covers the first trail build, which takes
# a minute or so on a cold volume.
HEALTHCHECK --interval=60s --timeout=30s --start-period=180s --retries=3 \
    CMD ["maltrail-sensor", "-T"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "server.py"]
