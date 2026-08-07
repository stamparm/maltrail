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

# Trails are NOT baked into the image. Downloading them at build time produces a large image
# full of indicators that are stale the moment it is published; both the server and the sensor
# refresh them at startup and every UPDATE_PERIOD into the volume below.
VOLUME ["/var/log/maltrail", "/var/lib/maltrail"]

# Server: 8338/tcp reporting UI, 8337/udp event intake from remote sensors.
EXPOSE 8338/tcp
EXPOSE 8337/udp

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "server.py"]
