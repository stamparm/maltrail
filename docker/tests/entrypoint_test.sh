#!/usr/bin/env bash
#
# What docker/entrypoint.sh promises, asserted against a real Docker daemon.
#
# The bugs this pins down all shipped, twice, because "the image builds and the container starts"
# was the only thing anyone checked (#19596):
#
#   * a bind-mounted log directory owned by an ordinary host user was not writable, so the
#     container ran, served its UI, and recorded nothing;
#   * `cap_add: NET_RAW` did nothing at all for a container with a non-root USER, so the sensor
#     could not open a capture socket.
#
# It builds a small harness image rather than the real one: the entrypoint is the thing under
# test, and a Rust release build would put five minutes between a change and its verdict. The
# harness copies the same entrypoint into the same directory layout, with a stub named
# `maltrail-sensor` so the capability path is exercised by name, exactly as in production.
#
#     bash docker/tests/entrypoint_test.sh
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

IMAGE=maltrail-entrypoint-test
WORK=$(mktemp -d)
failures=0
# The containers write as uids this shell is not, so the cleanup needs root too.
# shellcheck disable=SC2329  # invoked by the `trap cleanup EXIT` below
cleanup() {
    docker run --rm --entrypoint sh -v "$WORK:/w" "$IMAGE" -c 'rm -rf /w/*' >/dev/null 2>&1
    rm -rf "$WORK"
    docker rmi -f "$IMAGE" >/dev/null 2>&1
}
trap cleanup EXIT

build() {
    docker build -q -t "$IMAGE" -f - . >/dev/null <<'DOCKERFILE'
FROM python:3.12-slim-bookworm
RUN groupadd --system --gid 10001 maltrail && \
    useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin maltrail && \
    mkdir -p /var/log/maltrail /var/lib/maltrail && \
    chown -R maltrail:maltrail /var/log/maltrail /var/lib/maltrail
COPY docker/entrypoint.sh /usr/local/bin/maltrail-entrypoint
# Stands in for the real sensor: the entrypoint decides on capabilities by argv, so the name is
# the part that matters here.
RUN printf '#!/bin/sh\nid -u; id -g; grep ^CapEff /proc/self/status\n' > /usr/local/bin/maltrail-sensor && \
    chmod 0755 /usr/local/bin/maltrail-entrypoint /usr/local/bin/maltrail-sensor
WORKDIR /opt/maltrail
ENTRYPOINT ["/usr/local/bin/maltrail-entrypoint"]
CMD ["sh", "-c", "id -u; id -g"]
DOCKERFILE
}

# Ownership the calling user cannot set (root-owned directories, and cleaning up after a
# container that wrote as another uid) is set from a throwaway root container, so this runs
# unchanged as an ordinary user and in CI.
# --entrypoint sh on purpose: the entrypoint under test would drop the privileges this needs.
sudocker() { docker run --rm --entrypoint sh -v "$WORK:/w" "$IMAGE" -c "$1" >/dev/null 2>&1; }

mkdir_owned() { # name owner mode -> path
    mkdir -p "$WORK/$1" 2>/dev/null || sudocker "mkdir -p /w/$1"
    sudocker "chown $2 /w/$1 && chmod $3 /w/$1"
    printf '%s/%s' "$WORK" "$1"
}

check() { # description expected-substring actual
    if [[ "$3" == *"$2"* ]]; then
        printf '  ok    %s\n' "$1"
    else
        printf '  FAIL  %s\n         expected to contain: %s\n         got: %s\n' "$1" "$2" "${3//$'\n'/ | }"
        failures=$((failures + 1))
    fi
}

printf 'building the harness image\n'
build || { printf 'could not build the harness image\n'; exit 1; }

printf '\nadapting to the storage it was given\n'

d=$(mkdir_owned bind1000 1000:1000 775)
out=$(docker run --rm -v "$d:/var/log/maltrail" "$IMAGE" sh -c 'id -u; id -g; touch /var/log/maltrail/x && echo WROTE' 2>&1)
check "a bind mount owned by 1000:1000 is written as 1000:1000 (#19596)" "1000
1000
WROTE" "$out"

d=$(mkdir_owned bindroot 0:0 755)
out=$(docker run --rm -v "$d:/var/log/maltrail" "$IMAGE" sh -c 'id -u; touch /var/log/maltrail/x && echo WROTE' 2>&1)
check "a root-owned bind mount is taken over and stays on the image's uid" "10001" "$out"
check "  ... and is writable afterwards" "WROTE" "$out"

d=$(mkdir_owned bindgroup 0:1000 775)
out=$(docker run --rm -v "$d:/var/log/maltrail" "$IMAGE" sh -c 'id -u; id -g; touch /var/log/maltrail/x && echo WROTE' 2>&1)
check "a group-writable root:1000 directory is joined, not chowned" "10001
1000
WROTE" "$out"

out=$(docker run --rm "$IMAGE" 2>&1)
check "with no mounts at all it runs as the image's own user" "10001" "$out"

d=$(mkdir_owned puid 1000:1000 775)
out=$(docker run --rm -e PUID=1234 -e PGID=1234 -v "$d:/var/log/maltrail" "$IMAGE" sh -c 'id -u; id -g; touch /var/log/maltrail/x && echo WROTE' 2>&1)
check "PUID/PGID override the directory's owner" "1234
1234
WROTE" "$out"

printf '\nsaying so instead of failing quietly\n'

d=$(mkdir_owned explicit 0:0 755)
out=$(docker run --rm --user 1000:1000 -v "$d:/var/log/maltrail" "$IMAGE" 2>&1)
status=$?
check "--user with an unwritable directory names the directory" "/var/log/maltrail is not writable" "$out"
check "  ... and refuses to start" "1" "$status"

d=$(mkdir_owned readonly 0:0 755)
out=$(docker run --rm -v "$d:/var/log/maltrail:ro" "$IMAGE" 2>&1)
status=$?
check "a read-only mount is reported as such" "cannot be made writable" "$out"
check "  ... and refuses to start" "1" "$status"

printf '\ncapabilities across the privilege drop\n'

# 0x2000 = CAP_NET_RAW, 0x1000 = CAP_NET_ADMIN. Docker grants NET_RAW by default and NET_ADMIN
# only on request, so the sensor line below must show both and the server line neither.
out=$(docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN "$IMAGE" maltrail-sensor 2>&1)
check "the sensor keeps NET_RAW and NET_ADMIN as an unprivileged uid" "10001
10001
CapEff:	0000000000003000" "$out"

out=$(docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN "$IMAGE" sh -c 'grep ^CapEff /proc/self/status' 2>&1)
check "anything that is not the sensor keeps none of them" "CapEff:	0000000000000000" "$out"

printf '\n'
if [[ $failures -eq 0 ]]; then
    printf 'entrypoint: all checks passed\n'
else
    printf 'entrypoint: %d check(s) FAILED\n' "$failures"
fi
exit $((failures > 0))
