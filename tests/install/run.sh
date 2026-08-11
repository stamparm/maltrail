#!/usr/bin/env bash
#
# install.sh, run inside real distributions and then checked.
#
#     bash tests/install/run.sh              # every environment
#     bash tests/install/run.sh debian       # just one
#     VERBOSE=1 bash tests/install/run.sh    # show the installer's output even when it passes
#
# "It installed" is not the assertion. In each environment the server is started and asked for
# /ping, the sensor is asked to validate itself with -T, the units are checked for paths that
# resolve, the installer is re-run to prove an upgrade keeps operator configuration, and
# --uninstall is run. Everything a support thread ever came from - a package named differently, a
# missing setcap, a user that was never created, a unit pointing at a binary that is not there -
# fails here instead of on someone's box.
#
# Two limits, stated rather than discovered:
#
#   * systemd does not run in a plain container, so the units are RENDERED into --unit-dir and
#     checked there; `systemctl enable --now` is not exercised.
#   * BSD cannot be tested this way at all - containers share the host's Linux kernel. That needs a
#     VM, rc.d scripts and a FreeBSD sensor target, none of which exist yet.
#
# The clone is served from the working tree over file://, so this needs no network and still
# exercises the real git path. The sensor binary comes from sensor/target/release if it is built.
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1
REPO_ROOT=$PWD

ENVIRONMENTS="ubuntu debian fedora opensuse alpine"
image_for() {
    case $1 in
        ubuntu)   echo "ubuntu:24.04" ;;
        debian)   echo "debian:12" ;;
        fedora)   echo "fedora:41" ;;
        opensuse) echo "opensuse/leap:15.6" ;;
        alpine)   echo "alpine:3.20" ;;
        *)        echo "" ;;
    esac
}

# Alpine is musl: the prebuilt sensor is glibc-linked and cannot run there, so the installer is
# expected to say so plainly and still install the server, rather than pretend.
expects_sensor() { [ "$1" != "alpine" ]; }

# MALTRAIL_TEST_SENSOR points this at any binary - a locally built one, or a release artefact you
# want to check runs on all five distributions before publishing it.
SENSOR_BIN=${MALTRAIL_TEST_SENSOR:-sensor/target/release/maltrail-sensor}
[ -x "$SENSOR_BIN" ] || SENSOR_BIN=""
case $SENSOR_BIN in /*) SENSOR_MOUNT=$SENSOR_BIN ;; ?*) SENSOR_MOUNT=$REPO_ROOT/$SENSOR_BIN ;; *) SENSOR_MOUNT="" ;; esac

pass=0; fail=0; failed=""; findings=""
ok()  { printf '    \033[32mok\033[0m       %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '    \033[31mFAIL\033[0m     %s%s\n' "$1" "${2:+  ($2)}"; fail=$((fail + 1)); failed="$failed $3/$1"; }

# One container, judging nothing: the output is only captured, so all five environments can be in
# flight at once. They share nothing, and running them one after another was pure waiting.
install_in() {
    local env=$1 image
    image=$(image_for "$env")
    [ -n "$image" ] || { echo "unknown environment: $env"; return 1; }

    # A CI checkout is a detached HEAD, where --abbrev-ref says "HEAD" and no such branch exists.
    local ref; ref=$(git symbolic-ref --short -q HEAD || git rev-parse HEAD)
    local args=(--repo file:///src --ref "$ref"
                --no-service --unit-dir /run/maltrail-units)
    local mounts=(-v "$REPO_ROOT:/src:ro")
    if [ -n "$SENSOR_BIN" ]; then
        mounts+=(-v "$SENSOR_MOUNT:/sensor-under-test:ro")
        args+=(--sensor-bin /sensor-under-test)
    fi

    docker run --rm "${mounts[@]}" "$image" sh /src/tests/install/assert.sh "${args[@]}" 2>&1
}

judge() {
    local env=$1 out marks
    out=$(cat "$WORK/$env.out" 2>/dev/null)
    printf '\n\033[1;36m== %s (%s)\033[0m\n' "$env" "$(image_for "$env")"
    marks=$(printf '%s\n' "$out" | sed -n 's/^A //p')
    got() { printf '%s\n' "$marks" | grep -qx "$1"; }

    local skip_sensor=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        printf '    \033[35mFINDING\033[0m  %s\n' "$f"
        findings="$findings|$env: $f"
        case $f in glibc:*) skip_sensor=1 ;; esac
    done < <(printf '%s\n' "$out" | sed -n 's/^F //p')

    local expected=(tree conf user logdir logdir-writable conf-managed-block
                    unit-server unit-server-conf server-ping
                    rerun-ok conf-preserved tree-after-rerun
                    inplace-adopted inplace-kept-edit inplace-kept-custom-trail
                    inplace-cloned-nothing inplace-uninstall-kept-tree
                    dirty-tree-refused dirty-tree-edit-kept force-upgraded force-kept-custom-trail
                    uninstall-ran uninstall-removed-tree uninstall-removed-units
                    uninstall-kept-conf uninstall-kept-logs)
    if expects_sensor "$env" && [ -n "$SENSOR_BIN" ]; then
        expected+=(unit-sensor unit-sensor-conf)
        # A binary that cannot even start on this distribution says nothing about install.sh.
        [ "$skip_sensor" = 0 ] && expected+=(sensor-runs sensor-selftest)
    fi

    local before=$fail
    for check in "${expected[@]}"; do
        if got "$check"; then ok "$check"; else bad "$check" "" "$env"; fi
    done

    # Alpine must REFUSE the glibc binary rather than install something that cannot run.
    if ! expects_sensor "$env"; then
        if printf '%s\n' "$out" | grep -qi musl; then ok "musl-refused-clearly"
        else bad "musl-refused-clearly" "expected a warning naming musl" "$env"; fi
    fi

    if [ "$fail" -gt "$before" ] || [ -n "${VERBOSE:-}" ]; then
        printf '\n    ---- %s: what happened ----\n' "$env"
        printf '%s\n' "$out" | sed 's/^/    /'
        printf '    ---------------------------\n'
    fi
}

[ -n "$SENSOR_BIN" ] || printf '\033[1;33m[!]\033[0m no built sensor at %s - sensor checks skipped\n' "sensor/target/release"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
targets=${*:-$ENVIRONMENTS}
start=$(date +%s)

printf 'installing in parallel: %s\n' "$targets"
for env in $targets; do
    install_in "$env" > "$WORK/$env.out" 2>&1 &
done
wait

for env in $targets; do
    judge "$env"
done

printf '\n=============================================\n'
printf 'install.sh: %d passed, %d failed, %d seconds\n' "$pass" "$fail" "$(( $(date +%s) - start ))"
[ -n "$failed" ] && printf 'failed:%s\n' "$failed"
if [ -n "$findings" ]; then
    printf '\nfindings (real, but not install.sh bugs):\n'
    printf '%s\n' "$findings" | tr '|' '\n' | sed '/^$/d;s/^/  * /'
fi
exit $((fail > 0))
