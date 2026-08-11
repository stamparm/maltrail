#!/bin/sh
# Match the container's identity to the storage it was handed, then drop privileges.
#
# A bind mount keeps the HOST directory's ownership; it replaces whatever the image prepared.
# So an image that hard-codes "run as uid 10001" cannot write `-v ./logs:/var/log/maltrail`
# unless the host directory happens to be owned by 10001 — and demanding
# `sudo chown 10001:10001` on the host before a container will start is not a fix, it is a
# workaround the operator has to remember (issue #19596).
#
# This script runs as root for a few milliseconds, decides which uid/gid can actually write the
# log and state directories, and then execs the real command WITHOUT root. Nothing but this
# script ever runs privileged; the sensor and the server are unprivileged exactly as before.
#
# Order of preference for that uid/gid:
#
#   1. PUID / PGID, if set               — explicit operator instruction, never second-guessed
#   2. the owner of a directory we cannot write, when that owner is a real user
#                                        — a bind mount owned by uid 1000 is a statement of intent
#   3. the image's own `maltrail` user    — named volumes, and the default with no mounts at all
#
# If the container was started with `--user` (or by an orchestrator that pins a uid), there is no
# root to adapt with: this only checks that the directories are writable and says precisely what
# is wrong if they are not, instead of letting it surface later as a failed log write.
set -eu

LOG_DIR=${MALTRAIL_LOG_DIR:-/var/log/maltrail}
STATE_DIR=${MALTRAIL_STATE_DIR:-/var/lib/maltrail}

say() { printf 'maltrail-entrypoint: %s\n' "$*" >&2; }

# `test -w` answers for the *effective* uid, so ask it as the user we intend to become rather
# than deducing it from mode bits — that way supplementary groups, ACLs and read-only mounts all
# give the same answer here as they will give the sensor.
writable_as() { # uid gid dir
    setpriv --reuid="$1" --regid="$2" --clear-groups /usr/bin/test -w "$3" 2>/dev/null
}

default_uid=$(id -u maltrail)
default_gid=$(id -g maltrail)

if [ "$(id -u)" != "0" ]; then
    for d in "$LOG_DIR" "$STATE_DIR"; do
        [ -d "$d" ] || continue
        [ -w "$d" ] && continue
        say "FATAL: $d is not writable as uid $(id -u):$(id -g) — it is owned by $(stat -c '%u:%g, mode %a' "$d")."
        say "This container was given an explicit user, so it has no root left to fix that with."
        say "Either chown that directory to $(id -u):$(id -g), or drop --user and let this script pick"
        say "the uid itself. Starting anyway would serve a UI that records nothing."
        exit 1
    done
    exec "$@"
fi

want_uid=${PUID:-$default_uid}
want_gid=${PGID:-$default_gid}

for d in "$LOG_DIR" "$STATE_DIR"; do
    [ -d "$d" ] || mkdir -p "$d"
done

# 2. Adopt the owner of a directory that was mounted in and that our user cannot write. The log
#    directory is asked first: it is the one operators bind-mount, and the one that has to be
#    writable for anything to be recorded.
if [ -z "${PUID:-}" ]; then
    for d in "$LOG_DIR" "$STATE_DIR"; do
        writable_as "$want_uid" "$want_gid" "$d" && continue
        owner=$(stat -c '%u' "$d")
        group=$(stat -c '%g' "$d")

        if [ "$owner" != "0" ] && [ "$owner" != "$want_uid" ]; then
            want_uid=$owner
            want_gid=$group
            say "$d belongs to $want_uid:$want_gid — running as that user instead of $default_uid:$default_gid."
            break
        fi

        # A root-owned but group-writable directory (`root:staff 775`) is the other way operators
        # share one: take the group and leave the uid and the directory alone.
        mode=$(stat -c '%a' "$d")
        case ${mode%?} in
            *[2367]) [ "$group" = "0" ] || {
                want_gid=$group
                say "$d is group-writable by gid $want_gid — joining that group instead of chowning it."
                break
            } ;;
        esac
    done
fi

for d in "$LOG_DIR" "$STATE_DIR"; do
    writable_as "$want_uid" "$want_gid" "$d" && continue

    # Recurse only into a directory the image itself prepared, i.e. a fresh named volume: its
    # contents are ours by construction. A mounted-in directory gets its own mode changed and
    # nothing below it, because `chown -R` on someone else's tree (`-v /var/log:...`) would do
    # real damage to the host for the sake of starting a container.
    if [ "$(stat -c '%u' "$d")" = "$default_uid" ]; then
        chown -R "$want_uid:$want_gid" "$d" 2>/dev/null || :
    else
        say "$d is not writable as $want_uid:$want_gid — taking ownership of the directory itself."
        chown "$want_uid:$want_gid" "$d" 2>/dev/null || :
    fi

    writable_as "$want_uid" "$want_gid" "$d" && continue
    say "FATAL: $d cannot be made writable as $want_uid:$want_gid ($(stat -c 'owner %u:%g mode %a' "$d"))."
    say "A read-only mount does this. Mount it read-write, or point LOG_DIR somewhere else."
    exit 1
done

# Carry CAP_NET_RAW / CAP_NET_ADMIN across the uid change - for the sensor only.
#
# This is not just plumbing for the new entrypoint, it repairs something that never worked:
# `cap_add` has NO effect on a container whose USER is not root, because Docker grants the
# capability in the bounding set and leaves the ambient set empty. Measured on the 3.1 image:
#
#     docker run --user 10001 --cap-add NET_RAW ...  ->  CapEff: 0000000000000000
#     python3 -c 'socket.socket(AF_PACKET, SOCK_RAW)' -> PermissionError
#
# So `docker compose up`'s sensor could not open a capture socket at all, whatever cap_add said.
# Only a process that starts as root can put a capability into the ambient set, which is exactly
# what this script now is. With it: CapEff 0000000000003000 as uid 10001, and the socket opens.
#
# Only capabilities already in the bounding set can be requested (asking for more is an error),
# and only for the sensor: the server captures nothing, so it keeps running with none at all,
# the same as it did under `USER maltrail`.
caps=""
case " $* " in
    *" maltrail-sensor "*|*/maltrail-sensor" "*|*" sensor.py "*)
        caps=$(python3 -c '
import re
bnd = int(re.search(r"CapBnd:\s*([0-9a-fA-F]+)", open("/proc/self/status").read()).group(1), 16)
print(",".join("+" + n for n, bit in (("net_raw", 13), ("net_admin", 12)) if bnd >> bit & 1))
' 2>/dev/null) || caps=""
        ;;
esac

# shellcheck disable=SC2086  # $caps is deliberately word-split into two setpriv arguments
exec setpriv --reuid="$want_uid" --regid="$want_gid" --clear-groups \
    ${caps:+--inh-caps=$caps --ambient-caps=$caps} "$@"
