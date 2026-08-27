#!/bin/sh
#
# The container half of tests/install/run.sh: install, then check what is actually there.
#
# Runs INSIDE the distribution image, with the repository mounted read-only at /src. Every
# assertion prints one line:
#
#     A <name>        the check passed
#     F <detail>      a finding that is not install.sh's fault (recorded, not counted as a failure)
#
# Anything else is diagnostic output the host shows when something fails. Arguments are passed
# straight through to install.sh.
#
# A separate file on purpose: this used to be a quoted string inside the host script, and the host
# shell expanded the $(...) in it before the container ever saw it - producing a mangled script and
# a syntax error rather than a test result.
set -u

# git refuses a repository owned by another uid, and inside the container /src is exactly that. It
# has to be a real global config FILE: safe.directory is "protected configuration", so git ignores
# it from GIT_CONFIG_* and from -c by design. printf, because git is not installed yet - installing
# it is the installer's first job.
printf '[safe]\n\tdirectory = *\n' > /root/.gitconfig

PREFIX=/opt/maltrail
CONF=/etc/maltrail.conf
UNITS=/run/maltrail-units
SENSOR=$PREFIX/sensor/target/release/maltrail-sensor

sh /src/install.sh "$@" 2>&1
printf -- '--- ASSERT ---\n'

# 1. the tree, the configuration, the user, the directories
[ -f "$PREFIX/server.py" ] && echo "A tree"
[ -f "$CONF" ] && echo "A conf"
id maltrail >/dev/null 2>&1 && echo "A user"
[ -d /var/log/maltrail ] && echo "A logdir"
su -s /bin/sh maltrail -c 'touch /var/log/maltrail/.probe' 2>/dev/null && echo "A logdir-writable"
grep -q '^TRAILS_FILE /var/lib/maltrail/trails.csv' "$CONF" && echo "A conf-managed-block"

# 2. units: rendered for this installation's paths, and pointing at something executable
for role in server sensor; do
    unit="$UNITS/maltrail-$role.service"
    [ -f "$unit" ] || continue
    exec_path=$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$unit" | head -1)
    if [ -x "$exec_path" ]; then
        echo "A unit-$role"
    else
        echo "F unit-$role ExecStart is not executable: $exec_path"
    fi
    grep -q "^ExecStart=.* -c $CONF" "$unit" && echo "A unit-$role-conf"
done

# 3. the server serves, as the unprivileged user, on this distribution
python=$(command -v python3)
( cd "$PREFIX" && su -s /bin/sh maltrail -c "$python server.py -c $CONF" >/tmp/server.log 2>&1 & )
i=0
while [ "$i" -lt 40 ]; do
    i=$((i + 1))
    sleep 1
    if "$python" - <<'PING' 2>/dev/null
import sys, urllib.request
sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8338/ping", timeout=2).read().strip() == b"pong" else 1)
PING
    then
        echo "A server-ping"
        break
    fi
done
[ "$i" -lt 40 ] || { echo "server never answered /ping; its log:"; tail -15 /tmp/server.log; }
pkill -f 'server\.py' 2>/dev/null || true

# 4. the sensor binary: it has to START (which proves the libpcap link) before -T means anything.
#    A glibc-too-new binary is a property of how the release is BUILT, so it is a finding, not an
#    installer failure - the installer put the file exactly where it belongs.
if [ -x "$SENSOR" ]; then
    if /usr/local/bin/maltrail-sensor --version >/tmp/version.log 2>&1; then
        echo "A sensor-runs"
        # -T is a real check, so give it something real: a trail set it can load. Building the
        # actual 1.6M-trail file here would test the updater, not the installer, so updates are
        # off and two trails stand in. Without a trails file -T rightly FAILS ("would detect
        # NOTHING"), which is the sensor being correct, not a bug to assert around.
        printf 'evil.example,"malware (test)","(static)"\n1.2.3.4,"malware (test)","(static)"\n' > /var/lib/maltrail/trails.csv
        chown maltrail:maltrail /var/lib/maltrail/trails.csv
        printf '\nDISABLE_TRAIL_UPDATES true\n' >> "$CONF"
        if maltrail-sensor -c "$CONF" -T >/tmp/selftest.log 2>&1; then
            echo "A sensor-selftest"
        else
            echo "sensor -T failed:"; tail -6 /tmp/selftest.log
        fi
    elif grep -q 'GLIBC_' /tmp/version.log; then
        echo "F glibc: $(sed -n 's/.*maltrail-sensor: //p' /tmp/version.log | head -1)"
    else
        echo "F sensor did not start: $(tail -1 /tmp/version.log)"
    fi
fi

# 5. re-running IS the upgrade, and it must not eat operator configuration
echo '# operator marker' >> "$CONF"
if sh /src/install.sh "$@" >/tmp/rerun.log 2>&1; then
    echo "A rerun-ok"
else
    echo "re-run failed:"; tail -20 /tmp/rerun.log
fi
grep -q '# operator marker' "$CONF" && echo "A conf-preserved"
[ -f "$PREFIX/server.py" ] && echo "A tree-after-rerun"

# 6. run from inside a checkout (what someone who already cloned will type): it must adopt THAT
#    tree, clone nothing, and leave the working tree - including untracked custom trails and edited
#    tracked files - exactly as it found it.
# A shallow clone, NOT `cp -a /src`: the mounted repository carries sensor/target, which is 14 GB
# of build artifacts, and copying that once per environment was the entire runtime of this suite.
git clone --depth 1 --quiet file:///src /home/checkout
cd /home/checkout || exit 1
echo '# operator edit' >> maltrail.conf
mkdir -p trails/custom && echo 'evil.test,"mine","(custom)"' > trails/custom/mine.txt
sh ./install.sh --no-service --unit-dir "$UNITS" --role server >/tmp/inplace.log 2>&1
grep -q 'installing from this checkout' /tmp/inplace.log && echo "A inplace-adopted"
grep -q '# operator edit' maltrail.conf && echo "A inplace-kept-edit"
[ -f trails/custom/mine.txt ] && echo "A inplace-kept-custom-trail"
# /opt/maltrail already exists from step 1, so the meaningful check is that this run did not
# clone: it must have used the checkout it was started from.
grep -qE 'cloning [a-z]+://' /tmp/inplace.log || echo "A inplace-cloned-nothing"
# ...and its --uninstall must not delete the developer's tree
sh ./install.sh --uninstall --unit-dir "$UNITS" >/tmp/inplace-un.log 2>&1
[ -f /home/checkout/server.py ] && echo "A inplace-uninstall-kept-tree"
cd / || exit 1

# 7. clone mode: an existing managed tree with local changes must NOT be reset silently
sh /src/install.sh "$@" >/dev/null 2>&1
echo '# operator edit' >> "$PREFIX/maltrail.conf"
mkdir -p "$PREFIX/trails/custom" && echo 'evil.test,"mine","(custom)"' > "$PREFIX/trails/custom/mine.txt"
sh /src/install.sh "$@" >/tmp/dirty.log 2>&1
grep -q 'NOT updated' /tmp/dirty.log && echo "A dirty-tree-refused"
grep -q '# operator edit' "$PREFIX/maltrail.conf" && echo "A dirty-tree-edit-kept"
# with --force it upgrades, but an UNTRACKED custom trail is still not deleted (no `git clean`)
sh /src/install.sh "$@" --force >/tmp/force.log 2>&1
grep -q 'updating' /tmp/force.log && echo "A force-upgraded"
[ -f "$PREFIX/trails/custom/mine.txt" ] && echo "A force-kept-custom-trail"

# 8. uninstall: gone, but the evidence and the configuration are not
if sh /src/install.sh --uninstall --unit-dir "$UNITS" >/tmp/uninstall.log 2>&1; then
    echo "A uninstall-ran"
else
    echo "uninstall failed:"; tail -20 /tmp/uninstall.log
fi
[ ! -e "$PREFIX" ] && echo "A uninstall-removed-tree"
[ ! -e "$UNITS/maltrail-server.service" ] && echo "A uninstall-removed-units"
[ -f "$CONF" ] && echo "A uninstall-kept-conf"
[ -d /var/log/maltrail ] && echo "A uninstall-kept-logs"
exit 0
