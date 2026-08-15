#!/usr/bin/env bash
#
# link_libpcap_soname(), against the case it exists for and the case that defeated it.
#
#     bash tests/install/soname.sh
#
# The prebuilt sensor used to be linked against a shared libpcap, and the two distribution
# families disagree about that library's SONAME: upstream, RHEL, Fedora and SUSE call it
# libpcap.so.1, Debian and Ubuntu ship the identical ABI as libpcap.so.0.8. A binary built on one
# family therefore asks for a name the other does not have, and dies before main() on a machine
# with libpcap installed. install.sh links the missing name so that cannot happen.
#
# Releases after 3.1.1 link libpcap statically and never reach that code, but it still has to work
# for an older release and for --sensor-bin, and it was WRONG: the directory search reached
# /usr/lib/i386-linux-gnu before /usr/lib/x86_64-linux-gnu, so on any multiarch box that also had
# the 32-bit libpcap it linked a 32-bit library under the name a 64-bit sensor wanted. Still dead,
# now with a symlink implying otherwise.
#
# tests/install/run.sh does cover the mismatch itself — CI builds the sensor inside AlmaLinux 8 and
# hands that binary to the Debian and Ubuntu containers, so the wrong SONAME is genuinely there.
# What those containers are not is MULTIARCH: with only one architecture's libpcap installed, the
# directory search cannot pick the wrong one, and the bug is invisible. So this test adds the one
# missing ingredient — the i386 libpcap alongside the amd64 one — to a binary that needs
# libpcap.so.1 on an Ubuntu that has only libpcap.so.0.8.
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1
REPO_ROOT=$PWD
IMAGE=ubuntu:24.04

command -v docker >/dev/null 2>&1 || { echo "[!] docker is required"; exit 1; }

printf '\033[1;36m==>\033[0m manufacturing a libpcap.so.1 binary on a multiarch %s\n' "$IMAGE"

docker run --rm -v "$REPO_ROOT:/repo:ro" "$IMAGE" bash -euo pipefail -c '
    fail() { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }
    ok()   { printf "\033[1;32m[o]\033[0m %s\n" "$*"; }

    export DEBIAN_FRONTEND=noninteractive
    dpkg --add-architecture i386
    apt-get update -qq
    # The 32-bit libpcap is the whole point: it is what the old directory search found first.
    apt-get install -y -qq gcc libc6-dev libpcap0.8t64 libpcap0.8t64:i386 binutils >/dev/null

    ls /usr/lib/i386-linux-gnu/libpcap.so.* >/dev/null 2>&1 ||
        fail "the i386 libpcap did not install; this test would not reproduce the bug"
    [ -e /usr/lib/x86_64-linux-gnu/libpcap.so.1 ] &&
        fail "this image already has libpcap.so.1; there would be nothing to link"

    cd /tmp
    # A stub with libpcap.so.1 as its SONAME, linked against, then deleted: the program is left
    # needing a name that nothing on an Ubuntu system provides. Exactly the released binary.
    cat > stub.c <<"STUB"
char *pcap_lib_version(void);
char *pcap_lib_version(void) { return 0; }
STUB
    gcc -shared -fPIC -o libpcap.so.1 -Wl,-soname,libpcap.so.1 stub.c
    cat > prog.c <<"PROG"
#include <stdio.h>
char *pcap_lib_version(void);
int main(void) { printf("%s\n", pcap_lib_version()); return 0; }
PROG
    gcc -o prog prog.c -L/tmp -l:libpcap.so.1 -Wl,-rpath-link,/tmp
    rm -f /tmp/libpcap.so.1

    objdump -p prog | grep -q "NEEDED.*libpcap.so.1" || fail "the probe binary does not need libpcap.so.1"
    ldd prog 2>/dev/null | grep -q "libpcap.so.1 => not found" ||
        fail "the probe binary already resolves; this test cannot fail and so is not a test"
    ok "probe binary needs libpcap.so.1, which this system does not have"

    # Load the real installer, do not run it.
    MALTRAIL_INSTALL_SOURCE_ONLY=1 . /repo/install.sh
    command -v link_libpcap_soname >/dev/null ||
        fail "link_libpcap_soname is gone from install.sh; this test is checking nothing"

    link_libpcap_soname /tmp/prog

    ldd /tmp/prog 2>/dev/null | grep -q "not found" &&
        fail "still unresolved after link_libpcap_soname"
    ok "the loader resolves it now"

    [ -e /usr/lib/i386-linux-gnu/libpcap.so.1 ] &&
        fail "a 32-bit library was linked as libpcap.so.1 (the bug this test exists for)"
    [ -L /usr/lib/x86_64-linux-gnu/libpcap.so.1 ] ||
        fail "expected the symlink in the 64-bit multiarch directory"
    ok "linked in /usr/lib/x86_64-linux-gnu, and nothing left behind in the i386 one"

    # The assertion that matters: it RUNS, and reaches the real libpcap.
    out=$(/tmp/prog) || fail "the probe binary still does not execute"
    case $out in
        *libpcap*) ok "probe binary executed and called into libpcap: $out" ;;
        *) fail "probe binary ran but did not reach libpcap: $out" ;;
    esac
'
status=$?

if [ "$status" -eq 0 ]; then
    printf '\033[1;32m[o]\033[0m soname: passed\n'
else
    printf '\033[1;31m[x]\033[0m soname: FAILED\n'
fi
exit "$status"
