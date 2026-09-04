#!/bin/sh
#
# Maltrail installer.
#
#     curl -fsSL https://raw.githubusercontent.com/stamparm/maltrail/master/install.sh | sh
#
# Installs the server, the sensor, or both: dependencies, a shallow git clone, the prebuilt sensor
# binary for this architecture, an unprivileged user, log and state directories, systemd units, and
# the capabilities the sensor needs to capture without root. Re-running it is the upgrade path.
#
#     sh install.sh --role sensor          # sensor only (server lives elsewhere)
#     sh install.sh --ref 3.1              # pin to a release tag instead of master
#     sh install.sh --no-service           # install, do not touch systemd
#     sh install.sh --dry-run              # print every command, change nothing
#     sh install.sh --uninstall            # remove it again (logs and state are kept)
#     sh install.sh --force                # upgrade even if the tree has local changes
#
# Run from inside a checkout you already have, it installs THAT tree in place and never touches its
# git state; --prefix asks for a separate managed copy instead.
#
# git rather than a release tarball on purpose: the trail lists live IN the repository, so a clone
# brings current detection content with the code, and an upgrade is a fetch. `--depth 1` leaves the
# ~1.8 GB of history behind.
#
# Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
# See the file 'LICENSE' for copying permission
set -eu

REPO=${MALTRAIL_REPO:-https://github.com/stamparm/maltrail.git}
RELEASES=${MALTRAIL_RELEASES:-https://github.com/stamparm/maltrail/releases}
PREFIX=${MALTRAIL_PREFIX:-/opt/maltrail}
CONF=${MALTRAIL_CONF:-/etc/maltrail.conf}
REF=${MALTRAIL_REF:-master}
ROLE=${MALTRAIL_ROLE:-both}
SENSOR_BIN=${MALTRAIL_SENSOR_BIN:-}
LOG_DIR=${MALTRAIL_LOG_DIR:-/var/log/maltrail}
STATE_DIR=${MALTRAIL_STATE_DIR:-/var/lib/maltrail}
RUN_USER=${MALTRAIL_USER:-maltrail}
UNIT_DIR=${MALTRAIL_UNIT_DIR:-/etc/systemd/system}
UNIT_DIR_SET=0
PREFIX_SET=0
REPO_SET=0
FORCE=0
IN_PLACE=0
SERVICE=1
DRY=0
UNINSTALL=0
PYTHON=""
PKG=""
warned=0

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { warned=$((warned + 1)); printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Every mutating command goes through this, which is what makes --dry-run honest rather than a
# best-effort approximation of what would happen.
run() {
    if [ "$DRY" = 1 ]; then
        printf '    + %s\n' "$*"
        return 0
    fi
    "$@"
}

# Same, but the command's own chatter is only shown if it FAILS. A package manager unpacking 46
# dependencies is not information; its error message is.
run_quiet() {
    if [ "$DRY" = 1 ]; then
        printf '    + %s\n' "$*"
        return 0
    fi
    _log=$(mktemp)
    if "$@" >"$_log" 2>&1; then
        rm -f "$_log"
        return 0
    fi
    printf '\n--- output of: %s ---\n' "$*" >&2
    cat "$_log" >&2
    rm -f "$_log"
    return 1
}

usage() {
    sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --role)        ROLE=$2; shift 2 ;;
            --role=*)      ROLE=${1#*=}; shift ;;
            --ref|--version) REF=$2; shift 2 ;;
            --ref=*)       REF=${1#*=}; shift ;;
            --version=*)   REF=${1#*=}; shift ;;
            --prefix)      PREFIX=$2; PREFIX_SET=1; shift 2 ;;
            --prefix=*)    PREFIX=${1#*=}; PREFIX_SET=1; shift ;;
            --conf)        CONF=$2; shift 2 ;;
            --conf=*)      CONF=${1#*=}; shift ;;
            --sensor-bin)  SENSOR_BIN=$2; shift 2 ;;
            --sensor-bin=*) SENSOR_BIN=${1#*=}; shift ;;
            --repo)        REPO=$2; REPO_SET=1; shift 2 ;;
            --repo=*)      REPO=${1#*=}; REPO_SET=1; shift ;;
            --force)       FORCE=1; shift ;;
            --unit-dir)    UNIT_DIR=$2; UNIT_DIR_SET=1; shift 2 ;;
            --unit-dir=*)  UNIT_DIR=${1#*=}; UNIT_DIR_SET=1; shift ;;
            --no-service)  SERVICE=0; shift ;;
            --dry-run)     DRY=1; shift ;;
            --uninstall)   UNINSTALL=1; shift ;;
            -h|--help)     usage ;;
            *)             die "unknown option '$1' (try --help)" ;;
        esac
    done
    case $ROLE in
        server|sensor|both) ;;
        *) die "--role must be server, sensor or both (got '$ROLE')" ;;
    esac
}

# Someone who has already cloned the repository will type `sudo sh install.sh` in it, because that
# is what a file called install.sh invites. Cloning a SECOND copy into /opt/maltrail behind their
# back would be confusing; touching their git state would be worse. So when this script is a file
# inside a Maltrail checkout, that checkout IS the installation - nothing is cloned, fetched or
# reset. Passing --repo or --prefix asks for the clone explicitly and turns this off.
#
# `curl | sh` never matches: $0 is "sh" or "-" there, not a readable file.
detect_in_place() {
    [ "$PREFIX_SET" = 0 ] || return 0
    [ "$REPO_SET" = 0 ] || return 0
    [ -n "${0:-}" ] && [ -f "$0" ] || return 0
    _dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || return 0
    [ -d "$_dir/.git" ] && [ -f "$_dir/server.py" ] && [ -d "$_dir/core" ] || return 0
    IN_PLACE=1
    PREFIX=$_dir
}

need_root() {
    [ "$(id -u)" = 0 ] && return 0
    if have sudo; then
        die "this needs root. Re-run with: curl -fsSL <url> | sudo sh"
    fi
    die "this needs root, and sudo is not installed. Run it as root."
}

# ---------------------------------------------------------------------------------------------
# dependencies
# ---------------------------------------------------------------------------------------------
# Which OS family this is. Nothing here assumed anything but Linux, and everything it assumed -
# systemd, /proc, setcap, six Linux package managers - is genuinely Linux. The sensor itself is
# not: it captures through libpcap, which is native on macOS and the BSDs.
OS=$(uname -s 2>/dev/null || printf 'Linux')

detect_pkg() {
    # BSD and macOS first: a Homebrew user can have GNU tools on PATH, and matching apt-get on a
    # Mac because someone installed it would be a worse guess than matching brew.
    case $OS in
        FreeBSD)  have pkg && { PKG=pkg; return 0; } ;;
        NetBSD)   have pkgin && { PKG=pkgin; return 0; } ;;
        OpenBSD)  have pkg_add && { PKG=pkg_add; return 0; } ;;
        Darwin)   have brew && { PKG=brew; return 0; }
                  warn "Homebrew not found; install git, python3 and libpcap yourself, or install brew"
                  PKG=""; return 0 ;;
    esac
    for m in apt-get dnf yum zypper apk pacman; do
        have "$m" && { PKG=$m; return 0; }
    done
    PKG=""
    warn "no known package manager found; assuming git, python3, libpcap and setcap are present"
}

pkg_install() {
    [ -n "$PKG" ] || return 0
    case $PKG in
        apt-get)
            run_quiet env DEBIAN_FRONTEND=noninteractive apt-get update -qq
            run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@"
            ;;
        dnf)    run_quiet dnf install -y -q "$@" ;;
        yum)    run_quiet yum install -y -q "$@" ;;
        zypper) run_quiet zypper --quiet --non-interactive install --no-recommends "$@" ;;
        apk)    run_quiet apk add --no-cache -q "$@" ;;
        pacman) run_quiet pacman -Sy --needed --noconfirm --quiet "$@" ;;
        pkg)    run_quiet env ASSUME_ALWAYS_YES=yes pkg install -y "$@" ;;
        pkgin)  run_quiet pkgin -y install "$@" ;;
        pkg_add) run_quiet pkg_add "$@" ;;
        # brew refuses to run as root, and install.sh is normally run with sudo. Drop back to the
        # invoking user rather than failing the whole install on a Mac.
        brew)
            if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
                run_quiet sudo -u "$SUDO_USER" brew install "$@"
            else
                run_quiet brew install "$@"
            fi
            ;;
    esac
}

# libpcap and setcap are packaged under a different name almost everywhere, which is exactly the
# kind of detail that turns "curl | sh" into a support thread.
ensure_deps() {
    say "installing dependencies ($PKG)"

    # curl is asked for only when it is MISSING. RHEL 9 minimal images ship curl-minimal, which
    # provides /usr/bin/curl and CONFLICTS with the curl package - so `dnf install ... curl ...`
    # fails the ENTIRE transaction and git, python3 and libpcap are not installed either. The
    # installer then dies having changed nothing, on a distribution family the README claims to
    # support. Rocky 9 and AlmaLinux 9 both did exactly that.
    _curl=""
    have curl || _curl="curl"

    case $PKG in
        apt-get) pkg_install git ca-certificates $_curl tar python3 libpcap0.8 libcap2-bin ;;
        dnf|yum) pkg_install git ca-certificates $_curl tar python3 libpcap libcap ;;
        zypper)  pkg_install git-core ca-certificates $_curl tar python3 libpcap1 libcap-progs ;;
        apk)     pkg_install git ca-certificates $_curl tar python3 libpcap libcap ;;
        pacman)  pkg_install git ca-certificates $_curl tar python libpcap libcap ;;
        # The BSDs ship libpcap in base, and there is no setcap - privilege for capture is a BPF
        # device permission, not a file capability.
        # FreeBSD's python3 does NOT include the sqlite3 module - it is a separate port, and
        # without it server.py dies on `import sqlite3` before it can serve anything. The port is
        # named for the interpreter version, so it is derived rather than guessed.
        pkg)
            pkg_install git python3
            _pyv=$(python3 -c 'import sys; print("%d%d" % sys.version_info[:2])' 2>/dev/null || printf '')
            [ -n "$_pyv" ] && pkg_install "py${_pyv}-sqlite3"
            ;;
        pkgin)   pkg_install git python311 ;;
        pkg_add) pkg_install git python3 ;;
        brew)    pkg_install git python3 libpcap ;;
    esac

    for tool in git tar; do
        have "$tool" || die "'$tool' is still missing after installing dependencies"
    done
    have curl || have wget || die "neither curl nor wget is available"
}

# The interpreter the units will name explicitly. 3.6 is the floor (RHEL 8 / CentOS 7 / Leap 15 /
# Amazon Linux 2 ship it as python3), so on any current distribution the default is fine - but a
# box whose `python3` is 2.7, or a `python3` that is not Python at all, must not be discovered as
# usable and then fail later with an empty trail set.
detect_python() {
    for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6; do
        have "$candidate" || continue
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 6) else 1)' 2>/dev/null; then
            PYTHON=$(command -v "$candidate")
            info "python: $PYTHON ($("$PYTHON" -V 2>&1))"
            return 0
        fi
    done
    die "no Python 3.6+ found; the server runs on it and the sensor needs it to build trails"
}

# ---------------------------------------------------------------------------------------------
# source
# ---------------------------------------------------------------------------------------------
clone_or_update() {
    if [ "$IN_PLACE" = 1 ]; then
        say "installing from this checkout: $PREFIX"
        info "not cloning, fetching or resetting anything - it is your working tree"
        info "(pass --prefix to install a separate copy instead)"
        return 0
    fi
    if [ -d "$PREFIX/.git" ]; then
        say "updating $PREFIX (ref: $REF)"
        # A dirty tree is not ours to throw away. CUSTOM_TRAILS_DIR now defaults outside the
        # checkout, but an existing install may still have trails/custom/*.txt - an operator's OWN
        # indicators - are untracked, so `git clean -fd` would delete them, and local edits to
        # tracked files would go under `reset --hard`. Upgrade only what is clean, and say what was
        # skipped; --force is the way to say "yes, discard it".
        if [ "$FORCE" = 0 ] && [ -n "$(git -C "$PREFIX" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
            warn "$PREFIX has local changes, so it was NOT updated:"
            git -C "$PREFIX" status --short --untracked-files=no 2>/dev/null | sed 's/^/        /' >&2
            warn "commit or move them, or re-run with --force to discard them."
            return 0
        fi
        run git -C "$PREFIX" remote set-url origin "$REPO"
        run git -C "$PREFIX" fetch --depth 1 --quiet origin "$REF"
        # reset, not merge: a half-applied merge is worse than a replaced tree, and operator
        # configuration lives in $CONF precisely so this cannot reach it.
        run git -C "$PREFIX" checkout --quiet --detach FETCH_HEAD
        run git -C "$PREFIX" reset --hard --quiet FETCH_HEAD
    else
        say "cloning $REPO (ref: $REF, shallow)"
        run mkdir -p "$(dirname "$PREFIX")"
        case $REF in
            # A commit SHA is not a branch, so --branch rejects it. Fetching it explicitly also
            # covers a detached HEAD, which is what CI checkouts hand us.
            [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
                if git -C / ls-remote --exit-code --heads "$REPO" "$REF" >/dev/null 2>&1; then
                    run git clone --depth 1 --branch "$REF" --quiet "$REPO" "$PREFIX"
                else
                    run git clone --depth 1 --quiet "$REPO" "$PREFIX"
                    run git -C "$PREFIX" fetch --depth 1 --quiet origin "$REF"
                    run git -C "$PREFIX" checkout --quiet --detach FETCH_HEAD
                fi
                ;;
            *)  run git clone --depth 1 --branch "$REF" --quiet "$REPO" "$PREFIX" ;;
        esac
    fi
    [ "$DRY" = 1 ] || [ -f "$PREFIX/server.py" ] || die "$PREFIX/server.py missing after checkout"
}

# ---------------------------------------------------------------------------------------------
# sensor binary
# ---------------------------------------------------------------------------------------------
target_triple() {
    machine=$(uname -m)
    case $machine in
        x86_64|amd64)  arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *)             printf ''; return ;;
    esac

    # The OS and the libc are both part of the target, not reasons to give up. Alpine used to be
    # told to install a Rust toolchain and build its own, and macOS and FreeBSD were not
    # considered at all. The release ships all four families now, and docs/compat records each of
    # them installing and running.
    case $OS in
        Darwin)  printf '%s-apple-darwin' "$arch" ; return ;;
        FreeBSD) printf '%s-unknown-freebsd' "$arch" ; return ;;
    esac

    libc=gnu
    is_musl && libc=musl
    printf '%s-unknown-linux-%s' "$arch" "$libc"
}

is_musl() {
    # A gnu-target binary cannot run on musl, and the failure ("not found" from the loader) tells
    # the operator nothing. Detect it and say so instead.
    [ -n "$(find /lib /usr/lib -maxdepth 1 -name 'ld-musl-*' -print -quit 2>/dev/null)" ] && return 0
    if have ldd; then ldd --version 2>&1 | head -1 | grep -qi musl && return 0; fi
    return 1
}

fetch() { # url dest
    if have curl; then run curl -fsSL --retry 3 -o "$2" "$1"
    else run wget -qO "$2" "$1"; fi
}

latest_tag() {
    # Follow the /releases/latest redirect rather than calling the API: no rate limit, no token.
    if have curl; then
        curl -fsSLI -o /dev/null -w '%{url_effective}' "$RELEASES/latest" 2>/dev/null | sed 's#.*/tag/##'
    else
        wget -qS --max-redirect 5 -O /dev/null "$RELEASES/latest" 2>&1 | sed -n 's/.*[Ll]ocation:.*\/tag\///p' | tail -1 | tr -d '\r'
    fi
}

install_sensor_binary() {
    dest="$PREFIX/sensor/target/release/maltrail-sensor"      # the path the shipped systemd unit uses
    run mkdir -p "$(dirname "$dest")"

    if [ -n "$SENSOR_BIN" ]; then
        say "installing sensor binary from $SENSOR_BIN"
        run install -m 0755 "$SENSOR_BIN" "$dest"
    else
        triple=$(target_triple)
        if [ -z "$triple" ]; then
            warn "no prebuilt sensor for $(uname -m); build it with 'cd $PREFIX/sensor && cargo build --release'"
            return 1
        fi
        version=$REF
        case $version in
            master|main|*[!0-9.]*) version=$(latest_tag) ;;
        esac
        [ -n "$version" ] || { warn "could not work out the latest release; skipping the sensor binary"; return 1; }

        name="maltrail-sensor-$version-$triple"
        url="$RELEASES/download/$version/$name.tar.gz"
        tmp=$(mktemp -d)
        say "downloading sensor $version ($triple)"
        if ! fetch "$url" "$tmp/s.tar.gz"; then
            rm -rf "$tmp"
            warn "no sensor binary at $url; build it with 'cd $PREFIX/sensor && cargo build --release'"
            return 1
        fi
        # A detection engine downloaded over the network gets its checksum verified. A missing
        # checksum file is a warning, not a silent pass.
        if fetch "$url.sha256" "$tmp/s.sha256" 2>/dev/null && [ -s "$tmp/s.sha256" ]; then
            if have sha256sum; then
                expected=$(cut -d' ' -f1 < "$tmp/s.sha256")
                actual=$(sha256sum "$tmp/s.tar.gz" | cut -d' ' -f1)
                [ "$expected" = "$actual" ] || { rm -rf "$tmp"; die "sha256 mismatch for $name.tar.gz (expected $expected, got $actual)"; }
                info "sha256 verified"
            else
                warn "sha256sum not available; checksum not verified"
            fi
        else
            warn "no published checksum for $name.tar.gz; not verified"
        fi
        run tar -C "$tmp" -xzf "$tmp/s.tar.gz"
        run install -m 0755 "$tmp/$name/maltrail-sensor" "$dest"
        rm -rf "$tmp"
    fi

    run ln -sf "$dest" /usr/local/bin/maltrail-sensor
    link_libpcap_soname "$dest"
    verify_sensor "$dest" || true
    # Capture without root. Systemd grants these through AmbientCapabilities, but a manual run
    # needs them on the file, and this is also what `-T` checks.
    if have setcap; then
        run setcap cap_net_raw,cap_net_admin=eip "$dest" || warn "setcap failed; the sensor will need root to capture"
    else
        warn "setcap not found; the sensor will need root to capture"
    fi
    return 0
}

# A prebuilt binary carries the libpcap SONAME of the distribution it was BUILT on, and those
# differ: Debian and Ubuntu ship libpcap 1.x under the historical name libpcap.so.0.8, while
# Fedora, RHEL and SUSE use upstream's libpcap.so.1. Same library, same ABI - the loader just
# cannot find that name, and says so in a way that reads like the library is missing entirely:
#
#     error while loading shared libraries: libpcap.so.0.8: cannot open shared object file
#
# So link the name to the file that is actually installed. This is the kind of thing an installer
# exists to absorb; leaving it to the operator is how "curl | sh" earns its reputation.
#
# Binaries released after this was written link libpcap statically and never reach here; this is
# still what makes an older release, or a binary passed with --sensor-bin, work.
link_libpcap_soname() {
    have ldd || return 0
    [ "$DRY" = 1 ] && return 0
    missing=$(ldd "$1" 2>/dev/null | awk '/not found/ {print $1}')
    for lib in $missing; do
        case $lib in
            libpcap.so.*) ;;
            *) warn "$1 needs '$lib', which is not installed"; continue ;;
        esac
        linked=0
        # Architecture-matched directory FIRST. `/usr/lib/*` sorts alphabetically, so on a
        # multiarch Debian or Ubuntu that also has the i386 libpcap installed it reaches
        # i386-linux-gnu before x86_64-linux-gnu -- and a 32-bit library linked under the name a
        # 64-bit sensor wants leaves the sensor just as dead, with a symlink now suggesting
        # otherwise.
        for dir in "/usr/lib/$(uname -m)-linux-gnu" /usr/lib64 /usr/lib /lib64 /lib /usr/lib/*; do
            [ -d "$dir" ] || continue
            for candidate in "$dir"/libpcap.so.1* "$dir"/libpcap.so.0.8*; do
                [ -e "$candidate" ] || continue
                [ "$(basename "$candidate")" = "$lib" ] && continue    # that is the name we lack
                # Try it, then ASK THE LOADER. Picking by name cannot tell 32-bit from 64-bit,
                # and this is the one question that actually matters.
                run ln -sf "$candidate" "$dir/$lib"
                have ldconfig && run ldconfig >/dev/null 2>&1 || true
                if ldd "$1" 2>/dev/null | awk -v l="$lib" '$1 == l && /not found/ { bad = 1 } END { exit !bad }'; then
                    run rm -f "$dir/$lib"
                    have ldconfig && run ldconfig >/dev/null 2>&1 || true
                    continue
                fi
                say "linked $lib -> $candidate (this distribution names libpcap differently)"
                linked=1
                break
            done
            [ "$linked" = 1 ] && break
        done
        [ "$linked" = 1 ] ||
            warn "the sensor needs '$lib' and no usable libpcap was found; install your libpcap package"
    done
}

# Whatever produced the binary - a download, --sensor-bin, a local build - the only thing that
# settles whether it works here is running it. A sensor that cannot exec is the worst outcome of an
# install: everything looks done, and nothing is ever detected. So say so, in the operator's terms.
verify_sensor() {
    [ "$DRY" = 1 ] && return 0
    if out=$("$1" --version 2>&1); then
        info "sensor:  $out"
        return 0
    fi
    case $out in
        *GLIBC_*)
            warn "the prebuilt sensor needs a newer glibc than this system provides:"
            warn "  $(printf '%s' "$out" | head -1)"
            ;;
        *"not found"*|*"No such file"*|*"cannot execute"*)
            if is_musl; then
                warn "the musl sensor did not start on this musl system - that is a packaging bug, not your setup."
                warn "build it meanwhile: apk add cargo libpcap-dev && cd $PREFIX/sensor && cargo build --release"
                return 1
            fi
            warn "the sensor did not start: $(printf '%s' "$out" | head -1)"
            ;;
        *)  warn "the sensor did not start: $(printf '%s' "$out" | head -1)" ;;
    esac
    warn "build it from source here: cd $PREFIX/sensor && cargo build --release"
    warn "the SERVER is unaffected and is installed."
    return 1
}

# ---------------------------------------------------------------------------------------------
# user, directories, configuration
# ---------------------------------------------------------------------------------------------
ensure_user() {
    if id "$RUN_USER" >/dev/null 2>&1; then
        info "user $RUN_USER exists"
        return 0
    fi
    say "creating system user $RUN_USER"
    # The group is not optional: the units say Group=maltrail, and useradd only creates a matching
    # group on distributions that default to per-user groups.
    if have pw; then           # FreeBSD
        run pw groupadd "$RUN_USER" 2>/dev/null || true
        run pw useradd "$RUN_USER" -g "$RUN_USER" -d "$STATE_DIR" -s /usr/sbin/nologin -c "Maltrail"
    elif have groupadd; then
        run groupadd --system "$RUN_USER" 2>/dev/null || true
        run useradd --system --gid "$RUN_USER" --no-create-home --home-dir "$STATE_DIR" --shell /sbin/nologin "$RUN_USER"
    elif have addgroup; then   # busybox / Alpine
        run addgroup -S "$RUN_USER" 2>/dev/null || true
        run adduser -S -D -H -G "$RUN_USER" -h "$STATE_DIR" -s /sbin/nologin "$RUN_USER"
    elif have dscl; then       # macOS: no useradd at all, a daemon account is built by hand
        # Group and user get ids from their OWN free-id search: sharing one number worked until it
        # collided, and the first attempt swallowed the failure with `|| true`, so the group was
        # never created and the install died later on `install: unknown group maltrail` - a message
        # that says nothing about what actually went wrong.
        _gid=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | sort -n \
               | awk 'BEGIN{n=200} $1==n {n++} END{print n}')
        _uid=$(dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' | sort -n \
               | awk 'BEGIN{n=200} $1==n {n++} END{print n}')
        run dscl . -create "/Groups/$RUN_USER" PrimaryGroupID "$_gid"
        run dscl . -create "/Groups/$RUN_USER" Password '*' || true
        run dscl . -create "/Users/$RUN_USER"
        run dscl . -create "/Users/$RUN_USER" RealName "Maltrail"
        run dscl . -create "/Users/$RUN_USER" UniqueID "$_uid"
        run dscl . -create "/Users/$RUN_USER" PrimaryGroupID "$_gid"
        run dscl . -create "/Users/$RUN_USER" UserShell /usr/bin/false
        run dscl . -create "/Users/$RUN_USER" NFSHomeDirectory "$STATE_DIR"
        # Directory Services caches, and everything after this asks getgrnam() for the group.
        dscacheutil -flushcache 2>/dev/null || true
        if [ "$DRY" = 0 ] && ! dscl . -read "/Groups/$RUN_USER" >/dev/null 2>&1; then
            die "could not create the '$RUN_USER' group with dscl; create it manually"
        fi
    elif have pkg_add || have pkgin; then   # NetBSD / OpenBSD
        run groupadd "$RUN_USER" 2>/dev/null || true
        run useradd -g "$RUN_USER" -d "$STATE_DIR" -s /sbin/nologin "$RUN_USER"
    else
        die "no way to create a user on this system ($OS); create the '$RUN_USER' user manually"
    fi
}

# `su -s SHELL` is a GNU coreutils extension. BSD and macOS su read the shell from the account and
# reject -s outright - 'su: illegal option -- s' on macOS, 'su: unknown login: /bin/sh' on FreeBSD,
# both of which look like a broken user rather than a broken command line. The service account has
# nologin as its shell precisely so it cannot be used, so -m (keep environment, use the CALLER's
# shell) is the portable way to run one command as it.
as_user() {
    _who=$1; shift
    case $OS in
        Linux)  su -s /bin/sh "$_who" -c "$*" ;;
        *)      su -m "$_who" -c "$*" ;;
    esac
}

ensure_dirs() {
    say "creating $LOG_DIR and $STATE_DIR"
    for d in "$LOG_DIR" "$STATE_DIR"; do
        run install -d -o "$RUN_USER" -g "$RUN_USER" -m 0750 "$d"
    done
}

seed_trail_cache() {
    # Static trails are fetched from their own repository at runtime, so a first start with no
    # network has nothing to match on - and the release that introduces that split is exactly the
    # one people will install offline. Seed the cache from the snapshot shipped with the release,
    # so a deployment detects from the moment it starts rather than from its first successful
    # update.
    #
    # Never fatal: a deployment with connectivity gets the current set on first update anyway, and
    # failing an install over an optional accelerator would be the wrong trade.
    cache="$STATE_DIR/trails.csv.static"

    if [ -s "$cache" ]; then
        info "static trail cache already present ($cache)"
        return 0
    fi
    [ "$DRY" = 1 ] && { say "would seed the static trail cache"; return 0; }

    version=$REF
    case $version in
        master|main|*[!0-9.]*) version=$(latest_tag) ;;
    esac
    [ -n "$version" ] || { warn "could not work out the latest release; skipping the trail bootstrap"; return 0; }

    url="$RELEASES/download/$version/trails-bootstrap.csv.gz"
    tmp=$(mktemp -d)
    say "seeding the static trail cache from $version"
    if ! fetch "$url" "$tmp/t.csv.gz"; then
        rm -rf "$tmp"
        warn "no trail bootstrap at $url; the first update will fetch the set instead"
        return 0
    fi

    if ! gzip -dc "$tmp/t.csv.gz" > "$tmp/t.csv" 2>/dev/null; then
        rm -rf "$tmp"
        warn "the trail bootstrap could not be decompressed; the first update will fetch the set instead"
        return 0
    fi

    # Detection content downloaded over the network gets its checksum verified, exactly like the
    # sensor binary. The digest is published for the UNCOMPRESSED set.
    # The digest is published for the trail SET, so it is named after the uncompressed file -
    # trails-bootstrap.csv.gz -> trails-bootstrap.csv.sha256, the same convention the runtime
    # fetch uses.
    sha_url="${url%.gz}.sha256"
    if fetch "$sha_url" "$tmp/t.sha256" 2>/dev/null && [ -s "$tmp/t.sha256" ] && have sha256sum; then
        expected=$(cut -d' ' -f1 < "$tmp/t.sha256")
        actual=$(sha256sum "$tmp/t.csv" | cut -d' ' -f1)
        if [ "$expected" != "$actual" ]; then
            rm -rf "$tmp"
            warn "trail bootstrap checksum mismatch; discarding it (the first update will fetch the set)"
            return 0
        fi
        info "sha256 verified"
        run install -o "$RUN_USER" -g "$RUN_USER" -m 0640 "$tmp/t.sha256" "$cache.sha256"
    else
        warn "no published checksum for the trail bootstrap; not verified"
    fi

    run install -o "$RUN_USER" -g "$RUN_USER" -m 0640 "$tmp/t.csv" "$cache"
    info "seeded $(wc -l < "$cache") trails into $cache"
    rm -rf "$tmp"
}

install_conf() {
    if [ -f "$CONF" ]; then
        say "keeping the existing $CONF"
        return 0
    fi
    say "writing $CONF"
    run install -m 0640 -o root -g "$RUN_USER" "$PREFIX/maltrail.conf" "$CONF"
    [ "$DRY" = 1 ] && return 0
    # Appended, not edited: a later assignment wins, so the operator's own edits above stay
    # readable and this block is obviously the installer's.
    cat >> "$CONF" <<EOF

# --- written by install.sh; edit freely, it is never rewritten -------------------------------
# Paths, so both roles agree regardless of \$HOME (the units set it, a manual run may not).
LOG_DIR $LOG_DIR
TRAILS_FILE $STATE_DIR/trails.csv
EOF
    run chown root:"$RUN_USER" "$CONF"
    run chmod 0640 "$CONF"
}

# ---------------------------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------------------------
have_systemd() { [ -d /run/systemd/system ] && have systemctl; }

# Which init this machine actually uses. systemd is not a synonym for "has services": FreeBSD and
# NetBSD use rc.d, macOS uses launchd, and until this existed install.sh silently skipped service
# installation on all three while reporting success.
init_system() {
    if have_systemd; then printf 'systemd'; return; fi
    case $OS in
        FreeBSD|NetBSD|OpenBSD) [ -d /etc/rc.d ] && { printf 'rcd'; return; } ;;
        Darwin)                 [ -d /Library/LaunchDaemons ] && { printf 'launchd'; return; } ;;
    esac
    printf 'none'
}

# rc.d and launchd take the same three substitutions the systemd units do, from the same templates
# in packaging/. Nothing is maintained twice, on any platform.
install_rcd() {
    say "installing rc.d scripts"
    dir=${UNIT_DIR_SET:+$UNIT_DIR}; dir=${dir:-/usr/local/etc/rc.d}
    [ -d "$dir" ] || run mkdir -p "$dir"
    for role in $1; do
        src="$PREFIX/packaging/rc.d/maltrail_$role"
        [ -f "$src" ] || { warn "$src not found; skipping"; continue; }
        if [ "$DRY" = 1 ]; then printf '    + sed <%s >%s/maltrail_%s\n' "$src" "$dir" "$role"; continue; fi
        sed -e "s#@PREFIX@#$PREFIX#g" -e "s#@PYTHON@#$PYTHON#g" -e "s#@USER@#$RUN_USER#g" \
            "$src" > "$dir/maltrail_$role"
        chmod 0755 "$dir/maltrail_$role"
        info "$dir/maltrail_$role"
    done
    say "enable with: sysrc maltrail_${1%% *}_enable=YES && service maltrail_${1%% *} start"
}

install_launchd() {
    say "installing launchd jobs"
    dir=${UNIT_DIR_SET:+$UNIT_DIR}; dir=${dir:-/Library/LaunchDaemons}
    [ -d "$dir" ] || run mkdir -p "$dir"
    for role in $1; do
        src="$PREFIX/packaging/launchd/io.maltrail.$role.plist"
        [ -f "$src" ] || { warn "$src not found; skipping"; continue; }
        if [ "$DRY" = 1 ]; then printf '    + sed <%s >%s/io.maltrail.%s.plist\n' "$src" "$dir" "$role"; continue; fi
        sed -e "s#@PREFIX@#$PREFIX#g" -e "s#@PYTHON@#$PYTHON#g" -e "s#@USER@#$RUN_USER#g" \
            "$src" > "$dir/io.maltrail.$role.plist"
        chmod 0644 "$dir/io.maltrail.$role.plist"
        info "$dir/io.maltrail.$role.plist"
    done
    say "load with: sudo launchctl load -w $dir/io.maltrail.${1%% *}.plist"
}

install_units() {
    say "installing systemd units"
    for role in $1; do
        src="$PREFIX/packaging/systemd/maltrail-$role.service"
        [ -f "$src" ] || { warn "$src not found; skipping"; continue; }
        # One source of truth: the repository's unit, with the paths this installation actually
        # uses substituted in. Nothing is maintained twice.
        if [ "$DRY" = 1 ]; then
            printf '    + sed <%s >%s/maltrail-%s.service\n' "$src" "$UNIT_DIR" "$role"
            continue
        fi
        sed -e "s#^WorkingDirectory=.*#WorkingDirectory=$PREFIX#" \
            -e "s#^ExecStart=/usr/bin/python3 server.py.*#ExecStart=$PYTHON server.py -c $CONF#" \
            -e "s#^ExecStart=/opt/maltrail/sensor/target/release/maltrail-sensor.*#ExecStart=$PREFIX/sensor/target/release/maltrail-sensor -c $CONF#" \
            -e "s#^ExecStartPre=/opt/maltrail/sensor/target/release/maltrail-sensor.*#ExecStartPre=$PREFIX/sensor/target/release/maltrail-sensor -c $CONF -T#" \
            "$src" > "$UNIT_DIR/maltrail-$role.service"
        chmod 0644 "$UNIT_DIR/maltrail-$role.service"
        # A unit whose ExecStart does not exist fails at start with a message nobody reads.
        exec_path=$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$UNIT_DIR/maltrail-$role.service" | head -1)
        [ -x "$exec_path" ] || warn "maltrail-$role.service points at '$exec_path', which is not executable"
        info "$UNIT_DIR/maltrail-$role.service"
    done
}

start_units() {
    run systemctl daemon-reload
    for role in $1; do
        [ -f "$UNIT_DIR/maltrail-$role.service" ] || continue
        say "enabling maltrail-$role"
        run systemctl enable --now "maltrail-$role.service" || warn "maltrail-$role did not start; see 'journalctl -u maltrail-$role'"
    done
}

# ---------------------------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------------------------
do_uninstall() {
    say "removing Maltrail"
    if have_systemd; then
        for role in sensor server; do
            [ -f "$UNIT_DIR/maltrail-$role.service" ] || continue
            run systemctl disable --now "maltrail-$role.service" 2>/dev/null || true
            run rm -f "$UNIT_DIR/maltrail-$role.service"
        done
        run systemctl daemon-reload 2>/dev/null || true
    else
        run rm -f "$UNIT_DIR/maltrail-server.service" "$UNIT_DIR/maltrail-sensor.service"
    fi
    run rm -f /usr/local/bin/maltrail-sensor
    # Never delete a tree this script did not create. A checkout it merely adopted, or any
    # directory an operator pointed it at, is not ours to remove - that would take their work with
    # it. The record of what WAS created lives outside the tree, so it cannot dirty their git.
    if [ -f "$STATE_DIR/installed-prefix" ] && [ "$(cat "$STATE_DIR/installed-prefix")" = "$PREFIX" ]; then
        run rm -rf "$PREFIX"
        run rm -f "$STATE_DIR/installed-prefix"
    elif [ -d "$PREFIX" ]; then
        warn "$PREFIX was not created by this installer, so it was left alone"
    fi
    # Evidence and configuration are deliberately kept: this is an IDS, and an uninstall that
    # deletes the event log destroys the only record of what it saw.
    say "done"
    info "kept: $CONF, $LOG_DIR (events), $STATE_DIR (trails), user $RUN_USER"
    info "remove them yourself if you mean to: rm -rf $LOG_DIR $STATE_DIR $CONF"
}

# ---------------------------------------------------------------------------------------------
summary() {
    roles=$1
    printf '\n'
    say "Maltrail installed"
    info "tree     $PREFIX  ($(cd "$PREFIX" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo "$REF")$([ "$IN_PLACE" = 1 ] && printf ', your checkout, left as it is'))"

    info "config   $CONF"
    info "events   $LOG_DIR"
    info "trails   $STATE_DIR/trails.csv"
    case $roles in *server*)
        port=$(sed -n 's/^HTTP_PORT[[:space:]]\{1,\}\([0-9]\{1,\}\).*/\1/p' "$CONF" 2>/dev/null | tail -1)
        info "ui       http://127.0.0.1:${port:-8338}  (default login: admin / changeme!)" ;;
    esac
    if have_systemd && [ "$SERVICE" = 1 ]; then
        info "status   systemctl status maltrail-server maltrail-sensor"
    elif have_systemd; then
        info "start    systemctl enable --now maltrail-server maltrail-sensor"
    else
        info "no systemd here, so nothing was started. Run it by hand:"
        case $roles in *server*) info "  (cd $PREFIX && sudo -u $RUN_USER $PYTHON server.py -c $CONF)" ;; esac
        case $roles in *sensor*) info "  sudo -u $RUN_USER $PREFIX/sensor/target/release/maltrail-sensor -c $CONF" ;; esac
    fi
    info "The first trail build takes a few minutes; until it finishes nothing is detected."
    [ "$warned" -gt 0 ] && info "$warned warning(s) above - worth reading."
    printf '\n'
}

main() {
    parse_args "$@"
    need_root
    if [ "$UNINSTALL" = 1 ]; then
        # What to remove is what was INSTALLED, which is recorded outside the tree - not whatever
        # checkout this script happens to be sitting in. Running `sh install.sh --uninstall` from a
        # clone otherwise aimed the uninstall at the clone.
        if [ "$PREFIX_SET" = 0 ] && [ -s "$STATE_DIR/installed-prefix" ]; then
            PREFIX=$(cat "$STATE_DIR/installed-prefix")
            info "installed at $PREFIX (recorded in $STATE_DIR/installed-prefix)"
        fi
        do_uninstall
        return 0
    fi
    detect_in_place

    case $ROLE in
        both)   roles="server sensor" ;;
        server) roles="server" ;;
        sensor) roles="sensor" ;;
    esac

    detect_pkg
    ensure_deps
    detect_python
    clone_or_update
    ensure_user
    ensure_dirs
    install_conf
    [ "$IN_PLACE" = 1 ] || [ "$DRY" = 1 ] || printf '%s\n' "$PREFIX" > "$STATE_DIR/installed-prefix"
    case $roles in *sensor*) install_sensor_binary || true ;; esac
    seed_trail_cache || true
    if [ "$IN_PLACE" = 1 ]; then
        # Taking ownership of a developer's checkout would stop them editing their own files. The
        # processes only need to READ it, so check that instead of changing it.
        if [ "$DRY" = 0 ] && ! as_user "$RUN_USER" "test -r '$PREFIX/server.py'" 2>/dev/null; then
            warn "$RUN_USER cannot read $PREFIX (a home directory is often 0700)."
            warn "either loosen the path, or install a separate copy: sh install.sh --prefix /opt/maltrail"
        fi
    else
        run chown -R "$RUN_USER":"$RUN_USER" "$PREFIX" 2>/dev/null || true
    fi

    # Whichever init this machine has. It used to be "systemd or nothing", which meant FreeBSD and
    # macOS finished with a cheerful summary and no service files anywhere.
    case $(init_system) in
        systemd)
            run mkdir -p "$UNIT_DIR"
            install_units "$roles"
            if [ "$SERVICE" = 1 ]; then start_units "$roles"; fi
            ;;
        rcd)     install_rcd "$roles" ;;
        launchd) install_launchd "$roles" ;;
        none)
            # An explicit --unit-dir still renders systemd units: that is how the container tests
            # check them, and how someone stages units for a host that is not this one.
            if [ "$UNIT_DIR_SET" = 1 ]; then
                run mkdir -p "$UNIT_DIR"
                install_units "$roles"
                [ "$SERVICE" = 1 ] && warn "no init system detected here, so nothing was enabled; the units are in $UNIT_DIR"
            else
                warn "no init system detected ($OS); service files not installed (run it under your own supervisor)"
            fi
            ;;
    esac
    summary "$roles"
}

# Called on the last line so a truncated `curl | sh` cannot execute half an installer.
# MALTRAIL_INSTALL_SOURCE_ONLY lets tests/install/soname.sh load one function and exercise it
# against a real distribution, rather than re-implementing it and testing the copy.
[ "${MALTRAIL_INSTALL_SOURCE_ONLY:-}" = 1 ] || main "$@"
