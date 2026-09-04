# coding: utf-8
"""Record what Maltrail can do on Windows.

`assert.sh` cannot run here, and not for a shell reason: it drives `install.sh`, which creates a
system user with `pw`/`useradd`/`dscl`, writes a systemd/rc.d/launchd service, and uninstalls by
removing a prefix. None of those exist on Windows, so most of what it asserts is not a thing that
can fail here - it is a thing that does not apply.

What DOES apply is the part an operator actually cares about: the server serves and the sensor
runs. This probe checks exactly that, and prints the same `A`/`F`/`P` lines `assert.sh` prints, so
`record.py` builds a Windows row through the one recorder rather than a second code path.

Deliberately platform-neutral Python: it runs on Linux too, which is the only way to develop it
without a push-and-wait loop against a Windows runner.

    python3 tests/install/windows.py [--sensor-bin PATH]
"""

from __future__ import print_function

import io
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def say(line):
    # Unbuffered: record.py reads this from a file the process is still writing on failure paths.
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def facts():
    say("P os %s" % _os_name())
    say("P host_kernel %s" % platform.release())
    say("P machine %s" % (platform.machine() or "unknown"))
    say("P python %s" % platform.python_version())
    # No libc on Windows in any sense the other rows mean it; the C runtime is the MSVC one the
    # binary was linked against, which is a property of the build, not the platform.
    say("P libc %s" % ("msvcrt" if os.name == "nt" else "n/a"))


def _os_name():
    if os.name != "nt":
        return "%s %s" % (platform.system(), platform.release())
    # platform.win32_ver() -> ('10', '10.0.20348', 'SP0', 'Multiprocessor Free'); the build number
    # is what distinguishes Server 2022 from Windows 11, and both call themselves '10'.
    release, version = platform.win32_ver()[:2]
    edition = ""
    try:
        edition = platform.win32_edition() or ""
    except Exception:
        pass
    name = "Windows %s" % release
    if edition:
        name += " %s" % edition
    return "%s (%s)" % (name, version) if version else name


def free_port():
    # Never a fixed port: a stale process holding one turns a failed check into a hang.
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def write_config(work, port, trails):
    """A real maltrail.conf with only the paths moved, so this tests the shipped configuration."""
    with io.open(os.path.join(ROOT, "maltrail.conf"), encoding="utf-8") as handle:
        text = handle.read()
    lines = []
    for line in text.splitlines():
        key = line.split(" ")[0]
        if key == "HTTP_ADDRESS":
            line = "HTTP_ADDRESS 127.0.0.1"
        elif key == "HTTP_PORT":
            line = "HTTP_PORT %d" % port
        elif key == "LOG_DIR":
            line = "LOG_DIR %s" % os.path.join(work, "logs")
        lines.append(line)
    # Updates off and a two-row trail set: this is checking that the server and sensor RUN here,
    # not that the updater can reach the internet from a CI runner.
    lines += ["", "DISABLE_TRAIL_UPDATES true", "TRAILS_FILE %s" % trails]
    path = os.path.join(work, "maltrail.conf")
    with io.open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


def ping(port, timeout=60):
    try:
        from urllib.request import urlopen
    except ImportError:
        from urllib2 import urlopen
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        try:
            if urlopen("http://127.0.0.1:%d/ping" % port, timeout=2).read().strip() == b"pong":
                return True
        except Exception:
            continue
    return False


def check_server(work, conf, port):
    log = os.path.join(work, "server.log")
    with io.open(log, "w", encoding="utf-8") as handle:
        proc = subprocess.Popen([sys.executable, "server.py", "-c", conf],
                                cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT)
    try:
        if ping(port):
            say("A server-ping")
        else:
            say("F the server never answered /ping on Windows")
            with io.open(log, encoding="utf-8", errors="replace") as handle:
                for line in handle.read().splitlines()[-15:]:
                    say("  %s" % line)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()


def check_sensor(work, conf, sensor):
    if not sensor or not os.path.isfile(sensor):
        say("F no sensor binary to test (pass --sensor-bin)")
        return
    try:
        out = subprocess.check_output([sensor, "--version"], stderr=subprocess.STDOUT)
    except Exception as ex:
        say("F the sensor binary does not start: %s" % ex)
        return
    say("A sensor-runs")
    say("P sensor_version %s" % out.decode("utf-8", "replace").splitlines()[0].strip())

    log = os.path.join(work, "selftest.log")
    with io.open(log, "w", encoding="utf-8") as handle:
        rc = subprocess.call([sensor, "-c", conf, "-T"], stdout=handle, stderr=subprocess.STDOUT)
    if rc == 0:
        say("A sensor-selftest")
    else:
        # -T without capture privilege reports that and exits non-zero, which is the sensor being
        # correct. Print the log so the row's finding says which of the two happened.
        say("F sensor -T exited %d" % rc)
        with io.open(log, encoding="utf-8", errors="replace") as handle:
            for line in handle.read().splitlines()[-10:]:
                say("  %s" % line)


def main():
    sensor = None
    args = sys.argv[1:]
    while args:
        arg = args.pop(0)
        if arg == "--sensor-bin":
            sensor = args.pop(0)
        else:
            say("F unknown argument %s" % arg)
            return 2

    facts()
    work = tempfile.mkdtemp(prefix="maltrail-win-")
    try:
        os.makedirs(os.path.join(work, "logs"))
        trails = os.path.join(work, "trails.csv")
        with io.open(trails, "w", encoding="utf-8") as handle:
            handle.write(u'evil.example,"malware (test)","(static)"\n'
                         u'1.2.3.4,"malware (test)","(static)"\n')
        port = free_port()
        conf = write_config(work, port, trails)
        check_server(work, conf, port)
        check_sensor(work, conf, sensor)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
