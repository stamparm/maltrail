#!/usr/bin/env python3
# coding: utf-8
"""Trail update entry point for the Rust sensor.

Builds trails.csv via a hybrid pipeline instead of calling core.update.update_trails()
directly: the static aggregate alone is ~1.6M entries, and building one Python dict with
all of them (as core/update.py does) needs on the order of 200-350MB - more than this
host's 221MB of RAM. Observed consequence before this change: the build either thrashed
the whole box into swap, or (with swap denied) got OOM-killed every ~10s in an endless
restart loop, never finishing.

The fix keeps everything else about the pipeline - feeds, custom trails, local static
files, whitelist/bogon/CDN filtering, merge precedence, confidence scoring - semantically
identical to core/update.py, but splits the work:

  - feeds + custom + local-static trails: small (thousands of entries, not millions).
    Fetched and merged here in Python, reusing core/update.py's own fetch()/_merge-style
    logic (duplicated below rather than imported, since _merge is a private closure) -
    cheap enough that Python's per-object overhead doesn't matter.
  - the static aggregate: fetched/cached/sha256-verified here using the same logic as
    core.update.fetch_static_trails() (duplicated, not imported, specifically to stop
    short of its final step - building the 1.6M-entry dict - and instead leave the
    decompressed CSV on disk as plain text for the next stage to stream).
  - /usr/local/bin/trails-builder (Rust) then merges the two: it holds only the small
    feeds/custom/local-static dict in memory and streams the static file row-by-row,
    applying the identical merge-precedence and cleanup/filter rules (ported from
    core/update.py - see trails-builder's source for the line-by-line mapping), writing
    trails.csv directly. Peak memory there is O(small set), not O(1.6M).

    python3 sensor/tools/update_trails.py -c maltrail.conf [--offline]

Exit status: 0 on success, 1 on failure (the sensor keeps running with whatever trails it has).
"""

import argparse
import csv
import glob
import gzip
import hashlib
import inspect
import io
import os
import re
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True

TRAILS_BUILDER_BIN = "/usr/local/bin/trails-builder"
SENSOR_BIN = "/usr/local/bin/maltrail-sensor"

class _CountingWriter:
    """Thin csv.writer wrapper that counts rows - so the caller can log a row count without
    needing a second pass or holding anything extra in memory."""

    def __init__(self, inner):
        self._inner = inner
        self.count = 0

    def writerow(self, row):
        self._inner.writerow(row)
        self.count += 1


def write_raw_sources(writer, config, offline):
    """feeds + custom + local-static + remote-custom, written straight to `writer` as raw
    (unmerged) rows - one source at a time, in the SAME order the original precedence rule
    depended on (feeds in file order, then custom, then local-static, then remote-custom).

    This used to build one combined Python dict via _merge() first (see git history). That
    was fine when "small" genuinely meant thousands of entries, but it doesn't: a single feed
    (blocklist.de's aggregate, abuseipdb's) can run 25-45k entries on its own, and summed
    across 40 feeds the combined dict was observed at ~111MB RSS in practice - on a 221MB
    host, running alongside the live sensor (~75MB) plus darkstat/nginx/the server, that's
    another route back to the OOM this whole pipeline exists to avoid.

    Writing raw rows instead bounds Python's peak to roughly ONE feed's own dict at a time
    (tens of MB at most), and defers cross-source precedence entirely to trails-builder's
    streaming merge - the same `merge_one()` logic it already applies for the static
    aggregate, just applied here too instead of a simple CSV dump. Order is preserved by
    writing rows in fetch order and letting Rust resolve duplicates sequentially, which
    reproduces the original ordering-dependent precedence exactly.
    """
    from core import custom_trails
    from core import assemble
    from core.settings import ROOT_DIR, LOCAL_STATIC_TRAIL_FILES
    from core.common import retrieve_content
    from core.addr import addr_to_int, int_to_addr, make_mask

    def write_all(results):
        for key, (info, reference) in results.items():
            writer.writerow((key, info, reference))

    if not offline and config.USE_FEED_UPDATES:
        feeds_dir = os.path.abspath(os.path.join(ROOT_DIR, "feeds"))
        if feeds_dir not in sys.path:
            sys.path.append(feeds_dir)
        filenames = sorted(glob.glob(os.path.join(feeds_dir, "*.py")))
        filenames = [_ for _ in filenames if "__init__.py" not in _]
        if config.DISABLED_FEEDS:
            filenames = [f for f in filenames if os.path.splitext(os.path.split(f)[-1])[0] not in re.split(r"[^\w]+", config.DISABLED_FEEDS)]

        for filename in filenames:
            try:
                module = __import__(os.path.basename(filename).split(".py")[0])
            except (ImportError, SyntaxError) as ex:
                print("[x] something went wrong during import of feed file '%s' ('%s')" % (filename, ex))
                continue
            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "fetch":
                    url = module.__url__
                    print(" [o] '%s'" % url)
                    if config.DISABLED_TRAILS_INFO_REGEX and re.search(config.DISABLED_TRAILS_INFO_REGEX, getattr(module, "__info__", "")):
                        continue
                    try:
                        results = function()
                        write_all(results)
                        if not results:
                            print("[!] no indicators from '%s' (empty response, or the feed's format changed)" % url)
                    except Exception as ex:
                        print("[x] something went wrong during processing of feed file '%s' ('%s')" % (filename, ex))
            try:
                sys.modules.pop(module.__name__)
                del module
            except Exception:
                pass

    print(" [o] '(custom)'")
    write_all(custom_trails.fetch())

    for _ in LOCAL_STATIC_TRAIL_FILES:
        path = os.path.abspath(os.path.join(ROOT_DIR, "data", _))
        if os.path.isfile(path):
            write_all(assemble.merge_file(path, {}))
        else:
            print("[!] '%s' is missing - those trails will not be loaded" % path)

    if not offline and config.CUSTOM_TRAILS_URL:
        print(" [o] '(remote custom)'")
        for url in re.split(r"[;,]", config.CUSTOM_TRAILS_URL):
            url = url.strip()
            if not url:
                continue
            url = ("http://%s" % url) if "//" not in url else url
            content = retrieve_content(url)
            if not content:
                print("[x] unable to retrieve data (or empty response) from '%s'" % url)
                continue
            __info__ = "blacklisted"
            __reference__ = "(remote custom)"
            # No "already covered by custom/static" skip here (the original dict-based
            # version had one, as an optimization) - trails-builder's merge_one() reaches the
            # identical outcome downstream regardless, since it's the same precedence rule.
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                line = re.sub(r"\s*#.*", "", line)
                if '://' in line:
                    line = re.search(r"://(.*)", line).group(1)
                line = line.rstrip('/')
                if '/' in line:
                    writer.writerow((line, __info__, __reference__))
                    line = line.split('/')[0]
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                    writer.writerow((line, __info__, __reference__))
                else:
                    writer.writerow((line.strip('.'), __info__, __reference__))
            for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", content):
                prefix, mask = match.groups()
                mask = int(mask)
                if mask > 32:
                    continue
                start_int = addr_to_int(prefix) & make_mask(mask)
                end_int = start_int | ((1 << 32 - mask) - 1)
                if 0 <= end_int - start_int <= 1024:
                    address = start_int
                    while start_int <= address <= end_int:
                        writer.writerow((int_to_addr(address), __info__, __reference__))
                        address += 1


def fetch_and_cache_static(config, offline):
    """Network/cache/sha256-verify logic duplicated from core.update.fetch_static_trails(),
    stopping short of its final step: instead of parsing the result into a dict, this writes
    the decompressed CSV straight to a cache file and returns its path (or None)."""
    from core.common import retrieve_content
    from core.settings import UNICODE_ENCODING

    cache = "%s.static" % config.TRAILS_FILE
    stamp = "%s.sha256" % cache

    def _cached_sha():
        try:
            with open(stamp, "r") as f:
                return f.read().strip()
        except (OSError, IOError):
            return None

    if not config.STATIC_TRAILS_URL:
        return cache if os.path.isfile(cache) else None

    if offline:
        return cache if os.path.isfile(cache) else None

    url = config.STATIC_TRAILS_URL
    sha_url = "%s.sha256" % (url[:-len(".gz")] if url.endswith(".gz") else url)
    published = (retrieve_content(sha_url) or "").strip().split(' ')[0].strip()
    published = published if re.match(r"\A[0-9a-f]{64}\Z", published) else None

    if published and published == _cached_sha() and os.path.isfile(cache):
        print(" [o] '%s' (unchanged, %s)" % (url, published[:12]))
        return cache

    print(" [o] '%s'" % url)
    raw = retrieve_content(url, binary=True)
    if not raw:
        print("[x] unable to retrieve the static trails from '%s'" % url)
        return cache if os.path.isfile(cache) else None

    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.GzipFile("", "rb", 9, io.BytesIO(raw)).read()
        except Exception as ex:
            print("[x] the static trails could not be decompressed ('%s')" % ex)
            return cache if os.path.isfile(cache) else None

    digest = hashlib.sha256(raw).hexdigest() if raw else None
    if published and digest and digest != published:
        print("[x] the static trails do not match their published sha256 (%s != %s) - keeping the cache" % (digest[:12], published[:12]))
        return cache if os.path.isfile(cache) else None

    if not raw or raw.count(b',') <= 1:
        print("[x] unable to retrieve the static trails from '%s'" % url)
        return cache if os.path.isfile(cache) else None

    tmp = "%s.new" % cache
    with open(tmp, "wb") as f:
        f.write(raw)
    os.replace(tmp, cache)
    if digest:
        with open("%s.new" % stamp, "w") as f:
            f.write(digest)
        os.replace("%s.new" % stamp, stamp)

    return cache


def update_trails_hybrid(config, offline, config_file):
    from core.settings import ROOT_DIR, USERS_DIR, read_whitelist

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0o755)
    except Exception as ex:
        sys.exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    if not (config.offline_force or not os.path.isfile(config.TRAILS_FILE) or (time.time() - os.stat(config.TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD or os.stat(config.TRAILS_FILE).st_size == 0):
        return True  # fresh enough - don't touch anything, don't spend any memory

    print("[i] updating trails (hybrid builder)...")
    read_whitelist()

    workdir = USERS_DIR
    small_csv = os.path.join(workdir, "trails_small.csv.tmp")
    row_count = 0
    with open(small_csv, "w", newline="") as f:
        writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        counted_writer = _CountingWriter(writer)
        write_raw_sources(counted_writer, config, offline)
        row_count = counted_writer.count
    print("[i] feeds+custom+local-static: %d raw row(s) written (unmerged - trails-builder resolves precedence)" % row_count)

    static_cache = fetch_and_cache_static(config, offline)

    cmd = [
        TRAILS_BUILDER_BIN,
        "--small", small_csv,
        "--data-dir", os.path.abspath(os.path.join(ROOT_DIR, "data")),
        "--output", config.TRAILS_FILE,
        "--ip-minimum-feeds", str(config.get("IP_MINIMUM_FEEDS", 3)),
    ]
    if static_cache:
        cmd += ["--static", static_cache]
    if config.USER_WHITELIST:
        cmd += ["--user-whitelist", config.USER_WHITELIST]

    print("[i] running trails-builder...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        print(line)
    for line in result.stderr.splitlines():
        print(line)

    try:
        os.remove(small_csv)
    except OSError:
        pass

    if result.returncode != 0:
        print("[x] trails-builder failed (exit %d)" % result.returncode)
        return False

    print("[i] trails stored to '%s'" % config.TRAILS_FILE)

    # Build the mmap trail-store cache HERE, in this short-lived one-shot process, rather than
    # letting the long-running sensor build it on its own next reload. Same reasoning as
    # trails-builder itself: the expensive, memory-heavy step belongs in a process that exits
    # right after, not in the one that has to keep running alongside darkstat/nginx/the server
    # for the rest of the day. If this fails for any reason, the sensor's own load_with() still
    # falls back to building the cache itself - slower and memory-heavier, but not wrong.
    print("[i] building mmap trail-store cache...")
    cache_result = subprocess.run(
        [SENSOR_BIN, "--build-trails-bin", "-c", config_file],
        capture_output=True, text=True,
    )
    for line in cache_result.stdout.splitlines():
        print(line)
    for line in cache_result.stderr.splitlines():
        print(line)
    if cache_result.returncode != 0:
        print("[x] trail store cache build failed (exit %d) - the sensor will build it on its own next reload" % cache_result.returncode)

    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-c", dest="config_file", required=True, help="Maltrail configuration file")
    parser.add_argument("--offline", action="store_true", help="do not use the network (static/custom only)")
    parser.add_argument("--force", action="store_true", help="rebuild even if trails.csv looks fresh")
    options = parser.parse_args()

    from core.settings import config, read_config
    read_config(options.config_file)
    config.offline = options.offline
    config.offline_force = options.force

    from core.common import check_connection
    from core.settings import CHECK_CONNECTION_MAX_RETRIES
    from core.update import update_ipcat

    offline = options.offline
    if not offline:
        retries = 0
        while retries < CHECK_CONNECTION_MAX_RETRIES and not check_connection():
            sys.stdout.write("[!] can't update because of lack of Internet connection (waiting..."
                             if not retries else '.')
            sys.stdout.flush()
            time.sleep(10)
            retries += 1
        if retries:
            print(")")
        if retries == CHECK_CONNECTION_MAX_RETRIES:
            print("[x] going to continue without online update")
            offline = True

    try:
        ok = update_trails_hybrid(config, offline, options.config_file)
        if ok and not offline:
            update_ipcat()
    except KeyboardInterrupt:
        print("[x] trail update interrupted")
        return 1
    except Exception as ex:
        print("[!] trail update failed (%s)" % ex)
        return 1

    if not os.path.isfile(config.TRAILS_FILE):
        print("[!] trail update produced no '%s'" % config.TRAILS_FILE)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
