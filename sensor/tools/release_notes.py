#!/usr/bin/env python3
"""Print the GitHub release notes for a tag, from its CHANGELOG entry.

    python3 sensor/tools/release_notes.py 3.5          # markdown on stdout
    python3 sensor/tools/release_notes.py 3.5 --check  # exit 1 if 3.5 has no entry

GitHub's generated notes list merged pull requests, and almost nothing here lands through one -
so 3.5, the release that made the sensor fit a 256 MB Raspberry Pi and shipped a 32-bit ARM
build, went out titled "Regenerate settings_gen.rs" eleven times over. The CHANGELOG is where
the release is actually described, so the notes come from there, and the release gate refuses a
tag that has no entry before anything is built.
"""

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
CHANGELOG = os.path.join(ROOT, "CHANGELOG")
KINDS = (("[+]", "Added"), ("[=]", "Changed"), ("[!]", "Fixed"), ("[-]", "Removed"))


def entry(version):
    """The raw text of `version`'s entry, or None. A pre-release suffix ('3.5-rc1') is dropped."""

    version = re.sub(r"^v", "", version.split("-")[0])
    with open(CHANGELOG) as f:
        text = f.read()
    match = re.search(r"^- Version \S+ -> %s \([^)]*\)\n(.*?)(?=^- Version |\Z)" % re.escape(version), text, re.M | re.S)
    return match.group(1).strip("\n") if match else None


def render(raw, version, previous):
    """CHANGELOG items as markdown, grouped by kind. Continuation lines are re-joined."""

    items = []
    for block in re.split(r"\n\s*\n", raw):
        block = block.strip("\n")
        if not block:
            continue
        lines = block.split("\n")
        if lines[0][:3] in dict(KINDS):
            kind, first = lines[0][:3], lines[0][3:].strip()
            body = [first]
            for line in lines[1:]:
                stripped = line.strip()
                if stripped.startswith("- "):
                    body.append("\n  " + stripped)
                elif body[-1].startswith("\n  "):
                    body[-1] += " " + stripped
                else:
                    body[-1] += " " + stripped
            items.append((kind, "".join(body)))
        elif items:
            items[-1] = (items[-1][0], items[-1][1] + " " + " ".join(_.strip() for _ in lines))

    out = []
    for kind, title in KINDS:
        group = [text for k, text in items if k == kind]
        if group:
            out.append("## %s\n" % title)
            out.extend("- %s" % text for text in group)
            out.append("")
    if previous:
        out.append("**Full Changelog**: https://github.com/stamparm/maltrail/compare/%s...%s" % (previous, version))
    return "\n".join(out).rstrip() + "\n"


def main():
    args = [_ for _ in sys.argv[1:] if not _.startswith("--")]
    if not args:
        sys.exit("usage: %s TAG [--check]" % sys.argv[0])
    tag = args[0]
    raw = entry(tag)
    if raw is None:
        print("[x] CHANGELOG has no '- Version ... -> %s (...)' entry" % tag.split("-")[0], file=sys.stderr)
        sys.exit(1)
    if "--check" in sys.argv:
        print("[i] CHANGELOG has an entry for %s" % tag)
        return
    with open(CHANGELOG) as f:
        match = re.search(r"^- Version (\S+) -> %s " % re.escape(re.sub(r"^v", "", tag.split("-")[0])), f.read(), re.M)
    sys.stdout.write(render(raw, tag, match.group(1) if match else None))


if __name__ == "__main__":
    main()
