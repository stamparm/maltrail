---
title: Maltrail Security Vulnerability Reports
category: contributing
layout: default
SPDX-License-Identifier: MIT
---

## Reporting Maltrail Security Vulnerability

Maltrail team appreciates your efforts on discovering security vulnerabilities in [Maltrail](https://github.com/stamparm/maltrail): Malicious traffic detection system.

If you discover a Maltrail security vulnerability, we'd appreciate a non-public disclosure. Maltrail team developers can be contacted privately on the **maltrail.vulns[@]gmail.com** email address.

The disclosure of discovered security vulnerability will be coordinated with Maltrail team.

Maltrail's [issues tracker](https://github.com/stamparm/maltrail/issues) and [pull requests tracker](https://github.com/stamparm/maltrail/pulls) are fully public.

We aim to acknowledge a report within **3 working days** and to agree a disclosure timeline with
you at that point. If a fix needs longer than 90 days we will say so and explain why, rather than
letting the clock run out quietly.

## The private key Maltrail used to ship (`misc/server.pem`)

From February 2020 until commit `0f876cfa` this repository contained `misc/server.pem`: a
self-signed certificate **and its private key**, in a public repository. Anyone who has ever
cloned, forked or mirrored Maltrail has that key, and `git show 0f876cfa^:misc/server.pem` still
prints it — deleting a file from the tip of a public branch is not key rotation and never was.
Nothing rotates it either, because there is no single "the" key to rotate: it is one file that an
unknown number of operators copied into `/etc/maltrail` years ago.

**If your `SSL_PEM` is that file, HTTPS on your server protects nothing** — anybody can
impersonate it or decrypt a recorded session, and the browser padlock looks exactly the same as it
would with a good key. Check and replace it:

```bash
# does your key match the published one? (prints 9395629637a4fc48... if so)
awk '/BEGIN PRIVATE KEY/{f=1;next} /END PRIVATE KEY/{f=0} f' /etc/maltrail/server.pem | base64 -d | sha256sum
# replace it
openssl req -new -x509 -keyout /etc/maltrail/server.pem -out /etc/maltrail/server.pem \
        -days 365 -nodes -subj '/O=Maltrail CA/C=EU'
```

The server now refuses to start when `SSL_PEM` contains that key or that certificate
(`core.common.uses_published_key`), matched by content, so a rename or a freshly issued
certificate around the same key is caught too. Report the failure as a vulnerability if it ever
starts anyway.

## Supported Versions

"All versions" was never a policy anyone could keep. Security fixes land on the current release
series; older series get them only if the fix is trivial to backport.

| Version | Supported |
| ------- | --------- |
| 3.x     | :white_check_mark: security fixes |
| 2.x     | :warning: critical fixes only, until 3.x has been out for six months |
| < 2.0   | :x: |

Trail data is not versioned: `trails.csv` is rebuilt from the current lists on every update, so a
bad or malicious indicator is fixed by correcting the list, not by releasing.

## Scope

In scope: the sensor's packet parsers (they consume attacker-controlled bytes by definition), the
server's HTTP and event-intake handling, authentication and session handling, and the trail
update path.

Out of scope: false positives and false negatives in trail data — please open an ordinary issue
or pull request for those.
