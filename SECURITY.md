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
