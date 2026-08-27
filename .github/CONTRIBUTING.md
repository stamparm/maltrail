# Contributing to Maltrail

## Reporting bugs

**Bug reports are welcome**!
Please report all bugs on the [issue tracker](https://github.com/stamparm/maltrail/issues).

If you have a security related report, take a time to read [Reporting Maltrail Security Vulnerability](https://github.com/stamparm/maltrail/blob/master/SECURITY.md) policy.

### Guidelines

* Before you submit a bug report, search both [open](https://github.com/stamparm/maltrail/issues?q=is%3Aopen+is%3Aissue) and [closed](https://github.com/stamparm/maltrail/issues?q=is%3Aissue+is%3Aclosed) issues to make sure the issue has not come up before.
* Make sure you can reproduce the bug with the latest release version of Maltrail.
* Your report should give detailed instructions on how to reproduce the problem. If Maltrail raises an unhandled exception, the entire traceback is needed. Details of the unexpected behaviour are welcome too. A small test case is ideal to have.
* If you are making an enhancement request (RFE, feature request), lay out the rationale for the feature you are requesting. Describe why would proposed feature be useful.

## Submitting code changes

All code contributions are greatly appreciated. First off, clone the [Git repository](https://github.com/stamparm/maltrail), read the [User's manual](https://github.com/stamparm/maltrail/blob/master/README.md) and the [Wiki pages](https://github.com/stamparm/maltrail/wiki) carefully, go through the code yourself and [drop us an email](mailto:maltrail.dev@gmail.com) if you are having a hard time grasping its structure and meaning.

Our preferred method of patch submission is via a Git [pull request](https://help.github.com/articles/using-pull-requests).

Many [people](https://github.com/stamparm/maltrail/graphs/contributors) have contributed in different ways to the Maltrail development. See also the Maltrail's ["Thank you" list](https://github.com/stamparm/maltrail#acknowledgements).

### Guidelines

In order to maintain consistency and readability throughout the code, we ask that you adhere to the following instructions:

* Each patch should make one logical change.
* Avoid tabbing, use four blank spaces instead.
* Before you put time into a non-trivial patch, it is worth discussing it privately by [email](mailto:maltrail.dev@gmail.com).
* Do not change style on numerous files in one single pull request, we can [discuss](mailto:maltrail.dev@gmail.com) about those before doing any major restyling, but be sure that personal preferences not having a strong support in [PEP 8](http://www.python.org/dev/peps/pep-0008/) will likely to be rejected.
* The sensor is Rust: `bash sensor/tools/check.sh` must pass (formatting, lints, tests in both profiles, and byte-identical event parity against the old Python sensor in `old/`).
* Make changes on less than five files per single pull request - there is rarely a good reason to have more than five files changed on one pull request, as this dramatically increases the review time required to land (commit) any of those pull requests.
* Style that is too different from main branch will be ''adapted'' by the developers side.

## Maltrail trails contribution

All contributions to static trails (adding new Maltrail detections, fixing false positives, updating whitelist, etc) are greatly appreciated. Before you submit a contribution to Maltrail detection trails database, take a time to read respective auxiliary articles in Maltrail's Wiki:

* [Trail classes](https://github.com/stamparm/maltrail/wiki/Trail-classes) - Information about different classes of trails.
* [Specific detections](https://github.com/stamparm/maltrail/wiki/Specific-detections) - Information about Maltrail specific detections.
* [Maltrail trails structure](https://github.com/stamparm/maltrail/wiki/Maltrail-trails-structure) - Information about Maltrail trails structure.
* [Maltrail trails base format](https://github.com/stamparm/maltrail/wiki/Maltrail-trails-base-format) - Information about Maltrail trails base format.
* [Maltrail detection nuances](https://github.com/stamparm/maltrail/wiki/Maltrail-detection-nuances) - Information about Maltrail detection nuances.
* [Maltrail trails contribution](https://github.com/stamparm/maltrail/wiki/Maltrail-trails-contribution) - Information about Maltrail trails contribution.

## Adding a feed

Everything under `feeds/` ends up in the trail set of every Maltrail install, so taking a new
source is an editorial decision, not a plumbing one. "The module imports, the URL answers and the
`__check__` string matches" is not a review - it only proves the feed is alive.

What a feed pull request has to make the case for:

* **A source that is known, or old enough to be judged.** A blocklist that appeared a few months ago,
  run by people nobody can name, does not go in - whatever its labels claim, and however clean the
  code is.
* **A label the source has earned.** `known attacker`, `bad reputation` and similar are low severity
  and forgiving of the odd mistake. `malicious` and `malware` assert that something is attacker
  infrastructure, and belong to sources with a track record and a published process for handling
  their own false positives.
* **Corroboration, measured.** Established attacker lists agree with each other substantially - as of
  writing, blocklist.de, greensnow and abuseipdb overlap by 29-56% of the smaller list. A list that
  shares almost nothing with its peers is either genuinely novel or it is noise, and the pull request
  is where that gets shown, not assumed.
* **A read of the actual entries.** Public mining pools, Tor nodes, mixers, CDNs, public resolvers and
  URL shorteners appear in IOC lists constantly, because malware *uses* them - an extractor that
  works from incident write-ups cannot tell the pool from the miner. Maltrail already classes those
  correctly (`suspicious/crypto_mining.txt` in the trails repository and friends), so a feed that calls them
  malicious is fighting our own curation.
* **A readable `__url__`.** `core/update.py` prints it to the operator on every run. If the feed needs
  several URLs, keep `__url__` human-readable and list them inside `fetch()` - see
  `feeds/dataplane.py`.
* **A `__check__` that only appears in a healthy response.** It is what keeps a redirect, an error
  page or an empty answer from silently emptying the feed.

A wrong entry in a feed is not a cosmetic bug here: it is a detection this project vouches for, on
someone else's network, with our name on it.

## Licensing

By submitting code contributions to the Maltrail developers or via Git pull request, checking them into the Maltrail source code repository, it is understood (unless you specify otherwise) that you are offering the Maltrail copyright holders the unlimited, non-exclusive right to reuse, modify, and relicense the code. This is important because the inability to relicense code has caused devastating problems for other software projects. If you wish to specify special license conditions of your contributions, just say so when you send them.
