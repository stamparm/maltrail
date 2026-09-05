# Where Maltrail is known to run

✅ — the capability was exercised and worked, ➖ it cannot apply on that platform, ❌ it did not. Every cell was produced by installing Maltrail on that platform and asking it questions - in a container where one can stand in for the real thing, and on a real FreeBSD VM or a real Mac where it cannot, because a container shares this kernel. Never by hand.

**19 platforms, 171 capabilities verified, 0 not applicable, 0 failing.** Last recorded 2026-09-04.

Kernel version is deliberately not listed: these run as containers, which share the host's kernel, so it would say the same thing on every row and describe none of them. The libc is listed instead - it is what decides which sensor build a platform needs.

| Platform | Arch | libc | Python | install | server | /ping | sensor | sensor runs | captures | upgrade | in-place | uninstall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **AlmaLinux 9.8 (Olive Jaguar)** | aarch64 | glibc 2.34 | 3.9.25 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AlmaLinux 9.8 (Olive Jaguar)** | x86_64 | glibc 2.34 | 3.9.25 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Alpine Linux v3.20** | x86_64 | musl | 3.12.13 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Arch Linux** | x86_64 | glibc 2.44 | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Debian GNU/Linux 12 (bookworm)** | x86_64 | glibc 2.36 | 3.11.2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Debian GNU/Linux 13 (trixie)** | aarch64 | glibc 2.41 | 3.13.5 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Debian GNU/Linux 13 (trixie)** | x86_64 | glibc 2.41 | 3.13.5 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fedora Linux 44 (Container Image)** | aarch64 | glibc 2.43 | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fedora Linux 44 (Container Image)** | x86_64 | glibc 2.43 | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fedora Linux 41 (Container Image)** | x86_64 | glibc 2.40 | 3.13.9 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **FreeBSD 14.2-RELEASE** | amd64 | FreeBSD libc | 3.12.14 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **macOS 26.6.2 (arm64)** | arm64 | libSystem | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **macOS 15.7.9 (x86_64)** | x86_64 | libSystem | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **openSUSE Leap 15.6** | x86_64 | glibc 2.38 | 3.6.15 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Rocky Linux 9.3 (Blue Onyx)** | x86_64 | glibc 2.34 | 3.9.25 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **openSUSE Tumbleweed** | x86_64 | glibc 2.44 | 3.13.14 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 24.04.4 LTS** | aarch64 | glibc 2.39 | 3.12.3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 24.04.4 LTS** | x86_64 | glibc 2.39 | 3.12.3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 22.04.5 LTS** | x86_64 | glibc 2.35 | 3.10.12 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## What each column means

| Column | The question it answers |
| --- | --- |
| install | Did `install.sh` produce a tree, a config, a user and a writable log directory? |
| server | Did the server unit render with paths that resolve? |
| /ping | Did the server actually start and answer? |
| sensor | Did the sensor unit render with paths that resolve? |
| sensor runs | Did the sensor start and pass its own `-T` self-test? |
| captures | Did it then see real packets? A DNS query for a trail domain and a TCP SYN to a trail address, matched live off the wire — two protocols and two matchers, so a green cell means more than one path through the sensor works. `-T` proves the configuration resolves; only this proves capture does, which is how `MONITOR_INTERFACE any` passed `-T` on Windows and then opened nothing. |
| upgrade | Did re-running the installer keep operator configuration? |
| in-place | Did installing from an existing checkout adopt it without cloning over it? |
| uninstall | Did `--uninstall` remove the tree and units but keep config and logs? |

## What `captures` is for

`-T` proves a configuration parses and an interface name resolves. It does not open a capture handle, so it cannot tell you whether a packet ever reaches the sensor — and for nineteen rows that was the only evidence the sensor worked at all.

The column was added, and on its first run it went red on every glibc Linux row. Not the check being wrong: the 3.3 release binary links libpcap 1.10.5 statically, that version refuses to activate the `any` device when promiscuous mode is requested, and `install.sh` never rewrites `MONITOR_INTERFACE` — so a machine installed from a release stopped at `opening interface 'any'` and captured nothing. A developer build links the system libpcap, which tolerates it, so nothing in development ever showed it. Fixed in 3.4, which is what these cells are now recorded against.

## Windows

Supported, released, and it captures. Verified on **Windows 10 IoT Enterprise LTSC 2021 (10.0.19044)** from the shipped `maltrail.conf` unedited: DNS queries, a wildcard-regex domain and an ICMP destination all matched against their trails and written to the event log.

| | |
| --- | --- |
| Binary | `x86_64-pc-windows-msvc`, on the releases page with a SHA-256 |
| Needs | Windows 10 or later, 64-bit, and [Npcap](https://npcap.com). `wpcap.dll` is a load-time dependency, so nothing starts without it — not even `--version` |
| Run as | An elevated prompt. Capture needs Administrator here the way it needs root or `CAP_NET_RAW` elsewhere |
| First command | `maltrail-sensor.exe -T -c maltrail.conf` — checks a configuration and reports what would and would not work |

Every push runs the Windows build for real, on a Linux runner: mingw-w64 cross-compiles it, `wpcap.dll` is lifted out of the Npcap installer's NSIS archive without installing anything, and Wine executes the result. `sensor/tools/check_windows.sh` runs the whole Windows unit suite, `-T` against the shipped configuration, every pcap in the corpus through both the Windows and the native binary with the detections compared byte for byte, and the server answering `/ping` under a real Windows Python. That found four bugs compiling could not, and the VM run found a fifth — `MONITOR_INTERFACE any` is a Linux pseudo-device, so it is now substituted with the real interface names wherever the platform has no such device, exactly as Maltrail v1 did.

There is no row in the table above because the table records what `install.sh` did, and Windows has no `install.sh` — no system user, no service unit, no prefix to remove. `python3 tests/install/record.py record --windows <label>` writes one on a Windows machine if you want the remaining columns filled in.

## Rows

One JSON file per platform under [`rows/`](rows), each carrying what the platform is, every mark the container printed, any findings, and who recorded it when.

### AlmaLinux 9.8 (Olive Jaguar)

`almalinux:9` · aarch64 · glibc 2.34 · python 3.9.25 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### AlmaLinux 9.8 (Olive Jaguar)

`almalinux:9` · x86_64 · glibc 2.34 · python 3.9.25 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Alpine Linux v3.20

`alpine:3.20` · x86_64 · musl · python 3.12.13 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Arch Linux

`archlinux:latest` · x86_64 · glibc 2.44 · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Debian GNU/Linux 12 (bookworm)

`debian:12` · x86_64 · glibc 2.36 · python 3.11.2 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Debian GNU/Linux 13 (trixie)

`debian:13` · aarch64 · glibc 2.41 · python 3.13.5 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Debian GNU/Linux 13 (trixie)

`debian:13` · x86_64 · glibc 2.41 · python 3.13.5 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Fedora Linux 44 (Container Image)

`fedora:latest` · aarch64 · glibc 2.43 · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Fedora Linux 44 (Container Image)

`fedora:latest` · x86_64 · glibc 2.43 · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Fedora Linux 41 (Container Image)

`fedora:41` · x86_64 · glibc 2.40 · python 3.13.9 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### FreeBSD 14.2-RELEASE

`native` · amd64 · FreeBSD libc · python 3.12.14 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### macOS 26.6.2 (arm64)

`native` · arm64 · libSystem · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### macOS 15.7.9 (x86_64)

`native` · x86_64 · libSystem · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### openSUSE Leap 15.6

`opensuse/leap:15.6` · x86_64 · glibc 2.38 · python 3.6.15 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Rocky Linux 9.3 (Blue Onyx)

`rockylinux:9` · x86_64 · glibc 2.34 · python 3.9.25 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### openSUSE Tumbleweed

`opensuse/tumbleweed` · x86_64 · glibc 2.44 · python 3.13.14 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Ubuntu 24.04.4 LTS

`ubuntu:24.04` · aarch64 · glibc 2.39 · python 3.12.3 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Ubuntu 24.04.4 LTS

`ubuntu:24.04` · x86_64 · glibc 2.39 · python 3.12.3 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`

### Ubuntu 22.04.5 LTS

`ubuntu:22.04` · x86_64 · glibc 2.35 · python 3.10.12 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.4 {https://maltrail.github.io}`
