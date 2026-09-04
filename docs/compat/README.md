# Where Maltrail is known to run

✅ — the capability was exercised and worked, ➖ it cannot apply on that platform, ❌ it did not. Every cell was produced by installing Maltrail on that platform and asking it questions - in a container where one can stand in for the real thing, and on a real FreeBSD VM or a real Mac where it cannot, because a container shares this kernel. Never by hand.

**19 platforms, 152 capabilities verified, 0 not applicable, 0 failing.** Last recorded 2026-09-04.

Kernel version is deliberately not listed: these run as containers, which share the host's kernel, so it would say the same thing on every row and describe none of them. The libc is listed instead - it is what decides which sensor build a platform needs.

| Platform | Arch | libc | Python | install | server | /ping | sensor | sensor runs | upgrade | in-place | uninstall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **AlmaLinux 9.8 (Olive Jaguar)** | aarch64 | glibc 2.34 | 3.9.25 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AlmaLinux 9.8 (Olive Jaguar)** | x86_64 | glibc 2.34 | 3.9.25 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Alpine Linux v3.20** | x86_64 | musl | 3.12.13 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Arch Linux** | x86_64 | glibc 2.44 | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Debian GNU/Linux 12 (bookworm)** | x86_64 | glibc 2.36 | 3.11.2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Debian GNU/Linux 13 (trixie)** | aarch64 | glibc 2.41 | 3.13.5 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Debian GNU/Linux 13 (trixie)** | x86_64 | glibc 2.41 | 3.13.5 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fedora Linux 44 (Container Image)** | aarch64 | glibc 2.43 | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fedora Linux 44 (Container Image)** | x86_64 | glibc 2.43 | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fedora Linux 41 (Container Image)** | x86_64 | glibc 2.40 | 3.13.9 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **FreeBSD 14.2-RELEASE** | amd64 | FreeBSD libc | 3.12.14 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **macOS 26.6.2 (arm64)** | arm64 | libSystem | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **macOS 15.7.9 (x86_64)** | x86_64 | libSystem | 3.14.7 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **openSUSE Leap 15.6** | x86_64 | glibc 2.38 | 3.6.15 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Rocky Linux 9.3 (Blue Onyx)** | x86_64 | glibc 2.34 | 3.9.25 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **openSUSE Tumbleweed** | x86_64 | glibc 2.44 | 3.13.14 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 24.04.4 LTS** | aarch64 | glibc 2.39 | 3.12.3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 24.04.4 LTS** | x86_64 | glibc 2.39 | 3.12.3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 22.04.5 LTS** | x86_64 | glibc 2.35 | 3.10.12 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## What each column means

| Column | The question it answers |
| --- | --- |
| install | Did `install.sh` produce a tree, a config, a user and a writable log directory? |
| server | Did the server unit render with paths that resolve? |
| /ping | Did the server actually start and answer? |
| sensor | Did the sensor unit render with paths that resolve? |
| sensor runs | Did the sensor start and pass its own `-T` self-test? |
| upgrade | Did re-running the installer keep operator configuration? |
| in-place | Did installing from an existing checkout adopt it without cloning over it? |
| uninstall | Did `--uninstall` remove the tree and units but keep config and logs? |

## Windows, and why it is not a row here

Windows is not in the table because the table is a record of what `install.sh` did on a platform, and Windows has no `install.sh` - no system user to create, no service unit to render, no prefix to uninstall. Six of the eight columns would be asking about machinery that does not exist.

Both halves are nonetheless exercised on every push, on a Linux runner. `wpcap` is linked at load time and `wpcap.dll` ships with the Npcap driver, whose free edition refuses a silent install - but the installer is an NSIS archive, so the userspace library can be extracted from it without installing anything, mingw-w64 cross-compiles the sensor, and Wine runs it. `sensor/tools/check_windows.sh` does all of that: the Windows sensor's entire unit suite, its `-T` self-test against the shipped `maltrail.conf`, every pcap in the corpus replayed through both the Windows and the native binary with the detections compared byte for byte, and the server answering `/ping` under a real Windows Python. The first run of it found four bugs that compiling could not.

Live capture needs the kernel driver, so it was verified separately on a **Windows 10 IoT Enterprise LTSC 2021 (10.0.19044)** virtual machine: Npcap installed, the sensor opened the adapters, and DNS queries, a wildcard-regex domain and an ICMP destination were all matched against their trails and written to the event log — from the shipped `maltrail.conf`, unedited.

It did not work at first, and that is the point of having run it. `MONITOR_INTERFACE any` is a Linux pseudo-device; Npcap has no such thing, so `-T` reported `[o] interface: any` and the sensor then died with `Error opening adapter: The filename, directory name, or volume label syntax is incorrect. (123)`. `any` is now substituted with the real interface names wherever the platform does not provide it — which is what Maltrail v1's `sensor.py` did — so the same configuration file works on Linux, Windows, macOS and the BSDs. Linux is untouched: it really does have an `any` device, and the kernel merging it does is better than opening every adapter.

`python3 tests/install/record.py record --windows <label>` produces a row on a Windows machine, the same way every other row here was produced. There is no row yet because the matrix records what `install.sh` did, and it did nothing here.

## Rows

One JSON file per platform under [`rows/`](rows), each carrying what the platform is, every mark the container printed, any findings, and who recorded it when.

### AlmaLinux 9.8 (Olive Jaguar)

`almalinux:9` · aarch64 · glibc 2.34 · python 3.9.25 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### AlmaLinux 9.8 (Olive Jaguar)

`almalinux:9` · x86_64 · glibc 2.34 · python 3.9.25 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Alpine Linux v3.20

`alpine:3.20` · x86_64 · musl · python 3.12.13 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Arch Linux

`archlinux:latest` · x86_64 · glibc 2.44 · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Debian GNU/Linux 12 (bookworm)

`debian:12` · x86_64 · glibc 2.36 · python 3.11.2 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Debian GNU/Linux 13 (trixie)

`debian:13` · aarch64 · glibc 2.41 · python 3.13.5 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Debian GNU/Linux 13 (trixie)

`debian:13` · x86_64 · glibc 2.41 · python 3.13.5 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Fedora Linux 44 (Container Image)

`fedora:latest` · aarch64 · glibc 2.43 · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Fedora Linux 44 (Container Image)

`fedora:latest` · x86_64 · glibc 2.43 · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Fedora Linux 41 (Container Image)

`fedora:41` · x86_64 · glibc 2.40 · python 3.13.9 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### FreeBSD 14.2-RELEASE

`native` · amd64 · FreeBSD libc · python 3.12.14 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### macOS 26.6.2 (arm64)

`native` · arm64 · libSystem · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### macOS 15.7.9 (x86_64)

`native` · x86_64 · libSystem · python 3.14.7 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### openSUSE Leap 15.6

`opensuse/leap:15.6` · x86_64 · glibc 2.38 · python 3.6.15 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Rocky Linux 9.3 (Blue Onyx)

`rockylinux:9` · x86_64 · glibc 2.34 · python 3.9.25 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### openSUSE Tumbleweed

`opensuse/tumbleweed` · x86_64 · glibc 2.44 · python 3.13.14 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Ubuntu 24.04.4 LTS

`ubuntu:24.04` · aarch64 · glibc 2.39 · python 3.12.3 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Ubuntu 24.04.4 LTS

`ubuntu:24.04` · x86_64 · glibc 2.39 · python 3.12.3 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`

### Ubuntu 22.04.5 LTS

`ubuntu:22.04` · x86_64 · glibc 2.35 · python 3.10.12 · recorded 2026-09-04 by ci

Sensor tested: `Maltrail (sensor) #v3.3 {https://maltrail.github.io}`
