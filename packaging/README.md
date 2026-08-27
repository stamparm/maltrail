# Packaging

Service definitions for running Maltrail under an init system.

```
systemd/    maltrail-server.service, maltrail-sensor.service
```

`install.sh` installs the systemd units when it finds systemd; on anything else it says so and
leaves the processes to you.

These lived at the repository root until 3.3, which quietly said systemd was *the* way to run
Maltrail. It is not — the server is `python3 server.py` and the sensor is a single binary, and
both are perfectly happy under rc.d, OpenRC, runit, s6 or a supervisor of your choosing. There is
a FreeBSD port, and it does not use any of these files.

Contributions of definitions for other init systems are welcome here. The two systemd units are
the reference for what a supervisor needs to get right: an unprivileged `maltrail` user, the
capabilities the sensor needs instead of root (`CAP_NET_RAW`, `CAP_NET_ADMIN`), a preflight that
refuses to start a misconfigured deployment, and a restart policy.
