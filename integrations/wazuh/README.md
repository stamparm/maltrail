# Maltrail for Wazuh

A decoder and rules that turn the sensor's CEF events into Wazuh alerts.

## Install

On the Wazuh manager:

```sh
cp maltrail_decoders.xml /var/ossec/etc/decoders/
cp maltrail_rules.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

Point the sensor at the manager's syslog listener in `maltrail.conf`:

```text
SYSLOG_SERVER 192.0.2.10:514
```

The manager needs a `<remote>` block accepting syslog from the sensor (`<connection>syslog</connection>`,
`<protocol>udp</protocol>`, `<allowed-ips>` set to the sensor's address).

## What you get

| Rule | Level | Fires on |
| --- | --- | --- |
| 100631 | 3 | a low-severity Maltrail event |
| 100632 | 7 | a medium-severity event |
| 100633 | 10 | a high-severity event |
| 100634 | 12 | ten high-severity events from the same source address within two minutes |

Each alert carries `srcip`, `srcport`, `dstip`, `dstport`, `trail`, `category` (the trail's
classification), `ref` (where the trail came from) and `trails_date`. IPv4 and IPv6 events are both
decoded.

The rule IDs are in Wazuh's local range. Change them if they collide with rules of your own.

Thanks to Alfon ([@seguridadyredes](https://twitter.com/seguridadyredes)).
