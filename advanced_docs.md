# CLI Options

## Custom config file

Define a custom configuration file

`-c {config file location}`

## Offline pcap File

Open pcap file for offline analysis

`-i {pcap file location}`

## Custom plugins

To load additional plugins from the cli

`-p {plugins}`

## Console

print events to console (too)

`--console`

## Disable dynamic trail updates

disable (online) trail updates

`--no-updates`

## Debug

Enable debug mode

`--debug`

# Configuring

To configure Maltrail edit core/settings.py

## Add plugins

Use the `plugins` field to enable custom plugins

Example:

```txt
plugins plugin1,plugin2
```

# Extendability

You can extend Maltrail by adding a plugin in the plugins folder and appending it to the config file.

The format of a plugin is the following:

```python
# Define the plugin
def plugin(event_tuple, packet=None):
    # Do things with the event and packet
    return
```

## event_tuple

## packet
