#!/usr/bin/env bash

# Run with capture file, for debugging purposes
sudo python ./sensor.py -i ./captures/nessus-scan.pcap # -p test --no-updates

# Run for production use
# sudo python ./sensor.py --no-updates
