#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import time
from core.settings import config

class IcmpDestination:
    def __eq__ (self, other):
        return self.destination == other.destination

    def __hash__(self):
        return hash((self.destination))
    
    def __init__(self, destination: str, package_size: int, first_seen: int, last_seen: int):
        self.destination = destination
        self.first_seen = first_seen
        self.count = 0
        self.package_size_accumulator = package_size
        self.last_seen = last_seen
        self.src_ips = {}
        self.src_ips_period_accumulator = {}
        self.src_ips_last_seen = {}
        self.call_periods_count = 0
        self.period_accumulator = 0

    def add_src_ip(self, src_ip):
        last_seen = time.time()
        self.count += 1

        if src_ip not in self.src_ips:
            self.src_ips[src_ip] = 1
            self.src_ips_period_accumulator[src_ip] = 0
            self.src_ips_last_seen[src_ip] = last_seen
        else:
            self.src_ips[src_ip] += 1
            if self.last_seen - self.src_ips_last_seen[src_ip] < float(config.ICMP_DUPLICATE_PACKET_TIME_THRESHOLD):
                return
            self.src_ips_period_accumulator[src_ip] += last_seen - self.src_ips_last_seen[src_ip]
            self.src_ips_last_seen[src_ip] = last_seen

    def get_src_ip_average_traffic(self, src_ip):
        if self.src_ips_period_accumulator[src_ip] == 0:
            return 0

        return 1 / (self.src_ips_period_accumulator[src_ip] / self.src_ips[src_ip])

    def update_last_seen(self, last_seen):
        first_measurement = self.last_seen
        self.last_seen = last_seen

        if self.last_seen - first_measurement < float(config.ICMP_DUPLICATE_PACKET_TIME_THRESHOLD):
            return
        self.period_accumulator += self.last_seen - first_measurement
        self.call_periods_count += 1

    def get_largest_src_ip(self):
        return max(self.src_ips.keys(), key=lambda x: self.src_ips[x])

    def get_src_ips_as_string(self):
        return ", ".join(self.src_ips.keys())

    def get_average_traffic(self):
        if self.period_accumulator == 0.0:
            return 0

        return 1/(self.period_accumulator / self.call_periods_count)
