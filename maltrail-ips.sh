#!/bin/bash

###########################################################################################################################
#
# Copyright (c) 2014-2021 Maltrail developers (https://github.com/stamparm/maltrail/)
# See the file 'LICENSE' for copying permission
# 
# Mechanism, which allows Maltrail to be used as an Intrusion Prevention System (IPS).
#
# Works in Linux systems only!
#
# Wiki: https://github.com/stamparm/maltrail/wiki/Miscellaneous#1-setting-up-maltrail-as-an-intrusion-prevention-system-ips
###########################################################################################################################

ipset -q flush maltrail
ipset -q create maltrail hash:net
for ip in $(curl http://127.0.0.1:8338/fail2ban 2>/dev/null | grep -P '^[0-9.]+$'); do ipset add maltrail $ip; done
iptables -I INPUT -m set --match-set maltrail src -j DROP
