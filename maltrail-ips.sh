#!/bin/bash
ipset -q flush maltrail
ipset -q create maltrail hash:net
for ip in $(curl http://127.0.0.1:8338/fail2ban 2>/dev/null | grep -P '^[0-9.]+$'); do ipset add maltrail $ip; done
iptables -I INPUT -m set --match-set maltrail src -j DROP
