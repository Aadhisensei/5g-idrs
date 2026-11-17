#!/usr/bin/env bash
# Run on the CORE VM (as root) when Redis is bound to the LAN for the GTP-U sensor:
# only the UPF VM may reach port 6379; the gNB and UE VMs (and everything else) are dropped.
set -euo pipefail
UPF_IP=${1:-192.168.56.20}
iptables -C INPUT -p tcp --dport 6379 -s "$UPF_IP" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 6379 -s "$UPF_IP" -j ACCEPT
iptables -C INPUT -p tcp --dport 6379 ! -s 127.0.0.1 -j DROP 2>/dev/null || iptables -I INPUT 2 -p tcp --dport 6379 ! -s 127.0.0.1 -j DROP
echo "Redis 6379: allowed from 127.0.0.1 and $UPF_IP only. Verify from the gNB VM: nc -zv <core> 6379 must fail."
