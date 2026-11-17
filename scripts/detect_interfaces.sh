#!/usr/bin/env bash
# Detects the LAN interface carrying the 192.168.56.0/24 testbed
# network on the 5G-Core VM, and writes .env for docker-compose.
set -euo pipefail

LAN_IFACE=$(ip -o -4 addr show | awk '{print $2, $4}' | grep "192\.168\.56\." | awk '{print $1}' | head -n1)

if [ -z "${LAN_IFACE}" ]; then
  echo "WARNING: could not auto-detect an interface on 192.168.56.0/24." >&2
  echo "Set LAN_IFACE manually in .env (defaulting to eth1)." >&2
  LAN_IFACE="eth1"
fi

cat > .env <<ENVEOF
LAN_IFACE=${LAN_IFACE}
SBI_IFACE=lo
ENVEOF

echo "Wrote .env:"
cat .env
