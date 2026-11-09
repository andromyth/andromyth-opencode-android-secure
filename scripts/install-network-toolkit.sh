#!/bin/sh
# Optional Debian guest toolkit install. Run manually inside the Debian guest.
# Packages that need unavailable kernel capabilities will install but remain
# unusable until the Android host provides the relevant privilege/API bridge.
set -eu

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not found; run this inside the Debian 12 guest." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  iproute2 iputils-ping iputils-arping nmap fping dnsutils \
  curl openssl socat netcat-openbsd android-tools-adb \
  avahi-utils tcpdump iperf3 mtr-tiny traceroute whois iw

cat <<'EOF'
Network toolkit installed.

Capability limits still apply:
- nmap -sT works without CAP_NET_RAW; SYN/ARP scans do not.
- arping and tcpdump require CAP_NET_RAW.
- iw scanning/monitor mode and route/firewall changes require CAP_NET_ADMIN
  or Android-native APIs.
- avahi tools may not discover services if multicast is filtered; the app's
  Android NsdManager bridge is the preferred Android discovery path.
EOF
