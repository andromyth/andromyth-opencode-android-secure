#!/bin/sh
# Read-only network/sandbox capability report for the OpenCode Android guest.
# Safe by default: no host discovery, packet transmission, route changes or installs.
set -u

section() { printf '\n== %s ==\n' "$1"; }
yesno() { if "$@" >/dev/null 2>&1; then printf 'PASS'; else printf 'BLOCKED/UNAVAILABLE'; fi; }

section "identity"
printf 'uid: '; id 2>/dev/null || true
printf 'kernel: '; uname -r 2>/dev/null || true
printf 'architecture: '; uname -m 2>/dev/null || true

section "linux capabilities"
cap_eff=""
if [ -r /proc/self/status ]; then
  cap_eff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status 2>/dev/null | head -n 1)
fi
printf 'CapEff: %s\n' "${cap_eff:-unreadable}"
cap_has() {
  [ -n "$cap_eff" ] || return 1
  # Read the relevant hexadecimal nibble; POSIX awk has no portable bitwise ops.
  awk -v mask="$cap_eff" -v bit="$1" 'BEGIN {
    pos = length(mask) - int(bit / 4)
    digit = tolower(substr(mask, pos, 1))
    nibble = index("0123456789abcdef", digit) - 1
    if (nibble < 0) exit 1
    exit (int(nibble / (2 ^ (bit % 4))) % 2) ? 0 : 1
  }'
}
for item in "CAP_NET_BIND_SERVICE:10" "CAP_NET_ADMIN:12" "CAP_NET_RAW:13"; do
  name=${item%%:*}; bit=${item##*:}
  if cap_has "$bit"; then state=YES; else state=NO; fi
  printf '%s: %s\n' "$name" "$state"
done

section "proc and sys visibility"
for path in /proc/net/route /proc/net/arp /proc/net/dev /proc/net/tcp /proc/net/udp /sys/class/net; do
  if [ -r "$path" ]; then printf 'READABLE  %s\n' "$path"; else printf 'DENIED/MISSING %s\n' "$path"; fi
done
if [ -r /proc/net/dev ]; then
  printf 'interfaces:\n'
  awk -F: 'NR > 2 {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print "  " $1}' /proc/net/dev
fi

section "network configuration"
printf 'resolv.conf: '
if [ -r /etc/resolv.conf ]; then
  awk '/^[[:space:]]*nameserver[[:space:]]/ {print $2}' /etc/resolv.conf | paste -sd ' ' -
else
  printf 'unreadable\n'
fi
for name in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  eval 'value=${'"$name"'-}'
  if [ -n "$value" ]; then printf '%s: SET (value hidden)\n' "$name"; else printf '%s: unset\n' "$name"; fi
done
printf 'NO_PROXY: %s\n' "${NO_PROXY:+SET (value hidden)}"
printf 'no_proxy: %s\n' "${no_proxy:+SET (value hidden)}"

section "local connectivity"
if command -v ping >/dev/null 2>&1; then
  printf 'loopback ICMP: '; yesno ping -c 1 -W 1 127.0.0.1; printf '\n'
else
  printf 'loopback ICMP: ping not installed\n'
fi
if command -v nc >/dev/null 2>&1; then
  printf 'localhost ADB port 5037: '; yesno nc -z -w 1 127.0.0.1 5037; printf '\n'
elif command -v adb >/dev/null 2>&1; then
  printf 'adb client: present (server reachability not tested)\n'
else
  printf 'localhost ADB port 5037: cannot test (nc unavailable)\n'
fi
if command -v getent >/dev/null 2>&1; then
  printf 'DNS example.com: '; yesno getent ahostsv4 example.com; printf '\n'
elif command -v nslookup >/dev/null 2>&1; then
  printf 'DNS example.com: '; yesno nslookup example.com; printf '\n'
else
  printf 'DNS example.com: getent/nslookup unavailable\n'
fi

section "raw socket capability"
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import socket; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.close()' >/dev/null 2>&1
  if [ "$?" -eq 0 ]; then printf 'AF_PACKET raw socket creation: PASS\n'; else printf 'AF_PACKET raw socket creation: BLOCKED\n'; fi
else
  printf 'AF_PACKET raw socket creation: not tested (python3 unavailable)\n'
fi
printf 'No packets were transmitted by this test.\n'

section "toolchain"
for tool in ip ping arping nmap fping nslookup dig curl openssl socat nc adb avahi-browse avahi-resolve-host-name tcpdump iperf3 mtr traceroute whois iw; do
  if command -v "$tool" >/dev/null 2>&1; then printf 'present  %s\n' "$tool"; else printf 'missing  %s\n' "$tool"; fi
done
if command -v nmap >/dev/null 2>&1; then
  printf 'nmap connect scan: supported command is nmap -sT -Pn <explicit-LAN-host>\n'
  printf 'nmap SYN/raw scan: requires CAP_NET_RAW and is not attempted\n'
fi
printf '\nWi-Fi AP scan and mDNS discovery require Android WifiManager/NsdManager bridges; CLI tool presence alone does not grant Android API access.\n'
printf 'USB ADB additionally requires Android USB host permission and device passthrough.\n'

section "safe interpretation"
printf 'This report is read-only. It does not elevate privileges, change routes/firewall, scan LAN hosts, capture traffic, or print proxy credentials.\n'
