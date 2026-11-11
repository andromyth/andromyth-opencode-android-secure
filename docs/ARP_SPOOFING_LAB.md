# ARP security lab

This lab demonstrates ARP-cache anomaly detection without sending traffic or modifying a network.

## Safety boundary

- The offline simulator uses synthetic addresses and in-memory Java objects.
- It does not create ARP frames, open raw or packet sockets, transmit traffic, change routes, or enable forwarding.
- No root, VPN permission, or special Android permission is required.
- Synthetic results are not evidence about the connected Wi-Fi.

## Scenarios

- `NORMAL`: expected bindings; no alerts.
- `GATEWAY_MAC_CHANGE`: synthetic gateway IP appears with a different MAC.
- `DUPLICATE_IP_CLAIM`: synthetic host IP is observed with a second MAC.

The detector reports `IP_TO_MAC_CHANGED` when an observation differs from its baseline, and `IP_CLAIMED_BY_MULTIPLE_MACS` when one IP is observed with more than one distinct MAC.

## Android live-monitor behaviour

The app first attempts read-only sampling of `/proc/net/arp`. Android/OEM policy may deny access (for example, `EACCES`). When that happens, the app switches to supported Android connectivity APIs:

- Active network's default gateway from `ConnectivityManager` / `LinkProperties`.
- Wi-Fi access-point BSSID from `WifiManager`, only when Android exposes it (it may be redacted).

The fallback tracks changes in gateway and BSSID as **network-context warnings**. Changes may be normal (roaming, reconnecting, DHCP or network changes) and are not proof of spoofing.

The fallback does **not** enumerate LAN IP-to-MAC bindings, detect duplicate-IP claims, inspect ARP frames, or capture deauthentication frames. It is not a replacement for ARP packet capture. If Android exposes neither gateway nor BSSID, the app reports that no identity baseline is available rather than fabricating a result.

No permissions are escalated and no SELinux or Android security controls are bypassed.

## Tests

From the repository root:

    ./gradlew :app:testDebugUnitTest --tests ai.opencode.app.ArpSpoofLabTest
    ./gradlew :app:testDebugUnitTest --tests ai.opencode.app.NetworkContextMonitorTest

The tests use JUnit and perform no network operations.
