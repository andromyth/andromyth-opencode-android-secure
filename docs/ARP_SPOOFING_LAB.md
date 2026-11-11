# Offline ARP spoofing simulation lab\n\nThis lab demonstrates ARP-cache anomaly detection without interacting with a real network.\n\n## Safety boundary\n\n- All addresses and MAC values are synthetic documentation/test values.\n- The simulator operates only on in-memory Java objects.\n- It does not create ARP frames, open raw or packet sockets, transmit traffic, inspect the device ARP cache, change routes, or enable forwarding.\n- No root, VPN permission, or special Android permission is required.\n- Synthetic results are not evidence about the connected Wi-Fi.\n\n## Scenarios\n\n- NORMAL: expected bindings; no alerts.\n- GATEWAY_MAC_CHANGE: synthetic gateway IP appears with a different MAC.\n- DUPLICATE_IP_CLAIM: synthetic host IP is observed with a second MAC.\n\nThe detector reports IP_TO_MAC_CHANGED when an observation differs from the supplied baseline, and IP_CLAIMED_BY_MULTIPLE_MACS when one IP is seen with more than one distinct MAC.\n\n## Run tests\n\nFrom the repository root:\n\n    ./gradlew :app:testDebugUnitTest --tests ai.opencode.app.ArpSpoofLabTest\n\nThe tests use the existing JUnit 4 dependency and perform no network operations.\n

## Android live-monitor fallback

On devices where Android denies read access to `/proc/net/arp`, the live monitor falls back to public Android connectivity APIs:
- Active network's default gateway from `ConnectivityManager` / `LinkProperties`.
- Wi-Fi access-point BSSID from `WifiManager`, only when Android exposes it (it may be redacted).

This fallback can warn when the observed gateway or BSSID changes. Such changes can be normal (roaming, reconnecting, DHCP/network changes) and are not proof of ARP spoofing. It cannot enumerate LAN IP-to-MAC bindings, detect duplicate-IP claims, inspect ARP frames, or capture deauthentication frames. The UI explicitly labels this as network context rather than live ARP visibility.

No permissions are escalated and no SELinux or Android security controls are bypassed. If Android exposes neither gateway nor BSSID, the monitor reports that no identity baseline is available and continues without fabricating a result.

Run the fallback tracker tests:

    ./gradlew :app:testDebugUnitTest --tests ai.opencode.app.NetworkContextMonitorTest
