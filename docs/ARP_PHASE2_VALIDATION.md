# ARP Phase 2 — Android compatibility and validation

## Scope
This phase adds passive sampling of the IPv4 neighbour cache exposed by /proc/net/arp. It does not capture Ethernet frames. Android VpnService is an IP-layer interface and is not an ARP capture mechanism.

## Runtime compatibility check
The app performs a real read attempt when the user requests a snapshot or starts monitoring. Results are reported as:
- **LIVE** — the table was readable and at least one complete ARP entry was present.
- **ACCESSIBLE / EMPTY** — the file was readable, but no complete IPv4 ARP entries were exposed at that moment.
- **UNAVAILABLE** — the OS denied access or the read failed.

There is no reliable API-level-only allowlist: access depends on Android release, OEM kernel, SELinux policy and device state. Therefore the runtime probe is authoritative for that device/build. An empty table is not evidence that the network is clean.

## Detection semantics
- A per-session baseline is captured from the first non-empty readable snapshot.
- A newly observed MAC for an IP already in the baseline creates a mapping-change warning.
- Repeated samples of the same changed binding are deduplicated; a distinct new MAC can create a new warning.
- The exposed ARP cache generally provides one current MAC per IPv4 address. It cannot reliably prove simultaneous duplicate-IP claims or detect transient ARP frames that never remain in the cache.
- Legitimate router failover, roaming, DHCP changes, mesh handoff and device replacement can change bindings. Warnings require investigation and are not proof of an attack.

## Threading and lifecycle
File reads run on a single background executor, not the UI thread. Polling is every 3 seconds while the screen is active. Monitoring stops when the screen is paused or destroyed.

## Automated validation
Run:

```sh
./gradlew :app:testDebugUnitTest --tests ai.opencode.app.ArpSpoofLabTest --tests ai.opencode.app.ArpNeighbourMonitorTest
./gradlew :app:assembleDebug
```

Tests cover complete and incomplete rows, malformed rows, empty tables, MAC normalization, normal bindings, changed bindings, repeat-alert suppression, and a second distinct MAC change.

## Required on-device matrix
Record the Android version, API level, OEM/build fingerprint, Wi-Fi/Ethernet state, and displayed probe result for each device:
1. Wi-Fi connected to a trusted LAN.
2. Wi-Fi connected but idle / neighbour cache empty.
3. Wi-Fi disconnected.
4. App backgrounded and resumed.
5. Repeated polling for at least 5 minutes.

A successful build or parser test does not establish that /proc/net/arp is readable on a particular handset. That requires a real-device run.
