# Android Wi-Fi Security Integration

## Scope
This feature is a defensive, passive assessment module inspired by the defensive reporting goals of wireless auditing tools. It does not vendor or execute Airgeddon. Airgeddon is a Linux shell toolkit whose offensive workflows and Linux-specific dependencies are not compatible with the safe Android-only scope selected for this app.

## Implemented
- Android-native Wi-Fi scan request and OS-provided scan-result handling.
- Defensive classification of open, WEP, legacy WPA, WPA2, WPA3/SAE and OWE metadata.
- Basic Android Wi-Fi capability report, including API level, Wi-Fi service, band support, scan-always availability and a non-authoritative root indicator.
- Read-only USB-host diagnostics: enumerates attached USB devices and reports vendor/product IDs plus interface descriptors when Android exposes USB host support.
- Cloud AI handoff through the existing OpenCode chat/provider configuration. The assessment is prefilled in chat; the user reviews and explicitly sends it.
- JVM tests for normal, high-risk, secure, empty and boundary cases.

## Compatibility limits
- Wi-Fi scan results require Android permission and may also depend on location settings, OEM policy and scan throttling.
- Scan results may be cached; a successful API call does not prove freshness.
- Public Android APIs do not expose general monitor-mode control or raw 802.11 frame capture to ordinary applications.
- USB enumeration only confirms that Android can see a USB device. It does not identify every Wi-Fi chipset, prove a driver is loaded, or establish monitor-mode support. Vendor/product IDs must be checked against the exact adapter and Android kernel/driver; no generic compatibility claim is made.
- The USB diagnostic does not open the device, request USB access, load drivers, change permissions, or alter Android security settings.
- Root indicator detection is heuristic, not proof of root. Root does not guarantee chipset/driver monitor-mode support or override SELinux.
- The assessment does not prove AP identity, detect every rogue AP, or establish that a network is safe. SSIDs and advertised capabilities can be spoofed.
- No permission escalation, SELinux bypass, driver patching, packet injection, deauthentication, credential capture, handshake cracking, rogue AP creation or attack automation is implemented.

## Device validation
On each target handset:
1. Open Settings → Network & LAN diagnostics → Wi-Fi security assessment.
2. Check compatibility output on both rooted and non-rooted test devices.
3. Connect the adapter through a powered USB-OTG cable/hub, then select **Check USB-OTG adapter**. Record the reported VID:PID and interface descriptors.
4. Verify the exact VID:PID against the adapter manufacturer's chipset documentation and the handset's kernel/driver support. Treat monitor mode as unsupported until separately verified on-device.
5. Grant location permission if requested and enable Wi-Fi in Android Settings.
6. Run a scan twice, noting whether Android returns fresh or cached results.
7. Compare classification against a controlled lab AP configured for open, WPA2 and WPA3 modes.
8. Tap Analyze findings with cloud AI, review the prefilled prompt and send only if the report is approved for cloud processing.

## Build/test
Run:
```sh
./gradlew :app:testDebugUnitTest :app:assembleDebug
```

CI validates JVM logic and APK build. It cannot establish the target phone's scan freshness, OEM permission behavior or chipset capabilities; those require physical-device testing.
