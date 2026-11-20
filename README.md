# OpenCode Android Secure Build

This repository builds and maintains the Android application, its Android-specific integration and its app-side security controls. Upstream engine development is governed by [the official upstream and feature-preservation policy](docs/UPSTREAM_POLICY.md).

## Approved engine sources

OpenCode engine and native-runtime work is restricted to these exact official repositories:

- [anomalyco/opencode](https://github.com/anomalyco/opencode) — engine and CLI
- [anomalyco/opentui](https://github.com/anomalyco/opentui) — terminal UI and native renderer
- [anomalyco/opencode-pty](https://github.com/anomalyco/opencode-pty) — process and PTY runtime



## Build and checks

The GitHub Actions workflow validates the upstream policy, builds the Android application, restores and verifies the frozen compatibility payload, runs JVM tests, builds the APK, verifies the APK signature and uploads the APK and reports as a workflow artifact.

Do not treat a compatibility APK as an official-source release. An official-source release additionally requires the build-from-source and physical-device release gates in [docs/UPSTREAM_POLICY.md](docs/UPSTREAM_POLICY.md).

## Persistent signing (recommended)

Optional repository secrets: `ANDROID_SIGNING_KEYSTORE_B64`, `ANDROID_SIGNING_STORE_PASSWORD`, `ANDROID_SIGNING_KEY_ALIAS`, and `ANDROID_SIGNING_KEY_PASSWORD`. Use a keystore you own; never commit it. Without these secrets, CI generates a one-run key, so later builds will not install as in-place updates over that APK.

## Security limitations

A successful build and signature check do not prove malware-free behavior. Agent/shell subprocesses may inherit the OpenCode server password environment variable; the hardening reduces unauthenticated loopback access but does not provide a strong app sandbox boundary.

Do not treat an APK as verified unless the workflow passes and its APK, SHA-256, signing certificate, JVM test report and available security reports are inspected.
