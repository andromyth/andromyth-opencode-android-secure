# OpenCode Android Secure Build

This private repository contains the vendored Android project source from upstream `turanmertkaraca-bit/opencode-android`, pinned to `v0.52.0-p52`, with local security hardening applied. The native OpenCode payload is intentionally restored during CI from the upstream release APK only after validating its published SHA-256, so a large generated binary is not committed to Git.

## Build and checks

The GitHub Actions workflow builds from the source checked into this repository, restores and verifies the native payload, runs JVM tests, builds the APK, verifies its APK signature, and scans the APK and native payload with ClamAV. The APK and reports are uploaded as a workflow artifact.

## Persistent signing (recommended)

Optional repository secrets: `ANDROID_SIGNING_KEYSTORE_B64`, `ANDROID_SIGNING_STORE_PASSWORD`, `ANDROID_SIGNING_KEY_ALIAS`, and `ANDROID_SIGNING_KEY_PASSWORD`. Use a keystore you own; never commit it. Without these secrets, CI generates a one-run key, so later builds will not install as in-place updates over that APK.

## Security limitations

A clean ClamAV scan is not proof of malware-free behavior. Agent/shell subprocesses may inherit the OpenCode server password environment variable; the hardening reduces unauthenticated loopback access but does not provide a strong app sandbox boundary. The upstream signing key remains in upstream Git history even though its keystore file is removed from this repository's current tree.

Do not treat an APK as verified unless the workflow passes and its APK, SHA-256, signing certificate, JVM test report, and malware scan are inspected.
