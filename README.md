# OpenCode Android Secure Build

Private hardening/build repository for upstream `turanmertkaraca-bit/opencode-android`, pinned to tag `v0.52.0-p52`.

## CI
Fetches pinned source, applies `scripts/apply_security_hardening.py`, verifies the native payload SHA-256, runs JVM tests, builds the APK, verifies the APK signature, and scans the APK and native payload with ClamAV. The APK and reports are uploaded as a GitHub Actions artifact.

## Persistent signing (recommended)
Optional repository secrets: `ANDROID_SIGNING_KEYSTORE_B64`, `ANDROID_SIGNING_STORE_PASSWORD`, `ANDROID_SIGNING_KEY_ALIAS`, `ANDROID_SIGNING_KEY_PASSWORD`. Use a keystore you own; never commit it. Without these secrets, CI generates a one-run key. That APK installs, but later builds cannot update it in place because the signer changes.

## Limitations
A clean ClamAV scan is not proof of malware-free behavior. Agent/shell subprocesses may inherit the OpenCode server password environment variable; this hardening reduces unauthenticated loopback access but does not provide a strong app sandbox boundary. The upstream signing key remains in Git history even though it is removed from the current build tree.

Do not treat an APK as verified unless the workflow passes and its APK, SHA-256, signing certificate, test report, and malware scan are inspected.
