# OpenCode Android Secure Build

This repository builds and maintains the Android application, its Android-specific integration and its app-side security controls. Upstream engine development is governed by [the official upstream and feature-preservation policy](docs/UPSTREAM_POLICY.md).

## Approved engine sources

- [anomalyco/opencode](https://github.com/anomalyco/opencode) — engine and CLI
- [anomalyco/opentui](https://github.com/anomalyco/opentui) — native terminal renderer
- [ghostty-org/ghostty](https://github.com/ghostty-org/ghostty) — PTY/VT native source pinned by OpenCode
- [dmtrKovalenko/fff](https://github.com/dmtrKovalenko/fff) — engine's lockfile-pinned FFF native file-search dependency
- [oven-sh/bun](https://github.com/oven-sh/bun) and [ziglang/zig](https://github.com/ziglang/zig) — pinned build tools

Unknown forks, unofficial mirrors, repackaged fork APKs and unverified engine binaries are not approved. CI runs `scripts/verify_upstream_policy.py` to enforce the exact source allowlist.

## Official Android source build

`OFFICIAL_ANDROID_BUILD.json` records the pinned source commits/tool versions. `scripts/port_official_android.py` applies only the app-owned Android/Bionic target and integration changes to pristine official source checkouts. The `official-source-android.yml` workflow builds the OpenCode CLI, PTY daemon and OpenTUI Android ARM64 renderer from source, packages them using the existing app asset contract, runs JVM tests, builds the APK and verifies its signature and hashes.

The source-build job runs on every PR but skips the expensive compile when the PR does not change the engine source pins, Android port, native runtime integration, token-safety guard or source build workflow. Its job check is named `source-build`.

## Token/context safety — preserved from the previous app

Automatic context compaction remains **OFF by default**. Before starting the official OpenCode process, the Android app writes `compaction.auto=false` into the server configuration. The pinned official engine honors this setting for both normal automatic compaction and overflow-triggered compaction, so the app does not silently replace the conversation with a summary. Explicit manual compaction and the existing Settings opt-in are retained.

The P41 recent-context preservation floor, P42 per-model context-window cap/slider, token meter, cost accounting and warnings remain compatibility requirements. CI runs `scripts/verify_token_safety.py` against the pinned official engine and runs the existing P42/P45 JVM regression tests.

With automatic compaction disabled, a full context may produce a provider overflow error rather than a summary. That is intentional memory-preservation behavior; it does not increase the provider's maximum context size.

## Legacy rollback

The current `standalone-payload-v1` runtime remains checksum-locked and frozen as compatibility-only fallback. It is not used to add engine features and does not qualify as an official-source build. The ordinary compatibility workflow still builds the existing app without changing that fallback.

## Build and verification

The compatibility workflow validates the source policy, runs JVM tests, builds the Android APK, verifies its signature and uploads reports. The official-source workflow additionally checks token/context compatibility and builds the CLI, PTY and OpenTUI native library from the pinned official source checkouts.

## Persistent signing (recommended)

Optional repository secrets: `ANDROID_SIGNING_KEYSTORE_B64`, `ANDROID_SIGNING_STORE_PASSWORD`, `ANDROID_SIGNING_KEY_ALIAS`, and `ANDROID_SIGNING_KEY_PASSWORD`. Use a keystore you own; never commit it.

## Security limitations

A successful build and signature check do not prove malware-free behavior. Agent/shell subprocesses may inherit the OpenCode server password environment variable; hardening reduces unauthenticated loopback access but does not provide a strong app sandbox boundary.
