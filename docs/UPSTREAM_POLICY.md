# Official upstream and feature-preservation policy

This policy governs every engine update, native runtime, Android build, dependency change and APK release.

## Exact approved sources

| Component | Official repository | Pinned source |
|---|---|---|
| OpenCode engine and CLI | [anomalyco/opencode](https://github.com/anomalyco/opencode) | `dev` at `b958fc84d73e34a2fa021c285cd38c6de674adb9` |
| OpenTUI native renderer | [anomalyco/opentui](https://github.com/anomalyco/opentui) | `v0.9.4`, commit `ff939592dc7bd102a4665bf340c4960b868b306b` |
| PTY source | `anomalyco/opencode/packages/process-daemon` | Included in the pinned OpenCode commit |
| Ghostty VT native source | [ghostty-org/ghostty](https://github.com/ghostty-org/ghostty) | `ab0b9da9e88fcb4b0533a1854e84628f663930af` (pinned by OpenCode) |
| FFF file-search dependency | [dmtrKovalenko/fff](https://github.com/dmtrKovalenko/fff) | `@ff-labs/fff-bun` 0.10.5; Android ARM64 package integrity is pinned by OpenCode's `bun.lock` |
| Bun compiler/runtime | [oven-sh/bun](https://github.com/oven-sh/bun) | `bun-v1.4.4` |
| Zig compiler | [ziglang/zig](https://github.com/ziglang/zig) | `0.16.0` for PTY; `0.17.1` for OpenTUI |

A source is approved only when both its owner/repository and pinned version or commit match `UPSTREAM_POLICY.json` and `OFFICIAL_ANDROID_BUILD.json`. An unknown fork, unofficial mirror, repackaged fork APK or unverified engine binary is denied. The current engine keeps its PTY implementation inside the official OpenCode repository; a separate old PTY repository is not used as the engine source.

## Android ARM64 build requirement

The target is Android ARM64 using Bionic and the Android NDK. The source workflow clones only the pinned official repositories and applies the app-owned, deterministic portability layer in `scripts/port_official_android.py`. That layer is limited to Android target selection, NDK API 28 linking, Android temporary-directory handling, and native library resolution. It does not replace or vendor engine implementation from a fork.

The workflow builds:
1. The OpenCode CLI from the pinned official OpenCode TypeScript/Bun source.
2. The PTY daemon from `anomalyco/opencode/packages/process-daemon` and its pinned Ghostty source.
3. The OpenTUI native renderer from the engine-matched official OpenTUI source.
4. The Android APK in this application repository, bundling those freshly built runtime components using the existing app asset extraction contract.

The OpenTUI shared library is extracted to app-private storage and selected through `OPENTUI_LIB_PATH`. The Android app's existing native UI remains intact; the OpenTUI library supports the official CLI's native terminal renderer. FFF's Android ARM64 binary is supplied only through the official engine's exact lockfile-pinned dependency.

## Token and context exhaustion protection — required compatibility

The previous app's token/context behavior is part of the release contract. Upstream updates must not silently revert it.

- **Automatic compaction is OFF by default.** The app preference `compact_auto` defaults to `false`; before the server process is spawned, `ServerService` writes the corresponding `compaction.auto=false` into the exact `opencode.json` configuration read by OpenCode.
- **No silent automatic summary when the context fills.** In the pinned official OpenCode source, `ConfigCompactionPlugin` loads `compaction.auto` from the config. `SessionCompaction.compact` skips every non-manual compaction reason when `auto=false`, including overflow-triggered recovery. The original transcript stays in the session; the provider's overflow is surfaced instead of silently summarizing it.
- **Manual/user choice remains.** Explicit manual compaction remains available, and the existing Settings switch can opt into automatic compaction. Existing preference state and user-owned `opencode.json` values are preserved according to the ownership merge rules.
- **Keep the memory-retention floor.** The P41 `compaction.preserve_recent_tokens` setting remains in place for sessions where the user explicitly enables compaction or requests a manual compaction.
- **Keep the per-model context-window cap and meter.** The P42 slider/presets, `limit.context` override, server-first context denominator, token/cost accounting and warning behavior remain part of the app.
- **Regression enforcement.** `scripts/verify_token_safety.py` checks the Android boot/config path, the pinned official server's config loading and overflow behavior, and the P42/P45 test surfaces. The source-build workflow runs it before native compilation; the app's `P42Test` and `P45Test` run in the JVM regression suite.

**Important behavior:** With automatic compaction OFF, a full context can cause a provider overflow error. That is intentional: the app must not silently replace the conversation's memory. The user can start a fresh chat, request a manual compaction, or explicitly enable the Settings toggle. Disabling automatic compaction does not enlarge the model's context window or guarantee that every provider accepts the full prompt.

## Temporary legacy compatibility state

The `standalone-payload-v1/oc_pkg.bin` artifact remains frozen solely as a rollback/build fallback until the official-source APK completes validation. It is not an approved engine source and cannot receive new engine features. A successful compatibility APK build is not evidence of official-source migration.

## Preserve this application's capabilities

The Android application is not to be replaced wholesale by upstream code. Port upstream improvements selectively and preserve every existing application-side setting, configuration, authentication path, UI customization, security control, permission, integration, offline/Termux behavior and previously added feature.

Every upstream integration must include a before/after feature and settings comparison. Resolve conflicts by adapting upstream changes around the existing app functionality. Do not remove, reset, or silently downgrade a feature or setting. Any unavoidable breaking change requires an explicit repository-owner decision before implementation.

## Required release gates

1. Verify the exact repository owner, canonical URL, pinned commit and dependency provenance.
2. Build the Android ARM64 CLI, PTY daemon and OpenTUI renderer from the pinned official source checkouts.
3. Verify ELF architecture, Android linker/API compatibility, native library dependencies and source checksums.
4. Run the official-source policy guard, token/context compatibility guard, native build checks, this app's JVM regression tests and APK assembly/signature checks.
5. Compare existing application settings, UI, authentication, security and integration behavior before and after the engine update.
6. Install and test on a physical Android ARM64 device, including `opencode --version`, server health, file search, PTY spawn/output/resize/termination, TUI native loading, app restart and in-place update.
7. Retain build provenance, hashes, signing certificate and test reports. Do not publish as production until all gates pass.

A failure in any release gate blocks production publication. Keep the existing production APK as the rollback point until the new official-source build passes validation.

## Main-branch merge protection

The repository should require both `build` (the existing Android regression/build workflow) and `source-build` (this official-source workflow) as status checks. The `source-build` workflow emits the named check for every pull request and skips the expensive build only when no Android runtime source/build integration files changed. Keep force-push and deletion restrictions enabled, do not restore the previous `Restrict updates` rule, and leave bypass actors empty.

The GitHub connection used during this implementation can inspect branch rules but cannot write repository administration settings. The owner must activate the required status checks under **Settings → Rules → Rulesets**.

## Change control

Changes to `UPSTREAM_POLICY.json`, `OFFICIAL_ANDROID_BUILD.json`, the port script, the token-safety guard, or the approved-source list require explicit review. Never weaken the source guard to accommodate a convenient fork or prebuilt binary.
