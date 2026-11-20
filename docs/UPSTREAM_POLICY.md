# Official upstream and feature-preservation policy

This policy governs every future engine update, dependency change, native runtime, APK build and release in this repository.

## Approved upstreams — exact repositories only

| Component | Approved repository | Default branch |
|---|---|---|
| OpenCode engine and CLI | [anomalyco/opencode](https://github.com/anomalyco/opencode) | `dev` |
| Terminal UI and native renderer | [anomalyco/opentui](https://github.com/anomalyco/opentui) | `main` |
| Process / PTY runtime | [anomalyco/opencode-pty](https://github.com/anomalyco/opencode-pty) | `master` |

No fork, mirror, repackaged fork binary, renamed fork, or third-party substitute is an approved engine source. A repository is not trusted because its name contains “opencode” or because it claims to be a fork of the official project. The machine-readable allowlist is `UPSTREAM_POLICY.json`; CI enforces it through `scripts/verify_upstream_policy.py`.

## Build-from-source requirement

The target architecture is Android ARM64 using Android's Bionic userspace and the Android NDK. New engine releases must be built from reviewed commits in the approved repositories. Release builds must record and pin exact commit SHAs for the engine and each native dependency. Do not use a moving branch, an unverified prebuilt binary, or an asset copied from an unapproved repository as the release source.

The Android runtime must be built as part of this application’s own reproducible build pipeline. Do not replace that requirement with downloading or repackaging another Android app's APK or native payload.

## Temporary legacy compatibility state

The current `standalone-payload-v1/oc_pkg.bin` asset is a frozen compatibility artifact retained solely to keep the existing application buildable while the official Android ARM64 runtime is developed. It is **not** an approved upstream, is not considered an official OpenCode build, and must not receive new engine features or updates. Its SHA-256 is locked in `UPSTREAM_POLICY.json` and checked in CI. Replace it only after the official-source Android runtime has passed the release gates below.

A successful compatibility APK build does not mean the official-source migration is complete.

## Preserve this application's existing capabilities

The Android application is not to be replaced wholesale by upstream code. Port upstream changes selectively and retain all existing application-side settings, configuration, authentication, UI, security controls, permissions, integrations, offline/Termux handling and previously added features.

Every upstream integration must include a before/after feature and settings comparison. Existing settings and behavior must remain compatible by default. If an upstream change conflicts with an existing app feature, adapt the upstream change or keep the app-side implementation; do not delete or silently downgrade an existing capability. Any unavoidable breaking change requires an explicit decision from the repository owner before implementation.

## Required release gates

1. Verify the source repository owner and URL against the exact allowlist above.
2. Pin the reviewed upstream commit SHA and all native dependency SHAs.
3. Build the Android ARM64 engine, renderer and PTY from source in CI.
4. Run upstream tests relevant to the selected commits and this application's regression tests.
5. Compare existing settings, UI, authentication, security and integration behavior before and after the change.
6. Build the APK in this repository, verify its signature and checksums, and retain build logs and provenance.
7. Test installation, update-in-place behavior and runtime operation on a physical Android ARM64 device before release.

A failure in any gate blocks publication. Keep the existing production APK as the rollback point until the new official-source build passes all gates.

## Change control

Changes to `UPSTREAM_POLICY.json`, the enforcement script or the approved-source list require explicit review. Do not weaken the CI guard to accommodate a convenient fork or binary. If the official repositories add a required dependency, verify that it is owned and maintained by the official OpenCode organization before adding it to the allowlist.
