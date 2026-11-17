# Graphify Android MCP integration spike

Status: investigation branch only; no runtime integration has been enabled yet.

Branch: `feat/local-graphify-mcp`
Base: `7a8ec8caabfc119dd56654e0dd7d47cfcddbb2cc`

## Goal

Add the upstream Graphify skill and a local Graphify MCP server to OpenCode Android. The integration must be opt-in, account-free, local-first, and must not change the existing OpenCode server lifecycle or remove existing app features.

## Findings from source inspection

- The app installs its existing bundled skill at `$HOME/.config/opencode/skills/mobile-agentic-master/SKILL.md` from `app/src/main/assets`. `Binaries.installMobileAgenticSkill()` preserves an existing user-edited skill.
- `ServerService.runServer()` launches the native OpenCode binary directly with `serve --port ... --hostname ...`; it does not launch the agent inside Debian/proot.
- The app has a Debian 12 ARM64/proot implementation in `Debian.java`, including a rootfs, apt bootstrap, proxy configuration, and a probe. The feature is opt-in and must not be assumed installed or active.
- `Debian.envReport()` checks for Python 3, but that check is diagnostic only; it does not establish that Python or Graphify is installed.
- The app's project working directory is selected by `ServerService.servingDir()`. A Graphify process must be scoped to this directory and its persistent output must remain in the app's project storage.
- The app build deliberately has no shipped runtime Java dependencies. Keep Graphify's Python dependencies inside the Debian guest, not in the Android app process.

## Upstream Graphify facts to validate against the pinned revision

- Package name: `graphifyy`; executable: `graphify`.
- Python requirement: currently declared as Python >=3.10 and <3.15.
- MCP is an optional extra; upstream exposes a local STDIO MCP server and graph tools including `query_graph`, `get_node`, `get_neighbors`, `get_community`, `god_nodes`, `graph_stats`, and `shortest_path`.
- The OpenCode-specific skill is `graphify/skill-opencode.md`; it references companion files under `references/`. Install the complete skill bundle, not only the top-level Markdown file.
- The package's native dependencies (especially Tree-sitter grammar wheels and any optional clustering backend) must be tested in the Debian ARM64 guest before committing to automatic installation.

## Implementation sequence

1. Pin an upstream Graphify tag/commit and record its license and dependency metadata.
2. Confirm the existing Debian guest is installed, active, ARM64, and has a supported Python version. Do not install or upgrade anything automatically.
3. Verify ARM64 wheels for the required package set. If a dependency needs a compiler or lacks a compatible wheel, document the exact blocker before changing the app.
4. Add an explicit, user-triggered Graphify install action that installs into the Debian guest, not the Android host. Keep it separate from normal server startup.
5. Add the complete upstream OpenCode skill bundle to app assets and install it with the existing write-if-absent pattern. Never overwrite a user's copy.
6. Register Graphify as a project-scoped local STDIO MCP server only after installation succeeds. Use a fixed executable/argument list (no shell interpolation), a project-scoped working directory, and a private persistent graph output path.
7. Add diagnostics and an uninstall/disable path. Disabling Graphify must not delete project graph data unless the user explicitly requests deletion.
8. Test MCP initialization, tool listing, graph build, query, incremental update, process exit/restart, project switching, and normal chat with Graphify disabled.
9. Run the existing JVM test suite and secure APK workflow. No merge to main without review and successful CI.

## Security and compatibility constraints

- No Graphify account, OAuth, hosted endpoint, or API key.
- No repository or prompt content uploaded by this integration.
- Never put credentials in MCP arguments, environment diagnostics, or logs.
- Do not alter OpenCode's existing server command, SSE ownership, chat submission path, model selection, permission handling, attachments, Wi-Fi/LAN functionality, or other skills.
- Do not add Graphify to every project automatically; make it opt-in per project.
- Do not silently download a Debian rootfs or Python dependencies on first chat/server startup.

## Current verification status

- Branch creation: complete.
- Source inspection: partial; enough to identify the Debian/proot path and existing skill installer.
- Android ARM64 dependency installation: not tested.
- MCP stdio launch from OpenCode on-device: not tested.
- APK build and device test: not run.
