# Graphify Android MCP integration

Status: implementation on an isolated branch; device-level runtime validation remains outstanding.

Branch: `feat/local-graphify-mcp`
Base: `7a8ec8caabfc119dd56654e0dd7d47cfcddbb2cc`
Pull request: #27 (draft)

## Implemented

- Bundled the upstream Graphify OpenCode skill, its eight reference files, and upstream licensing/notice files from Graphify v8 commit `480b61ed91cbc08177dc2c60caa9ffd6c9b95749`.
- Pinned the Python package to `graphifyy==0.9.111` with its `mcp` extra. This release requires Python >=3.11; Debian 12's default Python line is 3.11.
- Added an opt-in Settings action. Installation runs only after an explicit user action and only when the existing Debian 12 environment and apt bootstrap are already active.
- Installs Python prerequisites and Graphify into an isolated `/opt/graphify-venv` inside Debian; it does not install Python packages into Android or change the native OpenCode server.
- Adds a host-side launcher that enters the Debian guest through the app's existing proot runtime. It uses OpenCode's workspace cwd and binds that one project into Debian. Graph output is stored in that project's `graphify-out/` directory.
- Registers one local STDIO MCP entry (`graphify-local`) in the existing OpenCode config. Other MCP entries are preserved. The launcher bootstraps an empty graph file so the MCP process can initialize before the first graph build; Graphify's upstream MCP server supports graph hot-reload.
- Installs the skill with write-if-absent semantics, preserving user-edited copies.
- Adds a disable action that only disables the app-owned MCP config entry and does not delete project graph data.

## Design constraints

- No Graphify account, OAuth, hosted endpoint, Graphify API key, or remote Graphify server.
- No automatic install during app startup or ordinary chat.
- No changes to the native OpenCode process lifecycle.
- No edits to the existing chat, sessions, permission cards, resume, attachment, Wi-Fi/LAN, or existing skill paths.
- Graphify package and runtime dependencies remain inside the optional Debian guest.

## Verification status

- Source review: completed.
- OpenCode local MCP config shape: checked against official documentation (`mcp.<name>`, `type=local`, command array, workspace cwd).
- Android Java/JVM tests and APK build: CI run pending.
- Python dependency resolution on Debian ARM64: not yet tested on the target device.
- Actual proot-launched MCP STDIO handshake/tool listing and graph query: not yet device-tested.
- Main branch: unchanged; no merge performed.

## First device test after installing the branch APK

1. Ensure Debian 12 is installed, active, and apt-ready in Settings.
2. Open Settings → Environment → Local Graphify MCP → Install.
3. Wait for the installer to report the Python import and MCP CLI smoke tests.
4. Restart the OpenCode server when prompted.
5. In a project chat, invoke `/graphify .` to build the project's graph.
6. Then ask a codebase question and explicitly request the `graphify-local` MCP tools. Verify `graph_stats` and `query_graph`.
7. Switch projects and verify the new project gets its own `graphify-out/` and no graph is read from the previous project.
8. Disable Graphify and verify normal chat still works.

If installation fails, retain the full installer output; do not add a compiler toolchain or silently fall back to a hosted service.
