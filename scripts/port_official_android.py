#!/usr/bin/env python3
"""Apply the app-owned Android/Bionic portability layer to pinned official source checkouts.

This does not fetch or import code from a fork. Both source trees must be exact,
clean checkouts of the revisions in OFFICIAL_ANDROID_BUILD.json.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "OFFICIAL_ANDROID_BUILD.json").read_text(encoding="utf-8"))


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def verify_checkout(repo: Path, expected_repo: str, expected_sha: str) -> None:
    if not repo.is_dir():
        raise SystemExit(f"source checkout does not exist: {repo}")
    remote = run_git(repo, "remote", "get-url", "origin").removesuffix(".git")
    expected_url = f"https://github.com/{expected_repo}"
    if remote.rstrip("/") != expected_url:
        raise SystemExit(f"unapproved source remote: {remote}; expected {expected_url}.git")
    actual = run_git(repo, "rev-parse", "HEAD")
    if actual != expected_sha:
        raise SystemExit(f"source SHA mismatch for {expected_repo}: {actual} != {expected_sha}")
    if run_git(repo, "status", "--porcelain"):
        raise SystemExit(f"source checkout is not clean before applying the Android port: {expected_repo}")


def replace_once(path: Path, before: str, after: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(before)
    if count != 1:
        raise SystemExit(f"{label}: expected one exact source anchor in {path}, found {count}")
    path.write_text(text.replace(before, after, 1), encoding="utf-8")


def patch_opencode(repo: Path) -> None:
    build = repo / "packages/cli/script/build.ts"
    replace_once(
        build,
        '  { os: "linux", arch: "x64", abi: "musl", avx2: false },\n  { os: "darwin", arch: "arm64" },',
        '  { os: "linux", arch: "x64", abi: "musl", avx2: false },\n'
        '  { os: "android", arch: "arm64" },\n'
        '  { os: "darwin", arch: "arm64" },',
        "OpenCode CLI Android target matrix",
    )
    replace_once(
        build,
        '      target: target.replace(binary, "bun") as Bun.Build.CompileTarget,',
        '      target: compileTarget(item) as Bun.Build.CompileTarget,',
        "OpenCode CLI Bun Android compile target",
    )
    replace_once(
        build,
        '  const platform = item.os === "win32" ? "windows" : item.os\n'
        '  const name = [\n'
        '    "bun",\n'
        '    platform,\n'
        '    item.arch === "arm64" ? "aarch64" : item.arch,\n'
        '    item.abi,',
        '  const platform = item.os === "win32" ? "windows" : item.os === "android" ? "linux" : item.os\n'
        '  const name = [\n'
        '    "bun",\n'
        '    platform,\n'
        '    item.arch === "arm64" ? "aarch64" : item.arch,\n'
        '    item.abi,\n'
        '    item.os === "android" ? "android" : undefined,',
        "OpenCode CLI Android Bun runtime asset name",
    )
    target_name = (
        'function targetName(item: (typeof allTargets)[number]) {\n'
        '  return [\n'
        '    binary,\n'
        '    item.os === "win32" ? "windows" : item.os,\n'
        '    item.arch,\n'
        '    item.avx2 === false ? "baseline" : undefined,\n'
        '    item.abi,\n'
        '  ]\n'
        '    .filter(Boolean)\n'
        '    .join("-")\n'
        '}\n'
    )
    replace_once(
        build,
        target_name,
        target_name
        + '\n'
        + '// Bun names Android ARM64 as a Linux target with the Android ABI suffix.\n'
        + 'function compileTarget(item: (typeof allTargets)[number]) {\n'
        + '  if (item.os === "android") return "bun-linux-arm64-android"\n'
        + '  return targetName(item).replace(binary, "bun")\n'
        + '}\n',
        "OpenCode CLI compileTarget helper",
    )

    pty = repo / "packages/cli/script/opencode-pty.ts"
    replace_once(
        pty,
        '  if (target.platform !== "darwin" && target.platform !== "linux" && target.platform !== "win32") return undefined',
        '  if (!["darwin", "linux", "win32", "android"].includes(target.platform)) return undefined',
        "OpenCode PTY Android platform support",
    )
    replace_once(
        pty,
        '  if (local && (target.platform !== process.platform || target.arch !== process.arch))\n'
        '    throw new Error("OPENCODE_PTY_BIN can only be embedded in a build for the current platform and architecture")',
        '  if (local && (target.platform !== process.platform || target.arch !== process.arch)) {\n'
        '    if (target.platform !== "android" || target.arch !== "arm64")\n'
        '      throw new Error("OPENCODE_PTY_BIN cross-compilation is allowed only for Android ARM64")\n'
        '    const header = await readFile(local)\n'
        '    if (header.length < 20 || header.subarray(0, 4).toString("hex") !== "7f454c46" || header.readUInt16LE(18) !== 183)\n'
        '      throw new Error("OPENCODE_PTY_BIN must be an Android ARM64 ELF executable")\n'
        '  }',
        "OpenCode PTY cross-target binary validation",
    )

    build_rs = repo / "packages/process-daemon/build.rs"
    replace_once(
        build_rs,
        '    if env::var("HOST").as_deref() != Ok(target.as_str()) {',
        '    if env::var("HOST").as_deref() != Ok(target.as_str()) || target == "aarch64-linux-android" {',
        "OpenCode PTY force Android target selection",
    )
    replace_once(
        build_rs,
        '            "aarch64-pc-windows-msvc" => "aarch64-windows-msvc",\n'
        '            _ => panic!("unsupported Ghostty target: {target}"),',
        '            "aarch64-pc-windows-msvc" => "aarch64-windows-msvc",\n'
        '            "aarch64-linux-android" => "aarch64-linux-android.28",\n'
        '            _ => panic!("unsupported Ghostty target: {target}"),',
        "OpenCode PTY Android Ghostty target",
    )

    unix = repo / "packages/process-daemon/src/daemon/unix.rs"
    replace_once(
        unix,
        '        None => PathBuf::from("/tmp"),',
        '        None => default_socket_base(),',
        "OpenCode PTY Android temporary directory",
    )
    socket_root_tail = (
        '    Ok(base.join(format!("opencode-pty-{uid}")))\n'
        '}\n\n'
        'fn socket_file(root: &Path, canonical_directory: &Path) -> PathBuf {'
    )
    replace_once(
        unix,
        socket_root_tail,
        '    Ok(base.join(format!("opencode-pty-{uid}")))\n'
        '}\n\n'
        'fn default_socket_base() -> PathBuf {\n'
        '    // Android has no writable /tmp; the app sets TMPDIR to private storage.\n'
        '    #[cfg(target_os = "android")]\n'
        '    {\n'
        '        std::env::temp_dir()\n'
        '    }\n'
        '    #[cfg(not(target_os = "android"))]\n'
        '    {\n'
        '        PathBuf::from("/tmp")\n'
        '    }\n'
        '}\n\n'
        'fn socket_file(root: &Path, canonical_directory: &Path) -> PathBuf {',
        "OpenCode PTY Android TMPDIR default",
    )


def patch_opentui(repo: Path) -> None:
    build = repo / "packages/native/build.zig"
    replace_once(
        build,
        '    .{ .zig_target = "aarch64-linux-gnu.2.17", .output_name = "aarch64-linux", .description = "Linux aarch64" },',
        '    .{ .zig_target = "aarch64-linux-gnu.2.17", .output_name = "aarch64-linux", .description = "Linux aarch64" },\n'
        '    .{ .zig_target = "aarch64-linux-android.28", .output_name = "aarch64-android", .description = "Android aarch64" },',
        "OpenTUI Android native target",
    )
    replace_once(
        build,
        '        .linux => target.result.abi.isMusl() or target.result.abi == .gnu,',
        '        .linux => target.result.abi.isMusl() or target.result.abi == .gnu or target.result.abi == .android,',
        "OpenTUI Ghostty VT Android ABI",
    )
    replace_once(
        build,
        '        .linux => {\n'
        '            module.linkSystemLibrary("dl", .{});\n'
        '            module.linkSystemLibrary("pthread", .{});\n'
        '            module.linkSystemLibrary("m", .{});\n'
        '        },',
        '        .linux => {\n'
        '            module.linkSystemLibrary("dl", .{});\n'
        '            if (target.result.abi != .android) module.linkSystemLibrary("pthread", .{});\n'
        '            module.linkSystemLibrary("m", .{});\n'
        '        },',
        "OpenTUI Android Bionic system libraries",
    )

    runtime = repo / "packages/core/src/platform/runtime-assets.bun.ts"
    replace_once(
        runtime,
        'export async function resolveNativeLibraryPath(): Promise<string> {\n'
        '  const asset = getNativeAssetDescriptor(getCurrentNodeAssetTarget())\n'
        '  if (process.env.OPENTUI_LIB_PATH) {\n'
        '    return resolve(process.env.OPENTUI_LIB_PATH)\n'
        '  }',
        'export async function resolveNativeLibraryPath(): Promise<string> {\n'
        '  // The Android application extracts its own official-source native library into app-private storage.\n'
        '  if (process.env.OPENTUI_LIB_PATH) {\n'
        '    return resolve(process.env.OPENTUI_LIB_PATH)\n'
        '  }\n'
        '  const asset = getNativeAssetDescriptor(getCurrentNodeAssetTarget())',
        "OpenTUI app-private Android native library resolution",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opencode", type=Path, required=True)
    parser.add_argument("--opentui", type=Path, required=True)
    args = parser.parse_args()

    verify_checkout(args.opencode, MANIFEST["engine"]["repository"], MANIFEST["engine"]["commit"])
    verify_checkout(args.opentui, MANIFEST["opentui"]["repository"], MANIFEST["opentui"]["commit"])
    patch_opencode(args.opencode)
    patch_opentui(args.opentui)
    print("ANDROID SOURCE PORT PASS: official source SHAs verified; CLI, PTY, TMPDIR and OpenTUI Android targets applied.")


if __name__ == "__main__":
    main()
