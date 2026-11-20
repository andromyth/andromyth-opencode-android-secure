#!/usr/bin/env python3
"""Fail closed when build configuration adds an unapproved engine or action source."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "UPSTREAM_POLICY.json"
WORKFLOW_PATH = ROOT / ".github/workflows/secure-android-build.yml"
SELF_REPO = "andromyth/andromyth-opencode-android-secure"

GITHUB_REPO_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
    r"|git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)
ACTION_RE = re.compile(r"^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@", re.MULTILINE)
SOURCE_COMMAND_RE = re.compile(
    r"\bgit\s+(?:clone|fetch|pull|submodule\s+add|remote\s+add)\b"
    r"|\bgh\s+release\s+download\b"
    r"|\b(?:curl|wget)\b"
)
REPO_OPTION_RE = re.compile(r"--repo(?:=|\s+)[\"']?([^\"'\s]+)")
CHECKED_EXTENSIONS = {".gradle", ".kts", ".properties", ".toml", ".json", ".yml", ".yaml", ".sh"}


def fail(message: str) -> None:
    print(f"UPSTREAM POLICY FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalized_repo(owner: str, name: str) -> str:
    return f"{owner}/{name}".removesuffix(".git").lower()


def repo_references(line: str) -> set[str]:
    found = set()
    for match in GITHUB_REPO_RE.finditer(line):
        owner = match.group(1) or match.group(3)
        name = match.group(2) or match.group(4)
        found.add(normalized_repo(owner, name))
    return found


def policy_files() -> list[Path]:
    paths = list((ROOT / ".github/workflows").glob("*.yml"))
    paths += list((ROOT / ".github/workflows").glob("*.yaml"))
    paths += [
        ROOT / "settings.gradle",
        ROOT / "build.gradle",
        ROOT / "gradle.properties",
        ROOT / "app/build.gradle",
        ROOT / "scripts/build_apk.sh",
    ]
    return [path for path in paths if path.is_file() and path.suffix.lower() in CHECKED_EXTENSIONS]


def main() -> None:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read UPSTREAM_POLICY.json: {exc}")

    engine = policy.get("official_engine", {})
    deps = policy.get("official_native_dependencies", [])
    approved = {str(x).lower() for x in policy.get("approved_source_repositories", [])}
    expected = {"anomalyco/opencode", "anomalyco/opentui", "anomalyco/opencode-pty"}

    if engine.get("repository") != "anomalyco/opencode":
        fail("engine must be anomalyco/opencode")
    if engine.get("url") != "https://github.com/anomalyco/opencode.git":
        fail("engine URL must be the canonical official repository")
    if engine.get("default_branch") != "dev":
        fail("official OpenCode default branch changed; review and update policy deliberately")
    if engine.get("allow_forks") is not False:
        fail("forks must remain disabled")
    if engine.get("release_builds_require_pinned_commit") is not True:
        fail("official-source release builds must pin exact commits")
    dep_repos = {str(x.get("repository", "")).lower() for x in deps}
    if dep_repos != {"anomalyco/opentui", "anomalyco/opencode-pty"}:
        fail("native dependency allowlist must contain only official OpenTUI and OpenCode PTY")
    if approved != expected:
        fail("approved_source_repositories must exactly match the three official repositories")

    for dependency in deps:
        repo = dependency["repository"]
        if dependency.get("url") != f"https://github.com/{repo}.git":
            fail(f"non-canonical URL for approved dependency {repo}")

    legacy = policy.get("legacy_compatibility_payload", {})
    digest = str(legacy.get("sha256", "")).lower()
    if (
        legacy.get("status") != "frozen_compatibility_only"
        or legacy.get("approved_for_engine_updates") is not False
        or legacy.get("approved_for_new_features") is not False
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        fail("legacy payload must stay frozen and barred from engine updates/new features")

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    flattened_workflow = re.sub(r"\\\r?\n", " ", workflow)
    download = re.search(
        r"gh\s+release\s+download\s+([^\s]+).*?--repo\s+[\"']?\$GITHUB_REPOSITORY",
        flattened_workflow,
    )
    if not download or download.group(1) != legacy.get("release_tag"):
        fail("compatibility build must fetch only the locked release asset from this repository")
    if digest not in workflow:
        fail("build workflow payload checksum does not match UPSTREAM_POLICY.json")
    if (ROOT / ".github/workflows/vendor-upstream-source.yml").exists():
        fail("legacy source-vendoring workflow must not be reintroduced")

    errors: list[str] = []
    allowed_actions = {str(x).lower() for x in policy.get("approved_github_actions", [])}

    for path in policy_files():
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        content = re.sub(r"\\\r?\n", " ", content)

        for action in ACTION_RE.findall(content):
            if action.lower() not in allowed_actions:
                errors.append(f"{path.relative_to(ROOT)}: unapproved GitHub Action {action}")

        for line_number, line in enumerate(content.splitlines(), start=1):
            if not SOURCE_COMMAND_RE.search(line):
                continue

            refs = repo_references(line)
            if re.search(r"\bgh\s+release\s+download\b", line):
                repo_option = REPO_OPTION_RE.search(line)
                if repo_option:
                    value = repo_option.group(1)
                    if value in {'"$GITHUB_REPOSITORY"', "$GITHUB_REPOSITORY"}:
                        refs.add(SELF_REPO)
                    elif "/" in value and not value.startswith("$"):
                        refs.add(value.lower())
                    else:
                        errors.append(
                            f"{path.relative_to(ROOT)}:{line_number}: dynamic/ambiguous release source {value}"
                        )
                elif not refs:
                    refs.add(SELF_REPO)

            if not refs and re.search(r"\bgit\s+(?:clone|submodule\s+add|remote\s+add)\b", line):
                errors.append(
                    f"{path.relative_to(ROOT)}:{line_number}: source repository must be an explicit approved GitHub URL"
                )
                continue

            if not refs and re.search(r"\b(?:curl|wget)\b", line):
                errors.append(
                    f"{path.relative_to(ROOT)}:{line_number}: network download must name an approved GitHub repository"
                )
                continue

            for ref in refs:
                if ref == SELF_REPO and (
                    re.search(r"\bgh\s+release\s+download\b", line)
                    or re.search(r"\bgit\s+(?:clone|fetch|pull|remote\s+add)\b", line)
                ):
                    continue
                if ref not in approved:
                    errors.append(
                        f"{path.relative_to(ROOT)}:{line_number}: unapproved source repository {ref}"
                    )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        fail("unapproved source/action references found")

    # Normal and adversarial cases: only exact official repository IDs pass.
    assert repo_references("git clone https://github.com/anomalyco/opencode.git") == {
        "anomalyco/opencode"
    }
    unapproved = repo_references("git clone https://github.com/random-user/opencode-fork.git")
    assert unapproved == {"random-user/opencode-fork"}
    assert not (unapproved & approved)
    print("UPSTREAM POLICY PASS: official repositories only; forks and unlisted actions denied.")


if __name__ == "__main__":
    main()
