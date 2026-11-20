#!/usr/bin/env python3
"""Fail closed if the app's context/token-safety behavior or upstream semantics regress."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"TOKEN SAFETY FAIL: {message}", file=sys.stderr)
        raise SystemExit(1)


def source(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"TOKEN SAFETY FAIL: cannot read {path}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opencode", type=Path, required=True,
                        help="Pinned, pristine official OpenCode checkout")
    args = parser.parse_args()

    auth = source(ROOT / "app/src/main/java/ai/opencode/app/AuthStore.java")
    server = source(ROOT / "app/src/main/java/ai/opencode/app/ServerService.java")
    policy = source(ROOT / "app/src/main/java/ai/opencode/app/CompactionPolicy.java")
    context = source(ROOT / "app/src/main/java/ai/opencode/app/ContextPolicy.java")
    settings = source(ROOT / "app/src/main/java/ai/opencode/app/SettingsActivity.java")
    p45test = source(ROOT / "app/src/test/java/ai/opencode/app/P45Test.java")
    p42test = source(ROOT / "app/src/test/java/ai/opencode/app/P42Test.java")

    # App default is OFF. The boot path writes it before the official server is spawned.
    require('.getBoolean("compact_auto", false)' in auth,
            "automatic compaction must remain OFF by default")
    require("AuthStore.ensureCompactionAuto(this)" in server,
            "ServerService must persist compaction.auto at every server boot")
    boot = server.index("private void runServer(File bin)")
    ensure_auto = server.index("AuthStore.ensureCompactionAuto(this)", boot)
    spawn = server.find("new ProcessBuilder", boot)
    require(ensure_auto > boot and spawn > ensure_auto,
            "compaction.auto must be written before the OpenCode process starts")
    require("AuthStore.ensureCompactionPreserve(this" in server[boot:spawn],
            "the app-owned recent-context preservation floor must remain enabled")

    # Explicit Settings opt-in remains available; preserve config ownership semantics.
    require("AuthStore.setCompactionAuto(this, !on)" in settings,
            "the user-facing auto-compaction toggle must remain available")
    require("CompactionPolicy.mergeAuto(cfg, auto, appWritten, false)" in auth,
            "boot config merge must not overwrite a user-owned compaction setting")
    require("CompactionPolicy.mergeAuto(cfg, auto, -1, true)" in auth,
            "an explicit user toggle must write through to opencode.json")
    require("getBoolean(\"compact_auto\", false)" in auth,
            "a fresh install must not enable automatic compaction")
    require("compactionAuto_defaultsOff" in p45test,
            "P45 regression test for default-off behavior is missing")
    require("setThenEnsure_roundTripsThroughOpencodeJson" in p45test,
            "P45 regression test for the persisted server setting is missing")
    require("riskNote_offMode_namesTheOverflowTruth" in p45test,
            "P45 regression test for explicit overflow behavior is missing")

    # Keep the other token/context protections as part of the app compatibility baseline.
    require("preserve_recent_tokens" in policy,
            "P41 preserved-recent-context floor is missing")
    require("MIN" in context and "MAX" in context and "STEP" in context,
            "P42 model context-window cap and bounds are missing")
    require("contextLimit" in auth and "setContextLimit" in auth,
            "P42 persisted per-model context-window cap is missing")
    require("contextPolicy_normalizeBoundsAndQuantizes" in p42test
            and "contextPolicy_mergeWritesModelsDevShape" in p42test,
            "P42 context-cap regression coverage is missing")

    engine = args.opencode
    config_plugin = source(engine / "packages/core/src/config/plugin/compaction.ts")
    compaction_core = source(engine / "packages/core/src/session/compaction.ts")
    runner = source(engine / "packages/core/src/session/runner/llm.ts")

    # The upstream config loader must pass compaction.auto from opencode.json into the service.
    require("entry.info.compaction.auto" in config_plugin and "auto:" in config_plugin,
            "official OpenCode no longer loads compaction.auto from the app config")
    # The upstream service's auto:false gate must cover both proactive and overflow compaction.
    require('if (trigger.reason !== "manual" && !settings.auto) return { status: "skipped" }'
            in compaction_core,
            "official OpenCode no longer skips automatic and overflow compaction when auto=false")
    require('compact({ reason: "overflow"' in runner,
            "official overflow recovery path changed; review token-safety semantics before updating")
    require("auto: true" in compaction_core,
            "official default changed; app override must be revalidated against the new source")

    # Manifest and source SHA must agree with this workflow invocation.
    manifest = json.loads(source(ROOT / "OFFICIAL_ANDROID_BUILD.json"))
    require(manifest.get("engine", {}).get("commit") == "b958fc84d73e34a2fa021c285cd38c6de674adb9",
            "token-safety audit must run against the approved pinned OpenCode commit")
    token_policy = manifest.get("token_safety", {})
    require(token_policy.get("automatic_compaction_default") is False,
            "official Android release manifest must keep automatic compaction OFF by default")
    require(token_policy.get("config_key") == "compaction.auto",
            "official Android release manifest must identify the server compaction kill-switch")
    require(token_policy.get("manual_compaction_when_disabled")
            == "allowed only when the user explicitly requests it",
            "manual compaction behavior must remain user-controlled")
    require(set(token_policy.get("app_regression_tests", [])) >= {"P45Test", "P42Test"},
            "token and context regression suites must remain release gates")

    print(
        "TOKEN SAFETY PASS: app auto-compaction OFF by default; "
        "user opt-in retained; boot config enforced before spawn; "
        "upstream auto and overflow paths respect auto=false; "
        "P41 context retention and P42 context cap remain present."
    )


if __name__ == "__main__":
    main()
