#!/usr/bin/env bash
# ============================================================================
# build_apk.sh — the ONLY sanctioned way to build a release APK here.
#
# History: the v0.35.0 APK was hand-linked outside gradle and shipped without
# its uses-sdk manifest entries (modern Android refuses those installs) and
# with the bundled server binary under a name the code does not read (fresh
# installs could not boot the sandbox). This script makes the correct path
# the easy path and gates the output before anything can be uploaded.
#
# Usage: scripts/build_apk.sh            # → app/build/outputs/apk/debug/app-debug.apk
#
# Toolchain discovery: JAVA_HOME / ANDROID_HOME / GRADLE are honoured when set
# and usable; otherwise the usual local toolchain dirs are probed, so the same
# script works on x86_64 CI and on an arm64 (Termux/Debian) host.
# ============================================================================
set -euo pipefail

# ---- toolchain -------------------------------------------------------------
# JAVA_HOME: use it only if it actually contains a java binary; else probe.
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "$JAVA_HOME/bin/java" ]; then
  for j in /usr/lib/jvm/java-21-openjdk-* /usr/lib/jvm/java-17-openjdk-* \
           /usr/lib/jvm/default-java; do
    if [ -x "$j/bin/java" ]; then JAVA_HOME="$j"; break; fi
  done
fi
export JAVA_HOME
[ -x "$JAVA_HOME/bin/java" ] || { echo "FAIL: no JDK found (set JAVA_HOME)"; exit 1; }

# ANDROID_HOME: env wins when it is a real SDK dir; else probe known locations.
if [ -z "${ANDROID_HOME:-}" ] || [ ! -d "$ANDROID_HOME" ]; then
  for d in "$HOME/p0-tools/android-sdk" /tmp/tools/android-sdk "$HOME/Android/Sdk"; do
    if [ -d "$d" ]; then ANDROID_HOME="$d"; break; fi
  done
fi
export ANDROID_HOME
[ -d "$ANDROID_HOME" ] || { echo "FAIL: no Android SDK found (set ANDROID_HOME)"; exit 1; }

# GRADLE: env wins when executable; else probe known locations.
if [ -z "${GRADLE:-}" ] || [ ! -x "$GRADLE" ]; then
  for g in "$HOME/p0-tools/gradle-8.9/bin/gradle" /tmp/tools/gradle-8.9/bin/gradle; do
    if [ -x "$g" ]; then GRADLE="$g"; break; fi
  done
fi
[ -x "${GRADLE:-}" ] || { echo "FAIL: gradle not found (set GRADLE)"; exit 1; }

BT="$ANDROID_HOME/build-tools/34.0.0"
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ"

# ---- emulation for x86_64 ELF tools on non-x86_64 hosts --------------------
# The Linux SDK build-tools (aapt/aapt2/zipalign) are x86_64 ELF binaries. On
# an arm64 host they die with SIGILL unless run through qemu user-mode emulation.
EMU=""
if [ "$(uname -m)" != "x86_64" ]; then
  EMU="$(command -v qemu-x86_64-static || command -v qemu-x86_64 || true)"
fi

# Run an ELF tool, transparently emulating it when the host arch differs.
run_tool() {
  local t="$1"; shift
  if [ -n "$EMU" ] && [ "$(od -An -tx1 -j18 -N2 "$t" | tr -d ' \n')" = "3e00" ]; then
    "$EMU" "$t" "$@"
  else
    "$t" "$@"
  fi
}

# aapt2 is resolved by the Android Gradle Plugin from the Maven cache, not from
# the SDK, so Gradle needs an explicit override. Point AAPT2_OVERRIDE at any
# runnable aapt2; otherwise accept the conventional qemu wrapper location.
# The gate step below reuses this same binary, since the Maven aapt2 and the
# SDK aapt2 print slightly different `dump badging` labels.
AAPT2="${AAPT2_OVERRIDE:-}"
if [ -z "$AAPT2" ] && [ -x /tmp/tools/aapt2override/aapt2 ]; then
  AAPT2=/tmp/tools/aapt2override/aapt2
fi
GRADLE_ARGS=(assembleDebug --no-daemon)
if [ -n "$AAPT2" ]; then
  GRADLE_ARGS+=("-Pandroid.aapt2FromMavenOverride=$AAPT2")
elif [ -n "$EMU" ]; then
  echo "FAIL: non-x86_64 host: set AAPT2_OVERRIDE to a runnable aapt2" >&2
  echo "      (e.g. a wrapper that execs qemu-x86_64 on the Maven aapt2)" >&2
  exit 1
fi
AAPT2="${AAPT2:-$BT/aapt2}"

# ---- 0. the bundled binary must exist under a name the code reads ----------
ASSET="app/src/main/assets/oc_pkg.bin"
[ -f "$ASSET" ] || { echo "FAIL: $ASSET missing (the opencode tarball — not in git; restore it from a release asset)"; exit 1; }

# ---- 0b. the payload itself: gzip tarball, known-good digest ---------------
# The asset is the opencode TARBALL, not the uncompressed binary inside it —
# the raw 184 MB ELF went in by mistake once: TarGz.extractAll would reject it
# on first read and every fresh install would fail to boot the sandbox.
# Bump the digest below consciously, only when the payload legitimately changes.
EXPECT_SHA="6384e745af0ee988a6f51e8aa205c0d71b614e0bb100d22c4e535b355d673a7d"
ACTUAL_SHA="$(sha256sum "$ASSET" | cut -d' ' -f1)"
[ "$ACTUAL_SHA" = "$EXPECT_SHA" ] || {
  echo "FAIL: oc_pkg.bin sha mismatch: $ACTUAL_SHA" >&2
  echo "      expected: $EXPECT_SHA (wrong stage, or the payload changed — bump consciously)" >&2
  exit 1
}
[ "$(od -An -tx1 -N2 "$ASSET" | tr -d ' \n')" = "1f8b" ] || {
  echo "FAIL: oc_pkg.bin is not gzip — wrong stage (raw binary?), TarGz.extractAll cannot read it"; exit 1
}
echo "payload OK: oc_pkg.bin $ACTUAL_SHA"

# ---- 1. gradle build --------------------------------------------------------
"$GRADLE" "${GRADLE_ARGS[@]}" 2>&1 | tail -3
APK="app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "FAIL: gradle did not produce $APK"; exit 1; }

# ---- 2. gates: manifest, signature, alignment, storage ---------------------
echo "== manifest =="
BADGING="$(run_tool "$AAPT2" dump badging "$APK")"
printf '%s\n' "$BADGING" | sed -n '1p'
MIN="$(printf '%s\n' "$BADGING" | sed -n \
  -e "s/^minSdkVersion:'\([0-9]*\)'.*/\1/p" \
  -e "s/^sdkVersion:'\([0-9]*\)'.*/\1/p" | head -1)"
TARGET="$(printf '%s\n' "$BADGING" | sed -n "s/^targetSdkVersion:'\([0-9]*\)'.*/\1/p" | head -1)"
[ "$MIN" = "28" ] && [ "$TARGET" = "28" ] || {
  echo "FAIL: uses-sdk min=$MIN target=$TARGET (want 28/28) — NOT built by gradle; do not ship" >&2
  exit 1
}

echo "== signature =="
APK_CERT="$("$BT/apksigner" verify --print-certs "$APK" \
  | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1 | tr -d ':' | tr 'A-F' 'a-f')"
[ -n "$APK_CERT" ] || { echo "FAIL: APK is not signed"; exit 1; }
echo "APK signing cert SHA-256: $APK_CERT"
# The committed keystore is the persistent sideload key; verifying against it
# (instead of a hard-coded digest that silently drifts) is what guarantees an
# update installs in place. CI-secret builds may lack the file — warn there.
PERSIST_KS="${OPENCODE_SIGNING_KEYSTORE:-keystore/opencode-signing.p12}"
PERSIST_PASS="${OPENCODE_SIGNING_STORE_PASSWORD:-opencode-signing}"
if [ -f "$PERSIST_KS" ]; then
  PERSIST_CERT="$(keytool -list -v -keystore "$PERSIST_KS" -storepass "$PERSIST_PASS" 2>/dev/null \
    | sed -n 's/.*SHA256: //p' | head -1 | tr -d ':' | tr 'A-F' 'a-f')"
  [ -n "$PERSIST_CERT" ] || { echo "FAIL: cannot read signing cert from $PERSIST_KS"; exit 1; }
  if [ "$APK_CERT" != "$PERSIST_CERT" ]; then
    echo "FAIL: APK key $APK_CERT != persistent key $PERSIST_CERT — updates would not install in place" >&2
    exit 1
  fi
  echo "matches persistent key $PERSIST_CERT"
else
  echo "WARN: $PERSIST_KS not present (CI-secret signing?) — persistent key not verified"
fi

echo "== zipalign =="
run_tool "$BT/zipalign" -c 4 "$APK" && echo "aligned"

echo "== bundled asset stored uncompressed =="
unzip -v "$APK" assets/oc_pkg.bin | grep -q " Stored " && echo "stored 0%"

echo "BUILD + GATES OK: $APK"
