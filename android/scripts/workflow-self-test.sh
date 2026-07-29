#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="$repo_root/android"
workflow="$repo_root/.github/workflows/android-packaging.yml"
shell_source="$workspace/apps/gta-claw-android-shell/src/lib.rs"
shell_ui="$workspace/apps/gta-claw-android-shell/ui/app-window.slint"
apk_validator="$workspace/scripts/validate-apk-native-member.sh"

find "$workspace/scripts" -type f -name '*.sh' -print0 |
  while IFS= read -r -d '' script; do
    bash -n "$script"
  done

grep -F 'version = "=1.17.1"' "$workspace/Cargo.toml" >/dev/null
grep -F '"no-compile"' "$workspace/Cargo.toml" >/dev/null
grep -F 'min_sdk_version = 26' "$workspace/apps/gta-claw-android-shell/Cargo.toml" >/dev/null
grep -F 'target_sdk_version = 36' "$workspace/apps/gta-claw-android-shell/Cargo.toml" >/dev/null
grep -F 'android.permission.INTERNET' "$workspace/apps/gta-claw-android-shell/Cargo.toml" >/dev/null
grep -F 'snapshot.revision()' "$shell_source" >/dev/null
grep -F 'callback retry-requested();' "$shell_ui" >/dev/null
grep -F 'platform-notice: root.platform-notice;' "$shell_ui" >/dev/null
grep -F 'name = "skia-bindings"' "$workspace/Cargo.lock" >/dev/null
grep -F '46f267b4754ca3af59b4ef30d273425c9585f2cc5fd20481bac4125c1e6f8217' \
  "$workspace/scripts/fetch-skia.sh" >/dev/null
grep -F 'd691c9891d153466d5b99c0003fc6891482b97fb900b72c27b460b648f4e9534' \
  "$workspace/scripts/fetch-skia.sh" >/dev/null
grep -F 'cargo deny' "$workflow" >/dev/null
grep -F 'libfontconfig1-dev' "$workflow" >/dev/null
grep -F './android/scripts/check.sh' "$workflow" >/dev/null
grep -F './android/scripts/check-targets.sh' "$workflow" >/dev/null
grep -F './android/scripts/package.sh' "$workflow" >/dev/null
grep -F './android/scripts/validate-apk-native-member.sh' "$workflow" >/dev/null
grep -F 'MOBILE_SMOKE_REQUIRED: "1"' "$workflow" >/dev/null
grep -F './android/scripts/emulator-smoke.sh' "$workflow" >/dev/null

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/valid/lib/arm64-v8a" "$fixture/invalid/lib/not-arm64-v8a"
printf 'exact native bytes' \
  >"$fixture/valid/lib/arm64-v8a/libgta_claw_android_shell.so"
printf 'near-match native bytes' \
  >"$fixture/invalid/lib/not-arm64-v8a/libgta_claw_android_shell.so"
(cd "$fixture/valid" && zip -q -r "$fixture/valid.apk" .)
(cd "$fixture/invalid" && zip -q -r "$fixture/invalid.apk" .)
"$apk_validator" \
  "$fixture/valid.apk" \
  'lib/arm64-v8a/libgta_claw_android_shell.so'
if "$apk_validator" \
  "$fixture/invalid.apk" \
  'lib/arm64-v8a/libgta_claw_android_shell.so' >/dev/null 2>&1; then
  echo "APK validator accepted a loose native-library suffix match" >&2
  exit 1
fi

unexpected_curl="$(
  grep -RIl 'curl ' "$workspace" --include='*.sh' |
    grep -Fv "$workspace/scripts/fetch-skia.sh" |
    grep -Fv "$workspace/scripts/workflow-self-test.sh" || true
)"
if [[ -n "$unexpected_curl" ]]; then
  echo "Only fetch-skia.sh may download Android build artifacts: $unexpected_curl" >&2
  exit 1
fi
