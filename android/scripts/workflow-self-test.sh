#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="$repo_root/android"
workflow="$repo_root/.github/workflows/android-packaging.yml"
shell_source="$workspace/apps/gta-claw-android-shell/src/lib.rs"
shell_ui="$workspace/apps/gta-claw-android-shell/ui/app-window.slint"

find "$workspace/scripts" -type f -name '*.sh' -print0 |
  while IFS= read -r -d '' script; do
    bash -n "$script"
  done

grep -F 'version = "=1.17.1"' "$workspace/Cargo.toml" >/dev/null
grep -F '"no-compile"' "$workspace/Cargo.toml" >/dev/null
grep -F 'min_sdk_version = 26' "$workspace/apps/gta-claw-android-shell/Cargo.toml" >/dev/null
grep -F 'target_sdk_version = 36' "$workspace/apps/gta-claw-android-shell/Cargo.toml" >/dev/null
grep -F 'android.permission.INTERNET' "$workspace/apps/gta-claw-android-shell/Cargo.toml" >/dev/null
grep -F 'AndroidController::start_with_platform' "$shell_source" >/dev/null
grep -F 'handle.app_foregrounded()' "$shell_source" >/dev/null
grep -F 'handle.app_backgrounded()' "$shell_source" >/dev/null
grep -F 'handle.network_changed(NetworkStatus::Unknown)' "$shell_source" >/dev/null
grep -F 'retry_handle.retry()' "$shell_source" >/dev/null
grep -F 'snapshot.revision()' "$shell_source" >/dev/null
grep -F 'callback retry-requested();' "$shell_ui" >/dev/null
grep -F 'platform-notice: root.platform-notice;' "$shell_ui" >/dev/null
grep -F 'name = "skia-bindings"' "$workspace/Cargo.lock" >/dev/null
grep -F '46f267b4754ca3af59b4ef30d273425c9585f2cc5fd20481bac4125c1e6f8217' \
  "$workspace/scripts/fetch-skia.sh" >/dev/null
grep -F 'd691c9891d153466d5b99c0003fc6891482b97fb900b72c27b460b648f4e9534' \
  "$workspace/scripts/fetch-skia.sh" >/dev/null
grep -F 'cargo deny' "$workflow" >/dev/null
grep -F './android/scripts/check-targets.sh' "$workflow" >/dev/null
grep -F './android/scripts/package.sh' "$workflow" >/dev/null

unexpected_curl="$(
  grep -RIl 'curl ' "$workspace" --include='*.sh' |
    grep -Fv "$workspace/scripts/fetch-skia.sh" |
    grep -Fv "$workspace/scripts/workflow-self-test.sh" || true
)"
if [[ -n "$unexpected_curl" ]]; then
  echo "Only fetch-skia.sh may download Android build artifacts: $unexpected_curl" >&2
  exit 1
fi
