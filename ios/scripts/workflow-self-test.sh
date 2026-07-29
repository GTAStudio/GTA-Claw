#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workspace="$repo_root/ios"
workflow="$repo_root/.github/workflows/ios-packaging.yml"
host="$workspace/apps/gta-claw-ios-shell/src/host.rs"

find "$workspace/scripts" -type f -name '*.sh' -print0 |
  while IFS= read -r -d '' script; do
    bash -n "$script"
  done

grep -F 'version = "=1.17.1"' "$workspace/Cargo.toml" >/dev/null
grep -F '"renderer-skia"' "$workspace/apps/gta-claw-ios-shell/Cargo.toml" >/dev/null
grep -F '"no-compile"' "$workspace/Cargo.toml" >/dev/null
grep -F 'impl HostCredentialStore for SessionCredentialStore' "$host" >/dev/null
grep -F 'impl HostDiscoveryProvider<GatewayMdnsBackend>' "$host" >/dev/null
grep -F 'DiscoveryRemediation::AddInfoPlistDeclaration' "$host" >/dev/null
grep -F 'name = "skia-bindings"' "$workspace/Cargo.lock" >/dev/null
grep -F 'version = "0.99.0"' "$workspace/Cargo.lock" >/dev/null
grep -F '15e20f3265dfddd658f9ef0d0e30d50a73afccb88787812f65fb5e6cf4ec55c8' \
  "$workspace/scripts/fetch-skia.sh" >/dev/null
grep -F 'ade5b153818d9b7b81240f106df148a9c4b92fb3aba566f942a713b93914e11e' \
  "$workspace/scripts/fetch-skia.sh" >/dev/null
grep -F 'cargo deny' "$workflow" >/dev/null
grep -F './ios/scripts/check.sh' "$workflow" >/dev/null
grep -F './ios/scripts/check-targets.sh' "$workflow" >/dev/null
grep -F './ios/scripts/package.sh' "$workflow" >/dev/null
grep -F 'MOBILE_SMOKE_REQUIRED: "1"' "$workflow" >/dev/null
grep -F './ios/scripts/simulator-smoke.sh' "$workflow" >/dev/null

unexpected_curl="$(
  grep -RIl 'curl ' "$workspace" --include='*.sh' |
    grep -Fv "$workspace/scripts/fetch-skia.sh" |
    grep -Fv "$workspace/scripts/workflow-self-test.sh" || true
)"
if [[ -n "$unexpected_curl" ]]; then
  echo "Only fetch-skia.sh may download iOS build artifacts: $unexpected_curl" >&2
  exit 1
fi
