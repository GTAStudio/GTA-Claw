#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
workflow="$REPO_ROOT/.github/workflows/linux-packaging.yml"
[[ -f "$workflow" ]] || {
  printf 'missing workflow: %s\n' "$workflow" >&2
  exit 1
}

if awk '
  /uses:/ {
    split($0, parts, "@")
    if (length(parts) != 2 || parts[2] !~ /^[0-9a-f]{40}$/) {
      print "unpinned action: " $0 > "/dev/stderr"
      bad = 1
    }
  }
  END { exit bad }
' "$workflow"; then
  :
else
  exit 1
fi

for contract in \
  'name: Source policy and shell security' \
  'name: Root Rust, MSRV, deny, and audit' \
  'name: Native x86_64 runtime and packages' \
  'name: Cross-built arm64 layouts' \
  'retention-days: 3' \
  'persist-credentials: false' \
  'cargo metadata --locked --format-version 1' \
  'systemd-analyze verify' \
  'cmp -s' \
  'RELEASE_MODE'; do
  grep -F "$contract" "$workflow" >/dev/null || {
    printf 'workflow contract missing: %s\n' "$contract" >&2
    exit 1
  }
done

if grep -RInE '(^|[[:space:]])(npm|npx|node|nodejs|bun|pnpm)([[:space:]]|$)' \
  "$SCRIPT_DIR" "$workflow" \
  --include='*.sh' --include='*.yml'; then
  echo "JavaScript runtime or package-manager command found in Linux packaging" >&2
  exit 1
fi

if git -C "$REPO_ROOT" ls-files packaging/linux |
  grep -Ei '\.(deb|rpm|tar\.gz|oci|sig|asc|key|pem|crt|bin)$'; then
  echo "Generated package, signature, key, or binary committed under packaging/linux" >&2
  exit 1
fi

if grep -RIlF 'packaging/linux' \
  "$REPO_ROOT/.github/workflows/windows-packaging.yml" \
  "$REPO_ROOT/.github/workflows/macos-packaging.yml" |
  grep .; then
  echo "Existing non-Linux packaging workflows must not execute Linux scripts" >&2
  exit 1
fi

echo "Linux workflow trust-boundary self-tests passed"
