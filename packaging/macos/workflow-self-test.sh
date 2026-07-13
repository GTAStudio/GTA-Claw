#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
workflow="$REPO_ROOT/.github/workflows/macos-packaging.yml"
[[ -f "$workflow" ]] || {
  printf 'missing workflow: %s\n' "$workflow" >&2
  exit 1
}

accepts_release_ref() {
  [[ "$1" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

accepts_release_ref refs/tags/v1.2.3
for rejected in \
  refs/heads/main \
  refs/heads/release/v1.2.3 \
  refs/pull/15/merge \
  refs/tags/latest \
  refs/tags/v1.2 \
  refs/tags/v1.2.3-malicious; do
  if accepts_release_ref "$rejected"; then
    echo "arbitrary release ref unexpectedly accepted: $rejected" >&2
    exit 1
  fi
done

release_policy="$(sed -n '/^  release-policy:/,/^  protected-release-contract:/p' "$workflow")"
protected_release="$(sed -n '/^  protected-release-contract:/,$p' "$workflow")"

grep -F "github.event_name == 'workflow_dispatch' && inputs.release == true" \
  <<<"$release_policy" >/dev/null
grep -F 'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+' <<<"$release_policy" >/dev/null
grep -F 'git merge-base --is-ancestor' <<<"$release_policy" >/dev/null
grep -F 'RELEASE_COMMIT' <<<"$release_policy" >/dev/null
grep -F 'persist-credentials: false' <<<"$release_policy" >/dev/null

grep -F "github.event_name == 'workflow_dispatch' && inputs.release == true" \
  <<<"$protected_release" >/dev/null
grep -F 'environment: macos-release' <<<"$protected_release" >/dev/null
grep -F 'actions/download-artifact@' <<<"$protected_release" >/dev/null
grep -F 'if: always()' <<<"$protected_release" >/dev/null

if grep -F 'actions/checkout@' <<<"$protected_release" >/dev/null; then
  echo "protected release job must never checkout repository code" >&2
  exit 1
fi
if grep -E '^    env:' <<<"$protected_release" >/dev/null; then
  echo "protected release job must not define job-scoped secrets" >&2
  exit 1
fi
if grep -E 'packaging/macos/.*\.sh' <<<"$protected_release" >/dev/null; then
  echo "protected release job must not execute downloaded repository scripts" >&2
  exit 1
fi
if ! awk '
  /secrets\./ {
    match($0, /^ */)
    if (RLENGTH != 10) exit 1
    found = 1
  }
  END { if (!found) exit 1 }
' "$workflow"; then
  echo "release secrets must exist only in individual step env mappings" >&2
  exit 1
fi

echo "macOS workflow trust-boundary self-tests passed"
