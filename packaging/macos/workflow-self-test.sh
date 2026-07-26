#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
workflow="$REPO_ROOT/.github/workflows/macos-packaging.yml"
package_script="$REPO_ROOT/packaging/macos/package.sh"
[[ -f "$workflow" ]] || {
  printf 'missing workflow: %s\n' "$workflow" >&2
  exit 1
}
[[ -f "$package_script" ]] || {
  printf 'missing package script: %s\n' "$package_script" >&2
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
grep -Fx 'checksum_name=SHA256SUMS' "$package_script" >/dev/null
grep -F 'shasum -a 256 -c SHA256SUMS' "$workflow" >/dev/null

grep -F "github.event_name == 'workflow_dispatch' && inputs.release == true" \
  <<<"$protected_release" >/dev/null
grep -F 'environment: macos-release' <<<"$protected_release" >/dev/null
grep -F 'actions/download-artifact@' <<<"$protected_release" >/dev/null
grep -F 'if: always()' <<<"$protected_release" >/dev/null

test "$(grep -c 'uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' <<<"$protected_release")" -eq 1
# shellcheck disable=SC2016
grep -F 'ref: ${{ needs.release-policy.outputs.release-sha }}' \
  <<<"$protected_release" >/dev/null
grep -F 'fetch-depth: 1' <<<"$protected_release" >/dev/null
grep -F 'fetch-tags: false' <<<"$protected_release" >/dev/null
grep -F 'persist-credentials: false' <<<"$protected_release" >/dev/null
grep -F 'sparse-checkout: .github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh' \
  <<<"$protected_release" >/dev/null
grep -F 'sparse-checkout-cone-mode: false' <<<"$protected_release" >/dev/null
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

# The signed artifact must be the artifact a test ran against. The containers
# job used to run build.sh, producing a second binary that no test had ever
# executed against; these assertions keep that closed structurally rather than
# relying on nobody re-adding it.
native_job="$(sed -n '/^  native:/,/^  containers:/p' "$workflow")"
containers_job="$(sed -n '/^  containers:/,/^  release-disabled:/p' "$workflow")"
tested_artifact='macos-arm64-tested-build-${{ github.sha }}'

grep -F 'needs: [source-policy, native]' <<<"$containers_job" >/dev/null || {
  echo "containers job must consume the native job it depends on" >&2
  exit 1
}
if grep -E 'packaging/macos/build\.sh' <<<"$containers_job" >/dev/null; then
  echo "containers job must not rebuild: it must package what the native job tested" >&2
  exit 1
fi
grep -F 'transport.sh unpack arm64' <<<"$containers_job" >/dev/null || {
  echo "containers job must restore the tested arm64 build" >&2
  exit 1
}
grep -F 'transport.sh pack arm64' <<<"$native_job" >/dev/null || {
  echo "native job must pack the arm64 build it tested" >&2
  exit 1
}
# shellcheck disable=SC2016
for job_section in "$native_job" "$containers_job"; do
  grep -F "$tested_artifact" <<<"$job_section" >/dev/null || {
    echo "producer and consumer must name the same tested-build artifact" >&2
    exit 1
  }
done

echo "macOS workflow trust-boundary self-tests passed"
