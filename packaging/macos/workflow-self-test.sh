#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
: "${SPDX_VALIDATOR:?SPDX_VALIDATOR must name the official SPDX parser/validator}"
[[ -x "$SPDX_VALIDATOR" ]] || {
  printf 'SPDX validator is not executable: %s\n' "$SPDX_VALIDATOR" >&2
  exit 1
}
workflow="$REPO_ROOT/.github/workflows/macos-packaging.yml"
package_script="$REPO_ROOT/packaging/macos/package.sh"
spdx_requirements="$REPO_ROOT/packaging/macos/spdx-tools-requirements.txt"
[[ -f "$workflow" ]] || {
  printf 'missing workflow: %s\n' "$workflow" >&2
  exit 1
}
[[ -f "$package_script" ]] || {
  printf 'missing package script: %s\n' "$package_script" >&2
  exit 1
}
[[ -f "$spdx_requirements" ]] || {
  printf 'missing SPDX tool requirements: %s\n' "$spdx_requirements" >&2
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
grep -F 'contents: write' <<<"$protected_release" >/dev/null
grep -F 'actions/download-artifact@' <<<"$protected_release" >/dev/null
grep -F 'if: always()' <<<"$protected_release" >/dev/null
grep -F 'SHA256SUMS-macos' <<<"$protected_release" >/dev/null
grep -F 'manifest="$state/SHA256SUMS-macos"' <<<"$protected_release" >/dev/null
grep -F '"${artifact#./}"' <<<"$protected_release" >/dev/null
grep -F 'name: Assemble final signed and notarized release' \
  <<<"$protected_release" >/dev/null
grep -F 'macos-arm64-signed-notarized.app.zip' \
  <<<"$protected_release" >/dev/null
grep -F 'COPYFILE_DISABLE=1 ditto -c -k --keepParent "$app" "$app_zip"' \
  <<<"$protected_release" >/dev/null
grep -F 'write_supply_chain "$artifact"' <<<"$protected_release" >/dev/null
grep -F 'FileChecksum: SHA1: $sha1' <<<"$protected_release" >/dev/null
grep -F 'FileChecksum: SHA256: $sha256' <<<"$protected_release" >/dev/null
grep -F 'FileCopyrightText: NOASSERTION' <<<"$protected_release" >/dev/null
grep -F 'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Artifact' \
  <<<"$protected_release" >/dev/null
grep -F 'LicenseInfoInFile: NOASSERTION' <<<"$protected_release" >/dev/null
grep -F '"$SPDX_VALIDATOR" -i "$artifact.spdx"' \
  <<<"$protected_release" >/dev/null
if grep -F 'DocumentDescribes:' <<<"$protected_release" >/dev/null; then
  echo "protected release emits nonstandard SPDX tag/value DocumentDescribes" >&2
  exit 1
fi
grep -F '"$name.spdx" "$name.provenance.json"' \
  <<<"$protected_release" >/dev/null
grep -F 'Protected macOS release asset set is incomplete or unexpected.' \
  <<<"$protected_release" >/dev/null
grep -F 'name: Publish exact bytes to GitHub Release' <<<"$protected_release" >/dev/null
grep -F 'gh release upload "$tag" "$manifest"' \
  <<<"$protected_release" >/dev/null
grep -F 'gh release delete-asset "$tag" "$name" --yes' \
  <<<"$protected_release" >/dev/null
grep -F 'macOS release completion became valid and immutable; retaining published bytes.' \
  <<<"$protected_release" >/dev/null
grep -F 'macOS release completion is valid and immutable; retaining published bytes.' \
  <<<"$protected_release" >/dev/null
grep -F 'completion_state "$release_assets"' <<<"$protected_release" >/dev/null
grep -F 'remote_state' <<<"$protected_release" >/dev/null
grep -F 'remote_digest' <<<"$protected_release" >/dev/null
grep -F '"$remote_state" == "uploaded"' <<<"$protected_release" >/dev/null
grep -F 'gh release delete-asset "$tag" SHA256SUMS-macos --yes' \
  <<<"$protected_release" >/dev/null
if grep -F -- '--clobber' <<<"$protected_release" >/dev/null; then
  echo "protected release publishing must not replace existing asset bytes" >&2
  exit 1
fi
grep -F 'needs: protected-release-contract' <<<"$protected_release" >/dev/null
grep -F 'uses: ./.github/workflows/joint-release-finalize.yml' \
  <<<"$protected_release" >/dev/null

test "$(grep -c 'uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' <<<"$protected_release")" -eq 1
# shellcheck disable=SC2016
grep -F 'ref: ${{ needs.release-policy.outputs.release-sha }}' \
  <<<"$protected_release" >/dev/null
grep -F 'fetch-depth: 1' <<<"$protected_release" >/dev/null
grep -F 'fetch-tags: false' <<<"$protected_release" >/dev/null
grep -F 'persist-credentials: false' <<<"$protected_release" >/dev/null
grep -F '.github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh' \
  <<<"$protected_release" >/dev/null
grep -F 'packaging/macos/spdx-tools-requirements.txt' \
  <<<"$protected_release" >/dev/null
test "$(
  grep -c 'uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065' \
    "$workflow"
)" -eq 2
test "$(
  grep -c 'name: Install checksum-pinned official SPDX validator' "$workflow"
)" -eq 2
grep -F -- '--require-hashes' "$workflow" >/dev/null
grep -F 'spdx-tools==0.8.3' "$spdx_requirements" >/dev/null
grep -F 'sha256:638fd9bd8be61901316eb6d063574e16d5403a1870073ec4d9241426a997501a' \
  "$spdx_requirements" >/dev/null
grep -F 'click==8.3.3' "$spdx_requirements" >/dev/null
grep -F 'semantic-version==2.10.0' "$spdx_requirements" >/dev/null
grep -F 'sha256:de78a3b8e0feda74cabc54aab2da702113e33ac9d9eb9d2389bcf1f58b7d9177' \
  "$spdx_requirements" >/dev/null
test "$(
  grep -c 'importlib.metadata.version("spdx-tools")' "$workflow"
)" -eq 2
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

"$SCRIPT_DIR/joint-release-self-test.sh"

echo "macOS workflow trust-boundary self-tests passed"
