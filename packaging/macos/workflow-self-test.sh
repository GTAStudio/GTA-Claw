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

# build.sh runs the headless binaries it has just built, and can only do so when
# the build target matches the host. Every invocation here must therefore be
# `native`; a cross-build invocation would leave the packaged binaries unexecuted
# while the job still passed.
build_invocations="$(grep -F 'packaging/macos/build.sh' "$workflow" || true)"
if [[ -z "$build_invocations" ]]; then
  echo "workflow no longer invokes packaging/macos/build.sh" >&2
  exit 1
fi
while IFS= read -r invocation; do
  if [[ ! "$invocation" =~ packaging/macos/build\.sh[[:space:]]+native([[:space:]]|$) ]]; then
    echo "build.sh must be invoked as native so the execution check cannot be skipped:" >&2
    echo "$invocation" >&2
    exit 1
  fi
done <<<"$build_invocations"

# The candidate binaries are executed in the job that builds them, and that job
# must be the one that holds nothing worth stealing. protected-release-contract:
# is where the signing identity and the notarization credentials are, and it
# only ever inspects the downloaded candidate: running it there would execute
# unsigned candidate code in the one job that can sign on the project's behalf.
#
# Neither half is stated anywhere else, so both are asserted here rather than
# left as a property that happens to hold.
jobs_section="$(sed -n '/^jobs:/,$p' "$workflow")"
executing_jobs=0
while IFS= read -r job; do
  block="$(
    awk -v header="  $job:" '
      $0 == header { inside = 1; next }
      inside && /^  [^ ]/ { inside = 0 }
      inside { print }
    ' <<<"$jobs_section"
  )"
  grep -F 'packaging/macos/build.sh' <<<"$block" >/dev/null || continue
  executing_jobs=$((executing_jobs + 1))
  if grep -E '^    environment:' <<<"$block" >/dev/null; then
    echo "job '$job' executes candidate binaries and must not use a secret environment" >&2
    exit 1
  fi
  if grep -F 'secrets.' <<<"$block" >/dev/null; then
    echo "job '$job' executes candidate binaries and must not read release secrets" >&2
    exit 1
  fi
done <<<"$(grep -E '^  [a-z][a-z0-9-]*:[[:space:]]*$' <<<"$jobs_section" | tr -d ' :')"
if [[ "$executing_jobs" -eq 0 ]]; then
  echo "no workflow job invokes packaging/macos/build.sh" >&2
  exit 1
fi

if grep -F -- '--packaging-self-check' <<<"$protected_release" >/dev/null; then
  echo "protected release job must not run the downloaded candidate app" >&2
  exit 1
fi
# A line that continues the previous one is an argument, not a command: the
# signing step legitimately passes "$app" to codesign on its own line. Only
# lines that actually start a command are candidates for execution, and this
# catches the plain shapes rather than every possible obfuscation -- the rule
# that carries the weight is that this job may run no repository script and
# holds the only credentials worth protecting.
offenders="$(
  awk '
    !continued && $0 ~ /^ *([;&|(]+ *)?(open|"?\$\{?(binary|app|executable)\}?"?)([ \t]|$)/ {
      print $0
    }
    { continued = ($0 ~ /\\$/) }
  ' <<<"$protected_release"
)"
if [[ -n "$offenders" ]]; then
  echo "protected release job must not execute the downloaded candidate app:" >&2
  printf '%s\n' "$offenders" >&2
  exit 1
fi

echo "macOS workflow trust-boundary self-tests passed"