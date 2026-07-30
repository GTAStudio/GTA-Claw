#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
finalizer_workflow="$REPO_ROOT/.github/workflows/joint-release-finalize.yml"
macos_workflow="$REPO_ROOT/.github/workflows/macos-packaging.yml"
windows_workflow="$REPO_ROOT/.github/workflows/windows-packaging.yml"
test_root="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gta-claw-joint-release-test.XXXXXX")"

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM

for tool in awk cmp diff jq python3 shasum unzip zip; do
  command -v "$tool" >/dev/null || {
    echo "joint release self-test requires $tool" >&2
    exit 1
  }
done

extract_run_step() {
  local workflow="$1"
  local step="$2"
  local output="$3"
  awk -v marker="      - name: $step" '
    $0 == marker { found = 1; next }
    found && $0 == "        run: |" { body = 1; next }
    body && $0 == "" { print ""; next }
    body && substr($0, 1, 10) == "          " {
      print substr($0, 11)
      next
    }
    body { exit }
  ' "$workflow" >"$output"
  [[ -s "$output" ]] || {
    echo "unable to extract workflow step: $step" >&2
    exit 1
  }
  bash -n "$output"
}

finalizer="$test_root/finalizer.sh"
publisher="$test_root/publisher.sh"
assembler="$test_root/assembler.sh"
extract_run_step "$finalizer_workflow" "Validate and finalize joint release" "$finalizer"
extract_run_step "$macos_workflow" "Publish exact bytes to GitHub Release" "$publisher"
extract_run_step "$macos_workflow" "Assemble final signed and notarized release" "$assembler"

grep -F 'needs: protected-release-contract' "$macos_workflow" >/dev/null
grep -F 'needs: release' "$windows_workflow" >/dev/null
grep -F 'Windows release completion is already immutable' "$windows_workflow" >/dev/null
if grep -F 'release delete-asset' "$macos_workflow" "$windows_workflow" >/dev/null; then
  echo "completed platform manifests must never be deleted or replaced" >&2
  exit 1
fi
if grep -F -- '--clobber' "$macos_workflow" "$windows_workflow" >/dev/null; then
  echo "release publishers must never discard existing asset bytes" >&2
  exit 1
fi
test "$(
  awk '
    /uses: \.\/\.github\/workflows\/joint-release-finalize\.yml/ { count += 1 }
    END { print count + 0 }
  ' "$macos_workflow" "$windows_workflow"
)" -eq 2
grep -F 'cancel-in-progress: false' "$finalizer_workflow" >/dev/null

fake_bin="$test_root/bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

state="${FAKE_RELEASE:?}"
assets="$state/assets"
mkdir -p "$assets"

json() {
  local draft
  draft="$(cat "$state/draft")"
  printf '{"isDraft":%s,"assets":[' "$draft"
  local separator=""
  for path in "$assets"/*; do
    [[ -e "$path" ]] || continue
    printf '%s{"name":"%s"}' "$separator" "$(basename "$path")"
    separator=,
  done
  printf ']}\n'
}

[[ "${1:-}" == "release" ]] || exit 2
command="${2:-}"
shift 2
case "$command" in
  view)
    [[ -f "$state/draft" ]] || exit 1
    jq_filter=""
    has_json=0
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --jq)
          jq_filter="$2"
          shift 2
          ;;
        --json)
          has_json=1
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ "$jq_filter" == ".assets[].name" ]]; then
      for path in "$assets"/*; do
        [[ -e "$path" ]] && basename "$path"
      done
    elif [[ "$has_json" -eq 1 ]]; then
      json
    fi
    ;;
  create)
    mkdir -p "$assets"
    printf 'true\n' >"$state/draft"
    ;;
  delete-asset)
    rm -f -- "$assets/$2"
    printf 'delete %s\n' "$2" >>"$state/operations"
    ;;
  upload)
    shift
    for path in "$@"; do
      [[ "$path" == "--clobber" ]] && continue
      cp "$path" "$assets/$(basename "$path")"
      printf 'upload %s\n' "$(basename "$path")" >>"$state/operations"
    done
    ;;
  download)
    shift
    destination=""
    pattern=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --dir)
          destination="$2"
          shift 2
          ;;
        --pattern)
          pattern="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    [[ -n "$destination" ]]
    mkdir -p "$destination"
    for path in "$assets"/*; do
      [[ -e "$path" ]] || continue
      if [[ -z "$pattern" || "$(basename "$path")" == "$pattern" ]]; then
        cp "$path" "$destination/"
      fi
    done
    ;;
  edit)
    if [[ "$(cat "$state/draft")" == "true" ]]; then
      printf 'false\n' >"$state/draft"
      count="$(cat "$state/finalize-count" 2>/dev/null || printf '0')"
      printf '%s\n' "$((count + 1))" >"$state/finalize-count"
    fi
    ;;
  *)
    echo "unsupported fake gh command: $command" >&2
    exit 2
    ;;
esac
EOF
cat >"$fake_bin/ditto" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

source="${@: -2:1}"
destination="${@: -1}"
(
  cd "$(dirname "$source")"
  zip -qry "$destination" "$(basename "$source")"
)
EOF
chmod +x "$fake_bin/ditto" "$fake_bin/gh"

sha256_file() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

fixture="$test_root/fixture"
mkdir -p "$fixture/windows"
assembly_temp="$test_root/assembly"
assembly_state="$assembly_temp/gta-claw-release"
assembly_app="$assembly_state/release-input/GTA Claw.app"
assembly_distribution="$assembly_state/distribution"
mkdir -p "$assembly_app/Contents/MacOS" "$assembly_distribution"
printf '\000final stapled application bytes\377\n' \
  >"$assembly_app/Contents/MacOS/gta-claw-desktop"
chmod +x "$assembly_app/Contents/MacOS/gta-claw-desktop"
printf 'final notarized and stapled dmg bytes\n' \
  >"$assembly_distribution/gta-claw-1.2.3-macos.dmg"
printf 'final notarized and stapled pkg bytes\n' \
  >"$assembly_distribution/gta-claw-1.2.3-macos.pkg"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$assembly_temp" \
  EXPECTED_PAYLOAD_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  EXPECTED_RELEASE_REF=refs/tags/v1.2.3 \
  EXPECTED_RELEASE_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  EXPECTED_VERSION=1.2.3 \
  bash "$assembler"
mv "$assembly_distribution" "$fixture/macos"

app_zip="$fixture/macos/gta-claw-1.2.3-macos-arm64-signed-notarized.app.zip"
unzip -t "$app_zip" >/dev/null
unzip -p "$app_zip" 'GTA Claw.app/Contents/MacOS/gta-claw-desktop' |
  cmp - "$assembly_app/Contents/MacOS/gta-claw-desktop"
cat >"$test_root/expected-macos-assembly" <<'EOF'
gta-claw-1.2.3-macos-arm64-signed-notarized.app.zip
gta-claw-1.2.3-macos-arm64-signed-notarized.app.zip.provenance.json
gta-claw-1.2.3-macos-arm64-signed-notarized.app.zip.spdx
gta-claw-1.2.3-macos.dmg
gta-claw-1.2.3-macos.dmg.provenance.json
gta-claw-1.2.3-macos.dmg.spdx
gta-claw-1.2.3-macos.pkg
gta-claw-1.2.3-macos.pkg.provenance.json
gta-claw-1.2.3-macos.pkg.spdx
EOF
find "$fixture/macos" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
  LC_ALL=C sort >"$test_root/actual-macos-assembly"
diff -u "$test_root/expected-macos-assembly" "$test_root/actual-macos-assembly"
for artifact in "$app_zip" \
  "$fixture/macos/gta-claw-1.2.3-macos.dmg" \
  "$fixture/macos/gta-claw-1.2.3-macos.pkg"; do
  name="$(basename "$artifact")"
  sha1="$(shasum -a 1 "$artifact" | awk '{print $1}')"
  sha256="$(sha256_file "$artifact")"
  python3 "$assembly_state/validate-spdx-tag-value.py" \
    "$artifact.spdx" "$name" "$sha1" "$sha256" 1.2.3
  jq -e \
    --arg digest "$sha256" \
    --arg name "$name" \
    '.subject == [{"name": $name, "digest": {"sha256": $digest}}]' \
    "$artifact.provenance.json" >/dev/null
done

invalid_spdx="$test_root/invalid.spdx"
cp "$app_zip.spdx" "$invalid_spdx"
sed '/^FileChecksum: SHA1:/d' "$invalid_spdx" >"$invalid_spdx.tmp"
mv "$invalid_spdx.tmp" "$invalid_spdx"
if python3 "$assembly_state/validate-spdx-tag-value.py" \
  "$invalid_spdx" "$(basename "$app_zip")" \
  "$(shasum -a 1 "$app_zip" | awk '{print $1}')" \
  "$(sha256_file "$app_zip")" 1.2.3 >/dev/null 2>&1; then
  echo "structured SPDX parser accepted a file without its required SHA-1 checksum" >&2
  exit 1
fi

printf 'Windows signed archive bytes\n' \
  >"$fixture/windows/gta-claw-1.2.3-windows-x64-portable-release.zip"

for platform in macos windows; do
  manifest="$fixture/$platform/SHA256SUMS-$platform"
  : >"$manifest"
  for path in "$fixture/$platform"/*; do
    [[ "$(basename "$path")" == "SHA256SUMS-$platform" ]] && continue
    printf '%s  %s\n' "$(sha256_file "$path")" "$(basename "$path")" >>"$manifest"
  done
done

reset_release() {
  release="$test_root/release"
  rm -rf -- "$release"
  mkdir -p "$release/assets"
  printf 'true\n' >"$release/draft"
  printf '0\n' >"$release/finalize-count"
  : >"$release/operations"
  export FAKE_RELEASE="$release"
}

assert_fixture_bytes() {
  local platform="$1"
  for path in "$fixture/$platform"/*; do
    cmp "$path" "$FAKE_RELEASE/assets/$(basename "$path")"
  done
}

run_finalizer() {
  PATH="$fake_bin:$PATH" \
    RELEASE_TAG=v1.2.3 \
    RUNNER_TEMP="$test_root" \
    GH_TOKEN=fake \
    bash "$finalizer"
}

stage_platform() {
  cp "$fixture/$1"/* "$FAKE_RELEASE/assets/"
}

test_ordering() {
  local first="$1"
  local second="$2"
  reset_release
  stage_platform "$first"
  run_finalizer
  [[ "$(cat "$FAKE_RELEASE/draft")" == "true" ]]
  [[ "$(cat "$FAKE_RELEASE/finalize-count")" == "0" ]]
  assert_fixture_bytes "$first"

  stage_platform "$second"
  run_finalizer
  [[ "$(cat "$FAKE_RELEASE/draft")" == "false" ]]
  [[ "$(cat "$FAKE_RELEASE/finalize-count")" == "1" ]]
  assert_fixture_bytes "$first"
  assert_fixture_bytes "$second"

  run_finalizer
  [[ "$(cat "$FAKE_RELEASE/finalize-count")" == "1" ]]
}

test_ordering macos windows
test_ordering windows macos

reset_release
stage_platform windows
windows_hash="$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-windows-x64-portable-release.zip")"
distribution="$test_root/handoff/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/handoff" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$publisher"
assert_fixture_bytes macos
[[ "$windows_hash" == "$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-windows-x64-portable-release.zip")" ]]
[[ "$(tail -n 1 "$FAKE_RELEASE/operations")" == "upload SHA256SUMS-macos" ]]
macos_hash="$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg")"
printf 'different rerun bytes\n' >"$distribution/gta-claw-1.2.3-macos.dmg"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/handoff" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$publisher"
[[ "$macos_hash" == "$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg")" ]] ||
  {
    echo "completed macOS publication was mutated by a rerun" >&2
    exit 1
  }

reset_release
stage_platform windows
cp "$fixture/macos/gta-claw-1.2.3-macos.dmg" "$FAKE_RELEASE/assets/"
distribution="$test_root/partial/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/partial" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$publisher"
assert_fixture_bytes macos
assert_fixture_bytes windows

reset_release
stage_platform windows
printf 'different existing bytes\n' \
  >"$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg"
distribution="$test_root/conflict/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
if PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/conflict" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$publisher" >/dev/null 2>&1; then
  echo "macOS publisher replaced conflicting existing bytes" >&2
  exit 1
fi

reset_release
stage_platform macos
stage_platform windows
printf 'unexpected bytes\n' >"$FAKE_RELEASE/assets/unexpected.bin"
if run_finalizer >/dev/null 2>&1; then
  echo "joint finalizer accepted an unexpected release asset" >&2
  exit 1
fi
[[ "$(cat "$FAKE_RELEASE/draft")" == "true" ]]

reset_release
stage_platform macos
stage_platform windows
printf 'corrupted bytes\n' \
  >"$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg"
if run_finalizer >/dev/null 2>&1; then
  echo "joint finalizer accepted bytes that differ from SHA256SUMS-macos" >&2
  exit 1
fi
[[ "$(cat "$FAKE_RELEASE/draft")" == "true" ]]

echo "joint release race and byte-handling self-tests passed"
