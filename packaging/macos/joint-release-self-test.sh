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
finalizer_workflow="$REPO_ROOT/.github/workflows/joint-release-finalize.yml"
macos_workflow="$REPO_ROOT/.github/workflows/macos-packaging.yml"
windows_workflow="$REPO_ROOT/.github/workflows/windows-packaging.yml"
test_root="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gta-claw-joint-release-test.XXXXXX")"

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM

for tool in awk cmp diff jq shasum unzip zip; do
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
macos_publisher="$test_root/macos-publisher.sh"
windows_publisher="$test_root/windows-publisher.sh"
assembler="$test_root/assembler.sh"
extract_run_step "$finalizer_workflow" "Validate and finalize joint release" "$finalizer"
extract_run_step "$macos_workflow" "Publish exact bytes to GitHub Release" "$macos_publisher"
extract_run_step "$windows_workflow" "Publish exact bytes to GitHub Release" "$windows_publisher"
extract_run_step "$macos_workflow" "Assemble final signed and notarized release" "$assembler"

grep -F -- '- protected-release-contract' "$macos_workflow" >/dev/null
grep -F 'needs: release' "$windows_workflow" >/dev/null
grep -F 'group: macos-desktop-release-' "$macos_workflow" >/dev/null
grep -F 'group: windows-desktop-release-' "$windows_workflow" >/dev/null
grep -F 'group: joint-desktop-finalizer-' "$finalizer_workflow" >/dev/null
for workflow in "$macos_workflow" "$windows_workflow" "$finalizer_workflow"; do
  grep -F 'cancel-in-progress: false' "$workflow" >/dev/null
done
grep -F 'Windows release completion is valid and immutable' "$windows_workflow" >/dev/null
grep -F 'release delete-asset "$tag" SHA256SUMS-macos --yes' \
  "$macos_workflow" >/dev/null
grep -F 'release delete-asset "$tag" SHA256SUMS-windows --yes' \
  "$windows_workflow" >/dev/null
grep -F 'release delete-asset "$tag" "$name" --yes' \
  "$macos_workflow" >/dev/null
grep -F 'release delete-asset "$tag" "$name" --yes' \
  "$windows_workflow" >/dev/null
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
grep -F 'Joint release assets changed after validation; refusing publication.' \
  "$finalizer_workflow" >/dev/null

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
  local digest
  local asset_state
  draft="$(cat "$state/draft")"
  printf '{"isDraft":%s,"assets":[' "$draft"
  local separator=""
  for path in "$assets"/*; do
    [[ -e "$path" ]] || continue
    if command -v sha256sum >/dev/null; then
      digest="$(sha256sum "$path" | awk '{print $1}')"
    else
      digest="$(shasum -a 256 "$path" | awk '{print $1}')"
    fi
    asset_state=uploaded
    if [[ -e "$state/failed-assets/$(basename "$path")" ]]; then
      asset_state=failed
    fi
    printf '%s{"name":"%s","state":"%s","size":%s,"digest":"sha256:%s"}' \
      "$separator" \
      "$(basename "$path")" \
      "$asset_state" \
      "$(wc -c <"$path" | tr -d ' ')" \
      "$digest"
    separator=,
  done
  printf ']}\n'
}

if [[ "${1:-}" == "api" ]]; then
  case "${2:-}" in
    */git/ref/tags/v1.2.3)
      printf '{"object":{"type":"tag","sha":"cccccccccccccccccccccccccccccccccccccccc"}}\n'
      ;;
    */git/tags/cccccccccccccccccccccccccccccccccccccccc)
      printf '{"object":{"type":"commit","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}\n'
      ;;
    *)
      echo "unsupported fake gh api path: ${2:-}" >&2
      exit 2
      ;;
  esac
  exit 0
fi
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
    elif [[ "$jq_filter" == ".isDraft" ]]; then
      cat "$state/draft"
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
    rm -f -- "$state/failed-assets/$2"
    printf 'delete %s\n' "$2" >>"$state/operations"
    ;;
  upload)
    shift
    for path in "$@"; do
      [[ "$path" == "--clobber" ]] && continue
      cp "$path" "$assets/$(basename "$path")"
      rm -f -- "$state/failed-assets/$(basename "$path")"
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
    if [[ -n "${FAKE_GH_FAIL_DOWNLOAD_PATTERN:-}" &&
      "$pattern" == "$FAKE_GH_FAIL_DOWNLOAD_PATTERN" ]]; then
      exit 42
    fi
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
assembly_headless="$assembly_state/release-input/headless"
assembly_distribution="$assembly_state/distribution"
mkdir -p "$assembly_app/Contents/MacOS" "$assembly_headless" "$assembly_distribution"
printf '\000final stapled application bytes\377\n' \
  >"$assembly_app/Contents/MacOS/gta-claw-desktop"
chmod +x "$assembly_app/Contents/MacOS/gta-claw-desktop"
printf 'final notarized and stapled dmg bytes\n' \
  >"$assembly_distribution/gta-claw-1.2.3-macos.dmg"
printf 'final notarized and stapled pkg bytes\n' \
  >"$assembly_distribution/gta-claw-1.2.3-macos.pkg"
for component in gta-claw-cli gta-claw-daemon; do
  artifact="$assembly_headless/$component-1.2.3-macos-arm64.tar.gz"
  printf '%s reviewed headless archive bytes\n' "$component" >"$artifact"
  sha1="$(shasum -a 1 "$artifact" | awk '{print $1}')"
  sha256="$(sha256_file "$artifact")"
  printf '%s  %s\n' "$sha256" "$(basename "$artifact")" >"$artifact.sha256"
  cat >"$artifact.spdx" <<EOF
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: $(basename "$artifact") SBOM
DocumentNamespace: https://github.com/GTAStudio/GTA-Claw/releases/sbom/$sha256
Creator: Tool: GTA-Claw-macOS-Packaging
Created: 2000-01-01T00:00:00Z
FileName: ./$(basename "$artifact")
SPDXID: SPDXRef-Artifact
FileChecksum: SHA1: $sha1
FileChecksum: SHA256: $sha256
LicenseConcluded: NOASSERTION
LicenseInfoInFile: NOASSERTION
FileCopyrightText: NOASSERTION

PackageName: $component
SPDXID: SPDXRef-Package-$component
PackageVersion: 1.2.3
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: MIT
PackageCopyrightText: NOASSERTION

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Artifact
EOF
  "$SPDX_VALIDATOR" -i "$artifact.spdx"
  printf '%s\n' \
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"$(basename "$artifact")\",\"digest\":{\"sha256\":\"$sha256\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\"}" \
    >"$artifact.provenance.json"
done
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$assembly_temp" \
  EXPECTED_PAYLOAD_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  EXPECTED_RELEASE_REF=refs/tags/v1.2.3 \
  EXPECTED_RELEASE_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  EXPECTED_TAG_OBJECT=cccccccccccccccccccccccccccccccccccccccc \
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
gta-claw-cli-1.2.3-macos-arm64.tar.gz
gta-claw-cli-1.2.3-macos-arm64.tar.gz.provenance.json
gta-claw-cli-1.2.3-macos-arm64.tar.gz.sha256
gta-claw-cli-1.2.3-macos-arm64.tar.gz.spdx
gta-claw-daemon-1.2.3-macos-arm64.tar.gz
gta-claw-daemon-1.2.3-macos-arm64.tar.gz.provenance.json
gta-claw-daemon-1.2.3-macos-arm64.tar.gz.sha256
gta-claw-daemon-1.2.3-macos-arm64.tar.gz.spdx
release-identity-macos.json
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
  "$SPDX_VALIDATOR" -i "$artifact.spdx"
  grep -Fx "FileChecksum: SHA1: $sha1" "$artifact.spdx" >/dev/null
  grep -Fx "FileChecksum: SHA256: $sha256" "$artifact.spdx" >/dev/null
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
if "$SPDX_VALIDATOR" -i "$invalid_spdx" >/dev/null 2>&1; then
  echo "official SPDX validator accepted a file without its required SHA-1 checksum" >&2
  exit 1
fi

invalid_spdx="$test_root/invalid-relationship.spdx"
cp "$app_zip.spdx" "$invalid_spdx"
sed \
  's/^Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Artifact$/DocumentDescribes: SPDXRef-Artifact/' \
  "$invalid_spdx" >"$invalid_spdx.tmp"
mv "$invalid_spdx.tmp" "$invalid_spdx"
if "$SPDX_VALIDATOR" -i "$invalid_spdx" >/dev/null 2>&1; then
  echo "official SPDX validator accepted nonstandard DocumentDescribes tag/value" >&2
  exit 1
fi

for name in \
  gta-claw-1.2.3-windows-x64-signed.msi \
  gta-claw-desktop-1.2.3-windows-x64-signed.msix \
  gta-claw-desktop-1.2.3-windows-x64-portable-signed.zip \
  gta-claw-desktop-1.2.3-windows-arm64-signed.msix \
  gta-claw-desktop-1.2.3-windows-arm64-portable-signed.zip \
  gta-claw-desktop-1.2.3-windows-x64_arm64-signed.msixbundle \
  gta-claw-headless-1.2.3-windows-x64-portable-signed.zip \
  gta-claw-headless-1.2.3-windows-arm64-portable-signed.zip; do
  artifact="$fixture/windows/$name"
  printf '%s signed package bytes\n' "$name" >"$artifact"
  digest="$(sha256_file "$artifact")"
  printf '%s  %s\n' "$digest" "$name" >"$artifact.sha256"
  printf '{"spdxVersion":"SPDX-2.3","name":"%s"}\n' "$name" \
    >"$artifact.spdx.json"
  printf '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"%s","digest":{"sha256":"%s"}}]}\n' \
    "$name" "$digest" >"$artifact.provenance.json"
done
cat >"$fixture/windows/release-identity-windows.json" <<'JSON'
{"schema":1,"platform":"windows","version":"1.2.3","releaseCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","annotatedTagObject":"cccccccccccccccccccccccccccccccccccccccc"}
JSON

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
  mkdir -p "$release/assets" "$release/failed-assets"
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
    RELEASE_COMMIT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    RELEASE_TAG_OBJECT=cccccccccccccccccccccccccccccccccccccccc \
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
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-windows-x64-signed.msi")"
distribution="$test_root/handoff/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/handoff" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$macos_publisher"
assert_fixture_bytes macos
[[ "$windows_hash" == "$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-windows-x64-signed.msi")" ]]
[[ "$(tail -n 1 "$FAKE_RELEASE/operations")" == "upload SHA256SUMS-macos" ]]
macos_hash="$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg")"
printf 'different rerun bytes\n' >"$distribution/gta-claw-1.2.3-macos.dmg"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/handoff" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$macos_publisher"
[[ "$macos_hash" == "$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg")" ]] ||
  {
    echo "completed macOS publication was mutated by a rerun" >&2
    exit 1
  }

reset_release
stage_platform macos
operations_before="$(cat "$FAKE_RELEASE/operations")"
distribution="$test_root/macos-download-failure/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
if PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/macos-download-failure" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  FAKE_GH_FAIL_DOWNLOAD_PATTERN=SHA256SUMS-macos \
  bash "$macos_publisher" >/dev/null 2>&1; then
  echo "macOS publisher accepted an unverifiable completion asset" >&2
  exit 1
fi
[[ "$(cat "$FAKE_RELEASE/operations")" == "$operations_before" ]] || {
  echo "macOS publisher mutated release state after a completion download failure" >&2
  exit 1
}
assert_fixture_bytes macos

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
  bash "$macos_publisher"
assert_fixture_bytes macos
assert_fixture_bytes windows
if grep -Fq 'delete SHA256SUMS-windows' "$FAKE_RELEASE/operations" ||
  grep -Fq 'delete gta-claw-1.2.3-windows-x64-signed.msi' \
    "$FAKE_RELEASE/operations"; then
  echo "macOS retry deleted completed Windows assets" >&2
  exit 1
fi

reset_release
stage_platform windows
: >"$FAKE_RELEASE/assets/SHA256SUMS-macos"
printf 'partial macOS bytes\n' \
  >"$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg"
distribution="$test_root/empty-completion/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/empty-completion" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$macos_publisher"
assert_fixture_bytes macos
assert_fixture_bytes windows
grep -Fq 'delete SHA256SUMS-macos' "$FAKE_RELEASE/operations" || {
  echo "macOS retry did not retire an empty completion asset" >&2
  exit 1
}
[[ "$(tail -n 1 "$FAKE_RELEASE/operations")" == "upload SHA256SUMS-macos" ]]
if grep -Fq 'delete SHA256SUMS-windows' "$FAKE_RELEASE/operations"; then
  echo "macOS empty-completion retry deleted Windows completion" >&2
  exit 1
fi

reset_release
stage_platform windows
stage_platform macos
printf 'unterminated-garbage' >>"$FAKE_RELEASE/assets/SHA256SUMS-macos"
distribution="$test_root/trailing-garbage/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/trailing-garbage" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$macos_publisher"
assert_fixture_bytes macos
assert_fixture_bytes windows
grep -Fq 'delete SHA256SUMS-macos' "$FAKE_RELEASE/operations" || {
  echo "macOS retry did not retire completion with unterminated garbage" >&2
  exit 1
}

reset_release
stage_platform windows
printf 'different existing bytes\n' \
  >"$FAKE_RELEASE/assets/gta-claw-1.2.3-macos.dmg"
distribution="$test_root/conflict/gta-claw-release/distribution"
mkdir -p "$distribution"
cp "$fixture/macos"/* "$distribution/"
PATH="$fake_bin:$PATH" \
  RUNNER_TEMP="$test_root/conflict" \
  GITHUB_REF_NAME=v1.2.3 \
  GH_TOKEN=fake \
  bash "$macos_publisher"
assert_fixture_bytes macos
assert_fixture_bytes windows
grep -Fq 'delete gta-claw-1.2.3-macos.dmg' "$FAKE_RELEASE/operations" || {
  echo "macOS retry did not retire an incomplete owned asset" >&2
  exit 1
}
if grep -Fq 'delete SHA256SUMS-windows' "$FAKE_RELEASE/operations" ||
  grep -Fq 'delete gta-claw-1.2.3-windows-x64-signed.msi' \
    "$FAKE_RELEASE/operations"; then
  echo "macOS conflicting-byte retry deleted foreign Windows assets" >&2
  exit 1
fi

windows_workspace="$test_root/windows-workspace"
windows_publication="$windows_workspace/packaging/windows/out/release"
mkdir -p "$windows_publication"
cp "$fixture/windows"/* "$windows_publication/"

reset_release
stage_platform macos
printf 'different existing Windows bytes\n' \
  >"$FAKE_RELEASE/assets/gta-claw-1.2.3-windows-x64-signed.msi"
cp "$fixture/windows/SHA256SUMS-windows" \
  "$FAKE_RELEASE/assets/SHA256SUMS-windows"
touch "$FAKE_RELEASE/failed-assets/SHA256SUMS-windows"
printf 'X' |
  dd of="$FAKE_RELEASE/assets/SHA256SUMS-windows" bs=1 seek=0 conv=notrunc \
    >/dev/null 2>&1
(
  cd "$windows_workspace"
  PATH="$fake_bin:$PATH" \
    GITHUB_REF_NAME=v1.2.3 \
    GH_TOKEN=fake \
    bash "$windows_publisher"
)
assert_fixture_bytes macos
assert_fixture_bytes windows
[[ "$(tail -n 1 "$FAKE_RELEASE/operations")" == "upload SHA256SUMS-windows" ]]
grep -Fq 'delete SHA256SUMS-windows' "$FAKE_RELEASE/operations" || {
  echo "Windows retry did not retire a same-size corrupt completion asset" >&2
  exit 1
}
grep -Fq 'delete gta-claw-1.2.3-windows-x64-signed.msi' \
  "$FAKE_RELEASE/operations" || {
  echo "Windows retry did not retire an incomplete owned asset" >&2
  exit 1
}
if grep -Fq 'delete SHA256SUMS-macos' "$FAKE_RELEASE/operations" ||
  grep -Fq 'delete gta-claw-1.2.3-macos.dmg' "$FAKE_RELEASE/operations"; then
  echo "Windows retry deleted completed macOS assets" >&2
  exit 1
fi

windows_hash="$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-windows-x64-signed.msi")"
printf 'different rerun Windows bytes\n' \
  >"$windows_publication/gta-claw-1.2.3-windows-x64-signed.msi"
(
  cd "$windows_workspace"
  PATH="$fake_bin:$PATH" \
    GITHUB_REF_NAME=v1.2.3 \
    GH_TOKEN=fake \
    bash "$windows_publisher"
)
[[ "$windows_hash" == "$(sha256_file \
  "$FAKE_RELEASE/assets/gta-claw-1.2.3-windows-x64-signed.msi")" ]] ||
  {
    echo "completed Windows publication was mutated by a rerun" >&2
    exit 1
  }

reset_release
stage_platform windows
operations_before="$(cat "$FAKE_RELEASE/operations")"
(
  cd "$windows_workspace"
  if PATH="$fake_bin:$PATH" \
    GITHUB_REF_NAME=v1.2.3 \
    GH_TOKEN=fake \
    FAKE_GH_FAIL_DOWNLOAD_PATTERN=SHA256SUMS-windows \
    bash "$windows_publisher" >/dev/null 2>&1; then
    echo "Windows publisher accepted an unverifiable completion asset" >&2
    exit 1
  fi
)
[[ "$(cat "$FAKE_RELEASE/operations")" == "$operations_before" ]] || {
  echo "Windows publisher mutated release state after a completion download failure" >&2
  exit 1
}
assert_fixture_bytes windows

reset_release
stage_platform macos
stage_platform windows
name="gta-claw-1.2.3-windows-x64-signed.msi"
printf '%064d  %s\n' 0 "$name" >"$FAKE_RELEASE/assets/$name.sha256"
: >"$FAKE_RELEASE/assets/SHA256SUMS-windows"
for path in "$FAKE_RELEASE/assets"/*windows*; do
  [[ "$(basename "$path")" == "SHA256SUMS-windows" ]] && continue
  printf '%s  %s\n' "$(sha256_file "$path")" "$(basename "$path")" \
    >>"$FAKE_RELEASE/assets/SHA256SUMS-windows"
done
if run_finalizer >/dev/null 2>&1; then
  echo "joint finalizer accepted an internally inconsistent per-artifact checksum" >&2
  exit 1
fi
[[ "$(cat "$FAKE_RELEASE/draft")" == "true" ]]

reset_release
stage_platform macos
stage_platform windows
for name in \
  gta-claw-desktop-1.2.3-windows-arm64-signed.msix \
  gta-claw-desktop-1.2.3-windows-arm64-signed.msix.sha256 \
  gta-claw-desktop-1.2.3-windows-arm64-signed.msix.spdx.json \
  gta-claw-desktop-1.2.3-windows-arm64-signed.msix.provenance.json; do
  rm "$FAKE_RELEASE/assets/$name"
  grep -Fv "  $name" "$FAKE_RELEASE/assets/SHA256SUMS-windows" \
    >"$FAKE_RELEASE/assets/SHA256SUMS-windows.tmp"
  mv "$FAKE_RELEASE/assets/SHA256SUMS-windows.tmp" \
    "$FAKE_RELEASE/assets/SHA256SUMS-windows"
done
if run_finalizer >/dev/null 2>&1; then
  echo "joint finalizer accepted self-consistent reduced platform manifests" >&2
  exit 1
fi
[[ "$(cat "$FAKE_RELEASE/draft")" == "true" ]]

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
