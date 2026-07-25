#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

MACOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd "$MACOS_DIR/../.." && pwd -P)"
: "${OUTPUT_ROOT:=$REPO_ROOT/target/macos-package}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '==> %s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || die "this operation requires macOS"
}

validate_bundle_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$ ]] ||
    die "invalid bundle identifier: $1"
  [[ "${#1}" -le 255 ]] || die "bundle identifier exceeds 255 characters"
}

validate_release_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be numeric X.Y.Z: $1"
  [[ "${#1}" -le 18 ]] || die "release version exceeds 18 characters"
}

validate_build_version() {
  [[ "$1" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] ||
    die "build version must contain one to three numeric components: $1"
  [[ "${#1}" -le 18 ]] || die "build version exceeds 18 characters"
}

validate_macos_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+$ ]] || die "invalid macOS deployment target: $1"
  awk -v version="$1" 'BEGIN {
    split(version, part, ".")
    if (part[1] < 14) exit 1
  }' || die "minimum macOS version must be 14.0 or newer: $1"
}

validate_safe_component() {
  local value="$1"
  local kind="$2"
  [[ -n "$value" && "${#value}" -le 64 ]] ||
    die "$kind must contain 1 to 64 characters"
  [[ "$value" != *"/"* && "$value" != *"\\"* ]] ||
    die "$kind must be a single path component"
  [[ "$value" != "." && "$value" != ".." && "$value" != *".."* ]] ||
    die "$kind contains an ambiguous dot sequence"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] ||
    die "$kind contains a control character"
  if LC_ALL=C grep -q '[[:cntrl:]]' <<<"$value"; then
    die "$kind contains a control character"
  fi
  case "$kind" in
    APP_NAME)
      [[ "$value" =~ ^[A-Za-z0-9]([[:space:]A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
        die "APP_NAME must start and end with an alphanumeric character"
      ;;
    EXECUTABLE_NAME)
      [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
        die "EXECUTABLE_NAME must be an unspaced executable name"
      ;;
    *)
      [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
        die "$kind must be an unspaced path component"
      ;;
  esac
}

validate_absolute_path_components() {
  local path="$1"
  local label="$2"
  local remaining
  local component
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* ]] ||
    die "$label contains a control character"
  [[ "$path" != *"//"* ]] || die "$label contains an empty path component"
  remaining="${path#/}"
  while [[ -n "$remaining" ]]; do
    component="${remaining%%/*}"
    if [[ "$remaining" == */* ]]; then
      remaining="${remaining#*/}"
    else
      remaining=""
    fi
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] ||
      die "$label contains an ambiguous path component: $path"
  done
}

canonical_target_root() {
  local target="$REPO_ROOT/target"
  local repository
  repository="$(cd "$REPO_ROOT" && pwd -P)"
  [[ "$repository" == "$REPO_ROOT" ]] || die "repository root changed during validation"
  if [[ -L "$target" ]]; then
    die "repository target directory must not be a symlink"
  fi
  if [[ ! -e "$target" ]]; then
    mkdir -- "$target"
  fi
  [[ -d "$target" && ! -L "$target" ]] || die "repository target path is not a directory"
  local canonical
  canonical="$(cd "$target" && pwd -P)"
  [[ "$canonical" == "$target" ]] || die "repository target directory resolves outside the repository"
  printf '%s\n' "$canonical"
}

assert_no_symlink_components() {
  local boundary="$1"
  local path="$2"
  local relative
  local component
  local current="$boundary"
  local canonical
  [[ "$path" == "$boundary" || "$path" == "$boundary/"* ]] ||
    die "path escapes canonical target boundary: $path"
  relative="${path#"$boundary"}"
  relative="${relative#/}"
  while [[ -n "$relative" ]]; do
    component="${relative%%/*}"
    if [[ "$relative" == */* ]]; then
      relative="${relative#*/}"
    else
      relative=""
    fi
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] ||
      die "path contains an ambiguous component: $path"
    current="$current/$component"
    [[ ! -L "$current" ]] || die "path contains a symlink component: $current"
    if [[ -e "$current" ]]; then
      if [[ -d "$current" ]]; then
        canonical="$(cd "$current" && pwd -P)"
        [[ "$canonical" == "$current" ]] || die "path component resolves outside target: $current"
      elif [[ -n "$relative" ]]; then
        die "non-directory path component blocks output path: $current"
      fi
    fi
  done
}

assert_nearest_existing_parent() {
  local boundary="$1"
  local path="$2"
  local candidate
  local canonical
  candidate="$(dirname "$path")"
  while [[ ! -e "$candidate" && ! -L "$candidate" ]]; do
    [[ "$candidate" != "/" ]] || die "no existing parent found for $path"
    candidate="$(dirname "$candidate")"
  done
  [[ -d "$candidate" && ! -L "$candidate" ]] ||
    die "nearest existing parent is not a real directory: $candidate"
  canonical="$(cd "$candidate" && pwd -P)"
  case "$canonical/" in
    "$boundary/"*) ;;
    *) die "nearest existing parent resolves outside canonical target: $canonical" ;;
  esac
}

assert_output_root() {
  local target
  local canonical
  validate_absolute_path_components "$OUTPUT_ROOT" "OUTPUT_ROOT"
  target="$(canonical_target_root)"
  case "$OUTPUT_ROOT/" in
    "$target/"*) ;;
    *) die "OUTPUT_ROOT must remain below canonical target directory $target" ;;
  esac
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
  assert_nearest_existing_parent "$target" "$OUTPUT_ROOT"
  mkdir -p "$OUTPUT_ROOT"
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
  canonical="$(cd "$OUTPUT_ROOT" && pwd -P)"
  [[ "$canonical" == "$OUTPUT_ROOT" ]] || die "OUTPUT_ROOT resolves outside canonical target"
}

assert_output_path() {
  local path="$1"
  local target
  local canonical_parent
  assert_output_root
  validate_absolute_path_components "$path" "output path"
  [[ "$path" == "$OUTPUT_ROOT/"* ]] || die "path escapes OUTPUT_ROOT: $path"
  target="$(canonical_target_root)"
  assert_no_symlink_components "$target" "$path"
  assert_nearest_existing_parent "$target" "$path"
  canonical_parent="$(cd "$(dirname "$path")" 2>/dev/null && pwd -P || true)"
  if [[ -n "$canonical_parent" ]]; then
    case "$canonical_parent/" in
      "$OUTPUT_ROOT/"*) ;;
      *) die "existing output parent resolves outside OUTPUT_ROOT: $canonical_parent" ;;
    esac
  fi
}

assert_output_file_slot() {
  local path="$1"
  assert_output_path "$path"
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -f "$path" && ! -L "$path" ]] ||
      die "output file path collides with a non-regular object: $path"
  fi
}

ensure_output_directory() {
  local path="$1"
  assert_output_path "$path"
  [[ ! -e "$path" || -d "$path" ]] ||
    die "output directory path collides with a non-directory object: $path"
  mkdir -p "$path"
  assert_output_path "$path"
  [[ -d "$path" && ! -L "$path" ]] || die "failed to create a real output directory: $path"
}

remove_output_file() {
  local path="$1"
  assert_output_file_slot "$path"
  rm -f -- "$path"
  assert_output_path "$path"
  [[ ! -e "$path" && ! -L "$path" ]] || die "failed to remove output file: $path"
}

output_file_identity() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f '%d:%i' "$1"
  else
    stat -c '%d:%i' "$1"
  fi
}

safe_reset_dir() {
  local path="$1"
  local target
  assert_output_path "$path"
  [[ "$path" != "$OUTPUT_ROOT" ]] || die "refusing to reset OUTPUT_ROOT itself"
  target="$(canonical_target_root)"
  assert_no_symlink_components "$target" "$path"
  assert_nearest_existing_parent "$target" "$path"
  [[ ! -L "$path" ]] || die "refusing to delete a symlink: $path"
  rm -rf -- "$path"
  # Shell path APIs cannot hold the validated parent open; callers must exclusively own OUTPUT_ROOT.
  assert_output_path "$path"
  ensure_output_directory "$path"
}

reject_symlinks() {
  local root="$1"
  local link
  link="$(find "$root" -type l -print -quit)"
  [[ -z "$link" ]] || die "symlinks are not permitted in staged content: $link"
}

assert_no_javascript_payload() {
  local root="$1"
  local forbidden
  forbidden="$(find "$root" -type f \( \
    -iname 'node' -o -iname 'node.exe' -o -iname 'npm' -o -iname 'npx' -o \
    -iname 'bun' -o -iname 'pnpm' -o -iname 'package.json' -o \
    -iname '*.js' -o -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.node' \
  \) -print -quit)"
  [[ -z "$forbidden" ]] || die "JavaScript or Node runtime material is forbidden: $forbidden"
}

assert_binary_has_no_forbidden_markers() {
  local binary="$1"
  if strings "$binary" |
    grep -Eai '(slint|i-slint|node_modules|package\.json|javascript)' >/dev/null; then
    die "headless binary contains a forbidden GUI or JavaScript marker: $binary"
  fi
}

validate_headless_archive() {
  local archive="$1"
  local component="$2"
  local arch_label="$3"
  local expected_arch="$4"
  local expected_root="$component-$VERSION-macos-$arch_label"
  local inspection="$OUTPUT_ROOT/published-inspection/$expected_root"
  local listing="$inspection.listing"
  local extracted="$inspection/$expected_root"
  assert_output_path "$inspection"
  assert_output_path "$listing"
  safe_reset_dir "$inspection"
  tar -tzf "$archive" >"$listing"
  if grep -E '(^/|(^|/)\.\.(/|$)|\\)' "$listing" >/dev/null; then
    die "headless archive contains an unsafe path: $archive"
  fi
  if tar -tvzf "$archive" | awk '$1 ~ /^[lh]/ { found = 1 } END { exit !found }'; then
    die "headless archive contains a link entry: $archive"
  fi
  tar -xzf "$archive" -C "$inspection"
  reject_symlinks "$inspection"
  local actual
  local expected
  actual="$(cd "$inspection" && find . -type f -print | LC_ALL=C sort)"
  expected="$(printf './%s/%s\n./%s/SHA256SUMS\n' \
    "$expected_root" "$component" "$expected_root" | LC_ALL=C sort)"
  [[ "$actual" == "$expected" ]] || die "headless archive content differs from its allowlist"
  verify_sha256_manifest "$extracted" "$extracted/SHA256SUMS" >/dev/null
  assert_no_javascript_payload "$extracted"
  assert_binary_arches "$extracted/$component" "$expected_arch"
  assert_macho_minimum_version "$extracted/$component"
  validate_macho_dependencies "$extracted/$component" "$OUTPUT_ROOT"
  assert_binary_has_no_forbidden_markers "$extracted/$component"
  safe_reset_dir "$inspection"
  rm -f -- "$listing"
}

assert_headless_cargo_tree() {
  local target="$1"
  local tree
  tree="$(cargo tree \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    --target "$target" \
    --locked \
    --offline \
    --prefix none \
    --format '{p}')" || die "cargo tree failed for the headless workspace target $target"
  if grep -E '^(slint|slint-build|i-slint[-A-Za-z0-9]*) v' <<<"$tree" >/dev/null; then
    die "headless Cargo graph contains Slint for target $target"
  fi
}

sha256_file() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

write_artifact_supply_chain() {
  local artifact="$1"
  local component_set="$2"
  local rust_targets="$3"
  local artifact_name
  local artifact_hash
  local source_revision
  local sbom
  local provenance
  local tree
  local normalized_packages
  local package
  local name
  local version
  local spdx_id
  local target_label
  local target_triple
  local resolved_dependencies
  [[ -f "$artifact" && ! -L "$artifact" ]] || die "missing published artifact: $artifact"
  case "$component_set" in
    desktop | headless | combined) ;;
    *) die "invalid supply-chain component set: $component_set" ;;
  esac
  artifact_name="$(basename "$artifact")"
  artifact_hash="$(sha256_file "$artifact")"
  source_revision="${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
  [[ "$source_revision" =~ ^[0-9a-f]{40}$ ]] || die "invalid provenance source revision"
  sbom="$artifact.spdx"
  provenance="$artifact.provenance.json"
  assert_output_file_slot "$sbom"
  assert_output_file_slot "$provenance"
  case "$component_set" in
    desktop)
      resolved_dependencies="{\"uri\":\"desktop/Cargo.lock\",\"digest\":{\"sha256\":\"$(sha256_file "$REPO_ROOT/desktop/Cargo.lock")\"}}"
      ;;
    headless)
      resolved_dependencies="{\"uri\":\"Cargo.lock\",\"digest\":{\"sha256\":\"$(sha256_file "$REPO_ROOT/Cargo.lock")\"}}"
      ;;
    combined)
      resolved_dependencies="{\"uri\":\"Cargo.lock\",\"digest\":{\"sha256\":\"$(sha256_file "$REPO_ROOT/Cargo.lock")\"}},{\"uri\":\"desktop/Cargo.lock\",\"digest\":{\"sha256\":\"$(sha256_file "$REPO_ROOT/desktop/Cargo.lock")\"}}"
      ;;
  esac

  {
    printf 'SPDXVersion: SPDX-2.3\n'
    printf 'DataLicense: CC0-1.0\n'
    printf 'SPDXID: SPDXRef-DOCUMENT\n'
    printf 'DocumentName: %s SBOM\n' "$artifact_name"
    printf 'DocumentNamespace: https://github.com/GTAStudio/GTA-Claw/releases/sbom/%s\n' "$artifact_hash"
    printf 'Creator: Tool: GTA-Claw-macOS-Packaging\n'
    printf 'Created: 2000-01-01T00:00:00Z\n'
    printf 'DocumentDescribes: SPDXRef-Artifact\n\n'
    printf 'FileName: ./%s\n' "$artifact_name"
    printf 'SPDXID: SPDXRef-Artifact\n'
    printf 'FileChecksum: SHA256: %s\n' "$artifact_hash"
    printf 'LicenseConcluded: NOASSERTION\n'
    printf 'CopyrightText: NOASSERTION\n'

    tree=""
    while IFS= read -r target_label; do
      case "$target_label" in
        arm64) target_triple="aarch64-apple-darwin" ;;
        x86_64) target_triple="x86_64-apple-darwin" ;;
        *) die "invalid SBOM Rust target label: $target_label" ;;
      esac
      if [[ "$component_set" == "desktop" || "$component_set" == "combined" ]]; then
        tree+="$(cargo tree \
          --manifest-path "$REPO_ROOT/desktop/Cargo.toml" \
          --target "$target_triple" \
          --locked --offline --prefix none --format '{p}')"$'\n'
      fi
      if [[ "$component_set" == "headless" || "$component_set" == "combined" ]]; then
        tree+="$(cargo tree \
          --manifest-path "$REPO_ROOT/Cargo.toml" \
          --target "$target_triple" \
          --locked --offline --prefix none --format '{p}')"$'\n'
      fi
    done < <(tr ' ' '\n' <<<"$rust_targets" | sed '/^$/d')
    normalized_packages=""
    while IFS= read -r package; do
      [[ "$package" =~ ^([^[:space:]]+)[[:space:]]v([^[:space:]]+) ]] || continue
      name="${BASH_REMATCH[1]}"
      version="${BASH_REMATCH[2]}"
      normalized_packages+="$name $version"$'\n'
    done <<<"$tree"
    while read -r name version; do
      [[ -n "$name" && -n "$version" ]] || continue
      spdx_id="$(printf '%s-%s' "$name" "$version" | tr -c 'A-Za-z0-9.-' '-')"
      printf '\nPackageName: %s\n' "$name"
      printf 'SPDXID: SPDXRef-Package-%s\n' "$spdx_id"
      printf 'PackageVersion: %s\n' "$version"
      printf 'PackageDownloadLocation: NOASSERTION\n'
      printf 'FilesAnalyzed: false\n'
      printf 'PackageLicenseConcluded: NOASSERTION\n'
      printf 'PackageLicenseDeclared: NOASSERTION\n'
      printf 'PackageCopyrightText: NOASSERTION\n'
      printf 'ExternalRef: PACKAGE-MANAGER purl pkg:cargo/%s@%s\n' "$name" "$version"
    done < <(LC_ALL=C sort -u <<<"$normalized_packages")
  } >"$sbom"

  printf '%s\n' \
    "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"$artifact_name\",\"digest\":{\"sha256\":\"$artifact_hash\"}}],\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"buildType\":\"https://github.com/GTAStudio/GTA-Claw/packaging/macos/v1\",\"externalParameters\":{\"componentSet\":\"$component_set\",\"profile\":\"release\",\"rustTargets\":\"$rust_targets\",\"offline\":true},\"internalParameters\":{},\"resolvedDependencies\":[$resolved_dependencies]},\"runDetails\":{\"builder\":{\"id\":\"https://github.com/GTAStudio/GTA-Claw/.github/workflows/macos-packaging.yml\"},\"metadata\":{\"invocationId\":\"$source_revision\"}}}}" \
    >"$provenance"
  test_artifact_supply_chain "$artifact"
}

test_artifact_supply_chain() {
  local artifact="$1"
  local artifact_name
  local artifact_hash
  local sbom="$artifact.spdx"
  local provenance="$artifact.provenance.json"
  artifact_name="$(basename "$artifact")"
  artifact_hash="$(sha256_file "$artifact")"
  [[ -f "$sbom" && ! -L "$sbom" && -f "$provenance" && ! -L "$provenance" ]] ||
    die "artifact lacks SBOM or provenance companions: $artifact"
  grep -F "FileName: ./$artifact_name" "$sbom" >/dev/null ||
    die "SBOM does not name published artifact: $artifact"
  grep -F "FileChecksum: SHA256: $artifact_hash" "$sbom" >/dev/null ||
    die "SBOM does not hash published artifact: $artifact"
  grep -F "\"name\":\"$artifact_name\",\"digest\":{\"sha256\":\"$artifact_hash\"}" \
    "$provenance" >/dev/null ||
    die "provenance does not attest published artifact: $artifact"
  [[ -n "$(awk '$1 == "PackageName:" { print $2; exit }' "$sbom")" ]] ||
    die "SBOM has no package inventory: $artifact"
  [[ -z "$(awk '$1 == "SPDXID:" { print $2 }' "$sbom" | LC_ALL=C sort | uniq -d)" ]] ||
    die "SBOM contains duplicate SPDX identifiers: $artifact"
}

write_artifact_set_checksums() {
  local root="$1"
  local manifest_name="${2:-SHA256SUMS}"
  [[ "$manifest_name" =~ ^SHA256SUMS(-[a-z]+)?$ ]] ||
    die "invalid artifact checksum manifest name: $manifest_name"
  local manifest="$root/$manifest_name"
  write_sha256_manifest "$root" "$manifest"
  verify_sha256_manifest "$root" "$manifest" >/dev/null
}

write_sha256_manifest() {
  local root="$1"
  local output="$2"
  local relative
  local temporary="$output.tmp"
  local output_relative=""
  local temporary_relative=""
  local restore_noclobber=0
  local reserved_identity
  if [[ "$root" == "$OUTPUT_ROOT/"* ]]; then
    assert_output_path "$root"
  fi
  assert_output_file_slot "$output"
  assert_output_path "$temporary"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] ||
    die "temporary manifest path already exists: $temporary"
  if [[ "$output" == "$root/"* ]]; then
    output_relative="./${output#"$root/"}"
    temporary_relative="$output_relative.tmp"
  fi
  case "$-" in
    *C*) ;;
    *)
      set -o noclobber
      restore_noclobber=1
      ;;
  esac
  if ! exec 9>"$temporary"; then
    [[ "$restore_noclobber" -eq 0 ]] || set +o noclobber
    die "failed to reserve temporary manifest: $temporary"
  fi
  [[ "$restore_noclobber" -eq 0 ]] || set +o noclobber
  reserved_identity="$(output_file_identity "$temporary")"
  while IFS= read -r relative; do
    [[ "$relative" != "$output_relative" && "$relative" != "$temporary_relative" ]] || continue
    printf '%s  %s\n' "$(sha256_file "$root/$relative")" "$relative" >&9
  done < <(cd "$root" && find . -type f -print | LC_ALL=C sort)
  assert_output_file_slot "$output"
  assert_output_file_slot "$temporary"
  [[ "$(output_file_identity "$temporary")" == "$reserved_identity" ]] ||
    die "temporary manifest changed before publication: $temporary"
  # The exclusive OUTPUT_ROOT contract closes the remaining validation-to-rename shell race.
  mv "$temporary" "$output"
  assert_output_file_slot "$output"
  [[ "$(output_file_identity "$output")" == "$reserved_identity" ]] ||
    die "published manifest is not the reserved file: $output"
  exec 9>&-
}

verify_sha256_manifest() {
  local root="$1"
  local manifest="$2"
  local line
  local relative
  local manifest_relative=""
  local recorded=""
  local expected
  local recorded_sorted
  [[ -f "$manifest" && ! -L "$manifest" ]] || die "missing checksum manifest: $manifest"
  if [[ "$manifest" == "$root/"* ]]; then
    manifest_relative="./${manifest#"$root/"}"
  fi
  while IFS= read -r line; do
    [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]](\./.+)$ ]] ||
      die "invalid checksum manifest entry: $line"
    relative="${BASH_REMATCH[2]}"
    [[ "$relative" != *\\* && "/${relative#./}/" != */../* &&
      "/${relative#./}/" != */./* ]] ||
      die "unsafe checksum manifest path: $relative"
    [[ -f "$root/$relative" && ! -L "$root/$relative" ]] ||
      die "checksum manifest entry is not a plain file: $relative"
    recorded+="$relative"$'\n'
  done <"$manifest"
  [[ -n "$recorded" ]] || die "checksum manifest is empty: $manifest"
  expected="$(
    cd "$root"
    find . -type f -print |
      { if [[ -n "$manifest_relative" ]]; then grep -Fvx "$manifest_relative"; else cat; fi; } |
      LC_ALL=C sort
  )"
  recorded_sorted="$(printf '%s' "$recorded" | sed '/^$/d' | LC_ALL=C sort)"
  [[ "$recorded_sorted" == "$expected" ]] ||
    die "checksum manifest coverage differs from published files below $root"
  (cd "$root" && shasum -a 256 -c "$manifest")
}

expected_lipo_arch() {
  case "$1" in
    aarch64-apple-darwin | arm64) printf 'arm64\n' ;;
    x86_64-apple-darwin | x86_64) printf 'x86_64\n' ;;
    universal2) printf 'arm64 x86_64\n' ;;
    *) die "unsupported macOS architecture or target: $1" ;;
  esac
}

host_target() {
  rustc -vV | awk '/^host:/ { print $2 }'
}

assert_binary_arches() {
  local binary="$1"
  local expected="$2"
  [[ -f "$binary" && ! -L "$binary" ]] || die "missing regular Mach-O file: $binary"
  local actual
  actual="$(lipo -archs "$binary" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
  expected="$(
    printf '%s\n' "$expected" |
      tr ' ' '\n' |
      sed '/^$/d' |
      LC_ALL=C sort |
      tr '\n' ' ' |
      sed 's/ $//'
  )"
  [[ "$actual" == "$expected" ]] ||
    die "architecture mismatch for $binary (expected '$expected', found '$actual')"
}

macho_dependencies() {
  local output
  output="$(otool -L "$1")" || return 1
  tail -n +2 <<<"$output" |
    sed -E 's/^[[:space:]]*//; /:$/d; s/[[:space:]]+\(compatibility version.*$//' |
    LC_ALL=C sort -u
}

macho_rpaths() {
  local output
  output="$(otool -l "$1")" || return 1
  awk '
      $1 == "cmd" && $2 == "LC_RPATH" { in_rpath = 1; next }
      in_rpath && $1 == "path" { print $2; in_rpath = 0 }
    ' <<<"$output" |
    LC_ALL=C sort -u
}

macho_minimum_versions() {
  local output
  output="$(otool -l "$1")" || return 1
  awk '
      $1 == "cmd" && ($2 == "LC_BUILD_VERSION" || $2 == "LC_VERSION_MIN_MACOSX") {
        in_version = 1
        next
      }
      in_version && ($1 == "minos" || $1 == "version") {
        print $2
        in_version = 0
      }
    ' <<<"$output" |
    LC_ALL=C sort -u
}

assert_macho_minimum_version() {
  local binary="$1"
  local found=0
  local version
  local versions
  versions="$(macho_minimum_versions "$binary")" ||
    die "otool could not inspect minimum versions for $binary"
  while IFS= read -r version; do
    [[ -n "$version" ]] || continue
    found=1
    [[ "$version" == "$MINIMUM_MACOS_VERSION" || "$version" == "$MINIMUM_MACOS_VERSION.0" ]] ||
      die "deployment target mismatch for $binary (expected $MINIMUM_MACOS_VERSION, found $version)"
  done <<<"$versions"
  [[ "$found" -eq 1 ]] || die "no macOS deployment target found in $binary"
}

validate_macho_dependencies() {
  local binary="$1"
  local dependency
  local dependencies
  local allowed
  local matched
  dependencies="$(macho_dependencies "$binary")" ||
    die "otool could not inspect dependencies for $binary"
  while IFS= read -r dependency; do
    [[ -n "$dependency" ]] || continue
    matched=0
    while IFS= read -r allowed; do
      [[ -n "$allowed" && "$allowed" != \#* ]] || continue
      if [[ "$dependency" == "$allowed"* ]]; then
        matched=1
        break
      fi
    done <"$MACOS_DIR/dependencies.allowlist"
    if [[ "$dependency" == @rpath/* ]]; then
      local embedded="$2/Contents/Frameworks/${dependency#@rpath/}"
      [[ -f "$embedded" && ! -L "$embedded" ]] ||
        die "unresolved bundled dependency $dependency for $binary"
      matched=1
    fi
    [[ "$matched" -eq 1 ]] || die "unexpected dynamic dependency in $binary: $dependency"
  done <<<"$dependencies"

  local rpath
  local rpaths
  rpaths="$(macho_rpaths "$binary")" ||
    die "otool could not inspect rpaths for $binary"
  while IFS= read -r rpath; do
    [[ -n "$rpath" ]] || continue
    case "$rpath" in
      @executable_path/../Frameworks | @loader_path/../Frameworks) ;;
      *) die "unexpected LC_RPATH in $binary: $rpath" ;;
    esac
  done <<<"$rpaths"
}

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1"
}

assert_app_executable_contract() {
  local app="$1"
  local contents="$app/Contents"
  local macos="$contents/MacOS"
  local plist="$contents/Info.plist"
  local executable="$macos/gta-claw-desktop"
  local -a entries=()
  local entry

  [[ -d "$app" && ! -L "$app" ]] || die "invalid app bundle: $app"
  [[ -d "$contents" && ! -L "$contents" ]] || die "invalid app Contents directory"
  [[ -d "$macos" && ! -L "$macos" ]] || die "invalid app MacOS directory"
  [[ -f "$plist" && ! -L "$plist" ]] || die "invalid app Info.plist"
  reject_symlinks "$app"
  /usr/bin/plutil -lint "$plist" >/dev/null
  /usr/bin/cmp -s \
    <(/usr/bin/plutil -extract CFBundleExecutable raw -expect string -o - "$plist") \
    <(/usr/bin/printf 'gta-claw-desktop\n') ||
    die "CFBundleExecutable must be exactly gta-claw-desktop"
  while IFS= read -r -d '' entry; do
    entries+=("$entry")
  done < <(/usr/bin/find "$macos" -mindepth 1 -maxdepth 1 -print0)
  [[ "${#entries[@]}" -eq 1 && "${entries[0]}" == "$executable" ]] ||
    die "Contents/MacOS must contain only gta-claw-desktop"
  [[ -f "$executable" && ! -L "$executable" && -x "$executable" ]] ||
    die "canonical app executable is not a regular executable"
}

source "$MACOS_DIR/config.sh"
assert_output_root
