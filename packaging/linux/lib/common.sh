#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

LINUX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd "$LINUX_DIR/../.." && pwd -P)"
SAFEIO_HELPER="$LINUX_DIR/safeio.py"
: "${OUTPUT_ROOT:=$REPO_ROOT/target/linux-package}"

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

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die "this operation requires Linux"
}

assert_no_protected_payload_path() {
  local label="$1"
  local listing="$2"
  if grep -Eq '(^|/)(var/lib/gta-claw-protected)(/|$)' <<<"$listing"; then
    die "$label owns the LinuxProtected namespace or a descendant"
  fi
}

validate_release_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "version must be numeric X.Y.Z: $1"
  [[ "${#1}" -le 32 ]] || die "version exceeds 32 characters"
}

validate_safe_component() {
  local value="$1"
  local label="$2"
  [[ -n "$value" && "${#value}" -le 64 ]] ||
    die "$label must contain 1 to 64 characters"
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
    die "$label is not a safe path component: $value"
  [[ "$value" != *".."* ]] || die "$label contains an ambiguous dot sequence"
}

validate_absolute_path() {
  local path="$1"
  local label="$2"
  local remaining
  local component
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ "$path" != *"\\"* && "$path" != *"//"* ]] ||
    die "$label contains an unsafe separator: $path"
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* && "$path" != *$'\t'* ]] ||
    die "$label contains a control character"
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
  local repository
  local target="${GTA_CLAW_TARGET_ROOT:-$REPO_ROOT/target}"
  local canonical
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    "$SAFEIO_HELPER" check "$SAFEIO_TARGET_FD"
    printf '/proc/self/fd/%s\n' "$SAFEIO_TARGET_FD"
    return
  fi
  repository="$(cd "$REPO_ROOT" && pwd -P)"
  [[ "$repository" == "$REPO_ROOT" ]] || die "repository root changed during validation"
  validate_absolute_path "$target" "canonical target directory"
  [[ ! -L "$target" ]] || die "canonical target directory must not be a symlink"
  if [[ -n "${GTA_CLAW_TARGET_ROOT:-}" ]]; then
    [[ -d "$target" ]] || die "external target root must already exist"
    [[ "$(stat -c '%u:%a' "$target")" == "$(id -u):700" ]] ||
      die "external target root must be caller-owned mode 0700"
  else
    if [[ ! -e "$target" ]]; then
      mkdir -m 0700 -- "$target"
    fi
    [[ "$(stat -c '%u' "$target")" -eq "$(id -u)" ]] ||
      die "canonical target directory is not owned by the current user"
    chmod 0700 -- "$target"
  fi
  [[ -d "$target" && ! -L "$target" ]] ||
    die "canonical target path is not a real directory"
  [[ "$(stat -c '%a' "$target")" == "700" ]] ||
    die "repository target directory is not private"
  canonical="$(cd "$target" && pwd -P)"
  [[ "$canonical" == "$target" ]] ||
    die "canonical target directory changed during validation"
  printf '%s\n' "$canonical"
}

assert_no_symlink_components() {
  local boundary="$1"
  local path="$2"
  local relative
  local component
  local current="$boundary"
  local canonical
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    case "$path" in
      "/proc/self/fd/$SAFEIO_TARGET_FD"/* |\
        "/proc/self/fd/$SAFEIO_OUTPUT_FD"/* |\
        "/proc/self/fd/${SAFEIO_BUILD_FD:-missing}"/*) return ;;
    esac
  fi
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
        [[ "$canonical" == "$current" ]] ||
          die "path component resolves through an alias: $current"
      elif [[ -n "$relative" ]]; then
        die "non-directory component blocks output path: $current"
      fi
    fi
  done
}

assert_nearest_existing_parent() {
  local boundary="$1"
  local path="$2"
  local candidate
  local canonical
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    return
  fi
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
    *) die "nearest existing parent resolves outside target: $canonical" ;;
  esac
}

output_identity() {
  stat -Lc '%d:%i' "$1"
}

output_link_count() {
  stat -c '%h' "$1"
}

assert_output_candidate() {
  local path="$1"
  local target
  validate_absolute_path "$path" "output path"
  target="$(canonical_target_root)"
  case "$path/" in
    "$target/"*) ;;
    *) die "output path must remain below canonical target directory $target" ;;
  esac
  assert_no_symlink_components "$target" "$path"
  assert_nearest_existing_parent "$target" "$path"
}

validate_new_private_root_path() {
  local root="$1"
  local label="$2"
  local target
  validate_absolute_path "$root" "$label"
  target="$(canonical_target_root)"
  [[ "$root" != "$target" && "$root" == "$target/"* ]] ||
    die "$label must be a child of canonical repository target"
  assert_no_symlink_components "$target" "$root"
  assert_nearest_existing_parent "$target" "$root"
  [[ ! -e "$root" && ! -L "$root" ]] || die "$label must be new: $root"
}

assert_private_owned_root() {
  local root="$1"
  local target
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" &&
    "$root" == "/proc/self/fd/${SAFEIO_BUILD_FD:-missing}" ]]; then
    "$SAFEIO_HELPER" check "$SAFEIO_BUILD_FD"
    assert_regular_unaliased "$root/.linux-packaging-owner" "private root ownership marker"
    [[ "$(cat "$root/.linux-packaging-owner")" == "gta-claw-linux-packaging-v2" ]] ||
      die "private root ownership marker is invalid: $root"
    return
  fi
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" &&
    "$root" == "/proc/self/fd/${SAFEIO_OUTPUT_FD:-missing}" ]]; then
    "$SAFEIO_HELPER" check "$SAFEIO_OUTPUT_FD"
    assert_regular_unaliased "$root/.linux-packaging-owner" "private root ownership marker"
    [[ "$(cat "$root/.linux-packaging-owner")" == "gta-claw-linux-packaging-v2" ]] ||
      die "private root ownership marker is invalid: $root"
    return
  fi
  if [[ "${BUILD_MANIFEST_TEST_MODE:-0}" == "1" &&
    "${SAFEIO_ACTIVE:-0}" == "1" &&
    "$root" == "$OUTPUT_ROOT/cases/"* ]]; then
    assert_regular_unaliased "$root/.linux-packaging-owner" "test build ownership marker"
    [[ "$(cat "$root/.linux-packaging-owner")" == "gta-claw-linux-packaging-v2" ]] ||
      die "test build ownership marker is invalid: $root"
    return
  fi
  validate_absolute_path "$root" "private root"
  target="$(canonical_target_root)"
  [[ "$root" != "$target" && "$root" == "$target/"* ]] ||
    die "private root must be a child of repository target"
  assert_no_symlink_components "$target" "$root"
  [[ -d "$root" && ! -L "$root" ]] || die "private root is not a real directory: $root"
  [[ "$(stat -c '%u' "$root")" -eq "$(id -u)" ]] ||
    die "private root is not owned by the current user: $root"
  [[ "$(stat -c '%a' "$root")" == "700" ]] ||
    die "private root mode is not 0700: $root"
  assert_regular_unaliased "$root/.linux-packaging-owner" "private root ownership marker"
  [[ "$(cat "$root/.linux-packaging-owner")" == "gta-claw-linux-packaging-v2" ]] ||
    die "private root ownership marker is invalid: $root"
}

OUTPUT_LOCK_PATH=""
OUTPUT_LOCK_ID=""
OUTPUT_ROOT_ID=""
OUTPUT_LOCK_HELD=0

release_output_lock() {
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    OUTPUT_LOCK_HELD=0
    return
  fi
  if [[ "$OUTPUT_LOCK_HELD" -eq 1 ]]; then
    [[ -d "$OUTPUT_LOCK_PATH" && ! -L "$OUTPUT_LOCK_PATH" ]] ||
      die "output lock changed before release"
    [[ "$(output_identity "$OUTPUT_LOCK_PATH")" == "$OUTPUT_LOCK_ID" ]] ||
      die "output lock identity changed before release"
    rmdir -- "$OUTPUT_LOCK_PATH"
    OUTPUT_LOCK_HELD=0
  fi
}

initialize_output_root() {
  local target
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    [[ "$OUTPUT_ROOT" == "/proc/self/fd/$SAFEIO_OUTPUT_FD" ]] ||
      die "OUTPUT_ROOT does not match inherited safeio capability"
    "$SAFEIO_HELPER" check "$SAFEIO_OUTPUT_FD"
    OUTPUT_ROOT_ID="$(output_identity "$OUTPUT_ROOT")"
    OUTPUT_LOCK_HELD=1
    printf 'gta-claw-linux-packaging-v2\n' |
      "$SAFEIO_HELPER" write "$SAFEIO_OUTPUT_FD" .linux-packaging-owner 0600 \
        >/dev/null
    trap release_output_lock EXIT INT TERM
    assert_output_root_owned
    return
  fi
  validate_absolute_path "$OUTPUT_ROOT" "OUTPUT_ROOT"
  target="$(canonical_target_root)"
  case "$OUTPUT_ROOT/" in
    "$target/"*) ;;
    *) die "OUTPUT_ROOT must remain below canonical target directory $target" ;;
  esac
  [[ "$OUTPUT_ROOT" != "$target" ]] || die "OUTPUT_ROOT must not equal repository target"
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
  assert_nearest_existing_parent "$target" "$OUTPUT_ROOT"
  [[ ! -e "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" ]] ||
    die "OUTPUT_ROOT must be new and exclusively owned: $OUTPUT_ROOT"

  OUTPUT_LOCK_PATH="$OUTPUT_ROOT.lock"
  assert_output_candidate "$OUTPUT_LOCK_PATH"
  [[ ! -e "$OUTPUT_LOCK_PATH" && ! -L "$OUTPUT_LOCK_PATH" ]] ||
    die "output lock already exists: $OUTPUT_LOCK_PATH"
  mkdir -m 0700 -- "$OUTPUT_LOCK_PATH"
  chmod 0700 -- "$OUTPUT_LOCK_PATH"
  OUTPUT_LOCK_ID="$(output_identity "$OUTPUT_LOCK_PATH")"
  OUTPUT_LOCK_HELD=1
  trap release_output_lock EXIT INT TERM

  mkdir -m 0700 -- "$OUTPUT_ROOT"
  chmod 0700 -- "$OUTPUT_ROOT"
  [[ -d "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" ]] ||
    die "failed to create a real OUTPUT_ROOT"
  OUTPUT_ROOT_ID="$(output_identity "$OUTPUT_ROOT")"
  (
    set -o noclobber
    printf 'gta-claw-linux-packaging-v2\n' >"$OUTPUT_ROOT/.linux-packaging-owner"
  )
  chmod 0600 -- "$OUTPUT_ROOT/.linux-packaging-owner"
  assert_output_root_owned
}

adopt_safe_output_root() {
  [[ "${SAFEIO_ACTIVE:-0}" == "1" ]] ||
    die "safe output adoption requires an inherited directory capability"
  [[ "$OUTPUT_ROOT" == "/proc/self/fd/$SAFEIO_OUTPUT_FD" ]] ||
    die "OUTPUT_ROOT does not match inherited safeio capability"
  "$SAFEIO_HELPER" check "$SAFEIO_OUTPUT_FD"
  OUTPUT_ROOT_ID="$(output_identity "$OUTPUT_ROOT")"
  OUTPUT_LOCK_HELD=1
  assert_output_root_owned
}

assert_output_root_owned() {
  local target
  [[ "$OUTPUT_LOCK_HELD" -eq 1 ]] || die "exclusive output lock is not held"
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    "$SAFEIO_HELPER" check "$SAFEIO_OUTPUT_FD"
    [[ "$(output_identity "$OUTPUT_ROOT")" == "$OUTPUT_ROOT_ID" ]] ||
      die "OUTPUT_ROOT capability identity changed"
    assert_regular_unaliased \
      "$OUTPUT_ROOT/.linux-packaging-owner" \
      "OUTPUT_ROOT ownership marker"
    [[ "$(cat "$OUTPUT_ROOT/.linux-packaging-owner")" == "gta-claw-linux-packaging-v2" ]] ||
      die "OUTPUT_ROOT ownership marker changed"
    return
  fi
  [[ -d "$OUTPUT_LOCK_PATH" && ! -L "$OUTPUT_LOCK_PATH" ]] ||
    die "output lock is no longer a real directory"
  [[ "$(output_identity "$OUTPUT_LOCK_PATH")" == "$OUTPUT_LOCK_ID" ]] ||
    die "output lock identity changed"
  [[ -d "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" ]] ||
    die "OUTPUT_ROOT is no longer a real directory"
  [[ "$(output_identity "$OUTPUT_ROOT")" == "$OUTPUT_ROOT_ID" ]] ||
    die "OUTPUT_ROOT identity changed"
  [[ "$(stat -c '%u' "$OUTPUT_ROOT")" -eq "$(id -u)" ]] ||
    die "OUTPUT_ROOT owner changed"
  [[ "$(stat -c '%a' "$OUTPUT_ROOT")" == "700" ]] ||
    die "OUTPUT_ROOT is not private"
  assert_regular_unaliased \
    "$OUTPUT_ROOT/.linux-packaging-owner" \
    "OUTPUT_ROOT ownership marker"
  [[ "$(cat "$OUTPUT_ROOT/.linux-packaging-owner")" == "gta-claw-linux-packaging-v2" ]] ||
    die "OUTPUT_ROOT ownership marker changed"
  target="$(canonical_target_root)"
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
}

assert_output_path() {
  local path="$1"
  assert_output_root_owned
  validate_absolute_path "$path" "output path"
  [[ "$path" == "$OUTPUT_ROOT" || "$path" == "$OUTPUT_ROOT/"* ]] ||
    die "path escapes OUTPUT_ROOT: $path"
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    return
  fi
  assert_no_symlink_components "$(canonical_target_root)" "$path"
  if [[ "$path" != "$OUTPUT_ROOT" ]]; then
    assert_nearest_existing_parent "$OUTPUT_ROOT" "$path"
  fi
}

ensure_output_directory() {
  local path="$1"
  local relative
  local component
  local current="$OUTPUT_ROOT"
  assert_output_path "$path"
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    if [[ "$path" == "$OUTPUT_ROOT" ]]; then
      "$SAFEIO_HELPER" check "$SAFEIO_OUTPUT_FD"
      return
    fi
    "$SAFEIO_HELPER" mkdirs "$SAFEIO_OUTPUT_FD" "${path#"$OUTPUT_ROOT/"}"
    [[ -d "$path" && ! -L "$path" ]] || die "failed to create directory: $path"
    return
  fi
  [[ ! -e "$path" || -d "$path" ]] ||
    die "output directory collides with a non-directory object: $path"
  mkdir -p -- "$path"
  relative="${path#"$OUTPUT_ROOT"}"
  relative="${relative#/}"
  while [[ -n "$relative" ]]; do
    component="${relative%%/*}"
    if [[ "$relative" == */* ]]; then
      relative="${relative#*/}"
    else
      relative=""
    fi
    current="$current/$component"
    [[ -d "$current" && ! -L "$current" ]] ||
      die "output directory component is not a real directory: $current"
    [[ "$(stat -c '%u' "$current")" -eq "$(id -u)" ]] ||
      die "output directory component has an unexpected owner: $current"
    chmod 0700 -- "$current"
  done
  assert_output_path "$path"
  [[ -d "$path" && ! -L "$path" ]] || die "failed to create directory: $path"
}

assert_new_output_file() {
  local path="$1"
  assert_output_path "$path"
  [[ ! -e "$path" && ! -L "$path" ]] ||
    die "output file collision: $path"
}

OPEN_OUTPUT_FD=""
OPEN_OUTPUT_PATH=""
OPEN_OUTPUT_ID=""
OPEN_OUTPUT_PID=""
OPEN_OUTPUT_READ_FD=""

open_output_file() {
  local path="$1"
  local mode="$2"
  local restore_noclobber=0
  [[ -z "$OPEN_OUTPUT_FD" ]] || die "an output file is already open"
  [[ "$mode" =~ ^0[0-7][0-7][0-7]$ ]] || die "invalid output file mode: $mode"
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    assert_output_path "$path"
    coproc SAFEIO_WRITER {
      "$SAFEIO_HELPER" write "$SAFEIO_OUTPUT_FD" "${path#"$OUTPUT_ROOT/"}" "$mode"
    }
    OPEN_OUTPUT_READ_FD="${SAFEIO_WRITER[0]}"
    local coproc_write_fd="${SAFEIO_WRITER[1]}"
    exec {OPEN_OUTPUT_FD}>&"$coproc_write_fd"
    eval "exec $coproc_write_fd>&-"
    OPEN_OUTPUT_PID="$SAFEIO_WRITER_PID"
    OPEN_OUTPUT_PATH="$path"
    local ready
    read -r ready <&"$OPEN_OUTPUT_READ_FD" ||
      die "safeio writer failed before reserving output: $path"
    [[ "$ready" =~ ^READY\ ([0-9]+):([0-9]+)$ ]] ||
      die "safeio writer returned an invalid reservation: $ready"
    OPEN_OUTPUT_ID="${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
    return
  fi
  assert_new_output_file "$path"
  case "$-" in
    *C*) ;;
    *)
      set -o noclobber
      restore_noclobber=1
      ;;
  esac
  if ! exec {OPEN_OUTPUT_FD}>"$path"; then
    [[ "$restore_noclobber" -eq 0 ]] || set +o noclobber
    die "failed to reserve output file: $path"
  fi
  [[ "$restore_noclobber" -eq 0 ]] || set +o noclobber
  OPEN_OUTPUT_PATH="$path"
  OPEN_OUTPUT_ID="$(stat -Lc '%d:%i' "/proc/$BASHPID/fd/$OPEN_OUTPUT_FD")"
  chmod "$mode" "/proc/$BASHPID/fd/$OPEN_OUTPUT_FD"
  assert_regular_unaliased "$path" "reserved output"
  [[ "$(output_identity "$path")" == "$OPEN_OUTPUT_ID" ]] ||
    die "reserved output path does not identify its open file: $path"
}

finish_output_file() {
  local path="$OPEN_OUTPUT_PATH"
  local descriptor
  [[ -n "$OPEN_OUTPUT_FD" && -n "$path" ]] || die "no output file is open"
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    exec {OPEN_OUTPUT_FD}>&-
    if ! wait "$OPEN_OUTPUT_PID"; then
      OPEN_OUTPUT_FD=""
      OPEN_OUTPUT_PATH=""
      OPEN_OUTPUT_ID=""
      OPEN_OUTPUT_PID=""
      OPEN_OUTPUT_READ_FD=""
      die "safeio writer failed: $path"
    fi
    exec {OPEN_OUTPUT_READ_FD}>&- || true
    OPEN_OUTPUT_FD=""
    OPEN_OUTPUT_PATH=""
    OPEN_OUTPUT_ID=""
    OPEN_OUTPUT_PID=""
    OPEN_OUTPUT_READ_FD=""
    unset SAFEIO_WRITER SAFEIO_WRITER_PID
    assert_regular_unaliased "$path" "completed output"
    return
  fi
  descriptor="/proc/$BASHPID/fd/$OPEN_OUTPUT_FD"
  [[ "$(stat -Lc '%d:%i' "$descriptor")" == "$OPEN_OUTPUT_ID" ]] ||
    die "open output descriptor identity changed: $path"
  if [[ ! -f "$path" || -L "$path" || "$(output_identity "$path")" != "$OPEN_OUTPUT_ID" ]]; then
    exec {OPEN_OUTPUT_FD}>&-
    OPEN_OUTPUT_FD=""
    OPEN_OUTPUT_PATH=""
    OPEN_OUTPUT_ID=""
    die "output path changed while its file was open: $path"
  fi
  exec {OPEN_OUTPUT_FD}>&-
  OPEN_OUTPUT_FD=""
  OPEN_OUTPUT_PATH=""
  OPEN_OUTPUT_ID=""
  assert_regular_unaliased "$path" "completed output"
}

write_output_text() {
  local path="$1"
  local mode="$2"
  local content="$3"
  open_output_file "$path" "$mode"
  printf '%s' "$content" >&"$OPEN_OUTPUT_FD"
  finish_output_file
}

assert_regular_file() {
  local path="$1"
  local label="$2"
  [[ -f "$path" && ! -L "$path" ]] || die "$label is not a regular file: $path"
}

assert_regular_unaliased() {
  local path="$1"
  local label="$2"
  assert_regular_file "$path" "$label"
  [[ "$(output_link_count "$path")" -eq 1 ]] ||
    die "$label has multiple hard links: $path"
}

reject_links_and_special_files() {
  local root="$1"
  local bad
  local scan_root="$root"
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" && "$root" == "$OUTPUT_ROOT" ]]; then
    "$SAFEIO_HELPER" check "$SAFEIO_OUTPUT_FD"
    scan_root="$root/"
  else
    [[ -d "$root" && ! -L "$root" ]] || die "tree root is not a real directory: $root"
  fi
  bad="$(find "$scan_root" -type l -print -quit)"
  [[ -z "$bad" ]] || die "symlink is not permitted in staged content: $bad"
  bad="$(find "$scan_root" -type f -links +1 -print -quit)"
  [[ -z "$bad" ]] || die "hard-linked file is not permitted in staged content: $bad"
  bad="$(find "$scan_root" ! -type d ! -type f -print -quit)"
  [[ -z "$bad" ]] || die "special file is not permitted in staged content: $bad"
}

copy_regular_input() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  assert_regular_unaliased "$source" "input"
  ensure_output_directory "$(dirname "$destination")"
  open_output_file "$destination" "$mode"
  cat -- "$source" >&"$OPEN_OUTPUT_FD"
  finish_output_file
  assert_regular_unaliased "$destination" "copied output"
}

copy_verified_input() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local source_identity
  local source_sha
  assert_regular_file "$source" "trusted input"
  source_identity="$(output_identity "$source")"
  source_sha="$(sha256_file "$source")"
  ensure_output_directory "$(dirname "$destination")"
  open_output_file "$destination" "$mode"
  cat -- "$source" >&"$OPEN_OUTPUT_FD"
  finish_output_file
  assert_regular_file "$source" "trusted input after copy"
  [[ "$(output_identity "$source")" == "$source_identity" ]] ||
    die "trusted input identity changed during copy: $source"
  [[ "$(sha256_file "$source")" == "$source_sha" ]] ||
    die "trusted input content changed during copy: $source"
  assert_regular_unaliased "$destination" "copied output"
  [[ "$(sha256_file "$destination")" == "$source_sha" ]] ||
    die "copied output differs from trusted input: $destination"
}

publish_output_file() {
  local temporary="$1"
  local final="$2"
  local identity
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    assert_regular_unaliased "$temporary" "temporary output"
    assert_new_output_file "$final"
    "$SAFEIO_HELPER" publish \
      "$SAFEIO_OUTPUT_FD" \
      "${temporary#"$OUTPUT_ROOT/"}" \
      "${final#"$OUTPUT_ROOT/"}"
    assert_regular_unaliased "$final" "published output"
    return
  fi
  assert_regular_unaliased "$temporary" "temporary output"
  assert_new_output_file "$final"
  identity="$(output_identity "$temporary")"
  mv -T --no-clobber -- "$temporary" "$final"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] ||
    die "temporary output remained after publication: $temporary"
  assert_regular_unaliased "$final" "published output"
  [[ "$(output_identity "$final")" == "$identity" ]] ||
    die "published output is not the reserved file: $final"
}

sha256_file() {
  sha256sum "$1" | awk '{ print $1 }'
}

write_sha256_manifest() {
  local root="$1"
  local output="$2"
  local temporary="$output.tmp"
  local output_relative
  local temporary_relative
  local relative
  assert_output_path "$root"
  assert_new_output_file "$output"
  [[ "$output" == "$root/"* ]] || die "manifest must be written inside its scanned root"
  output_relative="./${output#"$root/"}"
  temporary_relative="$output_relative.tmp"
  open_output_file "$temporary" 0644
  while IFS= read -r -d '' relative; do
    [[ "$relative" != "$output_relative" && "$relative" != "$temporary_relative" ]] ||
      continue
    printf '%s  %s\n' "$(sha256_file "$root/$relative")" "$relative" >&"$OPEN_OUTPUT_FD"
  done < <(cd "$root" && find . -type f -print0 | LC_ALL=C sort -z)
  finish_output_file
  touch --date="@$SOURCE_DATE_EPOCH" "$temporary"
  publish_output_file "$temporary" "$output"
}

verify_sha256_manifest() {
  local root="$1"
  local manifest="$2"
  local manifest_relative
  local declared
  local actual
  (cd "$root" && sha256sum -c "$manifest")
  [[ "$manifest" == "$root/"* ]] || die "checksum manifest must be inside verified root"
  manifest_relative="./${manifest#"$root/"}"
  declared="$(
    awk '
      length($0) >= 67 && substr($0, 65, 2) == "  " {
        print substr($0, 67)
        next
      }
      { exit 1 }
    ' "$manifest" |
      LC_ALL=C sort
  )"
  actual="$(
    cd "$root"
    find . -type f ! -path "$manifest_relative" -print |
      LC_ALL=C sort
  )"
  [[ "$actual" == "$declared" ]] ||
    die "checksum manifest file set does not exactly match verified root"
}

normalize_tree() {
  local root="$1"
  reject_links_and_special_files "$root"
  find "$root" -type d -exec chmod 0755 {} +
  find "$root" -type f -exec touch --date="@$SOURCE_DATE_EPOCH" {} +
  find "$root" -type d -exec touch --date="@$SOURCE_DATE_EPOCH" {} +
}

create_deterministic_tar_gz() {
  local source_parent="$1"
  local source_name="$2"
  local output="$3"
  local temporary="$output.tmp"
  local identity
  assert_output_path "$source_parent/$source_name"
  reject_links_and_special_files "$source_parent/$source_name"
  assert_new_output_file "$output"
  open_output_file "$temporary" 0644
  identity="$OPEN_OUTPUT_ID"
  (
    cd "$source_parent"
    tar \
      --sort=name \
      --format=posix \
      --pax-option=delete=atime,delete=ctime \
      --mtime="@$SOURCE_DATE_EPOCH" \
      --clamp-mtime \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -cf - \
      "$source_name"
  ) | gzip -n -9 >&"$OPEN_OUTPUT_FD"
  finish_output_file
  assert_regular_unaliased "$temporary" "tar temporary"
  [[ "$(output_identity "$temporary")" == "$identity" ]] ||
    die "tar temporary identity changed while writing"
  touch --date="@$SOURCE_DATE_EPOCH" "$temporary"
  publish_output_file "$temporary" "$output"
}

arch_target() {
  case "$1" in
    x86_64) printf 'x86_64-unknown-linux-gnu\n' ;;
    arm64) printf 'aarch64-unknown-linux-gnu\n' ;;
    *) die "unsupported Linux architecture: $1" ;;
  esac
}

deb_arch() {
  case "$1" in
    x86_64) printf 'amd64\n' ;;
    arm64) printf 'arm64\n' ;;
    *) die "unsupported Debian architecture: $1" ;;
  esac
}

rpm_arch() {
  case "$1" in
    x86_64) printf 'x86_64\n' ;;
    arm64) printf 'aarch64\n' ;;
    *) die "unsupported RPM architecture: $1" ;;
  esac
}

oci_arch() {
  case "$1" in
    x86_64) printf 'amd64\n' ;;
    arm64) printf 'arm64\n' ;;
    *) die "unsupported OCI architecture: $1" ;;
  esac
}

validate_elf_arch() {
  local binary="$1"
  local arch="$2"
  assert_regular_file "$binary" "ELF binary"
  python3 "$LINUX_DIR/strict_elf.py" "$binary" "$arch" "$LINUX_GLIBC_CEILING" \
    >/dev/null
}

expected_elf_interpreter() {
  case "$1" in
    x86_64) printf '/lib64/ld-linux-x86-64.so.2\n' ;;
    arm64) printf '/lib/ld-linux-aarch64.so.1\n' ;;
    *) die "unsupported architecture for ELF interpreter: $1" ;;
  esac
}

elf_interpreter() {
  python3 "$LINUX_DIR/strict_elf.py" "$1" auto "$LINUX_GLIBC_CEILING" |
    jq -er '.interpreter'
}

max_glibc_version() {
  local maximum
  maximum="$(
    python3 "$LINUX_DIR/strict_elf.py" "$1" auto "$LINUX_GLIBC_CEILING" |
      jq -er '.maxGlibc'
  )"
  [[ -n "$maximum" ]] || die "ELF has no GLIBC version requirements: $1"
  printf '%s\n' "$maximum"
}

validate_glibc_requirement() {
  local binary="$1"
  local maximum
  maximum="$(max_glibc_version "$binary")"
  if ! printf '%s\n%s\n' "$maximum" "$LINUX_GLIBC_CEILING" | sort -VC; then
    die "ELF requires GLIBC $maximum above pinned ceiling $LINUX_GLIBC_CEILING: $binary"
  fi
}

validate_elf_dependencies() {
  local binary="$1"
  python3 "$LINUX_DIR/strict_elf.py" "$binary" auto "$LINUX_GLIBC_CEILING" \
    >/dev/null
}

validate_elf_binary() {
  assert_regular_file "$1" "ELF binary"
  python3 "$LINUX_DIR/strict_elf.py" "$1" "$2" "$LINUX_GLIBC_CEILING" \
    >/dev/null
}

reject_forbidden_runtime_content() {
  local root="$1"
  local bad
  bad="$(
    find "$root" -type f \( \
      -iname 'node' -o -iname 'nodejs' -o -iname 'npm' -o -iname 'npx' -o \
      -iname 'pnpm' -o -iname 'bun' -o -iname '*.js' -o -iname '*.mjs' -o \
      -iname '*.cjs' -o -iname '*.node' -o -iname '*slint*.so*' \
    \) -print -quit
  )"
  [[ -z "$bad" ]] || die "forbidden runtime or package-manager content: $bad"
}

validate_service_contract() {
  local network_directives
  local service="$1"
  local required
  for required in \
    'Requires=gta-claw-state-init.service' \
    'After=local-fs.target gta-claw-state-init.service' \
    'ConditionFileIsExecutable=/usr/libexec/gta-claw/gta-claw-daemon' \
    'ExecCondition=+/usr/libexec/gta-claw/gta-claw-start-authorized check' \
    'ExecCondition=+/usr/libexec/gta-claw/gta-claw-direct-config network-deny-check gta-claw-daemon.service' \
    'ExecStartPre=!/usr/bin/setpriv --reuid=gta-claw --regid=gta-claw --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- /usr/libexec/gta-claw/gta-claw-daemon --probe --state-profile linux-protected --state-path /var/lib/gta-claw-protected' \
    'ExecStart=!/usr/bin/setpriv --reuid=gta-claw --regid=gta-claw --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- /usr/libexec/gta-claw/gta-claw-daemon --state-profile linux-protected --state-path /var/lib/gta-claw-protected' \
    'EnvironmentFile=/run/gta-claw-state-init/gta-claw.env' \
    'Type=notify' \
    'NotifyAccess=main' \
    'TimeoutStartSec=60s' \
    'User=gta-claw' \
    'Group=gta-claw' \
    'SupplementaryGroups=' \
    'ReadOnlyPaths=/run/gta-claw-state-init' \
    'ReadWritePaths=/var/lib/gta-claw-protected' \
    'NoNewPrivileges=yes' \
    'PrivateTmp=yes' \
    'PrivateDevices=yes' \
    'ProtectSystem=strict' \
    'ProtectHome=yes' \
    'ProtectKernelTunables=yes' \
    'ProtectControlGroups=yes' \
    'CapabilityBoundingSet=CAP_SETGID CAP_SETPCAP CAP_SETUID' \
    'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
    'IPAddressDeny=any' \
    'SystemCallFilter=@system-service setgroups setresgid setresuid' \
    'LoadCredential=gta-claw-config:/etc/gta-claw/credentials/daemon.conf'; do
    grep -Fx "$required" "$service" >/dev/null ||
      die "service hardening contract missing: $required"
  done
  if grep -Eq '^(DynamicUser|StateDirectory)=' "$service"; then
    die "runtime service grants dynamic identity or state-directory mutation authority"
  fi
  if grep -Eiq 'Environment=.*(token|secret|password|private.?key)=' "$service"; then
    die "service embeds a secret-like environment literal"
  fi
  network_directives="$(
    awk -F= '
      /^[[:space:]]*(RestrictAddressFamilies|IPAddressDeny|IPAddressAllow)[[:space:]]*=/ {
        key = $1
        value = substr($0, index($0, "=") + 1)
        gsub(/[[:space:]]/, "", key)
        sub(/^[[:space:]]+/, "", value)
        sub(/[[:space:]]+$/, "", value)
        print key "=" value
      }
    ' "$service"
  )"
  [[ "$(printf '%s\n' "$network_directives" |
    grep -c '^RestrictAddressFamilies=' || true)" == "1" &&
    "$(printf '%s\n' "$network_directives" |
      grep -c '^IPAddressDeny=' || true)" == "1" ]] ||
    die "service network policy contains duplicate effective directives"
  if printf '%s\n' "$network_directives" | grep -q '^IPAddressAllow='; then
    die "package-owned service grants network access instead of requiring an operator drop-in"
  fi
  if grep -Eq '^ExecStart=.*--(listen|socket|config|log)' "$service"; then
    die "service invents a daemon runtime flag"
  fi
}

validate_initializer_service_contract() {
  local service="$1"
  local required
  for required in \
    'After=local-fs.target systemd-sysusers.service' \
    'Before=gta-claw-daemon.service' \
    'RequiresMountsFor=/var/lib' \
    'Type=oneshot' \
    'User=root' \
    'Group=root' \
    'ExecStart=/usr/libexec/gta-claw/gta-claw-state-init' \
    'RemainAfterExit=no' \
    'RuntimeDirectory=gta-claw-state-init' \
    'RuntimeDirectoryMode=0755' \
    'RuntimeDirectoryPreserve=yes' \
    'ReadWritePaths=/var/lib /run/gta-claw-state-init' \
    'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER' \
    'NoNewPrivileges=yes' \
    'ProtectSystem=strict' \
    'IPAddressDeny=any'; do
    grep -Fx "$required" "$service" >/dev/null ||
      die "initializer service contract missing: $required"
  done
  if grep -Eq '^Condition(File|Path)IsExecutable=' "$service"; then
    die "initializer service must fail rather than skip when its helper is unavailable"
  fi
}

validate_sysusers_contract() {
  local config="$1"
  local expected
  expected="$(
    printf '%s\n' \
      'g gta-claw -' \
      'u gta-claw - "GTA Claw service" /nonexistent /usr/sbin/nologin'
  )"
  [[ "$(cat "$config")" == "$expected" ]] ||
    die "sysusers contract must define only the locked gta-claw user and group"
}

validate_initializer_wrapper_contract() {
  local wrapper="$1"
  local required
  local marker_line
  local daemon_line
  for required in \
    'namespace=/var/lib/gta-claw-protected' \
    'runtime_directory=/run/gta-claw-state-init' \
    'failure_marker=$runtime_directory/initialization-failed' \
    'validated_environment=$runtime_directory/gta-claw.env' \
    'configuration_helper=/usr/libexec/gta-claw/gta-claw-direct-config' \
    '"$configuration_helper" materialize / "$environment_file" "$credential_file"' \
    'service_gid="$(getent group gta-claw | cut -d: -f3)"' \
    'if [ "$primary_gid" != "$service_gid" ]; then' \
    'touch "$failure_marker"' \
    'chown 0:0 "$failure_marker"' \
    'chmod 0644 "$failure_marker"' \
    '--provision-linux-protected' \
    '--initialize-linux-protected' \
    '--state-path "$namespace"' \
    '--service-uid "$service_uid"' \
    '--service-gid "$service_gid"' \
    'rm -f "$failure_marker"'; do
    grep -F -- "$required" "$wrapper" >/dev/null ||
      die "initializer wrapper contract missing: $required"
  done
  if grep -Eq \
    '(^|[[:space:]])(rm|unlink|mv|ln|chmod|chown)([[:space:]].*)?gta-claw-protected' \
    "$wrapper"; then
    die "initializer wrapper contains directory-entry repair logic"
  fi
  marker_line="$(grep -nF 'touch "$failure_marker"' "$wrapper" | head -n 1 | cut -d: -f1)"
  daemon_line="$(grep -nF 'if [ ! -x "$daemon" ]; then' "$wrapper" | head -n 1 | cut -d: -f1)"
  [[ -n "$marker_line" && -n "$daemon_line" && "$marker_line" -lt "$daemon_line" ]] ||
    die "initializer wrapper does not establish its failure fence before fallible initialization"
}

validate_runtime_ready_contract() {
  local wrapper="$1"
  local required
  for required in \
    'lock=/var/lib/gta-claw-protected/state.writer.lock' \
    'ready_marker=/run/gta-claw-daemon.ready-for-replacement' \
    'systemctl is-active --quiet gta-claw-daemon.service' \
    'main_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"' \
    'control_pid="$(systemctl show -P ControlPID gta-claw-daemon.service' \
    'ensure_failure_fence' \
    'lslocks --noheadings --notruncate --output PID,PATH' \
    'if [ "$lock_pid" = "$main_pid" ]; then' \
    'if ! main_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"; then' \
    'if ! touch "$ready_marker"; then'; do
    grep -F -- "$required" "$wrapper" >/dev/null ||
      die "runtime readiness contract missing: $required"
  done
}

validate_start_authorization_contract() {
  local wrapper="$1"
  local required
  for required in \
    'failure_marker=$runtime_directory/initialization-failed' \
    'replacement_fence=$runtime_directory/replacement-fenced' \
    'authorization_marker=$runtime_directory/start-authorized' \
    'persistent_runtime_directory=/var/lib/gta-claw-install' \
    'persistent_failure_marker=$persistent_runtime_directory/transaction-failed' \
    'process_start_time()' \
    'process_state="$1"' \
    'Z | X | x) return 1' \
    'authorization_valid()' \
    'arm_authorization()' \
    'clear_authorization()' \
    '[ "$authorized_pid" = "$PPID" ]' \
    '0:0:600:1' \
    'case "${1:-check}" in'; do
    grep -F -- "$required" "$wrapper" >/dev/null ||
      die "start authorization contract missing: $required"
  done
}

validate_direct_lifecycle_contract() {
  local installer="$1"
  local uninstaller="$2"
  local required
  local mask_line
  local stop_line
  local lock_line
  local unlink_line
  for required in \
    'refusing gta-claw downgrade' \
    'gta-claw-direct-config' \
    'persistent_failure_marker=$persistent_runtime_directory/transaction-failed' \
    'persistent_was_active_marker=$persistent_runtime_directory/was-active' \
    'authorization_helper=/usr/libexec/gta-claw/gta-claw-start-authorized' \
    'ensure_failure_fence' \
    'ensure_persistent_failure_fence' \
    'lifecycle_lock=/run/gta-claw-lifecycle.lock' \
    'acquire_lifecycle_lock' \
    '/usr/bin/sync -f "$persistent_failure_marker"' \
    '/usr/bin/sync -f /usr/libexec/gta-claw/gta-claw-daemon' \
    "trap 'cancel_incomplete_install 130' INT" \
    'stop_runtime_for_replacement' \
    'verify_runtime_stopped' \
    'active | activating | reloading | deactivating)' \
    'main_pid="$(systemctl show -P MainPID "$unit")"' \
    'control_pid="$(systemctl show -P ControlPID "$unit")"' \
    'lock_pid="$(lock_holder_pid)"' \
    'replacement_fence=$runtime_directory/replacement-fenced' \
    'stop_initializer_for_replacement' \
    'fail_install_runtime' \
    'systemctl kill' \
    '--kill-whom=all' \
    'systemctl reset-failed gta-claw-daemon.service' \
    '/usr/bin/systemd-sysusers /usr/lib/sysusers.d/gta-claw.conf' \
    '/usr/libexec/gta-claw/gta-claw-state-init' \
    '/usr/libexec/gta-claw/gta-claw-runtime-ready' \
    '"$authorization_helper" arm "$$"' \
    '"$authorization_helper" clear' \
    'systemctl restart gta-claw-daemon.service'; do
    grep -F -- "$required" "$installer" >/dev/null ||
      die "direct installer lifecycle contract missing: $required"
  done
  for required in \
    'persistent_enable_link=/etc/systemd/system/multi-user.target.wants/gta-claw-daemon.service' \
    'runtime_enable_link=/run/systemd/system/multi-user.target.wants/gta-claw-daemon.service' \
    'persistent_mask_link=/etc/systemd/system/gta-claw-daemon.service' \
    'runtime_mask_link=/run/systemd/system/gta-claw-daemon.service' \
    'persistent_failure_marker=$persistent_runtime_directory/transaction-failed' \
    'marker_state()' \
    'capture_link()' \
    'rollback_removal()' \
    'lifecycle_lock=/run/gta-claw-lifecycle.lock' \
    'acquire_lifecycle_lock' \
    "trap 'rollback_removal 130' INT" \
    'acquire_writer_lock' \
    'verify_held_writer_lock' \
    'main_pid="$(systemctl show -P MainPID "$unit")"' \
    'control_pid="$(systemctl show -P ControlPID "$unit")"' \
    'systemctl mask --runtime gta-claw-daemon.service' \
    'payload_mutated=1'; do
    grep -F -- "$required" "$uninstaller" >/dev/null ||
      die "direct uninstaller lifecycle contract missing: $required"
  done
  mask_line="$(
    grep -nF '  systemctl mask --runtime gta-claw-daemon.service' "$uninstaller" |
      tail -n 1 |
      cut -d: -f1
  )"
  stop_line="$(
    grep -nF '  systemctl stop gta-claw-daemon.service' "$uninstaller" |
      tail -n 1 |
      cut -d: -f1
  )"
  lock_line="$(grep -nF 'acquire_writer_lock' "$uninstaller" | tail -n 1 | cut -d: -f1)"
  unlink_line="$(grep -nF 'payload_mutated=1' "$uninstaller" | tail -n 1 | cut -d: -f1)"
  [[ -n "$mask_line" && -n "$stop_line" && -n "$lock_line" &&
    -n "$unlink_line" &&
    "$mask_line" -lt "$stop_line" &&
    "$stop_line" -lt "$lock_line" &&
    "$lock_line" -lt "$unlink_line" ]] ||
    die "direct uninstaller does not mask, stop, lock, and unlink in order"
  grep -F 'preserved /var/lib/gta-claw-protected' "$uninstaller" >/dev/null ||
    die "direct uninstaller does not declare protected-state preservation"
  if grep -Eq 'rm .*gta-claw-protected|rm -[^[:space:]]*r.*gta-claw-protected' \
    "$installer" "$uninstaller"; then
    die "direct lifecycle scripts remove protected state"
  fi
  if grep -F 'systemctl disable --now' "$uninstaller" >/dev/null; then
    die "direct uninstaller disables before proving the runtime stopped"
  fi
}

validate_oci_manifest_digest() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] ||
    die "OCI manifest digest must be exactly 64 lowercase hexadecimal characters"
}

validate_oci_orchestration_templates() {
  local compose="$1"
  local kubernetes="$2"
  local digest=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  assert_regular_file "$compose" "Compose orchestration template"
  assert_regular_file "$kubernetes" "Kubernetes orchestration template"
  python3 "$LINUX_DIR/tests/validate-orchestration.py" \
    --template \
    --repository "$LINUX_OCI_IMAGE_REPOSITORY" \
    --digest "$digest" \
    "$compose" \
    "$kubernetes"
}

render_oci_orchestration() {
  local template="$1"
  local output="$2"
  local digest="$3"
  local image
  validate_oci_manifest_digest "$digest"
  image="$LINUX_OCI_IMAGE_REPOSITORY@sha256:$digest"
  open_output_file "$output" 0644
  sed "s|@OCI_IMAGE_REFERENCE@|$image|g" "$template" >&"$OPEN_OUTPUT_FD"
  finish_output_file
}

validate_oci_orchestration_contract() {
  local compose="$1"
  local kubernetes="$2"
  local digest="$3"
  validate_oci_manifest_digest "$digest"
  python3 "$LINUX_DIR/tests/validate-orchestration.py" \
    --repository "$LINUX_OCI_IMAGE_REPOSITORY" \
    --digest "$digest" \
    "$compose" \
    "$kubernetes"
}

validate_cri_fixture_templates() {
  local digest=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  python3 "$LINUX_DIR/tests/validate-cri-fixtures.py" \
    --template \
    --repository "$LINUX_OCI_IMAGE_REPOSITORY" \
    --digest "$digest" \
    "$1" \
    "$2" \
    "$3"
}

validate_cri_fixture_contract() {
  local digest="$4"
  validate_oci_manifest_digest "$digest"
  python3 "$LINUX_DIR/tests/validate-cri-fixtures.py" \
    --repository "$LINUX_OCI_IMAGE_REPOSITORY" \
    --digest "$digest" \
    "$1" \
    "$2" \
    "$3"
}

reject_unexpected_rpm_scriptlets() {
  local artifact="$1"
  local unexpected_tag
  local unexpected_script
  local unexpected_program
  local trigger_tag
  for unexpected_tag in PRETRANS VERIFYSCRIPT; do
    unexpected_script="$(rpm -qp --qf "%{$unexpected_tag}" "$artifact")"
    [[ -z "$unexpected_script" || "$unexpected_script" == "(none)" ]] ||
      die "RPM contains unexpected $unexpected_tag scriptlet"
    unexpected_program="$(rpm -qp --qf "%{${unexpected_tag}PROG}" "$artifact")"
    [[ -z "$unexpected_program" || "$unexpected_program" == "(none)" ]] ||
      die "RPM contains an unexpected $unexpected_tag interpreter"
  done
  for trigger_tag in \
    TRIGGERSCRIPTS \
    TRIGGERCONDS \
    TRIGGERNAME \
    TRIGGERTYPE \
    FILETRIGGERSCRIPTS \
    FILETRIGGERCONDS \
    FILETRIGGERNAME \
    FILETRIGGERTYPE \
    TRANSFILETRIGGERSCRIPTS \
    TRANSFILETRIGGERCONDS \
    TRANSFILETRIGGERNAME \
    TRANSFILETRIGGERTYPE; do
    [[ -z "$(rpm -qp --qf "[%{$trigger_tag}\n]" "$artifact")" ]] ||
      die "RPM contains unexpected trigger metadata: $trigger_tag"
  done
}

reject_rpm_ghost_files() {
  local artifact="$1"
  local ghost
  ghost="$(
    rpm -qp --qf '[%{FILENAMES}\t%{FILEFLAGS:fflags}\n]' "$artifact" |
      awk -F '\t' 'index($2, "g") { print $1; exit }'
  )"
  [[ -z "$ghost" ]] || die "RPM contains an unexpected ghost path: $ghost"
}

reject_forbidden_rpm_requirements() {
  local artifact="$1"
  if rpm -qp --requires "$artifact" |
    grep -Eiq '(^|[[:space:]])(node|nodejs|npm|npx|pnpm|bun)([[:space:]]|$)'; then
    die "RPM declares a forbidden JavaScript runtime or package-manager dependency"
  fi
}

rpm_relationship_rows() {
  local artifact="$1"
  local prefix="$2"
  local rows
  if ! rows="$(
    rpm -qp \
      --qf "[%{${prefix}NAME}\t%{${prefix}VERSION}\t%{${prefix}FLAGS}\n]" \
      "$artifact"
  )"; then
    die "RPM $prefix relationship arrays could not be queried"
  fi
  printf '%s\n' "$rows" | LC_ALL=C sort
}

validate_exact_rpm_relationships() {
  local artifact="$1"
  local expected_provides="$2"
  local prefix
  [[ "$(rpm_relationship_rows "$artifact" PROVIDE)" == "$expected_provides" ]] ||
    die "RPM Provides arrays differ from the exact package policy"
  for prefix in CONFLICT OBSOLETE RECOMMEND SUGGEST SUPPLEMENT ENHANCE ORDER; do
    [[ -z "$(rpm_relationship_rows "$artifact" "$prefix")" ]] ||
      die "RPM contains an unexpected $prefix relationship"
  done
}

source "$LINUX_DIR/config.sh"
