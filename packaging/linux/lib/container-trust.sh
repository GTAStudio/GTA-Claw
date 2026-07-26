#!/usr/bin/env bash
# shellcheck disable=SC2034

SOURCE_SNAPSHOT_ROOT=""
SOURCE_SNAPSHOT_ROOT_ID=""
SOURCE_SNAPSHOT_ARCHIVE=""
SOURCE_SNAPSHOT_DIRECTORY=""
SOURCE_COMMIT=""
SOURCE_TREE=""
SOURCE_TREE_RECEIPT=""
SOURCE_EPOCH=""
OUTPUT_COMPONENT_PATH=""
OUTPUT_COMPONENT_LOCK=""
OUTPUT_COMPONENT_ID=""
OUTPUT_COMPONENT_FD=""
BUILD_COMPONENT_PATH=""
BUILD_COMPONENT_ID=""
BUILD_COMPONENT_FD=""
ARTIFACT_COMPONENT_PATH=""
ARTIFACT_COMPONENT_ID=""
ARTIFACT_COMPONENT_FD=""

physical_directory() {
  local path="$1"
  local label="$2"
  local physical
  physical="$(realpath -e -- "$path")" || die "$label cannot be resolved physically"
  [[ -d "$physical" && ! -L "$physical" ]] || die "$label is not a physical directory"
  printf '%s\n' "$physical"
}

path_identity() {
  stat -Lc '%d:%i' "$1"
}

mount_receipt() {
  local path="$1"
  local receipt
  receipt="$(findmnt -T "$path" -n -P -o TARGET,SOURCE,FSTYPE,FSROOT,MAJ:MIN)" ||
    die "mount identity cannot be resolved: $path"
  [[ -n "$receipt" ]] || die "mount identity is empty: $path"
  printf '%s\n' "$receipt"
}

filesystem_receipt() {
  local path="$1"
  local label="$2"
  local physical
  local mount_target
  local filesystem_root
  local device
  local relative
  local underlying
  physical="$(physical_directory "$path" "$label")"
  mount_target="$(findmnt -T "$physical" -rn -o TARGET)" ||
    die "$label mount target cannot be resolved"
  filesystem_root="$(findmnt -T "$physical" -rn -o FSROOT)" ||
    die "$label filesystem root cannot be resolved"
  device="$(findmnt -T "$physical" -rn -o MAJ:MIN)" ||
    die "$label filesystem device cannot be resolved"
  [[ -n "$mount_target" && -n "$filesystem_root" &&
    "$device" =~ ^[0-9]+:[0-9]+$ ]] ||
    die "$label filesystem receipt is incomplete"
  if [[ "$mount_target" == "/" ]]; then
    relative="${physical#/}"
  elif [[ "$physical" == "$mount_target" ]]; then
    relative=""
  else
    case "$physical/" in
      "$mount_target/"*) ;;
      *) die "$label path is outside its reported mount target" ;;
    esac
    relative="${physical#"$mount_target"/}"
  fi
  underlying="$(
    python3 - "$filesystem_root" "$relative" <<'PY'
import posixpath
import sys

root, relative = sys.argv[1:]
value = posixpath.normpath(posixpath.join("/", root.lstrip("/"), relative))
print(value)
PY
  )"
  [[ "$underlying" == /* && "$underlying" != *"/../"* ]] ||
    die "$label filesystem path could not be normalized"
  printf '%s|%s\n' "$device" "$underlying"
}

path_is_ancestor() {
  local ancestor="${1%/}"
  local path="${2%/}"
  [[ "$path" == "$ancestor" || "$path" == "$ancestor/"* ]]
}

identity_is_ancestor() {
  local expected="$1"
  local path="$2"
  local current="$path"
  local parent
  while :; do
    [[ "$(path_identity "$current")" != "$expected" ]] || return 0
    [[ "$current" != "/" ]] || return 1
    parent="$(dirname "$current")"
    [[ "$parent" != "$current" ]] || return 1
    current="$parent"
  done
}

assert_no_nested_mounts() {
  local path="$1"
  local label="$2"
  local physical
  local target
  physical="$(physical_directory "$path" "$label")"
  while IFS= read -r target; do
    [[ -n "$target" ]] || die "$label mount inventory contains an empty target"
    if [[ "$target" != "$physical" && "$target" == "$physical/"* ]]; then
      die "$label contains a nested mount: $target"
    fi
  done < <(findmnt -rn -o TARGET)
}

assert_no_path_overlap() {
  local left="$1"
  local left_label="$2"
  local right="$3"
  local right_label="$4"
  local left_physical
  local right_physical
  local left_id
  local right_id
  local left_filesystem
  local right_filesystem
  local left_device
  local right_device
  local left_underlying
  local right_underlying
  left_physical="$(physical_directory "$left" "$left_label")"
  right_physical="$(physical_directory "$right" "$right_label")"
  assert_no_nested_mounts "$left_physical" "$left_label"
  assert_no_nested_mounts "$right_physical" "$right_label"
  left_id="$(path_identity "$left_physical")"
  right_id="$(path_identity "$right_physical")"
  if identity_is_ancestor "$left_id" "$right_physical" ||
    identity_is_ancestor "$right_id" "$left_physical"; then
    die "$left_label and $right_label overlap by physical or bind-mount identity"
  fi
  left_filesystem="$(filesystem_receipt "$left_physical" "$left_label")"
  right_filesystem="$(filesystem_receipt "$right_physical" "$right_label")"
  IFS='|' read -r left_device left_underlying <<<"$left_filesystem"
  IFS='|' read -r right_device right_underlying <<<"$right_filesystem"
  if [[ "$left_device" == "$right_device" ]] &&
    { path_is_ancestor "$left_underlying" "$right_underlying" ||
      path_is_ancestor "$right_underlying" "$left_underlying"; }; then
    die "$left_label and $right_label overlap through a mount filesystem source"
  fi
}

assert_isolated_target_root() {
  local repository="$1"
  local git_common="$2"
  local target="$3"
  local target_physical
  target_physical="$(physical_directory "$target" "target root")"
  [[ "$(stat -Lc '%u:%a' "$target_physical")" == "$(id -u):700" ]] ||
    die "target root must be owned by the caller with mode 0700"
  assert_no_path_overlap "$repository" "source repository" "$target_physical" "target root"
  assert_no_path_overlap "$git_common" "Git common directory" "$target_physical" "target root"
}

trust_receipt() {
  local path="$1"
  local label="$2"
  local physical
  physical="$(physical_directory "$path" "$label")"
  printf '%s|%s|%s\n' \
    "$physical" \
    "$(path_identity "$physical")" \
    "$(mount_receipt "$physical")"
}

create_verified_source_snapshot() {
  local repository="$1"
  local commit
  local tree
  local archived_commit
  local verifier
  local verifier_mode
  local verifier_type
  local verifier_oid
  local verifier_path
  local verification
  : "${TMPDIR:?TMPDIR is required for immutable source snapshots}"
  SOURCE_SNAPSHOT_ROOT="$(mktemp -d "$TMPDIR/gta-claw-source.XXXXXXXX")"
  chmod 0700 "$SOURCE_SNAPSHOT_ROOT"
  SOURCE_SNAPSHOT_ROOT_ID="$(path_identity "$SOURCE_SNAPSHOT_ROOT")"
  SOURCE_SNAPSHOT_ARCHIVE="$SOURCE_SNAPSHOT_ROOT/source.tar"
  SOURCE_SNAPSHOT_DIRECTORY="$SOURCE_SNAPSHOT_ROOT/source"
  mkdir -m 0700 "$SOURCE_SNAPSHOT_DIRECTORY"
  commit="$(git -C "$repository" rev-parse 'HEAD^{commit}')"
  tree="$(git -C "$repository" rev-parse 'HEAD^{tree}')"
  SOURCE_EPOCH="$(git -C "$repository" show -s --format=%ct "$commit")"
  git -C "$repository" archive --format=tar "$commit" >"$SOURCE_SNAPSHOT_ARCHIVE"
  archived_commit="$(git get-tar-commit-id <"$SOURCE_SNAPSHOT_ARCHIVE")"
  [[ "$archived_commit" == "$commit" ]] || die "Git archive commit identity mismatch"
  tar -xf "$SOURCE_SNAPSHOT_ARCHIVE" -C "$SOURCE_SNAPSHOT_DIRECTORY" \
    --no-same-owner --no-same-permissions
  verifier="$SOURCE_SNAPSHOT_ROOT/verify-git-snapshot.py"
  IFS=$' \t' read -r verifier_mode verifier_type verifier_oid verifier_path < <(
    git -C "$repository" ls-tree \
      "$commit" \
      -- \
      packaging/linux/tests/verify-git-snapshot.py
  )
  [[ "$verifier_mode" == "100755" && "$verifier_type" == "blob" &&
    "$verifier_oid" =~ ^[0-9a-f]{40}$ &&
    "$verifier_path" == "packaging/linux/tests/verify-git-snapshot.py" ]] ||
    die "trusted snapshot verifier Git object is invalid"
  git -C "$repository" cat-file blob "$verifier_oid" >"$verifier"
  [[ "$(git -C "$repository" hash-object "$verifier")" == "$verifier_oid" ]] ||
    die "trusted snapshot verifier extraction changed"
  sudo chown -hR 0:0 "$SOURCE_SNAPSHOT_ROOT"
  sudo find "$SOURCE_SNAPSHOT_ROOT" -type d -exec chmod 0555 {} +
  sudo find "$SOURCE_SNAPSHOT_ROOT" -type f -perm /111 -exec chmod 0555 {} +
  sudo find "$SOURCE_SNAPSHOT_ROOT" -type f ! -perm /111 -exec chmod 0444 {} +
  sudo chmod 0555 "$verifier"
  verification="$(
    python3 "$verifier" \
      "$repository" \
      "$commit" \
      "$tree" \
      "$SOURCE_SNAPSHOT_ARCHIVE" \
      "$SOURCE_SNAPSHOT_DIRECTORY"
  )"
  IFS='|' read -r SOURCE_COMMIT SOURCE_TREE SOURCE_TREE_RECEIPT <<<"$verification"
  [[ "$SOURCE_COMMIT" == "$commit" && "$SOURCE_TREE" == "$tree" &&
    "$SOURCE_TREE_RECEIPT" =~ ^[0-9a-f]{64}$ ]] ||
    die "verified source snapshot receipt is invalid"
}

prepare_output_component() {
  local target_root="$1"
  local component="$2"
  validate_safe_component "$component" "output component"
  OUTPUT_COMPONENT_PATH="$target_root/$component"
  OUTPUT_COMPONENT_LOCK="$target_root/$component.lock"
  [[ ! -e "$OUTPUT_COMPONENT_PATH" && ! -L "$OUTPUT_COMPONENT_PATH" ]] ||
    die "output component already exists: $OUTPUT_COMPONENT_PATH"
  [[ ! -e "$OUTPUT_COMPONENT_LOCK" && ! -L "$OUTPUT_COMPONENT_LOCK" ]] ||
    die "output component lock already exists: $OUTPUT_COMPONENT_LOCK"
  mkdir -m 0700 "$OUTPUT_COMPONENT_LOCK"
  mkdir -m 0700 "$OUTPUT_COMPONENT_PATH"
  chmod 0700 "$OUTPUT_COMPONENT_LOCK" "$OUTPUT_COMPONENT_PATH"
  exec {OUTPUT_COMPONENT_FD}<"$OUTPUT_COMPONENT_PATH"
  OUTPUT_COMPONENT_ID="$(path_identity "/proc/$BASHPID/fd/$OUTPUT_COMPONENT_FD")"
  [[ "$(path_identity "$OUTPUT_COMPONENT_PATH")" == "$OUTPUT_COMPONENT_ID" ]] ||
    die "output component identity changed during creation"
}

open_build_component() {
  local target_root="$1"
  local component="$2"
  validate_safe_component "$component" "build component"
  BUILD_COMPONENT_PATH="$target_root/$component"
  [[ -d "$BUILD_COMPONENT_PATH" && ! -L "$BUILD_COMPONENT_PATH" ]] ||
    die "build component is not a physical directory"
  [[ "$(stat -Lc '%u:%a' "$BUILD_COMPONENT_PATH")" == "$(id -u):700" ]] ||
    die "build component must be caller-owned mode 0700"
  exec {BUILD_COMPONENT_FD}<"$BUILD_COMPONENT_PATH"
  BUILD_COMPONENT_ID="$(path_identity "/proc/$BASHPID/fd/$BUILD_COMPONENT_FD")"
  [[ "$(path_identity "$BUILD_COMPONENT_PATH")" == "$BUILD_COMPONENT_ID" ]] ||
    die "build component identity changed while opening"
}

open_artifact_component() {
  local target_root="$1"
  local component="$2"
  validate_safe_component "$component" "artifact component"
  ARTIFACT_COMPONENT_PATH="$target_root/$component"
  [[ -d "$ARTIFACT_COMPONENT_PATH" && ! -L "$ARTIFACT_COMPONENT_PATH" ]] ||
    die "artifact component is not a physical directory"
  [[ "$(stat -Lc '%u:%a' "$ARTIFACT_COMPONENT_PATH")" == "$(id -u):700" ]] ||
    die "artifact component must be caller-owned mode 0700"
  exec {ARTIFACT_COMPONENT_FD}<"$ARTIFACT_COMPONENT_PATH"
  ARTIFACT_COMPONENT_ID="$(path_identity "/proc/$BASHPID/fd/$ARTIFACT_COMPONENT_FD")"
  [[ "$(path_identity "$ARTIFACT_COMPONENT_PATH")" == "$ARTIFACT_COMPONENT_ID" ]] ||
    die "artifact component identity changed while opening"
}

verify_container_transaction_receipts() {
  [[ "$(path_identity "$OUTPUT_COMPONENT_PATH")" == "$OUTPUT_COMPONENT_ID" ]] ||
    die "output component identity changed during container transaction"
  mount_receipt "$OUTPUT_COMPONENT_PATH" >/dev/null
  if [[ -n "$BUILD_COMPONENT_PATH" ]]; then
    [[ "$(path_identity "$BUILD_COMPONENT_PATH")" == "$BUILD_COMPONENT_ID" ]] ||
      die "build component identity changed during container transaction"
    mount_receipt "$BUILD_COMPONENT_PATH" >/dev/null
  fi
  if [[ -n "$ARTIFACT_COMPONENT_PATH" ]]; then
    [[ "$(path_identity "$ARTIFACT_COMPONENT_PATH")" == "$ARTIFACT_COMPONENT_ID" ]] ||
      die "artifact component identity changed during container transaction"
    mount_receipt "$ARTIFACT_COMPONENT_PATH" >/dev/null
  fi
}

cleanup_container_trust() {
  local failed=0
  if [[ -n "$OUTPUT_COMPONENT_LOCK" && -d "$OUTPUT_COMPONENT_LOCK" &&
    ! -L "$OUTPUT_COMPONENT_LOCK" ]]; then
    if rmdir "$OUTPUT_COMPONENT_LOCK" >/dev/null 2>&1; then
      OUTPUT_COMPONENT_LOCK=""
    else
      failed=1
    fi
  fi
  if [[ -n "$SOURCE_SNAPSHOT_ROOT" ]]; then
    if [[ ! -d "$SOURCE_SNAPSHOT_ROOT" || -L "$SOURCE_SNAPSHOT_ROOT" ||
      "$(path_identity "$SOURCE_SNAPSHOT_ROOT")" != "$SOURCE_SNAPSHOT_ROOT_ID" ]]; then
      failed=1
    elif sudo rm -rf -- "$SOURCE_SNAPSHOT_ROOT"; then
      SOURCE_SNAPSHOT_ROOT=""
      SOURCE_SNAPSHOT_ROOT_ID=""
    else
      failed=1
    fi
  fi
  return "$failed"
}
