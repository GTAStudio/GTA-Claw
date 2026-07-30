#!/usr/bin/env bash

create_private_validation_directory() {
  local path="$1"
  local target
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    [[ "$path" == "$OUTPUT_ROOT/"* ]] ||
      die "validation directory must remain below safe output root"
    [[ ! -e "$path" && ! -L "$path" ]] || die "validation directory must be new: $path"
    ensure_output_directory "$path"
    return
  fi
  validate_absolute_path "$path" "validation directory"
  target="$(canonical_target_root)"
  [[ "$path" == "$target/"* ]] || die "validation directory must remain below target"
  assert_no_symlink_components "$target" "$path"
  assert_nearest_existing_parent "$target" "$path"
  [[ ! -e "$path" && ! -L "$path" ]] || die "validation directory must be new: $path"
  mkdir -m 0700 -- "$path"
  chmod 0700 -- "$path"
  [[ -d "$path" && ! -L "$path" && "$(stat -c '%u' "$path")" -eq "$(id -u)" ]] ||
    die "failed to create private validation directory: $path"
}

validate_archive_entries() {
  local archive="$1"
  local compression="$2"
  local max_compressed
  local max_expanded
  local max_file
  case "$compression" in
    gzip)
      max_compressed=$((64 * 1024 * 1024))
      max_expanded=$((64 * 1024 * 1024))
      max_file=$((32 * 1024 * 1024))
      ;;
    none)
      max_compressed=$((64 * 1024 * 1024))
      max_expanded=$((64 * 1024 * 1024))
      max_file=$((32 * 1024 * 1024))
      ;;
    *) die "unsupported archive compression: $compression" ;;
  esac
  python3 "$LINUX_DIR/strict_artifact.py" \
    tar \
    "$archive" \
    "$compression" \
    "$max_compressed" \
    "$max_expanded" \
    "$max_file" \
    4096 \
    >/dev/null
}

validate_descriptor_blob() {
  local layout="$1"
  local digest="$2"
  local expected_size="$3"
  local label="$4"
  local blob
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$label has an invalid digest"
  [[ "$expected_size" =~ ^[0-9]+$ ]] || die "$label has an invalid size"
  blob="$layout/blobs/sha256/${digest#sha256:}"
  assert_regular_unaliased "$blob" "$label blob"
  [[ "$(wc -c <"$blob" | tr -d ' ')" == "$expected_size" ]] ||
    die "$label blob size mismatch"
  [[ "sha256:$(sha256_file "$blob")" == "$digest" ]] ||
    die "$label blob digest mismatch"
  printf '%s\n' "$blob"
}

validate_published_oci() {
  local archive="$1"
  local arch="$2"
  local validation_root="$3"
  local expected_build_manifest="$4"
  local expected_build_key_sha="$5"
  local base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
  local expected_layout_name="$base_name.oci"
  local extract_root="$validation_root/extracted"
  local layout
  local manifest_digest
  local manifest_size
  local manifest
  local config_digest
  local config_size
  local config
  local layer_count
  local index
  local layer_digest
  local layer_size
  local layer
  local diff_id
  local root_layer=""
  local writable_layer=""
  local rootfs="$validation_root/rootfs"
  local listing
  local referenced
  local actual_blobs
  local staged_path
  local target_path
  local expected_sha
  local package_id
  local expected_version
  local expected_license
  local material_name
  local material_target
  local material_sha
  local archive_sha
  local root_layer_sha=""
  local expected_rootfs_files
  local actual_rootfs_files

  assert_regular_unaliased "$archive" "published OCI archive"
  verify_build_manifest "$expected_build_manifest" "$arch" "$expected_build_key_sha"
  archive_sha="$(sha256_file "$archive")"
  [[ ! -e "$validation_root" && ! -L "$validation_root" ]] ||
    die "OCI validation root must be new"
  create_private_validation_directory "$validation_root"
  create_private_validation_directory "$extract_root"
  validate_archive_entries "$archive" gzip
  listing="$(tar --quoting-style=escape -tzf "$archive")"
  [[ "$(awk -F/ 'NF { print $1 }' <<<"$listing" | LC_ALL=C sort -u)" == \
    "$expected_layout_name" ]] || die "OCI archive has an unexpected top-level layout"
  if tar --numeric-owner -tvzf "$archive" |
    awk '$2 != "0/0" { bad = 1 } END { exit !bad }'; then
    die "OCI layout archive contains non-root ownership"
  fi
  (
    umask 000
    tar \
      -xzf "$archive" \
      -C "$extract_root" \
      --no-overwrite-dir \
      --no-same-owner \
      --numeric-owner
  )
  [[ "$(sha256_file "$archive")" == "$archive_sha" ]] ||
    die "published OCI archive changed during extraction"
  reject_links_and_special_files "$extract_root"
  layout="$extract_root/$expected_layout_name"
  [[ -d "$layout" && ! -L "$layout" ]] || die "published OCI layout directory is missing"
  python3 "$LINUX_DIR/strict_artifact.py" json "$layout/oci-layout" >/dev/null
  python3 "$LINUX_DIR/strict_artifact.py" json "$layout/index.json" >/dev/null
  jq -e '.imageLayoutVersion == "1.0.0"' "$layout/oci-layout" >/dev/null ||
    die "published OCI layout version is invalid"
  jq -e '
    .schemaVersion == 2 and
    .mediaType == "application/vnd.oci.image.index.v1+json" and
    (.manifests | length == 1) and
    .manifests[0].mediaType == "application/vnd.oci.image.manifest.v1+json"
  ' "$layout/index.json" >/dev/null || die "published OCI index is invalid"
  [[ "$(jq -er '.manifests[0].platform.os' "$layout/index.json")" == "linux" &&
    "$(jq -er '.manifests[0].platform.architecture' "$layout/index.json")" == \
      "$(oci_arch "$arch")" ]] || die "published OCI index platform mismatch"

  manifest_digest="$(jq -er '.manifests[0].digest' "$layout/index.json")"
  manifest_size="$(jq -er '.manifests[0].size' "$layout/index.json")"
  manifest="$(validate_descriptor_blob "$layout" "$manifest_digest" "$manifest_size" "manifest")"
  python3 "$LINUX_DIR/strict_artifact.py" json "$manifest" >/dev/null
  jq -e '
    .schemaVersion == 2 and
    .mediaType == "application/vnd.oci.image.manifest.v1+json" and
    .config.mediaType == "application/vnd.oci.image.config.v1+json" and
    ([.layers[].mediaType] | all(. == "application/vnd.oci.image.layer.v1.tar"))
  ' "$manifest" >/dev/null || die "published OCI manifest is invalid"

  config_digest="$(jq -er '.config.digest' "$manifest")"
  config_size="$(jq -er '.config.size' "$manifest")"
  config="$(validate_descriptor_blob "$layout" "$config_digest" "$config_size" "config")"
  python3 "$LINUX_DIR/strict_artifact.py" json "$config" >/dev/null
  [[ "$(jq -er '.architecture' "$config")" == "$(oci_arch "$arch")" ]] ||
    die "published OCI config architecture mismatch"
  jq -e '
    .os == "linux" and
    .config.User == "65532:65532" and
    .config.Entrypoint == ["/usr/libexec/gta-claw/gta-claw-daemon"] and
    .config.WorkingDir == "/" and
    .config.Env == [
      "RUST_BACKTRACE=0",
      "GTA_CLAW_STATE_DIR=/var/lib/gta-claw"
    ] and
    .config.Labels["org.opencontainers.image.licenses"] ==
      "MIT AND LGPL-2.1-or-later AND (GPL-3.0-or-later WITH GCC-exception-3.1)"
  ' "$config" >/dev/null || die "published OCI config contract is invalid"
  for volume in \
    /var/lib/gta-claw /var/cache/gta-claw /var/log/gta-claw /run/gta-claw; do
    jq -e --arg volume "$volume" '.config.Volumes[$volume] == {}' "$config" >/dev/null ||
      die "published OCI config is missing volume $volume"
  done

  layer_count="$(jq -er '.layers | length' "$manifest")"
  [[ "$layer_count" -eq 2 ]] || die "published OCI manifest must contain exactly two layers"
  [[ "$(jq -er '.rootfs.diff_ids | length' "$config")" -eq "$layer_count" ]] ||
    die "published OCI config DiffID count mismatch"
  for ((index = 0; index < layer_count; index++)); do
    layer_digest="$(jq -er ".layers[$index].digest" "$manifest")"
    layer_size="$(jq -er ".layers[$index].size" "$manifest")"
    layer="$(validate_descriptor_blob "$layout" "$layer_digest" "$layer_size" "layer[$index]")"
    diff_id="$(jq -er ".rootfs.diff_ids[$index]" "$config")"
    [[ "$diff_id" == "sha256:$(sha256_file "$layer")" ]] ||
      die "published OCI layer[$index] DiffID mismatch"
    validate_archive_entries "$layer" none
    if [[ "$index" -eq 0 ]]; then
      root_layer="$layer"
      root_layer_sha="$(sha256_file "$layer")"
    else
      writable_layer="$layer"
    fi
  done

  referenced="$(
    {
      printf '%s\n' "${manifest_digest#sha256:}" "${config_digest#sha256:}"
      jq -r '.layers[].digest | sub("^sha256:"; "")' "$manifest"
    } | LC_ALL=C sort -u
  )"
  actual_blobs="$(
    find "$layout/blobs/sha256" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' |
      LC_ALL=C sort -u
  )"
  [[ "$actual_blobs" == "$referenced" ]] ||
    die "published OCI layout contains missing or unreferenced blobs"

  tar --numeric-owner -tvf "$root_layer" |
    awk '$2 != "0/0" { bad = 1 } END { exit bad }' ||
    die "published OCI root layer contains non-root ownership"
  create_private_validation_directory "$rootfs"
  (
    umask 000
    tar \
      -xf "$root_layer" \
      -C "$rootfs" \
      --no-overwrite-dir \
      --no-same-owner \
      --numeric-owner
  )
  [[ "$(sha256_file "$root_layer")" == "$root_layer_sha" ]] ||
    die "published OCI root layer changed during extraction"
  reject_links_and_special_files "$rootfs"
  validate_elf_binary "$rootfs/usr/bin/$LINUX_CLI_NAME" "$arch"
  validate_elf_binary "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" "$arch"
  [[ "$(sha256_file "$rootfs/usr/bin/$LINUX_CLI_NAME")" == "$(
    jq -er --arg name "$LINUX_CLI_NAME" '
      .binaries[] | select(.name == $name) | .sha256
    ' "$BUILD_MANIFEST"
  )" ]] || die "published OCI CLI differs from authenticated build"
  [[ "$(sha256_file "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME")" == "$(
    jq -er --arg name "$LINUX_DAEMON_NAME" '
      .binaries[] | select(.name == $name) | .sha256
    ' "$BUILD_MANIFEST"
  )" ]] || die "published OCI daemon differs from authenticated build"
  [[ "$(stat -c '%a' "$rootfs/usr/bin/$LINUX_CLI_NAME")" == "755" ]] ||
    die "published OCI CLI mode mismatch"
  [[ "$(stat -c '%a' "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME")" == "755" ]] ||
    die "published OCI daemon mode mismatch"
  [[ "$(stat -c '%a' "$rootfs/etc/passwd")" == "644" &&
    "$(stat -c '%a' "$rootfs/etc/group")" == "644" ]] ||
    die "published OCI account file mode mismatch"
  reject_forbidden_runtime_content "$rootfs"

  PUBLISHED_RUNTIME_MANIFEST="$rootfs/usr/share/doc/gta-claw/runtime-manifest.json"
  assert_regular_unaliased "$PUBLISHED_RUNTIME_MANIFEST" "published runtime manifest"
  python3 "$LINUX_DIR/strict_artifact.py" json "$PUBLISHED_RUNTIME_MANIFEST" >/dev/null
  python3 "$LINUX_DIR/strict_artifact.py" \
    json \
    "$rootfs/usr/share/doc/gta-claw/build-manifest.json" \
    >/dev/null
  python3 "$LINUX_DIR/strict_artifact.py" \
    json \
    "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" \
    >/dev/null
  python3 "$LINUX_DIR/strict_artifact.py" \
    json \
    "$rootfs/usr/share/doc/gta-claw/package-toolchain.json" \
    >/dev/null
  [[ "$(sha256_file "$rootfs/usr/share/doc/gta-claw/build-manifest.json")" == \
    "$(sha256_file "$BUILD_MANIFEST")" ]] ||
    die "published OCI build manifest differs from authenticated build manifest"
  [[ "$(sha256_file "$PUBLISHED_RUNTIME_MANIFEST")" == \
    "$(sha256_file "$BUILD_RUNTIME_MANIFEST")" ]] ||
    die "published OCI runtime manifest differs from authenticated runtime manifest"
  while IFS=$'\t' read -r package_id staged_path target_path expected_sha; do
    [[ "$staged_path" =~ ^runtime/rootfs/ && "$target_path" == /* ]] ||
      die "published runtime manifest contains an unsafe path"
    assert_regular_unaliased "$rootfs$target_path" "published runtime file"
    [[ "$(sha256_file "$rootfs$target_path")" == "$expected_sha" ]] ||
      die "published runtime file digest mismatch: $target_path"
    [[ "$(stat -c '%a' "$rootfs$target_path")" == "755" ]] ||
      die "published runtime file mode mismatch: $target_path"
    jq -e \
      --arg id "$package_id" \
      --arg file_name "./${target_path#/}" \
      --arg sha "$expected_sha" \
      '
        ((.files | map(select(
          .fileName == $file_name and
          any(.checksums[]; .algorithm == "SHA256" and .checksumValue == $sha)
        )) | length) == 1) and
        ((.files | map(select(.fileName == $file_name))[0].SPDXID) as $file_id |
          any(.relationships[];
            .spdxElementId == ("SPDXRef-Package-" + $id) and
            .relationshipType == "CONTAINS" and
            .relatedSpdxElement == $file_id
          )
        )
      ' \
      "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" >/dev/null ||
      die "published OCI SBOM does not bind runtime file $target_path"
  done < <(
    jq -r '
      .packages[] as $package |
      $package.files[] |
      [$package.id, .stagedPath, .targetPath, .sha256] |
      @tsv
    ' "$BUILD_RUNTIME_MANIFEST"
  )
  for package_id in libc6 libgcc-s1; do
    expected_version="$(
      jq -er --arg id "$package_id" '.packages[] | select(.id == $id) | .version' \
        "$BUILD_RUNTIME_MANIFEST"
    )"
    expected_license="$(
      jq -er --arg id "$package_id" '.packages[] | select(.id == $id) | .licenseExpression' \
        "$BUILD_RUNTIME_MANIFEST"
    )"
    jq -e \
      --arg id "$package_id" \
      --arg version "$expected_version" \
      --arg license "$expected_license" \
      '
        any(.packages[];
          .SPDXID == ("SPDXRef-Package-" + $id) and
          .versionInfo == $version and
          .licenseDeclared == $license and
          .filesAnalyzed == true
        ) and
        any(.relationships[];
          .spdxElementId == "SPDXRef-Package-GTA-Claw" and
          .relationshipType == "DEPENDS_ON" and
          .relatedSpdxElement == ("SPDXRef-Package-" + $id)
        )
      ' "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" >/dev/null ||
      die "published OCI SBOM does not bind runtime package $package_id"
  done
  while IFS=$'\t' read -r package_id material_name material_target material_sha; do
    assert_regular_unaliased "$rootfs$material_target" "published license material"
    [[ "$(sha256_file "$rootfs$material_target")" == "$material_sha" ]] ||
      die "published license material digest mismatch: $material_name"
    jq -e \
      --arg id "$package_id" \
      --arg file_name "./${material_target#/}" \
      --arg sha "$material_sha" \
      '
        ((.files | map(select(
          .fileName == $file_name and
          any(.checksums[]; .algorithm == "SHA256" and .checksumValue == $sha)
        )) | length) == 1) and
        ((.files | map(select(.fileName == $file_name))[0].SPDXID) as $file_id |
          any(.relationships[];
            .spdxElementId == ("SPDXRef-Package-" + $id) and
            .relationshipType == "CONTAINS" and
            .relatedSpdxElement == $file_id
          )
        )
      ' "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" >/dev/null ||
      die "published OCI SBOM does not bind license material $material_name"
  done < <(
    jq -r '
      .packages[].licenseMaterials[] |
      [.packageId, .name, .targetPath, .sha256] |
      @tsv
    ' "$BUILD_RUNTIME_MANIFEST"
  )
  verify_sha256_manifest \
    "$rootfs" \
    "$rootfs/usr/share/doc/gta-claw/SHA256SUMS"

  expected_rootfs_files="$(
    {
      printf '%s\n' \
        etc/group \
        etc/passwd \
        "usr/bin/$LINUX_CLI_NAME" \
        "usr/libexec/gta-claw/$LINUX_DAEMON_NAME" \
        usr/share/doc/gta-claw/LICENSE.txt \
        usr/share/doc/gta-claw/NOTICE.txt \
        usr/share/doc/gta-claw/README.md \
        usr/share/doc/gta-claw/SHA256SUMS \
        usr/share/doc/gta-claw/build-manifest.json \
        usr/share/doc/gta-claw/gta-claw-daemon.socket.deferred \
        usr/share/doc/gta-claw/package-toolchain.json \
        usr/share/doc/gta-claw/provenance.json \
        usr/share/doc/gta-claw/runtime-manifest.json \
        usr/share/doc/gta-claw/sbom.spdx.json
      jq -r '.packages[].files[].targetPath | sub("^/"; "")' "$BUILD_RUNTIME_MANIFEST"
      jq -r '.packages[].licenseMaterials[].targetPath | sub("^/"; "")' \
        "$BUILD_RUNTIME_MANIFEST"
    } | LC_ALL=C sort -u
  )"
  actual_rootfs_files="$(find "$rootfs" -type f -printf '%P\n' | LC_ALL=C sort -u)"
  [[ "$actual_rootfs_files" == "$expected_rootfs_files" ]] ||
    die "published OCI rootfs differs from independently derived file policy"

  listing="$(
    tar --numeric-owner -tvf "$writable_layer" |
      awk '{ sub(/\/$/, "", $NF); print $1 "\t" $2 "\t" $NF }' |
      LC_ALL=C sort
  )"
  [[ "$listing" == "$(
    printf '%s\n' \
      $'drwx------\t65532/65532\trun/gta-claw' \
      $'drwx------\t65532/65532\tvar/cache/gta-claw' \
      $'drwx------\t65532/65532\tvar/lib/gta-claw' \
      $'drwx------\t65532/65532\tvar/log/gta-claw' |
      LC_ALL=C sort
  )" ]] || die "published OCI writable layer entries, modes, or ownership are invalid"

}
