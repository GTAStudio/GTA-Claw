#!/usr/bin/env bash

create_private_validation_directory() {
  local path="$1"
  local target
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
  local listing
  local verbose
  case "$compression" in
    gzip)
      listing="$(tar --quoting-style=escape -tzf "$archive")"
      verbose="$(tar --numeric-owner --quoting-style=escape -tvzf "$archive")"
      ;;
    none)
      listing="$(tar --quoting-style=escape -tf "$archive")"
      verbose="$(tar --numeric-owner --quoting-style=escape -tvf "$archive")"
      ;;
    *) die "unsupported archive compression: $compression" ;;
  esac
  [[ -n "$listing" ]] || die "archive is empty: $archive"
  # shellcheck disable=SC2001
  listing="$(sed 's#^\./##; /^$/d' <<<"$listing")"
  if grep -E '(^/|(^|/)\.\.?(/|$)|\\|(^|/)\.wh\.)' <<<"$listing"; then
    die "archive contains an unsafe path: $archive"
  fi
  if awk 'substr($1, 1, 1) !~ /^[-d]$/ { bad = 1 } END { exit !bad }' <<<"$verbose"; then
    die "archive contains a link or special entry: $archive"
  fi
  if awk '$1 ~ /[sStT]/ { bad = 1 } END { exit !bad }' <<<"$verbose"; then
    die "archive contains setuid, setgid, or sticky mode bits: $archive"
  fi
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
  local copyright_sha
  local copyright_path

  assert_regular_unaliased "$archive" "published OCI archive"
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
  reject_links_and_special_files "$extract_root"
  layout="$extract_root/$expected_layout_name"
  [[ -d "$layout" && ! -L "$layout" ]] || die "published OCI layout directory is missing"
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
  jq -e '
    .schemaVersion == 2 and
    .mediaType == "application/vnd.oci.image.manifest.v1+json" and
    .config.mediaType == "application/vnd.oci.image.config.v1+json" and
    ([.layers[].mediaType] | all(. == "application/vnd.oci.image.layer.v1.tar"))
  ' "$manifest" >/dev/null || die "published OCI manifest is invalid"

  config_digest="$(jq -er '.config.digest' "$manifest")"
  config_size="$(jq -er '.config.size' "$manifest")"
  config="$(validate_descriptor_blob "$layout" "$config_digest" "$config_size" "config")"
  [[ "$(jq -er '.architecture' "$config")" == "$(oci_arch "$arch")" ]] ||
    die "published OCI config architecture mismatch"
  jq -e '
    .os == "linux" and
    .config.User == "65532:65532" and
    .config.Entrypoint == ["/usr/libexec/gta-claw/gta-claw-daemon"] and
    .config.WorkingDir == "/" and
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
  reject_links_and_special_files "$rootfs"
  validate_elf_binary "$rootfs/usr/bin/$LINUX_CLI_NAME" "$arch"
  validate_elf_binary "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" "$arch"
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
    ' "$PUBLISHED_RUNTIME_MANIFEST"
  )
  for package_id in libc6 libgcc-s1; do
    expected_version="$(
      jq -er --arg id "$package_id" '.packages[] | select(.id == $id) | .version' \
        "$PUBLISHED_RUNTIME_MANIFEST"
    )"
    expected_license="$(
      jq -er --arg id "$package_id" '.packages[] | select(.id == $id) | .licenseExpression' \
        "$PUBLISHED_RUNTIME_MANIFEST"
    )"
    copyright_sha="$(
      jq -er --arg id "$package_id" '.packages[] | select(.id == $id) | .copyrightSha256' \
        "$PUBLISHED_RUNTIME_MANIFEST"
    )"
    copyright_path="$rootfs/usr/share/licenses/$package_id/copyright"
    assert_regular_unaliased "$copyright_path" "published runtime copyright"
    [[ "$(sha256_file "$copyright_path")" == "$copyright_sha" ]] ||
      die "published runtime copyright digest mismatch: $package_id"
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
    jq -e \
      --arg id "$package_id" \
      --arg file_name "./usr/share/licenses/$package_id/copyright" \
      --arg sha "$copyright_sha" \
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
      die "published OCI SBOM does not bind runtime copyright $package_id"
  done
  verify_sha256_manifest \
    "$rootfs" \
    "$rootfs/usr/share/doc/gta-claw/SHA256SUMS"

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
