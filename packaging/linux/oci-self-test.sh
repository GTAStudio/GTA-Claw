#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in gzip jq python3 sha256sum tar wc; do
  require_tool "$tool"
done
[[ "$#" -eq 2 ]] || die "usage: oci-self-test.sh OCI_ARCHIVE ARCH"
source_archive="$1"
arch="$2"
assert_regular_unaliased "$source_archive" "OCI mutation source"
base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
layout_name="$base_name.oci"
: "${OUTPUT_ROOT:=$(canonical_target_root)/linux-oci-self-test-$BASHPID}"
initialize_output_root
ensure_output_directory "$OUTPUT_ROOT/discard"
tests=0
"$SCRIPT_DIR/validate-oci-artifact.sh" \
  "$source_archive" \
  "$arch" \
  "$OUTPUT_ROOT/validation-original"

expect_invalid() {
  local name="$1"
  local archive="$2"
  tests=$((tests + 1))
  if "$SCRIPT_DIR/validate-oci-artifact.sh" \
    "$archive" \
    "$arch" \
    "$OUTPUT_ROOT/validation-$name" \
    >"$OUTPUT_ROOT/$name.stdout" \
    2>"$OUTPUT_ROOT/$name.stderr"; then
    die "OCI mutation unexpectedly validated: $name"
  fi
}

prepare_case() {
  local name="$1"
  local root="$OUTPUT_ROOT/case-$name"
  ensure_output_directory "$root"
  tar -xzf "$source_archive" -C "$root" --no-same-owner
  printf '%s\n' "$root/$layout_name"
}

replace_json() {
  local path="$1"
  shift
  local source="$OUTPUT_ROOT/discard/json-$RANDOM"
  mv "$path" "$source"
  open_output_file "$path" 0644
  jq -S "$@" "$source" >&"$OPEN_OUTPUT_FD"
  finish_output_file
}

pack_case() {
  local name="$1"
  local layout="$2"
  local output="$OUTPUT_ROOT/$name.oci.tar.gz"
  open_output_file "$output" 0644
  (
    cd "$(dirname "$layout")"
    tar -cf - "$(basename "$layout")"
  ) | gzip -n -9 >&"$OPEN_OUTPUT_FD"
  finish_output_file
  printf '%s\n' "$output"
}

manifest_blob() {
  local layout="$1"
  local digest
  digest="$(jq -er '.manifests[0].digest' "$layout/index.json")"
  printf '%s/blobs/sha256/%s\n' "$layout" "${digest#sha256:}"
}

reseal_manifest_to_index() {
  local layout="$1"
  local manifest="$2"
  local digest
  local size
  local destination
  digest="$(sha256_file "$manifest")"
  size="$(wc -c <"$manifest" | tr -d ' ')"
  destination="$layout/blobs/sha256/$digest"
  if [[ "$manifest" != "$destination" ]]; then
    mv "$manifest" "$destination"
  fi
  replace_json \
    "$layout/index.json" \
    --arg digest "sha256:$digest" \
    --argjson size "$size" \
    '.manifests[0].digest = $digest | .manifests[0].size = $size'
}

reseal_all() {
  local layout="$1"
  local manifest
  local config_digest
  local config
  local layer0_digest
  local layer1_digest
  local layer0
  local layer1
  local new_layer0_digest
  local new_layer1_digest
  local layer0_size
  local layer1_size
  local new_config_digest
  local config_size
  manifest="$(manifest_blob "$layout")"
  config_digest="$(jq -er '.config.digest' "$manifest")"
  config="$layout/blobs/sha256/${config_digest#sha256:}"
  layer0_digest="$(jq -er '.layers[0].digest' "$manifest")"
  layer1_digest="$(jq -er '.layers[1].digest' "$manifest")"
  layer0="$layout/blobs/sha256/${layer0_digest#sha256:}"
  layer1="$layout/blobs/sha256/${layer1_digest#sha256:}"
  new_layer0_digest="$(sha256_file "$layer0")"
  new_layer1_digest="$(sha256_file "$layer1")"
  layer0_size="$(wc -c <"$layer0" | tr -d ' ')"
  layer1_size="$(wc -c <"$layer1" | tr -d ' ')"
  [[ "$layer0" == "$layout/blobs/sha256/$new_layer0_digest" ]] ||
    mv "$layer0" "$layout/blobs/sha256/$new_layer0_digest"
  [[ "$layer1" == "$layout/blobs/sha256/$new_layer1_digest" ]] ||
    mv "$layer1" "$layout/blobs/sha256/$new_layer1_digest"
  replace_json \
    "$config" \
    --arg layer0 "sha256:$new_layer0_digest" \
    --arg layer1 "sha256:$new_layer1_digest" \
    '.rootfs.diff_ids = [$layer0, $layer1]'
  new_config_digest="$(sha256_file "$config")"
  config_size="$(wc -c <"$config" | tr -d ' ')"
  if [[ "$config" != "$layout/blobs/sha256/$new_config_digest" ]]; then
    mv "$config" "$layout/blobs/sha256/$new_config_digest"
  fi
  replace_json \
    "$manifest" \
    --arg config_digest "sha256:$new_config_digest" \
    --argjson config_size "$config_size" \
    --arg layer0 "sha256:$new_layer0_digest" \
    --argjson layer0_size "$layer0_size" \
    --arg layer1 "sha256:$new_layer1_digest" \
    --argjson layer1_size "$layer1_size" \
    '
      .config.digest = $config_digest |
      .config.size = $config_size |
      .layers[0].digest = $layer0 |
      .layers[0].size = $layer0_size |
      .layers[1].digest = $layer1 |
      .layers[1].size = $layer1_size
    '
  reseal_manifest_to_index "$layout" "$manifest"
}

layout="$(prepare_case index-descriptor)"
replace_json "$layout/index.json" '.manifests[0].size += 1'
expect_invalid index-descriptor "$(pack_case index-descriptor "$layout")"

layout="$(prepare_case config-descriptor)"
manifest="$(manifest_blob "$layout")"
replace_json "$manifest" '.config.size += 1'
reseal_manifest_to_index "$layout" "$manifest"
expect_invalid config-descriptor "$(pack_case config-descriptor "$layout")"

layout="$(prepare_case layer-descriptor)"
manifest="$(manifest_blob "$layout")"
replace_json "$manifest" '.layers[0].size += 1'
reseal_manifest_to_index "$layout" "$manifest"
expect_invalid layer-descriptor "$(pack_case layer-descriptor "$layout")"

layout="$(prepare_case config-blob)"
manifest="$(manifest_blob "$layout")"
config_digest="$(jq -er '.config.digest' "$manifest")"
config="$layout/blobs/sha256/${config_digest#sha256:}"
mv "$config" "$OUTPUT_ROOT/discard/config-blob"
open_output_file "$config" 0644
cat "$OUTPUT_ROOT/discard/config-blob" >&"$OPEN_OUTPUT_FD"
printf 'x' >&"$OPEN_OUTPUT_FD"
finish_output_file
expect_invalid config-blob "$(pack_case config-blob "$layout")"

layout="$(prepare_case manifest-blob)"
manifest="$(manifest_blob "$layout")"
mv "$manifest" "$OUTPUT_ROOT/discard/manifest-blob"
open_output_file "$manifest" 0644
cat "$OUTPUT_ROOT/discard/manifest-blob" >&"$OPEN_OUTPUT_FD"
printf 'x' >&"$OPEN_OUTPUT_FD"
finish_output_file
expect_invalid manifest-blob "$(pack_case manifest-blob "$layout")"

layout="$(prepare_case layer-blob)"
manifest="$(manifest_blob "$layout")"
layer_digest="$(jq -er '.layers[0].digest' "$manifest")"
layer="$layout/blobs/sha256/${layer_digest#sha256:}"
mv "$layer" "$OUTPUT_ROOT/discard/layer-blob"
open_output_file "$layer" 0644
cat "$OUTPUT_ROOT/discard/layer-blob" >&"$OPEN_OUTPUT_FD"
printf 'x' >&"$OPEN_OUTPUT_FD"
finish_output_file
expect_invalid layer-blob "$(pack_case layer-blob "$layout")"

for kind in traversal symlink hardlink fifo device whiteout; do
  layout="$(prepare_case "layer-$kind")"
  manifest="$(manifest_blob "$layout")"
  layer_digest="$(jq -er '.layers[0].digest' "$manifest")"
  layer="$layout/blobs/sha256/${layer_digest#sha256:}"
  mv "$layer" "$OUTPUT_ROOT/discard/layer-$kind"
  python3 "$SCRIPT_DIR/tests/make-malicious-tar.py" "$kind" "$layer"
  chmod 0644 "$layer"
  reseal_all "$layout"
  expect_invalid "layer-$kind" "$(pack_case "layer-$kind" "$layout")"
done

layout="$(prepare_case outer-traversal)"
outer="$OUTPUT_ROOT/outer-traversal.oci.tar.gz"
open_output_file "$outer" 0644
(
  cd "$(dirname "$layout")"
  tar --transform='s#^#../#' -cf - "$(basename "$layout")"
) | gzip -n -9 >&"$OPEN_OUTPUT_FD"
finish_output_file
expect_invalid outer-traversal "$outer"

printf 'Published OCI mutation self-tests passed (%d cases)\n' "$tests"
