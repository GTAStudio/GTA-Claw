#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in chroot grep gzip jq python3 sha256sum stat tar timeout wc; do
  require_tool "$tool"
done

[[ "$#" -eq 4 ]] ||
  die "usage: oci-self-test.sh OCI_ARCHIVE ARCH BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
source_archive="$1"
arch="$2"
expected_build_manifest="$3"
expected_build_key_sha="$4"
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
  "$OUTPUT_ROOT/validation-original" \
  "$expected_build_manifest" \
  "$expected_build_key_sha"

expect_invalid() {
  local name="$1"
  local archive="$2"
  tests=$((tests + 1))
  if "$SCRIPT_DIR/validate-oci-artifact.sh" \
    "$archive" \
    "$arch" \
    "$OUTPUT_ROOT/validation-$name" \
    "$expected_build_manifest" \
    "$expected_build_key_sha" \
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

rewrite_rootfs_checksums() {
  local rootfs="$1"
  local manifest="$rootfs/usr/share/doc/gta-claw/SHA256SUMS"
  mv "$manifest" "$OUTPUT_ROOT/discard/SHA256SUMS-$RANDOM"
  open_output_file "$manifest" 0644
  while IFS= read -r -d '' relative; do
    printf '%s  %s\n' "$(sha256_file "$rootfs/$relative")" "$relative" \
      >&"$OPEN_OUTPUT_FD"
  done < <(cd "$rootfs" && find . -type f ! -path './usr/share/doc/gta-claw/SHA256SUMS' -print0 | LC_ALL=C sort -z)
  finish_output_file
}

repack_root_layer() {
  local layout="$1"
  local rootfs="$2"
  local manifest
  local layer_digest
  local layer
  manifest="$(manifest_blob "$layout")"
  layer_digest="$(jq -er '.layers[0].digest' "$manifest")"
  layer="$layout/blobs/sha256/${layer_digest#sha256:}"
  mv "$layer" "$OUTPUT_ROOT/discard/repacked-layer-$RANDOM"
  open_output_file "$layer" 0644
  (
    cd "$rootfs"
    tar \
      --sort=name \
      --format=posix \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -cf - \
      .
  ) >&"$OPEN_OUTPUT_FD"
  finish_output_file
  reseal_all "$layout"
}

prepare_rootfs_case() {
  local name="$1"
  local layout
  local manifest
  local layer_digest
  local rootfs="$OUTPUT_ROOT/rootfs-$name"
  layout="$(prepare_case "$name")"
  manifest="$(manifest_blob "$layout")"
  layer_digest="$(jq -er '.layers[0].digest' "$manifest")"
  ensure_output_directory "$rootfs"
  tar -xf "$layout/blobs/sha256/${layer_digest#sha256:}" -C "$rootfs"
  printf '%s|%s\n' "$layout" "$rootfs"
}

root_case="$(prepare_rootfs_case entrypoint-smoke)"
layout="${root_case%%|*}"
rootfs="${root_case##*|}"
manifest="$(manifest_blob "$layout")"
writable_digest="$(jq -er '.layers[1].digest' "$manifest")"
tar -xf "$layout/blobs/sha256/${writable_digest#sha256:}" -C "$rootfs"
config_digest="$(jq -er '.config.digest' "$manifest")"
config="$layout/blobs/sha256/${config_digest#sha256:}"
entrypoint="$(
  jq -er \
    '.config.Entrypoint | if length == 1 then .[0] else error("entrypoint") end' \
    "$config"
)"
state_directory="$(
  jq -er '
    .config.Env[] | select(startswith("GTA_CLAW_STATE_DIR=")) |
    sub("^GTA_CLAW_STATE_DIR="; "")
  ' "$config"
)"
[[ "$entrypoint" == "/usr/libexec/gta-claw/gta-claw-daemon" ]]
[[ "$state_directory" == "/var/lib/gta-claw" ]]
daemon="$rootfs$entrypoint"
[[ -x "$daemon" ]]
[[ "$(stat -c '%u:%g' "$rootfs$state_directory")" == "65532:65532" ]]
HOME=/nonexistent \
GTA_CLAW_STATE_DIR="$state_directory" \
  timeout 10 \
    chroot --userspec=65532:65532 "$rootfs" "$entrypoint" --check-config \
    >"$OUTPUT_ROOT/entrypoint-check.stdout"
HOME=/nonexistent \
GTA_CLAW_STATE_DIR="$state_directory" \
  timeout 10 \
    chroot --userspec=65532:65532 "$rootfs" "$entrypoint" --probe \
    >"$OUTPUT_ROOT/entrypoint-probe.stdout"
printf 'shutdown\n' |
  HOME=/nonexistent \
  GTA_CLAW_STATE_DIR="$state_directory" \
    timeout 15 \
      chroot \
        --userspec=65532:65532 \
        "$rootfs" \
        "$entrypoint" \
        --smoke \
        --listen 127.0.0.1:0 \
        --legacy-listen 127.0.0.1:0 \
        --gateway-listen 127.0.0.1:0 \
        --mcp-listen 127.0.0.1:0 \
        >"$OUTPUT_ROOT/entrypoint-serve.stdout"
grep -F 'ready protocol=1' "$OUTPUT_ROOT/entrypoint-serve.stdout" >/dev/null
grep -F 'stopped ' "$OUTPUT_ROOT/entrypoint-serve.stdout" >/dev/null
tests=$((tests + 1))

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

layout="$(prepare_case missing-state-environment)"
manifest="$(manifest_blob "$layout")"
config_digest="$(jq -er '.config.digest' "$manifest")"
config="$layout/blobs/sha256/${config_digest#sha256:}"
replace_json \
  "$config" \
  '.config.Env |= map(select(startswith("GTA_CLAW_STATE_DIR=") | not))'
reseal_all "$layout"
expect_invalid \
  missing-state-environment \
  "$(pack_case missing-state-environment "$layout")"

layout="$(prepare_case overridden-state-environment)"
manifest="$(manifest_blob "$layout")"
config_digest="$(jq -er '.config.digest' "$manifest")"
config="$layout/blobs/sha256/${config_digest#sha256:}"
replace_json \
  "$config" \
  '.config.Env += ["GTA_CLAW_STATE_DIR=/tmp/gta-claw"]'
reseal_all "$layout"
expect_invalid \
  overridden-state-environment \
  "$(pack_case overridden-state-environment "$layout")"

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

for kind in traversal symlink hardlink fifo device whiteout duplicate bomb; do
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

layout="$(prepare_case duplicate-json-key)"
manifest="$(manifest_blob "$layout")"
mv "$manifest" "$OUTPUT_ROOT/discard/duplicate-json-manifest"
open_output_file "$manifest" 0644
python3 -c '
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
position = text.index("{") + 1
sys.stdout.write(text[:position] + "\"schemaVersion\":2," + text[position:])
' "$OUTPUT_ROOT/discard/duplicate-json-manifest" >&"$OPEN_OUTPUT_FD"
finish_output_file
reseal_manifest_to_index "$layout" "$manifest"
expect_invalid duplicate-json-key "$(pack_case duplicate-json-key "$layout")"

layout="$(prepare_case oversized-json-number)"
manifest="$(manifest_blob "$layout")"
replace_json "$manifest" '.config.size = 9223372036854775808'
reseal_manifest_to_index "$layout" "$manifest"
expect_invalid oversized-json-number "$(pack_case oversized-json-number "$layout")"

root_case="$(prepare_rootfs_case extra-executable)"
layout="${root_case%%|*}"
rootfs="${root_case##*|}"
ensure_output_directory "$rootfs/usr/local/bin"
write_output_text "$rootfs/usr/local/bin/undeclared-executable" 0755 $'#!/bin/false\n'
rewrite_rootfs_checksums "$rootfs"
repack_root_layer "$layout" "$rootfs"
expect_invalid extra-executable "$(pack_case extra-executable "$layout")"

root_case="$(prepare_rootfs_case substituted-runtime)"
layout="${root_case%%|*}"
rootfs="${root_case##*|}"
runtime_target="$(
  jq -er '.packages[] | select(.id == "libc6") | .files[] | select(.targetPath | endswith("/libc.so.6")) | .targetPath' \
    "$(dirname "$expected_build_manifest")/runtime/runtime-manifest.json"
)"
runtime_file="$rootfs$runtime_target"
mv "$runtime_file" "$OUTPUT_ROOT/discard/original-libc"
copy_regular_input "$rootfs/usr/bin/gta-claw-cli" "$runtime_file" 0755
replace_json \
  "$rootfs/usr/share/doc/gta-claw/runtime-manifest.json" \
  --arg target "$runtime_target" \
  --arg sha "$(sha256_file "$runtime_file")" \
  '(.packages[].files[] | select(.targetPath == $target) | .sha256) = $sha'
replace_json \
  "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" \
  --arg name "./${runtime_target#/}" \
  --arg sha "$(sha256_file "$runtime_file")" \
  '(.files[] | select(.fileName == $name) | .checksums[] | select(.algorithm == "SHA256") | .checksumValue) = $sha'
rewrite_rootfs_checksums "$rootfs"
repack_root_layer "$layout" "$rootfs"
expect_invalid substituted-runtime "$(pack_case substituted-runtime "$layout")"

root_case="$(prepare_rootfs_case substituted-application)"
layout="${root_case%%|*}"
rootfs="${root_case##*|}"
application_file="$rootfs/usr/bin/gta-claw-cli"
mv "$application_file" "$OUTPUT_ROOT/discard/original-cli"
copy_regular_input \
  "$rootfs/usr/libexec/gta-claw/gta-claw-daemon" \
  "$application_file" \
  0755
replace_json \
  "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" \
  --arg name "./usr/bin/gta-claw-cli" \
  --arg sha "$(sha256_file "$application_file")" \
  '(.files[] | select(.fileName == $name) | .checksums[] | select(.algorithm == "SHA256") | .checksumValue) = $sha'
rewrite_rootfs_checksums "$rootfs"
repack_root_layer "$layout" "$rootfs"
expect_invalid substituted-application "$(pack_case substituted-application "$layout")"

layout="$(prepare_case outer-traversal)"
outer="$OUTPUT_ROOT/outer-traversal.oci.tar.gz"
open_output_file "$outer" 0644
(
  cd "$(dirname "$layout")"
  tar --transform='s#^#../#' -cf - "$(basename "$layout")"
) | gzip -n -9 >&"$OPEN_OUTPUT_FD"
finish_output_file
expect_invalid outer-traversal "$outer"

python3 "$SCRIPT_DIR/tests/make-malicious-tar.py" bomb "$OUTPUT_ROOT/decompression-bomb.tar"
bomb_archive="$OUTPUT_ROOT/decompression-bomb.oci.tar.gz"
open_output_file "$bomb_archive" 0644
gzip -n -9 -c "$OUTPUT_ROOT/decompression-bomb.tar" >&"$OPEN_OUTPUT_FD"
finish_output_file
expect_invalid decompression-bomb "$bomb_archive"

python3 \
  "$SCRIPT_DIR/tests/make-malicious-tar.py" \
  pax-bomb \
  "$OUTPUT_ROOT/pax-decompression-bomb.tar"
pax_bomb_archive="$OUTPUT_ROOT/pax-decompression-bomb.oci.tar.gz"
open_output_file "$pax_bomb_archive" 0644
gzip -n -9 -c "$OUTPUT_ROOT/pax-decompression-bomb.tar" >&"$OPEN_OUTPUT_FD"
finish_output_file
expect_invalid pax-decompression-bomb "$pax_bomb_archive"

printf 'Published OCI mutation self-tests passed (%d cases)\n' "$tests"
