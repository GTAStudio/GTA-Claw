#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in dpkg-deb jq readelf rpm sha256sum tar; do
  require_tool "$tool"
done
[[ "$#" -eq 2 ]] || die "usage: validate.sh OUTPUT_ROOT ARCH"
validation_root="$1"
arch="$2"
[[ "$validation_root" == /* ]] || die "validation root must be absolute"
[[ -d "$validation_root" && ! -L "$validation_root" ]] ||
  die "validation root is not a real directory"
target_root="$(canonical_target_root)"
case "$validation_root/" in
  "$target_root/"*) ;;
  *) die "validation root is outside repository target" ;;
esac
assert_no_symlink_components "$target_root" "$validation_root"
reject_links_and_special_files "$validation_root"

artifact_dir="$validation_root/artifacts"
work_dir="$validation_root/work"
base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
deb_architecture="$(deb_arch "$arch")"
rpm_architecture="$(rpm_arch "$arch")"
oci_architecture="$(oci_arch "$arch")"
tar_artifact="$artifact_dir/$base_name.tar.gz"
deb_artifact="$artifact_dir/${LINUX_PACKAGE_NAME}_${VERSION}-${LINUX_PACKAGE_RELEASE}_${deb_architecture}.deb"
rpm_artifact="$artifact_dir/$LINUX_PACKAGE_NAME-$VERSION-$LINUX_PACKAGE_RELEASE.$rpm_architecture.rpm"
oci_artifact="$artifact_dir/$base_name.oci.tar.gz"

for artifact in \
  "$tar_artifact" "$deb_artifact" "$rpm_artifact" "$oci_artifact" \
  "$artifact_dir/provenance-$arch.json" "$artifact_dir/SHA256SUMS"; do
  assert_regular_unaliased "$artifact" "artifact"
done
verify_sha256_manifest "$artifact_dir" "$artifact_dir/SHA256SUMS"

validate_archive_listing() {
  local archive="$1"
  local listing
  listing="$(tar -tzf "$archive")"
  if grep -E '(^/|(^|/)\.\.(/|$)|\\)' <<<"$listing"; then
    die "archive contains an unsafe path: $archive"
  fi
  if tar -tvzf "$archive" | awk '$1 ~ /^[lh]/ { found = 1 } END { exit !found }'; then
    die "archive contains a link entry: $archive"
  fi
}

validate_archive_listing "$tar_artifact"
validate_archive_listing "$oci_artifact"
tar -tzf "$tar_artifact" | grep -Fx "$base_name/bin/$LINUX_DAEMON_NAME" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/bin/$LINUX_CLI_NAME" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/provenance.json" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/sbom.spdx.json" >/dev/null
if tar -tzf "$tar_artifact" |
  grep -Eiq '(^|/)(node(js)?|npm|npx|pnpm|bun)(/|$)|\.(js|mjs|cjs|node)$'; then
  die "native archive contains a JavaScript runtime or package-manager file"
fi
if tar -tvzf "$tar_artifact" |
  awk '$2 != "0/0" { bad = 1; exit } END { exit !bad }'; then
  die "native archive contains non-root ownership"
fi

[[ "$(dpkg-deb --field "$deb_artifact" Architecture)" == "$deb_architecture" ]] ||
  die "Debian architecture mismatch"
dpkg-deb --contents "$deb_artifact" | grep -F './usr/bin/gta-claw-cli' >/dev/null
dpkg-deb --contents "$deb_artifact" |
  grep -F './usr/libexec/gta-claw/gta-claw-daemon' >/dev/null
deb_control_listing="$(dpkg-deb --ctrl-tarfile "$deb_artifact" | tar -tf -)"
if grep -Eq '(^|/)(preinst|postinst|prerm|postrm|config|triggers)$' \
  <<<"$deb_control_listing"; then
  die "Debian package unexpectedly contains a maintainer script"
fi

[[ "$(rpm -qp --qf '%{ARCH}' "$rpm_artifact")" == "$rpm_architecture" ]] ||
  die "RPM architecture mismatch"
rpm -qpl "$rpm_artifact" | grep -Fx '/usr/bin/gta-claw-cli' >/dev/null
rpm -qpl "$rpm_artifact" |
  grep -Fx '/usr/libexec/gta-claw/gta-claw-daemon' >/dev/null
[[ -z "$(rpm -qp --scripts "$rpm_artifact")" ]] ||
  die "RPM package unexpectedly contains maintainer scripts"

rootfs="$work_dir/rootfs"
validate_elf_binary "$rootfs/usr/bin/$LINUX_CLI_NAME" "$arch"
validate_elf_binary "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" "$arch"
validate_service_contract "$rootfs/usr/lib/systemd/system/gta-claw-daemon.service"
[[ ! -e "$rootfs/usr/lib/systemd/system/gta-claw-daemon.socket" ]] ||
  die "unsupported socket unit was installed"
[[ "$(stat -c '%a' "$rootfs/etc/gta-claw/gta-claw.env")" == "640" ]] ||
  die "environment file mode is not 0640"
[[ "$(stat -c '%a' "$rootfs/etc/gta-claw/credentials/daemon.conf")" == "600" ]] ||
  die "credential file mode is not 0600"
for directory in var/lib/gta-claw var/cache/gta-claw var/log/gta-claw run/gta-claw; do
  [[ "$(stat -c '%a' "$rootfs/$directory")" == "700" ]] ||
    die "writable directory mode is not 0700: $directory"
done
reject_forbidden_runtime_content "$rootfs"

oci_layout="$work_dir/oci/$base_name.oci"
manifest_digest="$(jq -er '.manifests[0].digest' "$oci_layout/index.json")"
manifest="$oci_layout/blobs/sha256/${manifest_digest#sha256:}"
config_digest="$(jq -er '.config.digest' "$manifest")"
config="$oci_layout/blobs/sha256/${config_digest#sha256:}"
[[ "$(jq -er '.architecture' "$config")" == "$oci_architecture" ]] ||
  die "OCI architecture mismatch"
[[ "$(jq -er '.os' "$config")" == "linux" ]] || die "OCI operating system mismatch"
[[ "$(jq -er '.config.User' "$config")" == "65532:65532" ]] ||
  die "OCI image does not use the dedicated non-root account"
[[ "$(jq -er '.config.Entrypoint[0]' "$config")" == \
  "/usr/libexec/gta-claw/gta-claw-daemon" ]] ||
  die "OCI entrypoint mismatch"
[[ "$(jq -er '.layers | length' "$manifest")" -eq 2 ]] ||
  die "OCI image must contain root and writable-ownership layers"
writable_digest="$(jq -er '.layers[1].digest' "$manifest")"
writable_layer="$oci_layout/blobs/sha256/${writable_digest#sha256:}"
if tar -tvf "$writable_layer" |
  awk '$2 != "65532/65532" { bad = 1; exit } END { exit !bad }'; then
  die "OCI writable directories are not owned by uid/gid 65532"
fi
for volume in \
  /var/lib/gta-claw /var/cache/gta-claw /var/log/gta-claw /run/gta-claw; do
  jq -e --arg volume "$volume" '.config.Volumes[$volume] == {}' "$config" >/dev/null ||
    die "OCI writable volume missing: $volume"
done
for sbom in \
  "$work_dir/archive/$base_name/sbom.spdx.json" \
  "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" \
  "$work_dir/oci-rootfs/usr/share/doc/gta-claw/sbom.spdx.json"; do
  jq -e '
    .spdxVersion == "SPDX-2.3" and
    .dataLicense == "CC0-1.0" and
    (.packages[0].packageVerificationCode.packageVerificationCodeValue |
      test("^[0-9a-f]{40}$")) and
    ([.files[] |
      (.fileName | startswith("./")) and
      ([.checksums[].algorithm] | index("SHA1") != null) and
      ([.checksums[].algorithm] | index("SHA256") != null)
    ] | all)
  ' "$sbom" >/dev/null || die "invalid SPDX 2.3 SBOM structure: $sbom"
done
jq -e '._type == "https://in-toto.io/Statement/v1"' \
  "$rootfs/usr/share/doc/gta-claw/provenance.json" >/dev/null

note "validated Linux $arch package and OCI layouts"
