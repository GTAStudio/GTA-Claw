#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in clang codesign lipo otool xcrun; do
  require_tool "$tool"
done

tests=0
expect_failure() {
  local name="$1"
  shift
  tests=$((tests + 1))
  if "$@" >"$work/$name.stdout" 2>"$work/$name.stderr"; then
    die "self-test expected failure but succeeded: $name"
  fi
}

expect_success() {
  local name="$1"
  shift
  tests=$((tests + 1))
  "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" || {
    cat "$work/$name.stderr" >&2
    die "self-test failed: $name (see $work/$name.stderr)"
  }
}

work="$OUTPUT_ROOT/self-test"
safe_reset_dir "$work"
common="$MACOS_DIR/lib/common.sh"
outside="$(mktemp -d "${TMPDIR:-/tmp}/gta-claw-output-escape.XXXXXX")"
escape_link="$REPO_ROOT/target/gta-claw-output-link-$$"
cleanup() {
  local link
  for link in "$OUTPUT_ROOT/headless" "$OUTPUT_ROOT/build" "$OUTPUT_ROOT/notarization"; do
    [[ ! -L "$link" ]] || rm -f -- "$link"
  done
  rm -f -- "$escape_link"
  rm -rf -- "$outside"
}
trap cleanup EXIT INT TERM

assert_absent() {
  [[ ! -e "$1" && ! -L "$1" ]] || die "self-test created an outside path: $1"
}

assert_sentinel() {
  [[ "$(cat "$1")" == "outside sentinel" ]] || die "self-test modified outside bytes: $1"
}

default_profile="$work/default-distribution-profile"
contract_profile="$work/contract-distribution-profile"
explicit_profile="$work/explicit-distribution-profile"
{
  distribution_app_archive_label
  distribution_expected_arches
  distribution_app_archive_name unsigned-non-release
  distribution_app_archive_name signed-notarized
} >"$default_profile"
{
  distribution_app_archive_label arm64
  distribution_expected_arches arm64
  distribution_app_archive_name unsigned-non-release arm64
  distribution_app_archive_name signed-notarized arm64
} >"$explicit_profile"
printf '%s\n' \
  arm64 \
  arm64 \
  "gta-claw-$VERSION-macos-arm64-unsigned-non-release.app.zip" \
  "gta-claw-$VERSION-macos-arm64-signed-notarized.app.zip" \
  >"$contract_profile"
cmp -s "$default_profile" "$explicit_profile" ||
  die "omitted distribution arguments differ from explicit arm64 values"
cmp -s "$default_profile" "$contract_profile" ||
  die "default distribution profile bytes differ from the arm64 contract"
tests=$((tests + 1))
[[ "$(distribution_app_archive_label arm64)" == "arm64" ]] ||
  die "arm64 app archive label override failed"
[[ "$(distribution_expected_arches arm64)" == "arm64" ]] ||
  die "arm64 distribution architecture override failed"
[[ "$(distribution_app_archive_name signed-notarized arm64)" == \
  "gta-claw-$VERSION-macos-arm64-signed-notarized.app.zip" ]] ||
  die "arm64 app archive name override failed"
tests=$((tests + 1))
expect_failure retired-universal-archive-label \
  bash -c "source '$common'; distribution_app_archive_label universal2"
expect_failure retired-dual-architecture-distribution \
  bash -c "source '$common'; distribution_expected_arches 'arm64 x86_64'"
expect_failure invalid-app-archive-label \
  bash -c "source '$common'; distribution_app_archive_label '../escape'"
expect_failure invalid-distribution-architectures \
  bash -c "source '$common'; distribution_expected_arches 'arm64 riscv64'"

mkdir -p "$work/mock-cargo"
cat >"$work/mock-cargo/cargo" <<'EOF'
#!/bin/sh
printf '%s' "$1" >>"$MOCK_CARGO_LOG"
shift
for argument in "$@"; do
  printf '|%s' "$argument" >>"$MOCK_CARGO_LOG"
done
printf '\n' >>"$MOCK_CARGO_LOG"
EOF
chmod +x "$work/mock-cargo/cargo"
mock_cargo_log="$work/mock-cargo.log"
expect_success complete-dependency-acquisition \
  env PATH="$work/mock-cargo:$PATH" MOCK_CARGO_LOG="$mock_cargo_log" \
  bash -c "source '$common'; acquire_locked_dependencies"
printf 'fetch|--manifest-path|%s/Cargo.toml|--locked\nfetch|--manifest-path|%s/desktop/Cargo.toml|--locked\n' \
  "$REPO_ROOT" "$REPO_ROOT" >"$work/expected-mock-cargo.log"
cmp -s "$mock_cargo_log" "$work/expected-mock-cargo.log" ||
  die "locked dependency acquisition did not cover both complete workspaces"
tests=$((tests + 1))

mkdir -p "$work/failing-cargo"
cat >"$work/failing-cargo/cargo" <<'EOF'
#!/bin/sh
exit 99
EOF
chmod +x "$work/failing-cargo/cargo"
expect_failure offline-graph-cache-precondition \
  env PATH="$work/failing-cargo:$PATH" \
  bash -c "source '$common'; assert_headless_cargo_tree aarch64-apple-darwin"
grep -F 'acquire locked dependencies with cargo fetch before running build.sh' \
  "$work/offline-graph-cache-precondition.stderr" >/dev/null ||
  die "offline graph failure omitted its dependency acquisition precondition"
tests=$((tests + 1))

package_inventory="$(write_spdx_package_inventory $'alpha 1.0.0\nbeta 2.0.0\nalpha 1.0.0')"
[[ "$(grep -c '^PackageName:' <<<"$package_inventory")" -eq 2 ]] ||
  die "SPDX package inventory did not deduplicate package rows"
grep -F 'PackageName: alpha' <<<"$package_inventory" >/dev/null ||
  die "SPDX package inventory omitted alpha"
grep -F 'PackageVersion: 2.0.0' <<<"$package_inventory" >/dev/null ||
  die "SPDX package inventory omitted beta version"
tests=$((tests + 1))

expect_failure invalid-bundle-id env BUNDLE_ID=invalid bash -c "source '$common'"
expect_failure invalid-version env VERSION=1.2-beta bash -c "source '$common'"
expect_failure invalid-build-version env BUILD_VERSION=1.beta bash -c "source '$common'"
expect_failure app-name-traversal env APP_NAME=../escape bash -c "source '$common'"
expect_failure app-name-absolute env APP_NAME=/tmp/escape bash -c "source '$common'"
expect_failure app-name-slash env APP_NAME=GTA/Claw bash -c "source '$common'"
expect_failure app-name-backslash env APP_NAME='GTA\Claw' bash -c "source '$common'"
expect_failure app-name-control env APP_NAME=$'GTA\nClaw' bash -c "source '$common'"
expect_failure app-name-leading-dot env APP_NAME=.GTA bash -c "source '$common'"
expect_failure executable-name-traversal env EXECUTABLE_NAME=../escape bash -c "source '$common'"
expect_failure executable-name-absolute env EXECUTABLE_NAME=/tmp/escape bash -c "source '$common'"
expect_failure executable-name-slash env EXECUTABLE_NAME=gta/claw bash -c "source '$common'"
expect_failure executable-name-backslash env EXECUTABLE_NAME='gta\claw' bash -c "source '$common'"
expect_failure executable-name-space env EXECUTABLE_NAME='gta claw' bash -c "source '$common'"
expect_failure missing-tool bash -c "source '$common'; require_tool gta-claw-tool-that-does-not-exist"
expect_failure path-traversal bash -c "source '$common'; assert_output_path '$OUTPUT_ROOT/../escape'"

mkdir -p "$outside/output-root-existing"
ln -s "$outside/output-root-existing" "$escape_link"
expect_failure output-root-intermediate-symlink \
  env OUTPUT_ROOT="$escape_link/package" bash -c "source '$common'"
assert_absent "$outside/output-root-existing/package"
rm -f -- "$escape_link"
ln -s "$outside/output-root-dangling" "$escape_link"
expect_failure output-root-dangling-symlink \
  env OUTPUT_ROOT="$escape_link/package" bash -c "source '$common'"
assert_absent "$outside/output-root-dangling"
rm -f -- "$escape_link"

mkdir -p "$work/symlink-root"
ln -s "$work" "$work/symlink-root/link"
expect_failure symlink-rejection bash -c "source '$common'; reject_symlinks '$work/symlink-root'"
mkdir -p "$outside/reset-existing"
printf 'outside sentinel\n' >"$outside/reset-existing/sentinel"
ln -s "$outside/reset-existing" "$work/intermediate-link"
expect_failure output-path-intermediate-symlink \
  bash -c "source '$common'; assert_output_path '$work/intermediate-link/file'"
expect_failure reset-dir-intermediate-symlink \
  bash -c "source '$common'; safe_reset_dir '$work/intermediate-link/delete'"
assert_sentinel "$outside/reset-existing/sentinel"
assert_absent "$outside/reset-existing/delete"
ln -s "$outside/reset-dangling" "$work/dangling-link"
expect_failure output-path-dangling-symlink \
  bash -c "source '$common'; assert_output_path '$work/dangling-link/file'"
expect_failure reset-dir-dangling-symlink \
  bash -c "source '$common'; safe_reset_dir '$work/dangling-link/delete'"
assert_absent "$outside/reset-dangling"

mkdir -p "$work/reset-race" "$work/fake-bin" "$outside/reset-race-target"
printf 'outside sentinel\n' >"$outside/reset-race-target/sentinel"
cat >"$work/fake-bin/rm" <<'EOF'
#!/usr/bin/env bash
set -e
/bin/rm "$@"
ln -s "$RESET_RACE_TARGET" "$RESET_RACE_PATH"
EOF
chmod 0755 "$work/fake-bin/rm"
expect_failure reset-recreate-race \
  env \
    PATH="$work/fake-bin:$PATH" \
    RESET_RACE_PATH="$work/reset-race" \
    RESET_RACE_TARGET="$outside/reset-race-target" \
    bash -c "source '$common'; safe_reset_dir '$work/reset-race'"
assert_sentinel "$outside/reset-race-target/sentinel"
assert_absent "$outside/reset-race-target/reset-race"
rm -f -- "$work/reset-race"

manifest_root="$work/manifest-guard"
mkdir -p "$manifest_root"
printf 'manifest content\n' >"$manifest_root/input.txt"
manifest="$manifest_root/SHA256SUMS"
manifest_temp="$manifest.tmp"

printf 'outside sentinel\n' >"$outside/manifest-temp-existing"
ln -s "$outside/manifest-temp-existing" "$manifest_temp"
expect_failure manifest-temp-symlink \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
assert_sentinel "$outside/manifest-temp-existing"
rm -f -- "$manifest_temp"

ln -s "$outside/manifest-temp-dangling" "$manifest_temp"
expect_failure manifest-temp-dangling-symlink \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
assert_absent "$outside/manifest-temp-dangling"
rm -f -- "$manifest_temp"

printf 'stale temporary\n' >"$manifest_temp"
expect_failure manifest-temp-regular-collision \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
[[ "$(cat "$manifest_temp")" == "stale temporary" ]] ||
  die "manifest reservation truncated a regular collision"
rm -f -- "$manifest_temp"

mkdir "$manifest_temp"
expect_failure manifest-temp-directory-collision \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
rmdir "$manifest_temp"

printf 'outside sentinel\n' >"$outside/manifest-final-existing"
ln -s "$outside/manifest-final-existing" "$manifest"
expect_failure manifest-final-symlink \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
assert_sentinel "$outside/manifest-final-existing"
rm -f -- "$manifest"

ln -s "$outside/manifest-final-dangling" "$manifest"
expect_failure manifest-final-dangling-symlink \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
assert_absent "$outside/manifest-final-dangling"
rm -f -- "$manifest"

mkdir "$manifest"
expect_failure manifest-final-directory-collision \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
rmdir "$manifest"
expect_success manifest-publication \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
[[ -f "$manifest" && ! -L "$manifest" ]] || die "manifest publication did not produce a regular file"
printf 'updated manifest content\n' >"$manifest_root/input.txt"
expect_success manifest-republication \
  bash -c "source '$common'; write_sha256_manifest '$manifest_root' '$manifest'"
[[ -f "$manifest" && ! -L "$manifest" && ! -e "$manifest_temp" ]] ||
  die "manifest replacement did not atomically publish a regular file"

complete_root="$work/complete-manifest"
mkdir -p "$complete_root"
printf 'complete content\n' >"$complete_root/artifact.bin"
expect_success complete-manifest \
  bash -c "source '$common'; write_artifact_set_checksums '$complete_root'; verify_sha256_manifest '$complete_root' '$complete_root/SHA256SUMS'"
printf 'not listed\n' >"$complete_root/unexpected.bin"
expect_failure incomplete-manifest \
  bash -c "source '$common'; verify_sha256_manifest '$complete_root' '$complete_root/SHA256SUMS'"

printf 'content\n' >"$work/hash.txt"
printf '%s  ./hash.txt\n' "$(sha256_file "$work/hash.txt")" >"$work/hash.sha256"
printf 'tampered\n' >"$work/hash.txt"
expect_failure hash-mismatch bash -c "source '$common'; verify_sha256_manifest '$work' '$work/hash.sha256'"

cat >"$work/hello.c" <<'EOF'
int main(void) { return 0; }
EOF
host_arch="$(expected_lipo_arch "$(host_target)")"
xcrun clang \
  -target "$host_arch-apple-macos$MINIMUM_MACOS_VERSION" \
  "$work/hello.c" \
  -o "$work/hello-$host_arch"

mkdir -p "$outside/archive-existing"
printf 'outside sentinel\n' >"$outside/archive-existing/sentinel"
ln -s "$outside/archive-existing" "$OUTPUT_ROOT/headless"
expect_failure archive-intermediate-symlink \
  "$MACOS_DIR/archive-headless.sh" "$work/hello-$host_arch" gta-claw-cli "$host_arch" "$host_arch"
assert_sentinel "$outside/archive-existing/sentinel"
assert_absent "$outside/archive-existing/$host_arch"
rm -f -- "$OUTPUT_ROOT/headless"
ln -s "$outside/archive-dangling" "$OUTPUT_ROOT/headless"
expect_failure archive-dangling-symlink \
  "$MACOS_DIR/archive-headless.sh" "$work/hello-$host_arch" gta-claw-cli "$host_arch" "$host_arch"
assert_absent "$outside/archive-dangling"
rm -f -- "$OUTPUT_ROOT/headless"

mkdir -p "$outside/build-existing"
printf 'outside sentinel\n' >"$outside/build-existing/sentinel"
ln -s "$outside/build-existing" "$OUTPUT_ROOT/build"
expect_failure build-intermediate-symlink "$MACOS_DIR/build.sh" native
assert_sentinel "$outside/build-existing/sentinel"
assert_absent "$outside/build-existing/$(host_target)"
rm -f -- "$OUTPUT_ROOT/build"
ln -s "$outside/build-dangling" "$OUTPUT_ROOT/build"
expect_failure build-dangling-symlink "$MACOS_DIR/build.sh" native
assert_absent "$outside/build-dangling"
rm -f -- "$OUTPUT_ROOT/build"

expect_failure assemble-app-name-traversal \
  env APP_NAME=../escape "$MACOS_DIR/assemble-app.sh" "$work/hello-$host_arch" "$host_arch" "$host_arch"
expect_failure assemble-executable-name-traversal \
  env EXECUTABLE_NAME=../escape "$MACOS_DIR/assemble-app.sh" "$work/hello-$host_arch" "$host_arch" "$host_arch"

expect_success archive-first \
  "$MACOS_DIR/archive-headless.sh" "$work/hello-$host_arch" gta-claw-cli "$host_arch" "$host_arch"
archive="$OUTPUT_ROOT/headless/$host_arch/gta-claw-cli-$VERSION-macos-$host_arch.tar.gz"
cp "$archive" "$work/first-headless.tar.gz"
expect_success archive-second \
  "$MACOS_DIR/archive-headless.sh" "$work/hello-$host_arch" gta-claw-cli "$host_arch" "$host_arch"
cmp -s "$work/first-headless.tar.gz" "$archive" ||
  die "headless archive is not deterministic on rerun"
tests=$((tests + 1))

xcrun clang -target "$host_arch-apple-macos13.0" "$work/hello.c" -o "$work/hello-old-target"
expect_failure minimum-os bash -c "source '$common'; assert_macho_minimum_version '$work/hello-old-target'"

cat >"$work/bad.c" <<'EOF'
int bad(void) { return 7; }
EOF
cat >"$work/bad-main.c" <<'EOF'
int bad(void);
int main(void) { return bad(); }
EOF
xcrun clang \
  -target "$host_arch-apple-macos$MINIMUM_MACOS_VERSION" \
  -dynamiclib "$work/bad.c" \
  -Wl,-install_name,"$work/libbad.dylib" \
  -o "$work/libbad.dylib"
xcrun clang \
  -target "$host_arch-apple-macos$MINIMUM_MACOS_VERSION" \
  "$work/bad-main.c" "$work/libbad.dylib" \
  -o "$work/hello-bad-dependency"
expect_failure unexpected-dylib \
  bash -c "source '$common'; validate_macho_dependencies '$work/hello-bad-dependency' '$work'"

xcrun clang \
  -target "$host_arch-apple-macos$MINIMUM_MACOS_VERSION" \
  "$work/hello.c" \
  -Wl,-rpath,"$work/absolute-rpath" \
  -o "$work/hello-bad-rpath"
expect_failure unexpected-rpath \
  bash -c "source '$common'; validate_macho_dependencies '$work/hello-bad-rpath' '$work'"

mkdir -p "$work/failing-tools"
cat >"$work/failing-tools/otool" <<'EOF'
#!/bin/sh
exit 99
EOF
chmod +x "$work/failing-tools/otool"
expect_failure otool-capture-fails-closed \
  env PATH="$work/failing-tools:$PATH" \
  bash -c "source '$common'; validate_macho_dependencies '$work/hello-${host_arch/arm64/arm64}' '$work'"

fixture_app="$OUTPUT_ROOT/apps/$host_arch/$APP_NAME.app"
fresh_fixture() {
  local label="$1"
  expect_success "assemble-$label" \
    "$MACOS_DIR/assemble-app.sh" \
    "$work/hello-${host_arch/arm64/arm64}" \
    "self-test-$label" \
    "$host_arch"
  fixture_app="$OUTPUT_ROOT/apps/self-test-$label/$APP_NAME.app"
}

expect_success assemble-first \
  "$MACOS_DIR/assemble-app.sh" "$work/hello-${host_arch/arm64/arm64}" "$host_arch" "$host_arch"
first_manifest="$work/first-app.sha256"
write_sha256_manifest "$fixture_app" "$first_manifest"
expect_success assemble-second \
  "$MACOS_DIR/assemble-app.sh" "$work/hello-${host_arch/arm64/arm64}" "$host_arch" "$host_arch"
second_manifest="$work/second-app.sha256"
write_sha256_manifest "$fixture_app" "$second_manifest"
cmp -s "$first_manifest" "$second_manifest" || die "app assembly is not deterministic on rerun"
tests=$((tests + 1))

mkdir -p "$outside/notarization-existing"
printf 'outside sentinel\n' >"$outside/notarization-existing/sentinel"
ln -s "$outside/notarization-existing" "$OUTPUT_ROOT/notarization"
expect_failure notarization-intermediate-symlink \
  env NOTARY_PROFILE=self-test "$MACOS_DIR/notarize.sh" "$fixture_app"
assert_sentinel "$outside/notarization-existing/sentinel"
assert_absent "$outside/notarization-existing/$APP_NAME.app.zip"
rm -f -- "$OUTPUT_ROOT/notarization"
ln -s "$outside/notarization-dangling" "$OUTPUT_ROOT/notarization"
expect_failure notarization-dangling-symlink \
  env NOTARY_PROFILE=self-test "$MACOS_DIR/notarize.sh" "$fixture_app"
assert_absent "$outside/notarization-dangling"
rm -f -- "$OUTPUT_ROOT/notarization"

"$MACOS_DIR/generate-icon.sh" "$work/icon-one.icns" >/dev/null
"$MACOS_DIR/generate-icon.sh" "$work/icon-two.icns" >/dev/null
cmp -s "$work/icon-one.icns" "$work/icon-two.icns" || die "icon generation is not deterministic"
tests=$((tests + 1))

expect_failure release-without-identity \
  env DEVELOPER_ID_APPLICATION= "$MACOS_DIR/sign.sh" release "$fixture_app"
expect_failure notarization-without-credentials \
  env NOTARY_PROFILE= ASC_KEY_PATH= ASC_KEY_ID= ASC_ISSUER_ID= "$MACOS_DIR/notarize.sh" "$fixture_app"

bad_entitlements="$work/bad.entitlements"
cat >"$bad_entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.network.client</key>
	<true/>
</dict>
</plist>
EOF
codesign \
  --force \
  --sign - \
  --options runtime \
  --timestamp=none \
  --entitlements "$bad_entitlements" \
  "$fixture_app"
expect_failure entitlement-mismatch \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture plist-decoy
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable decoy" \
  "$fixture_app/Contents/Info.plist"
expect_failure plist-executable-decoy \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture plist-non-string
/usr/libexec/PlistBuddy -c "Delete :CFBundleExecutable" \
  "$fixture_app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleExecutable array" \
  "$fixture_app/Contents/Info.plist"
expect_failure plist-executable-non-string \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture plist-trailing-newline
/usr/bin/plutil -replace CFBundleExecutable -string $'gta-claw-desktop\n' \
  "$fixture_app/Contents/Info.plist"
expect_failure plist-executable-trailing-newline \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture alternate-executable
touch "$fixture_app/Contents/MacOS/alternate-desktop"
chmod +x "$fixture_app/Contents/MacOS/alternate-desktop"
expect_failure alternate-executable \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture macos-decoy
touch "$fixture_app/Contents/MacOS/README"
expect_failure macos-decoy-file \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture executable-symlink
mv "$fixture_app/Contents/MacOS/gta-claw-desktop" \
  "$fixture_app/Contents/MacOS/real-desktop"
ln -s real-desktop "$fixture_app/Contents/MacOS/gta-claw-desktop"
expect_failure executable-symlink \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture non-executable
chmod -x "$fixture_app/Contents/MacOS/gta-claw-desktop"
expect_failure non-executable-main \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

fresh_fixture javascript-runtime
touch "$fixture_app/Contents/Resources/node"
expect_failure javascript-runtime-file \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc
rm -f -- "$fixture_app/Contents/Resources/node"

rm -f -- "$fixture_app/Contents/Info.plist"
expect_failure missing-plist \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

exec_probe="$work/headless-execution"
ensure_output_directory "$exec_probe"
write_report_stub() {
  local path="$1"
  local report="$2"
  local status="${3:-0}"
  cat >"$path" <<STUB
#!/bin/sh
echo '$report'
exit $status
STUB
  chmod +x "$path"
}

stub_target="aarch64-apple-darwin"
write_report_stub "$exec_probe/cli" "gta-claw-cli $VERSION"
write_report_stub "$exec_probe/daemon" "healthy runtime=macos-aarch64"
write_report_stub "$exec_probe/cli-other-build" "gta-claw-cli 0.0.0-other-build"
write_report_stub "$exec_probe/daemon-other-arch" "healthy runtime=macos-x86_64"
write_report_stub "$exec_probe/cli-fails" "gta-claw-cli $VERSION" 1
write_report_stub "$exec_probe/daemon-fails" "healthy runtime=macos-aarch64" 1
cp "$exec_probe/cli" "$exec_probe/cli-not-executable"
chmod -x "$exec_probe/cli-not-executable"

expect_success headless-execution-accepts-this-build \
  bash -c "source '$common'; assert_headless_binaries_execute \
    '$exec_probe/cli' '$exec_probe/daemon' '$stub_target'"

# Each of these is a binary that exists, is a valid Mach-O in the real build,
# and passes every byte-reading check. Only running it tells them apart.
expect_failure headless-execution-rejects-another-builds-version \
  bash -c "source '$common'; assert_headless_binaries_execute \
    '$exec_probe/cli-other-build' '$exec_probe/daemon' '$stub_target'"
expect_failure headless-execution-rejects-another-target-arch \
  bash -c "source '$common'; assert_headless_binaries_execute \
    '$exec_probe/cli' '$exec_probe/daemon-other-arch' '$stub_target'"
expect_failure headless-execution-rejects-failing-cli \
  bash -c "source '$common'; assert_headless_binaries_execute \
    '$exec_probe/cli-fails' '$exec_probe/daemon' '$stub_target'"
expect_failure headless-execution-rejects-failing-daemon \
  bash -c "source '$common'; assert_headless_binaries_execute \
    '$exec_probe/cli' '$exec_probe/daemon-fails' '$stub_target'"
expect_failure headless-execution-rejects-non-executable-cli \
  bash -c "source '$common'; assert_headless_binaries_execute \
    '$exec_probe/cli-not-executable' '$exec_probe/daemon' '$stub_target'"

app_probe="$work/app-execution"
app_report="gta-claw-desktop packaging self-check ok"
app_report+=" version=$VERSION runtime=macos-aarch64"

write_app_stub() {
  local label="$1"
  local report="$2"
  local status="${3:-0}"
  ensure_output_directory "$app_probe/$label/$APP_NAME.app/Contents/MacOS"
  write_report_stub \
    "$app_probe/$label/$APP_NAME.app/Contents/MacOS/$EXECUTABLE_NAME" \
    "$report" "$status"
}

write_app_stub accepted "$app_report"
write_app_stub other-build \
  "gta-claw-desktop packaging self-check ok version=0.0.0-other runtime=macos-aarch64"
write_app_stub other-arch \
  "gta-claw-desktop packaging self-check ok version=$VERSION runtime=macos-x86_64"
write_app_stub failing "$app_report" 1
write_app_stub not-executable "$app_report"
chmod -x "$app_probe/not-executable/$APP_NAME.app/Contents/MacOS/$EXECUTABLE_NAME"
ensure_output_directory "$app_probe/missing/$APP_NAME.app/Contents/MacOS"

# The report is the last thing the binary does, after the real shutdown path has
# returned. A bundle that prints it and then keeps talking did not complete the
# same run, so the comparison is equality and not containment.
ensure_output_directory "$app_probe/noisy/$APP_NAME.app/Contents/MacOS"
noisy_stub="$app_probe/noisy/$APP_NAME.app/Contents/MacOS/$EXECUTABLE_NAME"
{
  printf '#!/bin/sh\n'
  printf "echo '%s'\n" "$app_report"
  printf "echo 'controller shutdown timed out'\n"
  printf 'exit 0\n'
} >"$noisy_stub"
chmod +x "$noisy_stub"

expect_success app-execution-accepts-this-build \
  bash -c "source '$common'; assert_packaged_app_executes \
    '$app_probe/accepted/$APP_NAME.app' '$stub_target'"

expect_failure app-execution-rejects-another-builds-version \
  bash -c "source '$common'; assert_packaged_app_executes \
    '$app_probe/other-build/$APP_NAME.app' '$stub_target'"
expect_failure app-execution-rejects-another-target-arch \
  bash -c "source '$common'; assert_packaged_app_executes \
    '$app_probe/other-arch/$APP_NAME.app' '$stub_target'"
expect_failure app-execution-rejects-failing-app \
  bash -c "source '$common'; assert_packaged_app_executes \
    '$app_probe/failing/$APP_NAME.app' '$stub_target'"
expect_failure app-execution-rejects-extra-output \
  bash -c "source '$common'; assert_packaged_app_executes \
    '$app_probe/noisy/$APP_NAME.app' '$stub_target'"
expect_failure app-execution-rejects-missing-executable \
  bash -c "source '$common'; assert_packaged_app_executes \
    '$app_probe/missing/$APP_NAME.app' '$stub_target'"
expect_failure app-execution-rejects-non-executable-app \
  bash -c "source '$common'; assert_packaged_app_executes \
    '$app_probe/not-executable/$APP_NAME.app' '$stub_target'"

note "$tests macOS packaging self-tests passed"
