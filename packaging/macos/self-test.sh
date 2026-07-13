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
  "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" ||
    die "self-test failed: $name (see $work/$name.stderr)"
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

printf 'content\n' >"$work/hash.txt"
printf '%s  ./hash.txt\n' "$(sha256_file "$work/hash.txt")" >"$work/hash.sha256"
printf 'tampered\n' >"$work/hash.txt"
expect_failure hash-mismatch bash -c "source '$common'; verify_sha256_manifest '$work' '$work/hash.sha256'"

cat >"$work/hello.c" <<'EOF'
int main(void) { return 0; }
EOF
xcrun clang -target arm64-apple-macos"$MINIMUM_MACOS_VERSION" "$work/hello.c" -o "$work/hello-arm64"
xcrun clang -target x86_64-apple-macos"$MINIMUM_MACOS_VERSION" "$work/hello.c" -o "$work/hello-x86_64"
host_arch="$(expected_lipo_arch "$(host_target)")"

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
expect_success universal-merge \
  "$MACOS_DIR/merge-universal.sh" "$work/hello-arm64" "$work/hello-x86_64" "$work/hello-universal"
expect_failure wrong-slice \
  "$MACOS_DIR/merge-universal.sh" "$work/hello-arm64" "$work/hello-arm64" "$work/wrong-universal"
expect_failure missing-slice \
  "$MACOS_DIR/merge-universal.sh" "$work/hello-arm64" "$work/missing-x86_64" "$work/missing-universal"
assert_binary_arches "$work/hello-universal" "arm64 x86_64"
assert_binary_arches "$work/hello-universal" "x86_64 arm64"
tests=$((tests + 1))

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

fixture_app="$OUTPUT_ROOT/apps/$host_arch/$APP_NAME.app"
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

expect_success restore-fixture \
  "$MACOS_DIR/assemble-app.sh" "$work/hello-${host_arch/arm64/arm64}" "$host_arch" "$host_arch"
touch "$fixture_app/Contents/Resources/node"
expect_failure javascript-runtime-file \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc
rm -f -- "$fixture_app/Contents/Resources/node"

rm -f -- "$fixture_app/Contents/Info.plist"
expect_failure missing-plist \
  "$MACOS_DIR/validate.sh" "$fixture_app" "$host_arch" adhoc

note "$tests macOS packaging self-tests passed"
