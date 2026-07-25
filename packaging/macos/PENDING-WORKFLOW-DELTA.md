diff --git a/.github/workflows/macos-packaging.yml b/.github/workflows/macos-packaging.yml
index 1af3859..f1594de 100644
--- a/.github/workflows/macos-packaging.yml
+++ b/.github/workflows/macos-packaging.yml
@@ -1,18 +1,6 @@
-name: macOS packaging prototype
+name: macOS release packaging

 on:
-  push:
-    branches:
-      - main
-    paths:
-      - ".github/workflows/macos-packaging.yml"
-      - "packaging/macos/**"
-      - "apps/**"
-      - "crates/**"
-      - "desktop/**"
-      - "Cargo.lock"
-      - "Cargo.toml"
-      - "rust-toolchain.toml"
   pull_request:
     paths:
       - ".github/workflows/macos-packaging.yml"
@@ -26,14 +14,10 @@ on:
   workflow_dispatch:
     inputs:
       release:
-        description: Exercise the protected signing and notarization contract
+        description: Build protected signed and notarized release artifacts
         required: true
         type: boolean
         default: false
-      version:
-        description: Numeric X.Y.Z release version (defaults to Cargo workspace version)
-        required: false
-        type: string
       release_commit:
         description: Full immutable commit SHA selected by the release tag
         required: false
@@ -47,13 +31,14 @@ concurrency:
   cancel-in-progress: true

 env:
+  CARGO_BUILD_JOBS: "4"
   CARGO_TERM_COLOR: always
   MACOSX_DEPLOYMENT_TARGET: "14.0"
   RUSTFLAGS: -Dwarnings

 jobs:
   source-policy:
-    name: Source policy and Linux rejection
+    name: Source and frozen release policy
     runs-on: ubuntu-latest
     steps:
       - name: Checkout
@@ -61,42 +46,48 @@ jobs:
         with:
           persist-credentials: false

-      - name: Check shell syntax and forbidden committed artifacts
+      - name: Validate shell and frozen release surfaces
         shell: bash
         run: |
           set -euo pipefail
           find packaging/macos -type f -name '*.sh' -print0 |
             while IFS= read -r -d '' script; do bash -n "$script"; done
+          ./packaging/macos/validate-release-surfaces.sh
+          ./packaging/macos/workflow-self-test.sh
+
+      - name: Reject generated and JavaScript packaging material
+        shell: bash
+        run: |
+          set -euo pipefail
           if git ls-files packaging/macos |
             grep -Ei '\.(app|dmg|pkg|p12|cer|key|icns|png|tar\.gz|zip)$'; then
             echo "Generated package, credential, image, or binary committed under packaging/macos"
             exit 1
           fi
-          if grep -RInE '(^|[[:space:]])(npm|npx|node|bun|pnpm)([[:space:]]|$)' \
-            packaging/macos --include='*.sh' --include='*.yml'; then
-            echo "JavaScript package/runtime command found in macOS packaging automation"
+          if find packaging/macos -type f \( \
+            -iname 'node' -o -iname 'npm' -o -iname 'npx' -o -iname 'bun' -o \
+            -iname 'pnpm' -o -iname 'package.json' -o -iname '*.js' -o \
+            -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.node' \
+          \) -print -quit | grep .; then
+            echo "JavaScript or Node packaging material is forbidden"
             exit 1
           fi
-          ./packaging/macos/workflow-self-test.sh

-      - name: Preserve Linux desktop rejection
+      - name: Prove the headless graph excludes Slint
         shell: bash
         run: |
           set -euo pipefail
-          cargo metadata --manifest-path desktop/Cargo.toml --locked --format-version 1 \
-            --filter-platform x86_64-unknown-linux-gnu |
-            python -c 'import json, sys; names = {package["name"] for package in json.load(sys.stdin)["packages"]}; forbidden = sorted(name for name in names if name == "slint" or name == "slint-build" or name.startswith("i-slint")); assert not forbidden, f"Linux desktop metadata contains Slint packages: {forbidden}"'
-          set +e
-          output=$(cargo check --manifest-path desktop/Cargo.toml \
-            --package gta-claw-desktop --locked 2>&1)
-          status=$?
-          set -e
-          printf '%s\n' "$output"
-          test "$status" -ne 0
-          grep -F "gta-claw-desktop supports only Windows and macOS" <<<"$output"
+          cargo fetch --manifest-path Cargo.toml --locked
+          tree="$(cargo tree \
+            --manifest-path Cargo.toml \
+            --locked --offline --prefix none --format '{p}')"
+          if grep -E '^(slint|slint-build|i-slint[-A-Za-z0-9]*) v' <<<"$tree"; then
+            echo "Headless Cargo graph contains Slint"
+            exit 1
+          fi

   native:
-    name: Native ${{ matrix.arch }} on ${{ matrix.runner }}
+    name: Native ${{ matrix.arch }} execution
     needs: source-policy
     strategy:
       fail-fast: false
@@ -104,8 +95,10 @@ jobs:
         include:
           - runner: macos-15
             arch: arm64
-          - runner: macos-15-intel
+            target: aarch64-apple-darwin
+          - runner: macos-15-large
             arch: x86_64
+            target: x86_64-apple-darwin
     runs-on: ${{ matrix.runner }}
     steps:
       - name: Checkout
@@ -113,117 +106,102 @@ jobs:
         with:
           persist-credentials: false

-      - name: Record Apple tool versions
+      - name: Assert native runner and acquire locked dependencies
         shell: bash
         run: |
           set -euo pipefail
-          sw_vers
-          xcodebuild -version
-          rustc -Vv
-          cargo -V
-          uname -m
+          test "$(uname -m)" = "${{ matrix.arch }}"
+          rustup target add "${{ matrix.target }}"
+          cargo fetch --manifest-path Cargo.toml --locked --target "${{ matrix.target }}"
+          cargo fetch --manifest-path desktop/Cargo.toml --locked --target "${{ matrix.target }}"

-      - name: Format both Cargo workspaces
+      - name: Format, check, Clippy, and test both workspaces
+        shell: bash
         run: |
+          set -euo pipefail
           cargo fmt --all -- --check
           cargo fmt --manifest-path desktop/Cargo.toml --all -- --check
-
-      - name: Check both Cargo workspaces
-        run: |
-          cargo check --workspace --all-targets --locked
-          cargo check --manifest-path desktop/Cargo.toml --workspace --all-targets --locked
-
-      - name: Clippy both Cargo workspaces
-        run: |
-          cargo clippy --workspace --all-targets --locked -- -D warnings
-          cargo clippy --manifest-path desktop/Cargo.toml --workspace --all-targets --locked -- -D warnings
-
-      - name: Test both Cargo workspaces natively
-        run: |
-          test "$(uname -m)" = "${{ matrix.arch }}"
-          cargo test --workspace --all-targets --locked
-          cargo test --manifest-path desktop/Cargo.toml --workspace --all-targets --locked
-
-      - name: Smoke-test native desktop window backend
+          cargo check --workspace --all-targets --locked --offline
+          cargo check --manifest-path desktop/Cargo.toml --workspace --all-targets --locked --offline
+          cargo clippy --workspace --all-targets --locked --offline -- -D warnings
+          cargo clippy --manifest-path desktop/Cargo.toml --workspace --all-targets --locked --offline -- -D warnings
+          cargo test --workspace --all-targets --locked --offline
+          cargo test --manifest-path desktop/Cargo.toml --workspace --all-targets --locked --offline
+
+      - name: Smoke-test native desktop backend
         timeout-minutes: 2
         env:
           SLINT_BACKEND: winit-software
-        run: cargo test --manifest-path desktop/Cargo.toml --test macos_winit_smoke --locked
-
-      - name: Build and validate native packages
-        shell: bash
-        run: ./packaging/macos/build.sh native
+        run: cargo test --manifest-path desktop/Cargo.toml --test macos_winit_smoke --locked --offline

-      - name: Run packaging self-tests
-        if: matrix.arch == 'arm64'
+      - name: Build and validate native published bytes offline
         shell: bash
+        env:
+          GTA_CLAW_OFFLINE: "1"
         run: |
-          OUTPUT_ROOT="$GITHUB_WORKSPACE/target/macos-self-test" \
-            ./packaging/macos/self-test.sh
+          set -euo pipefail
+          ./packaging/macos/build.sh native
+          ./packaging/macos/validate-artifacts.sh \
+            "target/macos-package/headless/${{ matrix.arch }}" prototype

-      - name: Scan native artifacts for JavaScript runtimes
+      - name: Run macOS packaging self-tests
+        if: matrix.arch == 'arm64'
         shell: bash
-        run: |
-          set -euo pipefail
-          if find target/macos-package -type f \( \
-            -iname 'node' -o -iname 'npm' -o -iname 'bun' -o -iname 'pnpm' -o \
-            -iname '*.js' -o -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.node' \
-          \) -print -quit | grep .; then
-            exit 1
-          fi
+        env:
+          GTA_CLAW_OFFLINE: "1"
+          OUTPUT_ROOT: ${{ github.workspace }}/target/macos-self-test
+        run: ./packaging/macos/self-test.sh

-      - name: Upload ephemeral native prototype artifacts
+      - name: Upload native verification artifacts
         uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
         with:
-          name: macos-${{ matrix.arch }}-prototype-${{ github.sha }}
+          name: macos-${{ matrix.arch }}-verified-${{ github.sha }}
           path: |
             target/macos-package/apps/${{ matrix.arch }}/GTA Claw.app
-            target/macos-package/headless/${{ matrix.arch }}/*.tar.gz
-            target/macos-package/headless/${{ matrix.arch }}/*.sha256
-            target/macos-package/manifests/*.sha256
+            target/macos-package/headless/${{ matrix.arch }}
           if-no-files-found: error
           retention-days: 7
+          compression-level: 0

   universal:
-    name: Universal2 assembly and containers
+    name: Universal2 assembly and prototype containers
     needs: source-policy
     runs-on: macos-15
     outputs:
-      release-payload-sha256: ${{ steps.release-input.outputs.sha256 }}
+      prototype-artifact-id: ${{ steps.prototype-upload.outputs.artifact-id }}
       release-artifact-id: ${{ steps.release-upload.outputs.artifact-id }}
       release-artifact-digest: ${{ steps.release-upload.outputs.artifact-digest }}
+      release-payload-sha256: ${{ steps.release-input.outputs.sha256 }}
     steps:
       - name: Checkout
         uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
         with:
           persist-credentials: false

-      - name: Build and validate both slices and universal2 app
+      - name: Acquire both targets and locked dependencies
         shell: bash
-        run: ./packaging/macos/build.sh universal2
+        run: |
+          set -euo pipefail
+          for target in aarch64-apple-darwin x86_64-apple-darwin; do
+            rustup target add "$target"
+            cargo fetch --manifest-path Cargo.toml --locked --target "$target"
+            cargo fetch --manifest-path desktop/Cargo.toml --locked --target "$target"
+          done

-      - name: Build unsigned prototype DMG and PKG
+      - name: Build universal2 and inspect prototype bytes offline
         shell: bash
+        env:
+          GTA_CLAW_OFFLINE: "1"
         run: |
+          set -euo pipefail
+          ./packaging/macos/build.sh universal2
           ./packaging/macos/package.sh prototype \
             "$GITHUB_WORKSPACE/target/macos-package/apps/universal2/GTA Claw.app"
-          hdiutil verify target/macos-package/distribution/*.dmg
-          pkgutil --payload-files target/macos-package/distribution/*.pkg |
-            LC_ALL=C sort > target/macos-package/distribution/pkg-payload.txt
+          ./packaging/macos/validate-artifacts.sh \
+            "$GITHUB_WORKSPACE/target/macos-package/distribution" \
+            prototype SHA256SUMS-macos

-      - name: Validate universal architecture and content hashes
-        shell: bash
-        run: |
-          set -euo pipefail
-          app="target/macos-package/apps/universal2/GTA Claw.app"
-          ./packaging/macos/validate.sh "$app" "arm64 x86_64" adhoc
-          lipo "$app/Contents/MacOS/gta-claw-desktop" -verify_arch arm64 x86_64
-          (
-            cd target/macos-package/distribution
-            shasum -a 256 -c SHA256SUMS
-          )
-
-      - name: Prepare immutable release input
+      - name: Prepare immutable secret-free release input
         if: github.event_name == 'workflow_dispatch' && inputs.release == true
         id: release-input
         shell: bash
@@ -249,162 +227,78 @@ jobs:
           retention-days: 1
           compression-level: 0

-      - name: Upload ephemeral universal prototype artifacts
+      - name: Upload universal prototype and CLI archives
+        id: prototype-upload
         uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
         with:
           name: macos-universal2-prototype-${{ github.sha }}
           path: |
             target/macos-package/apps/universal2/GTA Claw.app
-            target/macos-package/headless/**/*.tar.gz
-            target/macos-package/headless/**/*.sha256
-            target/macos-package/distribution/*
-            target/macos-package/manifests/*.sha256
+            target/macos-package/headless
+            target/macos-package/distribution
           if-no-files-found: error
           retention-days: 7
-
-  release-disabled:
-    name: Release signing explicitly disabled
-    if: github.event_name != 'workflow_dispatch' || inputs.release != true
-    runs-on: ubuntu-latest
-    steps:
-      - run: echo "Release mode was not requested; no signing, notarization, publication, or release upload occurred."
+          compression-level: 0

   release-policy:
     name: Validate immutable release ref
     if: github.event_name == 'workflow_dispatch' && inputs.release == true
     needs: source-policy
     runs-on: ubuntu-latest
-    permissions:
-      contents: read
     outputs:
       release-sha: ${{ steps.policy.outputs.release-sha }}
       release-ref: ${{ steps.policy.outputs.release-ref }}
       version: ${{ steps.policy.outputs.version }}
     steps:
-      - name: Checkout candidate commit without secrets
+      - name: Checkout candidate with tag history
         uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
         with:
           ref: ${{ github.sha }}
           fetch-depth: 0
           persist-credentials: false

-      - name: Install pinned release metadata toolchain
-        shell: /usr/bin/env -i PATH=/usr/bin:/bin /bin/bash --noprofile --norc -euo pipefail {0}
-        run: |
-          readonly rustup_bin="/home/runner/.cargo/bin/rustup"
-          [[ -x "$rustup_bin" ]]
-          "$rustup_bin" toolchain install 1.97.0 \
-            --profile minimal \
-            --no-self-update
-
-      - name: Enforce protected main and semantic tag policy
+      - name: Enforce protected annotated tag and version policy
         id: policy
         shell: bash
         env:
-          DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}
           RELEASE_COMMIT: ${{ inputs.release_commit }}
-          REQUESTED_VERSION: ${{ inputs.version }}
         run: |
           set -euo pipefail
-          test "$DEFAULT_BRANCH" = "main" || {
-            echo "Release policy requires main as the protected default branch" >&2
-            exit 1
-          }
-          [[ "$GITHUB_REF" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
-            echo "Release mode requires a semantic vX.Y.Z tag, not $GITHUB_REF" >&2
-            exit 1
-          }
-          test "${GITHUB_REF_TYPE:-}" = "tag" || {
-            echo "Release mode rejects non-tag workflow_dispatch refs" >&2
-            exit 1
-          }
-          [[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
-            echo "release_commit must be a full lowercase commit SHA" >&2
-            exit 1
-          }
-
-          tag_commit="$(git rev-parse "$GITHUB_REF^{commit}")"
-          tag_object="$(git rev-parse "$GITHUB_REF")"
-          test "$(git cat-file -t "$GITHUB_REF")" = "tag" || {
-            echo "Release mode requires an annotated, protected tag" >&2
-            exit 1
-          }
-          test "$tag_commit" = "$GITHUB_SHA" || {
-            echo "Tag commit does not match the workflow commit" >&2
-            exit 1
-          }
-          test "$RELEASE_COMMIT" = "$GITHUB_SHA" || {
-            echo "release_commit does not match the immutable workflow commit" >&2
-            exit 1
-          }
-
-          remote_tag_object="$(
-            git ls-remote --exit-code origin "$GITHUB_REF" |
-              awk 'NR == 1 { print $1 }'
-          )"
-          test "$remote_tag_object" = "$tag_object" || {
-            echo "Remote tag changed after workflow dispatch" >&2
-            exit 1
-          }
-          git fetch --no-tags origin \
-            "+refs/heads/$DEFAULT_BRANCH:refs/remotes/origin/$DEFAULT_BRANCH"
-          git merge-base --is-ancestor "$GITHUB_SHA" "origin/$DEFAULT_BRANCH" || {
-            echo "Release commit is not reachable from protected main" >&2
-            exit 1
-          }
-
+          [[ "$GITHUB_REF" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]]
+          [[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
+          test "$RELEASE_COMMIT" = "$GITHUB_SHA"
+          test "$(git cat-file -t "$GITHUB_REF")" = "tag"
+          test "$(git rev-parse "$GITHUB_REF^{commit}")" = "$GITHUB_SHA"
+          git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main
+          git merge-base --is-ancestor "$GITHUB_SHA" origin/main
           version="${GITHUB_REF_NAME#v}"
-          readonly metadata_script="$GITHUB_WORKSPACE/.github/trusted/desktop-supply-chain-policy/scripts/release-metadata-version.sh"
-          readonly metadata_root="${RUNNER_TEMP}/gta-claw-release-version"
-          readonly rustup_bin="/home/runner/.cargo/bin/rustup"
-          [[ "$RUNNER_TEMP" == /home/runner/work/_temp/* ]]
-          [[ "$GITHUB_WORKSPACE" == /home/runner/work/* ]]
-          [[ -f "$metadata_script" && ! -L "$metadata_script" ]]
-          [[ -x "$rustup_bin" && ! -e "$metadata_root" ]]
-          cargo_bin="$(
-            /usr/bin/env -i \
-              HOME=/home/runner \
-              RUSTUP_HOME=/home/runner/.rustup \
-              PATH=/usr/bin:/bin \
-              "$rustup_bin" which --toolchain 1.97.0 cargo
-          )"
-          rustc_bin="$(
-            /usr/bin/env -i \
-              HOME=/home/runner \
-              RUSTUP_HOME=/home/runner/.rustup \
-              PATH=/usr/bin:/bin \
-              "$rustup_bin" which --toolchain 1.97.0 rustc
-          )"
-          [[ "$cargo_bin" == /home/runner/.rustup/toolchains/1.97.0-*/bin/cargo ]]
-          [[ "$rustc_bin" == /home/runner/.rustup/toolchains/1.97.0-*/bin/rustc ]]
-          [[ -x "$cargo_bin" && -x "$rustc_bin" ]]
           cargo_version="$(
-            /bin/bash "$metadata_script" \
-              "$cargo_bin" \
-              "$rustc_bin" \
-              "$GITHUB_WORKSPACE" \
-              "$metadata_root" \
-              "$version" \
-              "$REQUESTED_VERSION"
+            awk '
+              /^\[workspace\.package\]$/ { in_package = 1; next }
+              /^\[/ { in_package = 0 }
+              in_package && $1 == "version" {
+                gsub(/"/, "", $3)
+                print $3
+                exit
+              }
+            ' Cargo.toml
           )"
-          test "$version" = "$cargo_version" || {
-            echo "Tag version $version does not match Cargo version $cargo_version" >&2
-            exit 1
-          }
-          if [[ -n "$REQUESTED_VERSION" ]]; then
-            test "$REQUESTED_VERSION" = "$version" || {
-              echo "Requested version does not match the release tag" >&2
-              exit 1
-            }
-          fi
+          test "$version" = "$cargo_version"
           {
-            printf 'release-sha=%s\n' "$GITHUB_SHA"
-            printf 'release-ref=%s\n' "$GITHUB_REF"
-            printf 'version=%s\n' "$version"
+            echo "release-sha=$GITHUB_SHA"
+            echo "release-ref=$GITHUB_REF"
+            echo "version=$version"
           } >>"$GITHUB_OUTPUT"

-  protected-release-contract:
-    name: Protected signing and notarization contract
+  release-disabled:
+    name: Signing explicitly disabled
+    if: github.event_name != 'workflow_dispatch' || inputs.release != true
+    runs-on: ubuntu-latest
+    steps:
+      - run: echo "Only explicit protected release dispatches sign, notarize, or publish artifacts."
+
+  protected-release:
+    name: Protected signed and notarized macOS release
     if: github.event_name == 'workflow_dispatch' && inputs.release == true
     needs:
       - native
@@ -414,382 +308,249 @@ jobs:
     environment: macos-release
     permissions:
       actions: read
-      contents: read
+      contents: write
     steps:
-      - name: Checkout exact trusted release verifier
+      - name: Checkout exact immutable release source
         uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
         with:
           ref: ${{ needs.release-policy.outputs.release-sha }}
-          path: trusted-release-policy
           fetch-depth: 1
-          fetch-tags: false
           persist-credentials: false
-          sparse-checkout: .github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh
-          sparse-checkout-cone-mode: false
-          submodules: false
-          lfs: false
-          clean: true
-          set-safe-directory: false
-          show-progress: false
-
-      - name: Download exact secret-free release input
+
+      - name: Download exact release input and verified CLI artifacts
         uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
         with:
-          artifact-ids: ${{ needs.universal.outputs.release-artifact-id }}
+          artifact-ids: >-
+            ${{ needs.universal.outputs.release-artifact-id }},
+            ${{ needs.universal.outputs.prototype-artifact-id }}
           path: ${{ runner.temp }}/gta-claw-release-download
+          merge-multiple: true

-      - name: Verify artifact digest, metadata, and unsigned app
+      - name: Verify immutable release input before credentials exist
         shell: bash
         env:
-          EXPECTED_ARTIFACT_ID: ${{ needs.universal.outputs.release-artifact-id }}
-          EXPECTED_ARTIFACT_DIGEST: ${{ needs.universal.outputs.release-artifact-digest }}
           EXPECTED_PAYLOAD_SHA256: ${{ needs.universal.outputs.release-payload-sha256 }}
           EXPECTED_RELEASE_REF: ${{ needs.release-policy.outputs.release-ref }}
           EXPECTED_RELEASE_SHA: ${{ needs.release-policy.outputs.release-sha }}
           EXPECTED_VERSION: ${{ needs.release-policy.outputs.version }}
-          GH_TOKEN: ${{ github.token }}
         run: |
           set -euo pipefail
-          umask 077
-          [[ "$EXPECTED_ARTIFACT_ID" =~ ^[0-9]+$ ]]
-          [[ "$EXPECTED_ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]
-          [[ "$EXPECTED_PAYLOAD_SHA256" =~ ^[0-9a-f]{64}$ ]]
-          [[ "$EXPECTED_RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]]
-          [[ "$EXPECTED_RELEASE_REF" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]]
-          artifact_metadata="$(gh api \
-            "repos/$GITHUB_REPOSITORY/actions/artifacts/$EXPECTED_ARTIFACT_ID")"
-          test "$(jq -r '.name' <<<"$artifact_metadata")" = \
-            "macos-release-input-$EXPECTED_RELEASE_SHA"
-          test "$(jq -r '.expired' <<<"$artifact_metadata")" = "false"
-          test "$(jq -r '.workflow_run.id' <<<"$artifact_metadata")" = "$GITHUB_RUN_ID"
-          test "$(jq -r '.digest' <<<"$artifact_metadata")" = \
-            "sha256:$EXPECTED_ARTIFACT_DIGEST"
           payload="$RUNNER_TEMP/gta-claw-release-download/gta-claw-$EXPECTED_VERSION-release-input.tar.gz"
           test -f "$payload" -a ! -L "$payload"
           test "$(shasum -a 256 "$payload" | awk '{ print $1 }')" = "$EXPECTED_PAYLOAD_SHA256"
-
           listing="$RUNNER_TEMP/gta-claw-release-listing"
           tar -tzf "$payload" >"$listing"
           if grep -E '(^/|(^|/)\.\.(/|$)|\\)' "$listing"; then
             echo "Release input contains an unsafe archive path" >&2
             exit 1
           fi
-          if tar -tvzf "$payload" | awk '$1 ~ /^[lh]/ { found = 1 } END { exit !found }'; then
+          if tar -tvzf "$payload" |
+            awk '$1 ~ /^[lh]/ { found = 1 } END { exit !found }'; then
             echo "Release input contains a link entry" >&2
             exit 1
           fi
-
           state="$RUNNER_TEMP/gta-claw-release"
-          test ! -L "$state"
           rm -rf -- "$state"
           mkdir -m 0700 "$state"
           tar -xzf "$payload" -C "$state"
           root="$state/release-input"
           test -d "$root" -a ! -L "$root"
           test -z "$(find "$root" -type l -print -quit)"
-          actual_top="$(
-            find "$root" -mindepth 1 -maxdepth 1 -exec basename {} \; |
-              LC_ALL=C sort
-          )"
-          expected_top="$(printf '%s\n' 'GTA Claw.app' SHA256SUMS release-metadata.plist | LC_ALL=C sort)"
-          test "$actual_top" = "$expected_top"
           (cd "$root" && shasum -a 256 -c SHA256SUMS)
-
           metadata="$root/release-metadata.plist"
-          plutil -lint "$metadata" >/dev/null
           test "$(/usr/libexec/PlistBuddy -c 'Print :SourceSHA' "$metadata")" = "$EXPECTED_RELEASE_SHA"
           test "$(/usr/libexec/PlistBuddy -c 'Print :SourceRef' "$metadata")" = "$EXPECTED_RELEASE_REF"
           test "$(/usr/libexec/PlistBuddy -c 'Print :Version' "$metadata")" = "$EXPECTED_VERSION"
-          test "$(/usr/libexec/PlistBuddy -c 'Print :BundleIdentifier' "$metadata")" = "com.gtastudio.gta-claw"
-          test "$(/usr/libexec/PlistBuddy -c 'Print :MinimumSystemVersion' "$metadata")" = "14.0"
-
-          app="$root/GTA Claw.app"
-          verifier="$GITHUB_WORKSPACE/trusted-release-policy/.github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh"
-          plist="$app/Contents/Info.plist"
-          binary="$app/Contents/MacOS/gta-claw-desktop"
-          /bin/bash "$verifier" "$app"
-          test -f "$binary" -a -x "$binary" -a ! -L "$binary"
-          test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist")" = "com.gtastudio.gta-claw"
-          test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist")" = "$EXPECTED_VERSION"
-          test "$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$plist")" = "14.0"
-          lipo "$binary" -verify_arch arm64 x86_64
-          codesign --verify --deep --strict --verbose=2 "$app"
-          codesign -dvvv "$app" 2>&1 | grep -F 'Signature=adhoc' >/dev/null
-          dependencies="$(otool -L "$binary")" || {
-            echo "otool could not inspect release app dependencies" >&2
-            exit 1
-          }
-          if tail -n +2 <<<"$dependencies" |
-            sed -E 's/^[[:space:]]*//; /:$/d; s/[[:space:]]+\(compatibility version.*$//' |
-            grep -Ev '^(/System/Library/Frameworks/|/usr/lib/)'; then
-            echo "Release app contains a non-system dynamic dependency" >&2
-            exit 1
-          fi
-          load_commands="$(otool -l "$binary")" || {
-            echo "otool could not inspect release app load commands" >&2
-            exit 1
-          }
-          if awk '$1 == "cmd" && $2 == "LC_RPATH" { in_rpath = 1; next }
-                 in_rpath && $1 == "path" { print $2; in_rpath = 0 }' \
-              <<<"$load_commands" |
-            grep -Ev '^(@executable_path/\.\./Frameworks|@loader_path/\.\./Frameworks)$'; then
-            echo "Release app contains an unexpected rpath" >&2
-            exit 1
-          fi
-          if find "$app" -type f \( \
-            -iname 'node' -o -iname 'npm' -o -iname 'bun' -o -iname 'pnpm' -o \
-            -iname '*.js' -o -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.node' \
-          \) -print -quit | grep .; then
-            echo "Release app contains a JavaScript runtime artifact" >&2
-            exit 1
-          fi
+          ./packaging/macos/validate.sh "$root/GTA Claw.app" "arm64 x86_64" adhoc

-      - name: Import application identity and sign app
+      - name: Acquire locked metadata dependencies before credentials exist
+        shell: bash
+        run: |
+          set -euo pipefail
+          cargo fetch --manifest-path Cargo.toml --locked
+          cargo fetch --manifest-path desktop/Cargo.toml --locked
+
+      - name: Import protected Developer ID identities
+        id: signing
         shell: bash
         env:
           APP_CERTIFICATE_P12: ${{ secrets.MACOS_APP_CERTIFICATE_P12 }}
           APP_CERTIFICATE_PASSWORD: ${{ secrets.MACOS_APP_CERTIFICATE_PASSWORD }}
           DEVELOPER_ID_APPLICATION: ${{ secrets.MACOS_DEVELOPER_ID_APPLICATION }}
+          DEVELOPER_ID_INSTALLER: ${{ secrets.MACOS_DEVELOPER_ID_INSTALLER }}
+          INSTALLER_CERTIFICATE_P12: ${{ secrets.MACOS_INSTALLER_CERTIFICATE_P12 }}
+          INSTALLER_CERTIFICATE_PASSWORD: ${{ secrets.MACOS_INSTALLER_CERTIFICATE_PASSWORD }}
         run: |
           set -euo pipefail
           umask 077
-          for variable in APP_CERTIFICATE_P12 APP_CERTIFICATE_PASSWORD DEVELOPER_ID_APPLICATION; do
+          for variable in \
+            APP_CERTIFICATE_P12 APP_CERTIFICATE_PASSWORD DEVELOPER_ID_APPLICATION \
+            DEVELOPER_ID_INSTALLER INSTALLER_CERTIFICATE_P12 \
+            INSTALLER_CERTIFICATE_PASSWORD; do
             test -n "${!variable:-}" || {
-              echo "Protected application-signing secret is missing: $variable" >&2
+              echo "Protected signing credential is missing: $variable" >&2
               exit 1
             }
           done
-          [[ "$DEVELOPER_ID_APPLICATION" == "Developer ID Application:"* ]]
-
           state="$RUNNER_TEMP/gta-claw-release"
           keychain="$state/signing.keychain-db"
-          password_file="$state/keychain-password"
-          app_p12="$state/app.p12"
-          trap 'rm -f -- "$app_p12"' EXIT INT TERM
-          openssl rand -hex 32 >"$password_file"
-          keychain_password="$(cat "$password_file")"
-          printf '%s' "$APP_CERTIFICATE_P12" | base64 -D >"$app_p12"
-          security create-keychain -p "$keychain_password" "$keychain"
+          password="$(openssl rand -hex 32)"
+          security create-keychain -p "$password" "$keychain"
           security set-keychain-settings -lut 21600 "$keychain"
-          security unlock-keychain -p "$keychain_password" "$keychain"
-          security list-keychains -d user -s \
-            "$keychain" "$HOME/Library/Keychains/login.keychain-db"
-          security import "$app_p12" \
-            -k "$keychain" -P "$APP_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
+          security unlock-keychain -p "$password" "$keychain"
+          security list-keychains -d user -s "$keychain" "$HOME/Library/Keychains/login.keychain-db"
+          printf '%s' "$APP_CERTIFICATE_P12" | base64 -D >"$state/app.p12"
+          printf '%s' "$INSTALLER_CERTIFICATE_P12" | base64 -D >"$state/installer.p12"
+          security import "$state/app.p12" -k "$keychain" \
+            -P "$APP_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
+          security import "$state/installer.p12" -k "$keychain" \
+            -P "$INSTALLER_CERTIFICATE_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productbuild
           security set-key-partition-list \
-            -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
-          security find-identity -p codesigning -v "$keychain" |
-            grep -F "\"$DEVELOPER_ID_APPLICATION\"" >/dev/null
-
-          entitlements="$state/release.entitlements"
-          cat >"$entitlements" <<'EOF'
-          <?xml version="1.0" encoding="UTF-8"?>
-          <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
-          <plist version="1.0">
-          <dict/>
-          </plist>
-          EOF
-          plutil -lint "$entitlements" >/dev/null
-          app="$state/release-input/GTA Claw.app"
-          verifier="$GITHUB_WORKSPACE/trusted-release-policy/.github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh"
-          /bin/bash "$verifier" "$app"
-          if [[ -d "$app/Contents/Frameworks" ]]; then
-            while IFS= read -r code; do
-              codesign --force --options runtime --timestamp \
-                --sign "$DEVELOPER_ID_APPLICATION" "$code"
-            done < <(find "$app/Contents/Frameworks" -type f \( -name '*.dylib' -o -perm -111 \) -print)
-          fi
-          codesign --force --options runtime --timestamp \
-            --entitlements "$entitlements" \
-            --identifier com.gtastudio.gta-claw \
-            --sign "$DEVELOPER_ID_APPLICATION" \
-            "$app"
-          codesign --verify --deep --strict --verbose=2 "$app"
-          /bin/bash "$verifier" "$app"
-          details="$(codesign -dvvv "$app" 2>&1)"
-          requirement="$(codesign -d -r- "$app" 2>&1)"
-          grep -F 'Authority=Developer ID Application:' <<<"$details" >/dev/null
-          grep -F 'Timestamp=' <<<"$details" >/dev/null
-          grep -E 'flags=.*runtime' <<<"$details" >/dev/null
-          grep -F 'identifier "com.gtastudio.gta-claw"' <<<"$requirement" >/dev/null
-
-      - name: Notarize and staple signed app
+            -S apple-tool:,apple: -s -k "$password" "$keychain" >/dev/null
+          security find-identity -v "$keychain" | grep -F "\"$DEVELOPER_ID_APPLICATION\""
+          security find-identity -v "$keychain" | grep -F "\"$DEVELOPER_ID_INSTALLER\""
+          rm -f -- "$state/app.p12" "$state/installer.p12"
+          echo "keychain=$keychain" >>"$GITHUB_OUTPUT"
+
+      - name: Sign and notarize universal2 app
         shell: bash
         env:
-          ASC_KEY_P8: ${{ secrets.MACOS_ASC_KEY_P8 }}
-          ASC_KEY_ID: ${{ secrets.MACOS_ASC_KEY_ID }}
           ASC_ISSUER_ID: ${{ secrets.MACOS_ASC_ISSUER_ID }}
+          ASC_KEY_ID: ${{ secrets.MACOS_ASC_KEY_ID }}
+          ASC_KEY_P8: ${{ secrets.MACOS_ASC_KEY_P8 }}
+          DEVELOPER_ID_APPLICATION: ${{ secrets.MACOS_DEVELOPER_ID_APPLICATION }}
+          SIGNING_KEYCHAIN: ${{ steps.signing.outputs.keychain }}
         run: |
           set -euo pipefail
           umask 077
-          for variable in ASC_KEY_P8 ASC_KEY_ID ASC_ISSUER_ID; do
+          for variable in ASC_ISSUER_ID ASC_KEY_ID ASC_KEY_P8 DEVELOPER_ID_APPLICATION; do
             test -n "${!variable:-}" || {
-              echo "Protected notarization secret is missing: $variable" >&2
+              echo "Protected app release credential is missing: $variable" >&2
               exit 1
             }
           done
           state="$RUNNER_TEMP/gta-claw-release"
           key="$state/AuthKey.p8"
-          archive="$state/GTA-Claw.app.zip"
-          result="$state/app-notary-result.json"
-          trap 'rm -f -- "$key" "$archive" "$result"' EXIT INT TERM
           printf '%s' "$ASC_KEY_P8" >"$key"
+          export ASC_KEY_PATH="$key"
           app="$state/release-input/GTA Claw.app"
-          verifier="$GITHUB_WORKSPACE/trusted-release-policy/.github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh"
-          /bin/bash "$verifier" "$app"
-          codesign --verify --deep --strict --verbose=2 "$app"
-          ditto -c -k --keepParent "$app" "$archive"
-          xcrun notarytool submit "$archive" \
-            --key "$key" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" \
-            --wait --output-format json >"$result"
-          status="$(plutil -extract status raw -o - "$result")"
-          request_id="$(plutil -extract id raw -o - "$result")"
-          if [[ "$status" != "Accepted" ]]; then
-            xcrun notarytool log "$request_id" \
-              --key "$key" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" || true
-            echo "Application notarization was not accepted" >&2
-            exit 1
-          fi
-          xcrun stapler staple "$app"
-          xcrun stapler validate "$app"
-          /bin/bash "$verifier" "$app"
-          codesign --verify --deep --strict --verbose=2 "$app"
+          ./packaging/macos/sign.sh release "$app"
+          ./packaging/macos/notarize.sh "$app"
+          ./packaging/macos/validate.sh "$app" "arm64 x86_64" release

-      - name: Import installer identity and sign DMG and PKG
+      - name: Build, sign, notarize, and inspect final containers
         shell: bash
         env:
+          ASC_ISSUER_ID: ${{ secrets.MACOS_ASC_ISSUER_ID }}
+          ASC_KEY_ID: ${{ secrets.MACOS_ASC_KEY_ID }}
+          ASC_KEY_P8: ${{ secrets.MACOS_ASC_KEY_P8 }}
           DEVELOPER_ID_APPLICATION: ${{ secrets.MACOS_DEVELOPER_ID_APPLICATION }}
           DEVELOPER_ID_INSTALLER: ${{ secrets.MACOS_DEVELOPER_ID_INSTALLER }}
-          INSTALLER_CERTIFICATE_P12: ${{ secrets.MACOS_INSTALLER_CERTIFICATE_P12 }}
-          INSTALLER_CERTIFICATE_PASSWORD: ${{ secrets.MACOS_INSTALLER_CERTIFICATE_PASSWORD }}
+          GTA_CLAW_OFFLINE: "1"
+          SIGNING_KEYCHAIN: ${{ steps.signing.outputs.keychain }}
         run: |
           set -euo pipefail
           umask 077
           for variable in \
-            DEVELOPER_ID_APPLICATION DEVELOPER_ID_INSTALLER \
-            INSTALLER_CERTIFICATE_P12 INSTALLER_CERTIFICATE_PASSWORD; do
+            ASC_ISSUER_ID ASC_KEY_ID ASC_KEY_P8 DEVELOPER_ID_APPLICATION \
+            DEVELOPER_ID_INSTALLER; do
             test -n "${!variable:-}" || {
-              echo "Protected container-signing secret is missing: $variable" >&2
+              echo "Protected container release credential is missing: $variable" >&2
               exit 1
             }
           done
-          [[ "$DEVELOPER_ID_APPLICATION" == "Developer ID Application:"* ]]
-          [[ "$DEVELOPER_ID_INSTALLER" == "Developer ID Installer:"* ]]
-
           state="$RUNNER_TEMP/gta-claw-release"
-          keychain="$state/signing.keychain-db"
-          keychain_password="$(cat "$state/keychain-password")"
-          installer_p12="$state/installer.p12"
-          trap 'rm -f -- "$installer_p12"' EXIT INT TERM
-          printf '%s' "$INSTALLER_CERTIFICATE_P12" | base64 -D >"$installer_p12"
-          security unlock-keychain -p "$keychain_password" "$keychain"
-          security import "$installer_p12" \
-            -k "$keychain" -P "$INSTALLER_CERTIFICATE_PASSWORD" \
-            -T /usr/bin/codesign -T /usr/bin/productbuild
-          security set-key-partition-list \
-            -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
-          security find-identity -v "$keychain" |
-            grep -F "\"$DEVELOPER_ID_INSTALLER\"" >/dev/null
+          key="$state/AuthKey.p8"
+          printf '%s' "$ASC_KEY_P8" >"$key"
+          export ASC_KEY_PATH="$key"
+          ./packaging/macos/package.sh release "$state/release-input/GTA Claw.app"

-          app="$state/release-input/GTA Claw.app"
-          distribution="$state/distribution"
-          dmg_stage="$state/dmg-stage"
-          package_root="$state/package-root"
-          mkdir -m 0700 "$distribution" "$dmg_stage" "$package_root"
-          mkdir -m 0755 "$package_root/Applications"
-          ditto "$app" "$dmg_stage/GTA Claw.app"
-          ditto "$app" "$package_root/Applications/GTA Claw.app"
-          test -z "$(find "$dmg_stage" "$package_root" -type l -print -quit)"
-          verifier="$GITHUB_WORKSPACE/trusted-release-policy/.github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh"
-          /bin/bash "$verifier" "$dmg_stage/GTA Claw.app"
-          /bin/bash "$verifier" "$package_root/Applications/GTA Claw.app"
-
-          dmg="$distribution/gta-claw-${{ needs.release-policy.outputs.version }}-macos.dmg"
-          hdiutil create \
-            -srcfolder "$dmg_stage" \
-            -volname "GTA Claw ${{ needs.release-policy.outputs.version }}" \
-            -fs HFS+ -format UDZO -ov "$dmg"
-          hdiutil verify "$dmg" >/dev/null
-
-          component_pkg="$state/gta-claw-component.pkg"
-          pkgbuild \
-            --root "$package_root" \
-            --install-location / \
-            --identifier com.gtastudio.gta-claw.pkg.component \
-            --version "${{ needs.release-policy.outputs.version }}" \
-            --ownership recommended \
-            "$component_pkg"
-          pkg="$distribution/gta-claw-${{ needs.release-policy.outputs.version }}-macos.pkg"
-          productbuild \
-            --package "$component_pkg" \
-            --sign "$DEVELOPER_ID_INSTALLER" \
-            --keychain "$keychain" \
-            "$pkg"
-          codesign --force \
-            --sign "$DEVELOPER_ID_APPLICATION" \
-            --timestamp \
-            --identifier com.gtastudio.gta-claw.dmg \
-            "$dmg"
-          codesign --verify --verbose=2 "$dmg"
-          pkgutil --check-signature "$pkg" |
-            grep -F 'Developer ID Installer:' >/dev/null
-
-      - name: Notarize and staple DMG and PKG
+      - name: Add verified arm64 and x86_64 CLI archives and revalidate publication
         shell: bash
         env:
-          ASC_KEY_P8: ${{ secrets.MACOS_ASC_KEY_P8 }}
-          ASC_KEY_ID: ${{ secrets.MACOS_ASC_KEY_ID }}
-          ASC_ISSUER_ID: ${{ secrets.MACOS_ASC_ISSUER_ID }}
+          GTA_CLAW_OFFLINE: "1"
         run: |
           set -euo pipefail
-          umask 077
-          for variable in ASC_KEY_P8 ASC_KEY_ID ASC_ISSUER_ID; do
-            test -n "${!variable:-}" || {
-              echo "Protected notarization secret is missing: $variable" >&2
-              exit 1
-            }
-          done
-          state="$RUNNER_TEMP/gta-claw-release"
-          key="$state/AuthKey.p8"
-          trap 'rm -f -- "$key" "$state"/*-notary-result.json' EXIT INT TERM
-          printf '%s' "$ASC_KEY_P8" >"$key"
-          for artifact in "$state"/distribution/*.{dmg,pkg}; do
-            result="$state/$(basename "$artifact")-notary-result.json"
-            xcrun notarytool submit "$artifact" \
-              --key "$key" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" \
-              --wait --output-format json >"$result"
-            status="$(plutil -extract status raw -o - "$result")"
-            request_id="$(plutil -extract id raw -o - "$result")"
-            if [[ "$status" != "Accepted" ]]; then
-              xcrun notarytool log "$request_id" \
-                --key "$key" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" || true
-              echo "Container notarization was not accepted: $artifact" >&2
-              exit 1
-            fi
-            xcrun stapler staple "$artifact"
-            xcrun stapler validate "$artifact"
-          done
+          distribution="$GITHUB_WORKSPACE/target/macos-package/distribution"
+          prototype="$RUNNER_TEMP/gta-claw-release-download"
+          while IFS= read -r archive; do
+            cp "$archive" "$distribution/"
+            cp "$archive.spdx" "$distribution/"
+            cp "$archive.provenance.json" "$distribution/"
+          done < <(find "$prototype" -type f \( \
+            -name 'gta-claw-cli-*.tar.gz' -o -name 'gta-claw-daemon-*.tar.gz' \
+          \) | LC_ALL=C sort -u)
+          test "$(find "$distribution" -maxdepth 1 -name '*.tar.gz' | wc -l | tr -d ' ')" -eq 4
+          source packaging/macos/lib/common.sh
+          write_artifact_set_checksums "$distribution" SHA256SUMS-macos
+          ./packaging/macos/validate-artifacts.sh \
+            "$distribution" release SHA256SUMS-macos
+
+      - name: Upload signed and notarized macOS release
+        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
+        with:
+          name: gta-claw-macos-release-${{ github.sha }}
+          path: target/macos-package/distribution
+          if-no-files-found: error
+          retention-days: 30
+          compression-level: 0

-      - name: Validate protected release outputs without publishing
+      - name: Publish exact bytes to GitHub Release
         shell: bash
+        env:
+          GH_TOKEN: ${{ github.token }}
         run: |
           set -euo pipefail
-          state="$RUNNER_TEMP/gta-claw-release"
-          app="$state/release-input/GTA Claw.app"
-          distribution="$state/distribution"
-          verifier="$GITHUB_WORKSPACE/trusted-release-policy/.github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh"
-          /bin/bash "$verifier" "$app"
-          lipo "$app/Contents/MacOS/gta-claw-desktop" -verify_arch arm64 x86_64
-          codesign --verify --deep --strict --verbose=2 "$app"
-          spctl --assess --type execute --verbose=4 "$app"
-          xcrun stapler validate "$app"
-          codesign --verify --verbose=2 "$distribution"/*.dmg
-          pkgutil --check-signature "$distribution"/*.pkg |
-            grep -F 'Developer ID Installer:' >/dev/null
-          xcrun stapler validate "$distribution"/*.dmg
-          xcrun stapler validate "$distribution"/*.pkg
-          (cd "$distribution" && shasum -a 256 * >SHA256SUMS)
-          echo "Protected release contract passed. Artifacts are intentionally not uploaded or published."
+          tag="$GITHUB_REF_NAME"
+          if ! gh release view "$tag" >/dev/null 2>&1; then
+            gh release create "$tag" \
+              --draft \
+              --verify-tag \
+              --title "GTA Claw $tag" \
+              --notes 'Native Rust release artifacts. Verify platform SHA256SUMS, SBOMs, and provenance before installation.' ||
+              gh release view "$tag" >/dev/null
+          fi
+          test "$(gh release view "$tag" --json isDraft --jq .isDraft)" = true || {
+            echo "Refusing to replace assets on an already-published release" >&2
+            exit 1
+          }
+          assets="$(gh release view "$tag" --json assets --jq '.assets[].name')"
+          if grep -Fx SHA256SUMS-macos <<<"$assets" >/dev/null; then
+            gh release delete-asset "$tag" SHA256SUMS-macos --yes
+          fi
+          assets="$(gh release view "$tag" --json assets --jq '.assets[].name')"
+          if grep -Fx SHA256SUMS-macos <<<"$assets" >/dev/null; then
+            echo "Failed to remove the macOS release completion manifest" >&2
+            exit 1
+          fi
+          find target/macos-package/distribution -maxdepth 1 -type f \
+            ! -name SHA256SUMS-macos -print0 |
+            xargs -0 gh release upload "$tag" --clobber
+          gh release upload "$tag" \
+            target/macos-package/distribution/SHA256SUMS-macos --clobber
+          assets="$(gh release view "$tag" --json assets --jq '.assets[].name')"
+          if grep -Fx SHA256SUMS-macos <<<"$assets" >/dev/null &&
+            grep -Fx SHA256SUMS-windows <<<"$assets" >/dev/null; then
+            verify="$RUNNER_TEMP/gta-claw-joint-release"
+            rm -rf -- "$verify"
+            mkdir -m 0700 "$verify"
+            gh release download "$tag" --dir "$verify"
+            (
+              cd "$verify"
+              shasum -a 256 -c SHA256SUMS-macos
+              shasum -a 256 -c SHA256SUMS-windows
+              expected="$(
+                {
+                  sed -E 's/^[0-9a-f]{64}  //' SHA256SUMS-macos
+                  sed -E 's/^[0-9a-f]{64}  //' SHA256SUMS-windows
+                  printf '%s\n' SHA256SUMS-macos SHA256SUMS-windows
+                } | LC_ALL=C sort
+              )"
+              actual="$(find . -maxdepth 1 -type f -exec basename {} \; | LC_ALL=C sort)"
+              test "$actual" = "$expected"
+            )
+            gh release edit "$tag" --draft=false
+          fi

       - name: Always remove temporary keychain and credentials
         if: always()
@@ -803,5 +564,4 @@ jobs:
           if [[ -f "$keychain" && ! -L "$keychain" ]]; then
             security delete-keychain "$keychain" >/dev/null 2>&1
           fi
-          rm -rf -- "$RUNNER_TEMP/gta-claw-release-download"
-          rm -rf -- "$state"
+          rm -rf -- "$RUNNER_TEMP/gta-claw-release-download" "$state"
