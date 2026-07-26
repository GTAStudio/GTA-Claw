# Applied arm64-only workflow contract

The reviewed workflow transition landed in PR #60. No macOS workflow delta is
pending in this branch.

The active contract is:

- `native` retains arm64 and Intel host rows because the Intel row is workspace
  test coverage, not a shipped artifact producer.
- `containers` restores the arm64 app that the `native` job built and tested,
  at `target/macos-package/apps/arm64/GTA Claw.app`.
- The app archive is named
  `gta-claw-$VERSION-macos-arm64-$QUALIFIER.app.zip`.
- App, DMG, PKG, SBOM, provenance, and published-byte validation all require
  exactly the arm64 architecture.
- Headless release archives contain only the arm64 CLI and daemon.
- The protected release job consumes the immutable arm64 release-input artifact
  produced by `containers`.

`containers` no longer rebuilds. It downloads the `macos-arm64-tested-build`
artifact that `native` packed after its test, clippy, smoke and JavaScript-scan
steps, and packages those exact bytes. `transport.sh` moves them as an
uncompressed tar because `actions/upload-artifact` returns every file as mode
`0644`, which would strip the executable bit from
`Contents/MacOS/gta-claw-desktop`. `workflow-self-test.sh` asserts the
`needs:` edge, the matching artifact name, and the absence of `build.sh` from
`containers`, so the rebuild cannot return unnoticed.

What this does **not** establish: no job anywhere executes the release binary.
`native` tests a debug, host-target build; `build.sh` produces a
`--release --target aarch64-apple-darwin` binary, and every downstream check
(`lipo`, `otool`, `codesign`, `spctl --assess`, `shasum`) inspects that binary
without running it. This change makes the signed bytes the bytes the tested
host produced; it does not make them bytes any test executed.

Universal2 assembly, Intel release archives, and `merge-universal.sh` are
retired. Intel dependency and host-native test coverage remains active.
