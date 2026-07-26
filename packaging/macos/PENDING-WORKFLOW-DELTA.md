# Applied arm64-only workflow contract

The reviewed workflow transition landed in PR #60. No macOS workflow delta is
pending in this branch.

The active contract is:

- `native` retains arm64 and Intel host rows because the Intel row is workspace
  test coverage, not a shipped artifact producer.
- `containers` builds a native arm64 app at
  `target/macos-package/apps/arm64/GTA Claw.app`.
- The app archive is named
  `gta-claw-$VERSION-macos-arm64-$QUALIFIER.app.zip`.
- App, DMG, PKG, SBOM, provenance, and published-byte validation all require
  exactly the arm64 architecture.
- Headless release archives contain only the arm64 CLI and daemon.
- The protected release job consumes the immutable arm64 release-input artifact
  produced by `containers`.

`containers` currently rebuilds the arm64 app independently instead of
consuming the app built and tested by the `native` job. The release input is
therefore validated again as published bytes before credentials are exposed,
but it is not byte-identical by construction to the earlier native job output.

Universal2 assembly, Intel release archives, and `merge-universal.sh` are
retired. Intel dependency and host-native test coverage remains active.
