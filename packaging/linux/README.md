# Linux headless packaging prototype

This directory is the isolated P04d prototype for packaging the root Rust
`gta-claw-daemon` and `gta-claw-cli` binaries on Linux. It invokes no
JavaScript runtime or package manager, and the root Cargo graph is checked
explicitly for the absence of `slint`, `slint-build`, and every `i-slint-*`
crate. The desktop Cargo workspace is never resolved or built.

## Artifacts

For `x86_64` (`x86_64-unknown-linux-gnu`, Debian `amd64`, RPM `x86_64`, OCI
`amd64`) and `arm64` (`aarch64-unknown-linux-gnu`, Debian/RPM `aarch64`, OCI
`arm64`), `package.sh` emits:

- `gta-claw-VERSION-linux-ARCH.tar.gz`, containing separate daemon and CLI
  executables, README, license, notice, sorted SHA-256 manifest, SPDX 2.3
  SBOM, and SLSA-shaped in-toto provenance.
- `gta-claw_VERSION-1_ARCH.deb`, built with `dpkg-deb`, root ownership, gzip
  payload compression, ELF-derived dependencies, conffiles, and reviewed
  systemd lifecycle scripts.
- `gta-claw-VERSION-1.ARCH.rpm`, built with `rpmbuild`, deterministic build
  time/host/payload settings, `%config(noreplace)` configuration, an explicit
  disable preset, and reviewed systemd lifecycle scriptlets.
- `gta-claw-VERSION-linux-ARCH.oci.tar.gz`, an OCI image layout with a
  scratch root filesystem, numeric non-root user `65532:65532`, OCI labels,
  two deterministic layers, explicit writable volumes, and no shell or
  package manager. The first layer contains only the Rust executables,
  documentation/metadata, account files, and exact glibc/libgcc runtime objects
  from the pinned build sysroot. Their Debian versions, hashes, SPDX
  expressions, and copyright files are embedded in the SBOM and provenance.
  The second layer assigns the writable directories to uid/gid 65532.
- `provenance-ARCH.json` and `SHA256SUMS` for the final artifacts.

Builds run in the digest-pinned Rust 1.97.0 Bookworm image using the immutable
Debian `20260701T000000Z` snapshot and glibc ceiling 2.36. Each sealed build
manifest binds the clean Git commit/tree, Dockerfile digest, toolchain, target,
profile, flags, exact dpkg runtime packages, and binary hashes. GNU tar receives
sorted names, the Git commit timestamp, root uid/gid, stable PAX options, and
fixed modes; gzip receives `-n`. CI performs two complete builds and package
runs in distinct Cargo/output roots under input umasks 000 and 002, then
compares every final artifact byte.

## Filesystem and upgrade contract

The native packages install the CLI at `/usr/bin/gta-claw-cli`, the daemon at
`/usr/libexec/gta-claw/gta-claw-daemon`, the service at
`/usr/lib/systemd/system/gta-claw-daemon.service`, documentation under
`/usr/share/doc/gta-claw`, and administrator-controlled files below
`/etc/gta-claw`.

Debian conffiles and RPM `%config(noreplace)` preserve local environment and
credential-file edits on upgrade. Package removal removes package-owned
programs, units, and unmodified configuration according to the native package
manager. Native packages deliberately do not own `/var/lib/gta-claw`,
`/var/cache/gta-claw`, `/var/log/gta-claw`, or `/run/gta-claw`: systemd creates
the private/persistent or ephemeral paths declared by the unit. Fresh installs
stay disabled and stopped; active upgrades use `try-restart`, inactive upgrades
remain inactive, final removal stops/disables before executable unlink, and
post-transaction hooks reload systemd. No hook executes network or dynamic
code.

## systemd boundary

The service is disabled by default and uses `DynamicUser=yes`; no static
account is created by package scripts. systemd owns private state, cache, log,
and runtime directories. The unit removes all capabilities, denies IP
networking, permits only `AF_UNIX`, and enables `NoNewPrivileges`, private
temporary storage/devices, strict system/home/kernel/control-group
protections, namespace/personality/SUID restrictions, syscall filtering, and
a 15-second SIGTERM stop window with restart-on-failure.

The current daemon accepts only no arguments or `--probe`. It prints readiness
and health and then parks; it does not listen, consume systemd sockets, read
configuration or credentials, persist state, or implement an application
shutdown protocol. The package therefore invents no flags. The service uses
only the supported command forms. `gta-claw-daemon.socket.deferred` records a
future `AF_UNIX` endpoint but deliberately is not a `.socket` unit and is not
installed in the systemd unit search path.

`gta-claw.env` is for non-secret settings only and currently contains no
assignments. Secret material belongs in root-owned mode-0600
`/etc/gta-claw/credentials/daemon.conf`; systemd exposes it through
`LoadCredential` rather than an environment literal. The current binary does
not consume that credential, so adding actual secret-dependent behavior is
deferred until the Rust boundary supports `CREDENTIALS_DIRECTORY`.

## Output and release safety

Every Cargo and packaging output must be a new absolute path below the
repository's real mode-0700, current-user-owned `target` directory. The scripts
reject traversal, unsafe environment-controlled
components, existing outputs, every intermediate or final symlink (including
dangling links), hard links in staged/output trees, special files, and
non-regular collisions. Cargo may hard-link its final executable to a hashed
build artifact; that trusted input is copied into a fresh inode while its
source inode and before/after SHA-256 are revalidated. Output and lock roots are
explicitly mode 0700 regardless of caller umask. Files are opened once with
exclusive no-clobber semantics and written through that held descriptor;
publication revalidates its inode before an atomic no-clobber rename. A
deterministic replacement regression proves writes do not follow a path swapped
to a symlink after reservation. Shell path APIs still require exclusive
same-user ownership of the private roots.

`release.sh` fails unless release mode, an annotated semantic tag, and the full
matching commit are supplied. It then still fails because production signing
and repository publication backends are intentionally not configured. The CI
workflow has read-only repository permissions and uploads only short-lived
prototype artifacts.

## Usage and validation

On Ubuntu with Docker plus the declared native package tools, run:

```sh
export CARGO_TARGET_DIR="$PWD/target/linux-x86-build"
build_manifest="$(./packaging/linux/build-container.sh x86_64)"
OUTPUT_ROOT="$PWD/target/linux-x86-run1" \
  ./packaging/linux/package.sh x86_64 "$build_manifest"
./packaging/linux/self-test.sh
```

The dedicated workflow performs root formatting, checks, Clippy, tests, MSRV,
deny, audit, metadata proof, pinned-Bookworm x86_64 execution and Debian
installation, real arm64 Rust cross-build, PIE/interpreter/RPATH/versioned-symbol
checks, real Ubuntu systemd DEB/RPM install-start-upgrade-remove flows,
published-byte OCI descriptor/DiffID/layer inspection, fully resealed malicious
OCI mutations, deterministic reruns, checksums, license-aware SPDX/provenance,
and negative path/release/build-manifest tests. Arm64 is a build and
package/image layout proof only; no native or emulated arm64 runtime success is
claimed.

## Explicit non-claims

This prototype does not provide production signing or repository publication,
does not claim lifecycle proof beyond the pinned Bookworm and hosted Ubuntu
environments, does not provide daemon/OpenClaw feature parity, does not ship a
Linux GUI, and does not remove or replace the legacy root Dockerfile or
JavaScript deployment.
