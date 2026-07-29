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
  documentation/metadata, account files, and exact glibc/libm/libgcc runtime objects
  from the pinned build sysroot. Their Debian versions, hashes, SPDX
  expressions, and copyright files are embedded in the SBOM and provenance.
  The second layer assigns the writable directories to uid/gid 65532.
- `provenance-ARCH.json` and `SHA256SUMS` for the final artifacts.

Builds run in the digest-pinned Rust 1.97.1 Bookworm image using the immutable
Debian `20260701T000000Z` snapshot and glibc ceiling 2.36. Each sealed build
manifest binds the clean Git commit/tree, Dockerfile digest, toolchain, target,
profile, flags, exact dpkg runtime packages, license providers, and binary
hashes. The builder signs that manifest with an ephemeral Ed25519 key; packaging
accepts only the public-key fingerprint returned out of band by the builder.
GNU tar receives sorted names, the Git commit timestamp, root uid/gid, stable
PAX options, and fixed modes; gzip receives `-n`. Native package tools run in
independent instances of the same pinned image and record exact dpkg/rpm/tar/
gzip/jq/Python/cpio versions. CI performs two complete builds and package runs
in distinct Cargo/output roots under input umasks 000 and 002, then compares
every final artifact byte.

## Filesystem and upgrade contract

The native packages install the CLI at `/usr/bin/gta-claw-cli`, the daemon at
`/usr/libexec/gta-claw/gta-claw-daemon`, the service at
`/usr/lib/systemd/system/gta-claw-daemon.service`, documentation under
`/usr/share/doc/gta-claw`, and administrator-controlled files below
`/etc/gta-claw`.

Debian conffiles and RPM `%config(noreplace)` preserve local environment and
credential-file edits on upgrade. Package removal removes package-owned
programs and units; Debian keeps conffiles until purge, while RPM preserves
modified configuration as `.rpmsave`. Native packages deliberately do not own `/var/lib/gta-claw`,
`/var/cache/gta-claw`, `/var/log/gta-claw`, or `/run/gta-claw`: systemd creates
the private/persistent or ephemeral paths declared by the unit. Fresh installs
apply the explicit disable preset and stay stopped; active upgrades restart,
inactive upgrades remain inactive, final removal stops/disables before
executable unlink, and post-transaction hooks reload systemd. Stop/restart/
disable errors propagate with native `systemctl` diagnostics. Alternate-root
Debian transactions never invoke host `systemctl`. Before RPM mutates an
upgrade payload, `%pre` requires exactly one installed old NEVRA and journals
its active and persistent/runtime enablement state. A rejected preparation
removes only that new journal, leaving the old NEVRA, every old package byte,
and prior service state unchanged. `%posttrans` accepts only one replacement
NEVRA and retires the journal; an incomplete later activation remains fenced
from old-package erase. Failed final erase restores the captured enablement
before returning the failure. No hook executes network or dynamic code.

## systemd boundary

The service is disabled by default and uses `DynamicUser=yes`; no static
account is created by package scripts. systemd owns private state, cache, log,
and runtime directories. `GTA_CLAW_STATE_DIR=/var/lib/gta-claw` wires the
daemon to the `StateDirectory` systemd creates. The unit removes all
capabilities, permits `AF_UNIX`, IPv4, and IPv6 while limiting IP traffic to
localhost, and enables `NoNewPrivileges`, private temporary storage/devices,
strict system/home/kernel/control-group protections,
namespace/personality/SUID restrictions, syscall filtering, and a 15-second
SIGTERM stop window with restart-on-failure.

The current daemon opens its HTTP, legacy, Gateway, and MCP TCP listeners
itself and persists runtime state below the configured state directory. The
packaged defaults remain loopback-only. `gta-claw-daemon.socket.deferred`
records a future systemd-managed `AF_UNIX` endpoint but deliberately is not a
`.socket` unit and is not installed in the systemd unit search path.

`gta-claw.env` is for non-secret settings only and currently contains no
assignments. Secret material belongs in root-owned mode-0600
`/etc/gta-claw/credentials/daemon.conf`; systemd exposes it through
`LoadCredential` rather than an environment literal. The current binary does
not consume that credential, so adding actual secret-dependent behavior is
deferred until the Rust boundary supports `CREDENTIALS_DIRECTORY`.

## Output and release safety

Every Cargo and packaging root is a safe single component below `target`.
`safeio.py` opens the repository/target/output with no-follow directory FDs,
uses fail-closed `openat2` resolution for files, anchored `mkdirat` traversal,
and no-replace link publication. Container bind sources are root-owned host
mounts created from held directory FDs. During a build/package transaction the
target is temporarily root-owned mode 0700, excluding host peers; identities
and ownership are restored only after recursive no-link checks. Existing,
dangling, intermediate and final links, hard links, special files, traversal,
or non-regular collisions fail closed. Deterministic ancestor- and final-path
swap regressions prove outside sentinels are never created or modified.
Partially-created anchored mount roots are removed on setup failure, and the
ephemeral build-manifest key is created and erased inside the held build output
capability rather than in a shared temporary directory.

ELF validation uses a bounded binary parser rather than human `readelf` output:
it checks ELF64 structure, PIE type, exact PT_INTERP bytes, canonical
DT_NEEDED, no RPATH/RUNPATH, loader-used DT_VERNEED entries, section agreement,
and the GLIBC ceiling. OCI validation rejects duplicate JSON keys/numbers,
duplicate archive members, links/devices/FIFOs/whiteouts, and bounded
compressed/expanded/member/file sizes before extraction. Published rootfs
contents and application/runtime hashes are compared to the independently
authenticated build manifest, not image-local declarations.
The published native tarball is likewise bounded and extracted once, then its
exact file set, embedded checksum closure, strict JSON, binary modes, ELF
contracts, and binary/build/runtime-manifest bytes are checked against the
authenticated build inputs.

`release.sh` fails unless release mode, an annotated semantic tag, and the full
matching commit are supplied. It then still fails because production signing
and repository publication backends are intentionally not configured. The CI
workflow has read-only repository permissions and uploads only short-lived
prototype artifacts.

## Usage and validation

On Ubuntu with Docker plus the declared native package tools, run:

```sh
export CARGO_TARGET_DIR="$PWD/target/linux-x86-build"
build_result="$(./packaging/linux/build-container.sh x86_64)"
build_manifest="${build_result%%|*}"
build_key_sha="${build_result##*|}"
OUTPUT_ROOT="$PWD/target/linux-x86-run1" \
  ./packaging/linux/package-container.sh \
    x86_64 "$build_manifest" "$build_key_sha"
./packaging/linux/self-test.sh
./packaging/linux/lifecycle-contract-self-test.sh
./packaging/linux/container-mount-self-test.sh
```

With the x86 native archive from the package run, its independent published-byte
mutation checks can be run in the pinned container:

```sh
OUTPUT_ROOT="$PWD/target/linux-native-mutations" \
  ./packaging/linux/native-self-test-container.sh \
    x86_64 \
    "$PWD"/target/linux-x86-run1/artifacts/gta-claw-*-linux-x86_64.tar.gz \
    "$build_manifest" \
    "$build_key_sha"
```

The dedicated workflow performs root formatting, checks, Clippy, tests, MSRV,
deny, audit, metadata proof, pinned-Bookworm x86_64 execution and Debian
installation, real arm64 Rust cross-build, PIE/interpreter/RPATH/versioned-symbol
checks, a fresh minimal snapshot-pinned Bookworm resolver install, real Ubuntu
systemd DEB/RPM install-start-upgrade-remove and forced-failure flows,
published-byte native archive and OCI descriptor/DiffID/layer inspection,
strict duplicate/
resource limits, fully resealed extra-executable/application/runtime mutations,
deterministic reruns, complete provider-attributed license materials,
license-aware SPDX/provenance, and negative path/release/forged-build tests.
Arm64 is a build and package/image layout proof only; no native or emulated
arm64 runtime success is claimed.

## Explicit non-claims

This prototype does not provide production signing or repository publication,
does not claim lifecycle proof beyond the pinned Bookworm and hosted Ubuntu
environments, does not provide daemon/OpenClaw feature parity, does not ship a
Linux GUI, and does not remove or replace the legacy root Dockerfile or
JavaScript deployment.
