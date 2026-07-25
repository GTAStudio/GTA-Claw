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
  executables, reviewed direct install/remove scripts, sysusers and systemd
  definitions, README, license, notice, sorted SHA-256 manifest, SPDX 2.3 SBOM,
  and SLSA-shaped in-toto provenance.
- `gta-claw_VERSION-1_ARCH.deb`, built with `dpkg-deb`, root ownership, gzip
  payload compression, ELF-derived dependencies, conffiles, and reviewed
  systemd lifecycle scripts.
- `gta-claw-VERSION-1.ARCH.rpm`, built with `rpmbuild`, deterministic build
  time/host/payload settings, `%config(noreplace)` configuration, an explicit
  disable preset, and reviewed systemd lifecycle scriptlets.
- `gta-claw-VERSION-linux-ARCH.oci.tar.gz`, an OCI image layout with a
  scratch root filesystem, numeric non-root runtime user `65532:65532`, an
  explicit root init command, OCI labels, two deterministic layers, shared
  `/var/lib` storage, and no shell or package manager. The first layer contains only the Rust executables,
  documentation/metadata, account files, and exact glibc/libm/libgcc runtime objects
  from the pinned build sysroot. Their Debian versions, hashes, SPDX
  expressions, and copyright files are embedded in the SBOM and provenance.
  The second layer assigns cache, log, and runtime directories to uid/gid
  65532. It deliberately does not assign `/var/lib` to the runtime identity.
- Compose, Kubernetes, and CRI fixtures bind both phases to the same
  `ghcr.io/gtastudio/gta-claw@sha256:...` reference derived from the packaged
  manifest. The CRI probe uses root initialization followed by a
  `65532:65532` runtime whose only supplementary GID is redundant `65532`.
- `provenance-ARCH.json` and `SHA256SUMS` for the final artifacts.

Builds run in the digest-pinned Rust 1.97.0 Bookworm image using the immutable
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

## LinuxProtected filesystem and upgrade contract

Every Linux delivery uses `/var/lib/gta-claw-protected`. Its parent is a
root-owned, `gta-claw`-group directory at mode `0750`; the service group can
traverse it but cannot add, remove, link, or rename entries. It contains exactly
these service-owned, mode-`0600`, single-link regular files:

```text
state.sqlite
state.sqlite-wal
state.writer.lock
snapshot-0.sqlite
snapshot-0.meta
snapshot-1.sqlite
snapshot-1.meta
snapshot.selector
```

SHM, rollback journals, links, aliases, special files, extra names, partial
state, and ownership/mode/ACL/filesystem drift fail closed. Provisioning creates
only an absent namespace or an already-canonical empty directory. It never
repairs existing entries. No repair-oriented tmpfiles `d`/`f` rule is shipped;
the root production provisioner is the only namespace creator. The root wrapper
first runs the production
`--provision-linux-protected` command and then the accepted LP3
`--initialize-linux-protected` command with the resolved static UID/GID. The
second command performs the SQLite/WAL handoff while holding the fixed writer
lock. A live runtime therefore makes initialization fail rather than race.

The native packages install the CLI at `/usr/bin/gta-claw-cli`, the daemon at
`/usr/libexec/gta-claw/gta-claw-daemon`, the service at
`/usr/lib/systemd/system/gta-claw-daemon.service`, documentation under
`/usr/share/doc/gta-claw`, and administrator-controlled files below
`/etc/gta-claw`.

Debian conffiles and RPM `%config(noreplace)` preserve local environment and
credential-file edits on upgrade. Package removal removes package-owned
programs, units, and unmodified configuration according to the native package
manager. The package payload does not own the protected namespace. Root
maintainer hooks create the identity, provision and initialize the namespace,
and only then allow a previously active service to restart. Fresh installs stay
disabled and stopped; inactive upgrades remain inactive; downgrade attempts are
rejected before service disruption; final removal stops/disables before
executable unlink. Ordinary removal and Debian purge preserve protected state
and the stable service identity. LP4 intentionally ships no automated state
purge action. No hook executes network or dynamic code.
The root wrapper creates
`/run/gta-claw-state-init/initialization-failed` before every handoff. The
root-owned mode-0755 runtime directory is preserved by the initializer oneshot;
only root can change the marker while the runtime can read it. Failed direct,
Debian, RPM, or manual initialization therefore remains fenced.
RPM may report `%post` failures as warnings, but the runtime unit still refuses
startup until a later successful root initialization clears the marker.

The tar archive's `install.sh` applies the same contract and `uninstall.sh`
preserves `/var/lib/gta-claw-protected`. Both require real/effective root.

## systemd boundary

`sysusers.d` creates a locked `gta-claw` user and group with no home or login
shell. The account persists across upgrades and restarts. A root
`gta-claw-state-init.service` oneshot runs after sysusers/local filesystems and
before the runtime. `gta-claw-daemon.service` requires that oneshot, uses the
static identity, uses `setpriv` to clear systemd's implicit supplementary
primary group and drop the launcher's temporary credential capabilities, and always supplies
`--state-profile linux-protected --state-path /var/lib/gta-claw-protected`.
The unit is `Type=notify`; the daemon sends readiness only after state open and
health complete, and package hooks additionally require `MainPID` to own the
fixed writer lock.
`ProtectSystem=strict` is paired with a namespace `ReadWritePaths` exception;
filesystem mode `0750` still withholds directory-entry mutation while the held
`0600` files remain writable. The runtime has no capabilities, denies IP
networking, permits only `AF_UNIX`, and retains the existing shutdown/restart
hardening.

`gta-claw-daemon.socket.deferred` records a future `AF_UNIX` endpoint but is not
a `.socket` unit and is not installed in the systemd unit search path.

`gta-claw.env` is for non-secret settings only and currently contains no
assignments. Secret material belongs in root-owned mode-0600
`/etc/gta-claw/credentials/daemon.conf`; systemd exposes it through
`LoadCredential` rather than an environment literal. The current binary does
not consume that credential, so adding actual secret-dependent behavior is
deferred until the Rust boundary supports `CREDENTIALS_DIRECTORY`.

## OCI two-phase startup

The OCI image is not a transparent privilege-dropping single process. Mount one
shared volume at `/var/lib` in both phases:

1. Run the image as root with entrypoint
   `/usr/libexec/gta-claw/gta-claw-daemon` and arguments
   `--prepare-linux-protected --state-path /var/lib/gta-claw-protected
   --service-uid 65532 --service-gid 65532`. The command provisions and invokes
   the accepted initializer, then exits.
2. Start the normal image only after phase one succeeds. Its baked-in user is
   `65532:65532` and its baked-in command selects the LinuxProtected profile.

Compose uses an init service with
`user: "0:0"` and a main service pinned to `user: "65532:65532"` with
`depends_on: { gta-claw-init: { condition: service_completed_successfully } }`.
Kubernetes uses a `Recreate` Deployment so the old writer exits before the root
`initContainer` runs, then starts a main container
with `runAsUser/runAsGroup: 65532`, `allowPrivilegeEscalation: false`,
`readOnlyRootFilesystem: true`, and all capabilities dropped. Both containers
mount the same PVC at `/var/lib`; do not set `fsGroup` or an ownership-changing
CSI policy. The volume must expose an accepted ext/XFS/Btrfs/F2FS filesystem.
The runtime volume remains writable for held-file I/O, but mode `0750` prevents
UID 65532 from mutating the namespace directory.
Generated orchestration rejects mutable tags, short image names, divergent
phase digests, malformed YAML, and duplicate keys. The CRI probe also requires
an explicit fully qualified `CRI_RUNTIME_ENDPOINT`.

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

ELF validation uses a bounded binary parser rather than human `readelf` output:
it checks ELF64 structure, PIE type, exact PT_INTERP bytes, canonical
DT_NEEDED, no RPATH/RUNPATH, loader-used DT_VERNEED entries, section agreement,
and the GLIBC ceiling. OCI validation rejects duplicate JSON keys/numbers,
duplicate archive members, links/devices/FIFOs/whiteouts, and bounded
compressed/expanded/member/file sizes before extraction. Published rootfs
contents and application/runtime hashes are compared to the independently
authenticated build manifest, not image-local declarations.

`release.sh` fails unless release mode, an annotated semantic tag, and the full
matching commit are supplied. It then still fails because production signing
and repository publication backends are intentionally not configured. The CI
workflow has read-only repository permissions and uploads only short-lived
prototype artifacts.

## Usage and validation

On Ubuntu with Docker plus the declared native package tools, run:

```sh
export GTA_CLAW_TARGET_ROOT="${RUNNER_TEMP:-/tmp}/gta-claw-target"
export TMPDIR="${RUNNER_TEMP:-/tmp}/gta-claw-tmp"
install -d -m 0700 "$GTA_CLAW_TARGET_ROOT" "$TMPDIR"
export CARGO_TARGET_DIR="$GTA_CLAW_TARGET_ROOT/linux-x86-build"
build_result="$(./packaging/linux/build-container.sh x86_64)"
build_manifest="${build_result%%|*}"
build_key_sha="${build_result##*|}"
OUTPUT_ROOT="$GTA_CLAW_TARGET_ROOT/linux-x86-run1" \
  ./packaging/linux/package-container.sh \
    x86_64 "$build_manifest" "$build_key_sha"
./packaging/linux/self-test.sh
```

For a direct install, extract the tar and run `sudo ./install.sh`. Run
`sudo ./uninstall.sh` from the same extracted release for ordinary removal.

The dedicated workflow performs root formatting, checks, Clippy, tests, MSRV,
deny, audit, metadata proof, pinned-Bookworm x86_64 execution and Debian
installation, real arm64 Rust cross-build, PIE/interpreter/RPATH/versioned-symbol
checks, a fresh minimal snapshot-pinned Bookworm resolver install, real Ubuntu
systemd DEB/RPM install-start-upgrade-remove and forced-failure flows,
published-byte OCI descriptor/DiffID/layer inspection, strict duplicate/
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
