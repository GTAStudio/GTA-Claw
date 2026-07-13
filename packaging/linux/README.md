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
  payload compression, explicit dependencies, conffiles, and no maintainer
  scripts.
- `gta-claw-VERSION-1.ARCH.rpm`, built with `rpmbuild`, deterministic build
  time/host/payload settings, `%config(noreplace)` configuration, and no
  scriptlets.
- `gta-claw-VERSION-linux-ARCH.oci.tar.gz`, an OCI image layout with a
  scratch root filesystem, numeric non-root user `65532:65532`, OCI labels,
  two deterministic layers, explicit writable volumes, and no shell or
  package manager. The first layer contains only the Rust executables,
  documentation/metadata, account files, and the target glibc runtime objects.
  The second layer assigns the writable directories to uid/gid 65532.
- `provenance-ARCH.json` and `SHA256SUMS` for the final artifacts.

GNU tar receives sorted names, the Git commit timestamp, root uid/gid, stable
PAX options, and fixed modes; gzip receives `-n`. Package metadata and OCI JSON
are sorted. CI builds each architecture twice in separate fresh output roots
and compares final artifact bytes. RPM and Debian reproducibility is therefore
proved on the pinned runner/tool versions used by that run, not across all
future distributions or native-tool releases.

## Filesystem and upgrade contract

The native packages install the CLI at `/usr/bin/gta-claw-cli`, the daemon at
`/usr/libexec/gta-claw/gta-claw-daemon`, the service at
`/usr/lib/systemd/system/gta-claw-daemon.service`, documentation under
`/usr/share/doc/gta-claw`, and administrator-controlled files below
`/etc/gta-claw`.

Debian conffiles and RPM `%config(noreplace)` preserve local environment and
credential-file edits on upgrade. Package removal removes package-owned
programs, units, and unmodified configuration according to the native package
manager. State, cache, and logs live at `/var/lib/gta-claw`,
`/var/cache/gta-claw`, and `/var/log/gta-claw`; non-empty runtime data is not
treated as disposable package content and requires explicit administrator
removal. No install, upgrade, or uninstall hook executes a network command,
dynamic code, or any command at all.

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

Every packaging output must be a new absolute path below the repository's real
`target` directory. The scripts reject traversal, unsafe environment-controlled
components, existing outputs, every intermediate or final symlink (including
dangling links), hard links in staged/output trees, special files, and
non-regular collisions. Cargo may hard-link its final executable to a hashed
build artifact; that trusted input is copied into a fresh inode while its
source inode and before/after SHA-256 are revalidated. An adjacent directory
lock and inode checks establish exclusive output ownership. Publication
revalidates the reserved file identity after an atomic no-clobber rename.
Shell path APIs cannot make a hostile process race-free, so the contract
explicitly requires exclusive ownership of both the Cargo target and package
output roots and never claims that preflight checks alone close a TOCTOU race.

`release.sh` fails unless release mode, an annotated semantic tag, and the full
matching commit are supplied. It then still fails because production signing
and repository publication backends are intentionally not configured. The CI
workflow has read-only repository permissions and uploads only short-lived
prototype artifacts.

## Usage and validation

On Ubuntu, install the declared native tools (`jq`, `rpm`, cross GCC/glibc for
arm64, ShellCheck, and systemd utilities), install the Rust target, and run:

```sh
export CARGO_TARGET_DIR=/absolute/disposable/cargo-target
binary_dir="$(./packaging/linux/build.sh x86_64)"
OUTPUT_ROOT="$PWD/target/linux-x86-run1" \
  ./packaging/linux/package.sh x86_64 "$binary_dir"
./packaging/linux/self-test.sh
```

The dedicated workflow performs root formatting, checks, Clippy, tests, MSRV,
deny, audit, metadata proof, native x86_64 runtime probes, real arm64 Rust
cross-build, ELF architecture/interpreter/dependency checks, Debian/RPM/OCI
inspection, systemd verification/security analysis, deterministic reruns,
checksums, SBOM/provenance validation, and negative path/release tests. Arm64
is a build and package/image layout proof only; no native or emulated arm64
runtime success is claimed.

## Explicit non-claims

This prototype does not provide production signing or repository publication,
does not prove clean-machine installation, upgrade, rollback, or removal, does
not provide daemon/OpenClaw feature parity, does not ship a Linux GUI, and does
not remove or replace the legacy root Dockerfile or JavaScript deployment.
