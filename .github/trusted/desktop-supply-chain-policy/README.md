# Trusted desktop supply-chain policy

This directory and the two desktop-policy workflow files form a bootstrap trust root
for P04f. The authoritative workflow compiles this validator only from the exact
protected base SHA. It treats the immutable pull-request head as bounded data.

## Authority is external

Merging these files does not make the check authoritative. At the time this trust root
was created, `main` had no ruleset or branch protection. P04f must remain blocked until
repository administrators configure and the coordinator verifies all of the following:

1. Reviewed pull requests are required for `main`, and branches must be up to date.
2. A GitHub ruleset **required workflow** references
   `.github/workflows/trusted-desktop-supply-chain-policy.yml` on protected `main`.
   Requiring only a status/check name is insufficient.
3. Force pushes and branch deletion are blocked.
4. Bypass actors are narrowly restricted.
5. Code-owner review protects:
   - `.github/CODEOWNERS`
   - `.github/workflows/trusted-desktop-supply-chain-policy.yml`
   - `.github/workflows/bootstrap-desktop-supply-chain-policy.yml`
   - `.github/trusted/desktop-supply-chain-policy/**`

The stable authoritative identity is:

- Workflow: `GTA Claw authoritative desktop supply-chain policy`
- Job/check: `[AUTHORITATIVE] Trusted desktop supply-chain policy`

The ordinary pull-request bootstrap check is deliberately distinct and is never an
authority:

- Workflow: `GTA Claw non-authoritative desktop policy bootstrap`
- Job/check: `[NON-AUTHORITATIVE] Candidate desktop policy validator CI`

## Validation states

The authoritative workflow has no `paths` or `paths-ignore` filter. It runs on every
pull request targeting `main` and computes the complete direct base-to-head changed
paths with trusted Git. It fetches the exact protected base at depth 1 and the exact
immutable head at depth 10,001, never fetches tags or wildcard fork refs, and rejects
direct pull-request ranges above 10,000 commits.

The validator recognizes two base states:

- **Bootstrap:** product-policy files rooted at
  `8137bccb6e47097f41f016afe5c4b7b2e3d63002` and both protected trust-root workflows
  exactly match the Bootstrap fingerprint. An unrelated change may pass while those
  exact bytes are retained. Any policy-relevant change must establish complete final
  P04f state in one pull request.
- **Final:** the base satisfies complete final P04f policy. Every candidate must retain
  final policy, including candidates whose changed files are otherwise unrelated.

An unknown non-final base fails. Final state never falls back to bootstrap state.
The head must contain the current base commit; stale pull requests fail even before the
repository's up-to-date rule is considered.

## Frozen and extensible boundaries

The validator exact-freezes:

- both workflow definitions and the complete trusted tree;
- reserved workflow/job/check identities;
- canonical Unicode-normalized, full-case-folded path-component collisions while
  retaining strict ASCII-only security-sensitive names;
- the legacy `rust-toolchain` basename at every depth, with canonical ownership coverage
  for attempted additions and only `rust-toolchain.toml` permitted;
- deny, audit, toolchain, and intentional exception policies;
- root/headless GUI exclusion including Slint, GTK4, GDK4, and GSK4 package families,
  renamed dependencies, metadata, and transitive lock entries;
- the desktop workspace's sole app member;
- the desktop package name, manifest, build script, Slint declarations, targets,
  dependencies, smoke test, lock agreement, and Cargo metadata paths;
- locked offline Cargo-metadata release-version agreement across root and desktop
  workspaces, independent of TOML whitespace;
- one exact `CFBundleExecutable`, one regular non-symlink executable in
  `Contents/MacOS`, and repeated pre/post-signing and notarization verification;
- raw LF execution bytes and executable modes for adversarial shell-tool fixtures;
- an independent 48-case archived mutation inventory bound to exact artifact rule
  classes and messages;
- the three required lockfile locations — root, desktop, and this validator — plus a bounded
  admitted set that adds only `android/Cargo.lock` and `ios/Cargo.lock`.

## Mobile workspace admission

Slint cannot live anywhere in the root headless workspace: `FORBIDDEN_GUI_NAMES`, the `i-slint`
prefix rule, the renamed-dependency check, and the root lock scan close every route, and the
excluded-workspace route is closed by the byte-pinned `workspace.exclude`. Two top-level sibling
workspaces are therefore admitted alongside `desktop`, mirroring it: `android` and `ios`.

Admission is bounded and conditional, never a prefix rule and never a bypass:

- the lock and manifest inventories remain `required ⊆ actual ⊆ admitted`. The admitted set adds
  exactly `android/Cargo.toml`, `android/apps/gta-claw-android-shell/Cargo.toml`,
  `android/Cargo.lock` and their `ios` counterparts, derived from the platform table so a second
  list cannot disagree with it. Any other sibling workspace still fails closed;
- each shipped platform is one complete policy unit: workspace manifest, sole app manifest, lock,
  exact `deny.toml`, exact packaging workflow, and every workflow-executed packaging input. The
  deny files are admitted only at `android/deny.toml` and `ios/deny.toml`; the dependency policies,
  renderer-feature manifests, shell scripts, iOS project specification, and iOS plist are
  byte-checked against the base-compiled reviewed policy, and both workflows execute cargo-deny
  0.20.2;
- the historical Bootstrap lock inventory is a separate frozen constant, so widening what a Final
  state admits can never rewrite what the pre-P04f snapshot contained;
- a platform is a complete unit. Its manifests, lock, dependency policy, workflow, and packaging
  inputs are present together; partial presence is rejected and names both sides;
- a present platform is validated, not merely admitted: exact top-level and workspace schemas with
  no `exclude` key, `resolver = "3"`, exactly one canonical app member, release version agreement
  with the root workspace, a lint policy no weaker than the desktop one, exact member lint
  inheritance, and a lock whose packages come only from the crates.io registry with valid
  checksums or are declared local workspace packages;
- both mobile manifests run through the same dependency validation the root members do, with the
  GUI rejection lifted and nothing else. Git and alternate-registry sources, wildcard versions,
  renamed sources, and `path` values that resolve outside the repository or to something that is
  not a declared member all fail closed;
- a mobile lock may not introduce a second Slint line. Any `slint` entry must match the release
  recorded in the protected desktop lock.

The two mobile app members are `gta-claw-android-shell` and `gta-claw-ios-shell`, deliberately
distinct from the root `gta-claw-android` client core, so a shell can path-depend on its core
without a package-name collision.

### Mobile Skia archives are pinned outside Cargo.lock

`i-slint-renderer-skia` is a non-optional dependency of `i-slint-backend-winit` under
`cfg(all(target_vendor = "apple", not(target_os = "macos")))`, so an iOS Slint build cannot avoid
Skia by feature selection. `skia-bindings` downloads a prebuilt archive from
`https://github.com/rust-skia/skia-binaries/releases/download/{tag}/skia-binaries-{key}.tar.gz`
through `curl -L -f -sS` and verifies nothing about it; its own source carries a literal
`// TODO: verify key`. A build that fetches a prebuilt artifact the lockfile does not describe is
trusting something outside the supply chain.

The reviewed position is the pattern `rust.yml` already applies to cargo-audit, cargo-deny, and
actionlint: fetch the archive over hardened TLS, verify it against a reviewed SHA-256, and hand the
verified file to the crate through `SKIA_BINARIES_URL`, which accepts a `file://` URL, so the
crate's own unverified fetch never runs. Building Skia from source was rejected: the C++ tree is not
vendored in the published crate and is itself fetched at build time, so a source build relocates the
unverified fetch rather than removing it, at ten to forty-five minutes and roughly a gigabyte.

The rules are driven by lock contents rather than by platform, because the exposure follows Skia
and not Apple. Whenever **any** mobile lock contains `skia-bindings` it must be the pinned release,
cross-checked against the protected desktop lock so the two can never drift, and every Skia target
that platform declares must carry a reviewed digest. iOS treats the *absence* of `skia-bindings` as
an unresolved lock because it cannot avoid Skia. Slint 1.17.1's Android activity backend also
depends directly on Skia. The Skia 0.99.0 release publishes matching Android archives for arm64
devices and x86_64 emulators but none for armv7, so the Android shell does not claim armeabi-v7a.

`PINNED_BUILD_ARTIFACTS` records reviewed `(package, version, target, url, SHA-256)` pins for every
package known to fetch at build time, listed in `BUILD_TIME_FETCHING_PACKAGES` — today exactly
`skia-bindings`, so a second such package cannot appear silently. The archive key embeds the crate
commit, target, and resolved feature set, so the pins were selected only after both mobile locks
resolved. Four official 0.99.0 release assets are pinned:

| Target | Resolved feature key | SHA-256 |
| --- | --- | --- |
| `aarch64-linux-android` | `gl-jpegd-jpege-pdf-textlayout-vulkan` | `46f267b4754ca3af59b4ef30d273425c9585f2cc5fd20481bac4125c1e6f8217` |
| `x86_64-linux-android` | `gl-jpegd-jpege-pdf-textlayout-vulkan` | `d691c9891d153466d5b99c0003fc6891482b97fb900b72c27b460b648f4e9534` |
| `aarch64-apple-ios` | `gl-jpegd-jpege-metal-pdf-textlayout` | `15e20f3265dfddd658f9ef0d0e30d50a73afccb88787812f65fb5e6cf4ec55c8` |
| `aarch64-apple-ios-sim` | `gl-jpegd-jpege-metal-pdf-textlayout` | `ade5b153818d9b7b81240f106df148a9c4b92fb3aba566f942a713b93914e11e` |

Each digest came from release asset metadata, which publishes a SHA-256 the build script ignores:

```text
gh api repos/rust-skia/skia-binaries/releases/tags/<version> \
  --jq '.assets[] | select(.name | test("aarch64-apple-ios")) | [.name, .digest] | @tsv'
```

#### Why the lockfile does not already cover this

**The `Cargo.lock` checksum covers the crates.io package — it says nothing about the tarball
fetched later. The lockfile describes the code that performs the download, not the thing
downloaded.** This is the point most likely to be missed, because the checksum is a real control,
correctly implemented, over something adjacent to the claim. `skia-bindings` 0.99.0 proves it in its
own manifest: its `include` list is `Cargo.toml`, `bindings_docs.rs`, `build.rs`,
`build_support/**/*.rs`, and `src/**`. The published `.crate` file cannot contain the artifact, so
no checksum over it can cover the artifact.

Three further facts, each verified against `rust-skia` at tag `0.99.0`, underpin the reviewed
`PINNED_BUILD_ARTIFACTS` entries:

- **The artifact host is a different repository from the crate source.** The crate declares
  `repository = "https://github.com/rust-skia/rust-skia"`; the archive is served from
  `rust-skia/skia-binaries`. Vetting the crate's project does not vet the artifact's host, and the
  two have different contributor sets and release automation. Reasoning "rust-skia is well known"
  vets the wrong thing.
- **GitHub already serves a SHA-256 for every release asset, and the build never asks for it.** The
  `gh api` command above reads `.digest` from the same host that serves the archive. So the missing
  verification is a choice made by `skia-bindings`, not an unavoidable property of the ecosystem —
  which is what makes the `file://` handover a use of available data rather than a workaround.
- **`no-compile` is a Cargo feature, not an environment variable**, declared as `no-compile = []`
  with the comment *"Panic when any compilation steps are required to run."* Anyone attempting to
  forbid a fallback compile by exporting an environment variable will silently achieve nothing.

The archive key is the first twenty hex characters of the `rust-skia` commit plus the target triple
plus the sorted feature set. **It is not content-addressed and carries no digest**, so the URL alone
can never establish what was served. `FORCE_SKIA_BUILD` does not fix this: it relocates the trust,
because the Skia source archive, the many third-party repositories `git-sync-deps` clones, and the
GN binary from `chrome-infra-packages.appspot.com` are each themselves unverified.

These findings come from reading the pinned source rather than executing it; no Windows host can run
a `skia-bindings` build for an Apple target, so the first real iOS build remains the proof.

### Mobile CI and packaging boundary

`android-packaging.yml` checks both published Android targets, runs the exact Android dependency
policy, and assembles an arm64 cargo-apk prototype. `ios-packaging.yml` checks device and simulator
targets, runs the exact iOS dependency policy, and produces an unsigned Xcode archive. Both
workflows prefetch their target-specific Skia archive through hardened TLS, verify the reviewed
digest, and pass only the verified `file://` URL through `SKIA_BINARIES_URL`; the direct
`skia-safe/no-compile` feature prevents a source-build fallback.

Android's artifact uses cargo-apk's local signing behavior and is not a Play Store release. iOS
distribution signing, provisioning, export, and upload remain outside CI because they require Apple
credentials. Neither workflow claims device execution.

`rust.yml` is unchanged and is not the place for this: it is byte-frozen, and the authoritative
policy workflow carries no path filter, so every rule above already runs on every pull request
regardless of which paths a change touches. A tree containing `android/` can never classify as
Bootstrap, so it fails closed into Final validation.

The `.github/workflows` directory is a closed inventory. Eight historical workflow files are
**required** in both Bootstrap and Final states. Two further exact paths,
`.github/workflows/ios-packaging.yml` and `.github/workflows/android-packaging.yml`,
remain **admitted** at inventory level so the immutable historical Bootstrap snapshot can still be
classified. Complete Final policy requires both through the mobile platform units and exact-checks
their base-compiled bytes in addition to tagged-YAML, ASCII-identity, reserved-identity
anti-spoofing, duplicate-name, and isolated-actionlint validation. No other path may appear at any
depth, and no historical required path may be removed. Admitting a further workflow still requires
an audited trust-root update.

The root headless workspace remains extensible. A new canonical `crates/<name>` or
`apps/<name>` member can pass without changing this trust root when it is explicitly
declared, uses the required workspace inheritance, introduces no nested workspace or
local lock, uses only approved sources, contains no Slint/GUI dependency, and passes
trusted metadata, deny, and audit checks. The root lock contents may evolve under those
same invariants. Every member except the existing `claw-config` generated-code exception
must inherit the workspace lint policy exactly, with one path-and-package-bound exception:
only `crates/claw-sqlite-file-control` / `claw-sqlite-file-control` may declare the audited
native-FFI lint table (`missing_docs = "warn"`, `unsafe_code = "allow"`,
`unsafe_op_in_unsafe_fn = "deny"`, `unreachable_pub = "warn"`, and
`clippy.all = "warn"`). Aliases, sibling paths, additional lint keys, and any level drift
fail closed.

The Final root `deny.toml` is the exact reviewed policy. Its license allow-list adds only
`Apache-2.0 WITH LLVM-exception` to the former P03b set; the LLVM exception is more permissive
than plain Apache-2.0 and is required by the Wasmtime/Cranelift plugin-host dependency graph.
The policy permits only the version-pinned duplicate skips recorded there; wildcard or
versionless skips, source widening, advisory exceptions, graph target filtering, and any other
drift are rejected. The discovery transition pins only the reviewed older `getrandom`, `rand`,
`core-foundation`, `syn`, and `sha3` lines that coexist with their newer ecosystem versions.

## Legacy Node shrink-only ratchet

For every Final protected base, the validator independently inventories both trees. The
candidate legacy surface must be a subset of the base surface, and both must remain within the
exact historical ceiling of 18 `src/**/*.ts` files plus `Dockerfile`, `package.json`,
`package-lock.json`, and `tsconfig.json`. Deletion passes; a deleted artifact can never return.
Tracked symbolic links, gitlinks, new package-manager artifacts, and new Node workflow or local
action debt fail from the base side.

`crates/claw-repo-policy` is transitionally absent until its accepted product-policy pull request
lands. Its first appearance must have the exact dependency-free workspace shape, explicit
ceiling, fixture exceptions, add-fails/delete-passes tests, workflow/action and index tests, and
both CI execution paths. Once it exists in a protected base, removing or weakening that shape is
forbidden. Activation also requires zero remaining Node workflow/action violations.

## Trust-root updates

An ordinary pull request cannot change either workflow definition or this directory
and still pass the authoritative job. A future update requires:

1. A dedicated trust-root-only pull request.
2. Independent security and full reviews of the complete against-main diff.
3. Explicit use of the narrowly restricted ruleset bypass by an authorized maintainer.
4. Re-verification of the effective required-workflow and branch rules.
5. Subsequent product-policy pull requests based on the new protected main.

No hash stored in a candidate checkout authorizes an update.

The required-workflow eligibility follow-up based on
`a3288d7d5eabea9fc2464a4c54b75727cd5ee99b` intentionally changes the authoritative
workflow and this frozen validator tree. The base-owned
`[AUTHORITATIVE] Trusted desktop supply-chain policy` check is therefore expected to
reject that pull request as a protected-file mutation. It must not be weakened to pass.
Only the already-audited pull-request-mode ruleset bypass may unblock that hosted check,
after the candidate-owned `[NON-AUTHORITATIVE] Candidate desktop policy validator CI`
and the independent reviews are green. Required-workflow authority is not established
until an administrator separately binds the eligible workflow after this update merges.

### Sole-maintainer ownership limitation

The canonical `.github/CODEOWNERS` currently assigns these security-critical paths only
to `@aizhihuxiao`. GitHub does not permit a pull-request author to approve their own
change, so a trust-root or CODEOWNERS update authored by the sole maintainer can require
the narrowly restricted repository-rules bypass.

That bypass is an audited exception, not normal approval. It is acceptable only after
independent SECURITY and FULL reviews of the complete diff are recorded `CLEAN`, the
bootstrap/final gates pass, and an authorized maintainer verifies the exact change.
This repository code does not grant the bypass or configure repository permissions.

## P04f absorption and live proof

After this prerequisite is merged and repository rules are verified, the P04f branch
must:

1. Merge current `main`.
2. Delete and stop compiling
   `crates/claw-security/tests/desktop_supply_chain_policy.rs` and its fixture.
3. Remove the obsolete `serde_yaml_ng` and `toml` dev dependencies and recompute the
   root lock delta.
4. Rename cargo-audit data locks to `Cargo.lock.fixture`, because only the required and admitted
   `Cargo.lock` locations are permitted.
5. Change `rust.yml`, `macos-packaging.yml`, desktop manifests, desktop lock, and deny
   policy to the exact protected final fixtures. `rust.yml` must not compile or run the
   deleted mutable policy test.
6. Recompute and re-review the complete diff against the new `main`.
7. Capture a successful base-owned required-workflow run showing exact base/head OIDs,
   a policy-relevant transition, and complete final policy.

P04f must not merge before that live proof and repository-rule evidence exist.

## Local validation

The standalone crate declares Rust `1.94.0` as its exact MSRV and keeps a separate
locked dependency graph:

```text
cargo +1.94.0 fmt --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --all -- --check
cargo +1.94.0 check --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked --all-targets
cargo +1.94.0 clippy --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked --all-targets -- -D warnings
cargo +1.94.0 test --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked --all-targets
```

The Bootstrap snapshot is a historical anchor/composite, not a mirror of current Final policy.
The validator does not require global equality between the archive and the live checkout.
Instead, the trusted Git `ChangeManifest` forces a per-path decision whenever a direct
base-to-head change names one of the exact 28 Bootstrap inputs:

1. **Synchronize:** the candidate archive remains canonical with the exact Bootstrap inventory,
   the changed path's embedded payload equals the normalized candidate live bytes, and the
   archive's semantic fingerprint equals the single strictly parsed `BOOTSTRAP_FINGERPRINT`
   declaration. The trusted manifest must name both `policy/bootstrap.snapshot` and
   `src/policy.rs`; changing only one companion cannot authorize synchronization.
2. **Preserve:** the embedded historical payload for that path remains byte-for-byte unchanged,
   and the candidate appends one record to
   `policy/bootstrap-source-decisions.toml`. The record binds the exact path, normalized
   protected-base Git OID, normalized protected-base and candidate live SHA-256 values,
   candidate embedded-payload SHA-256, candidate semantic archive fingerprint, and a bounded
   non-empty rationale. The trusted manifest must name the decision ledger.
3. **Standing preservation:** the protected base already carries a reviewed `[[standing]]` entry
   for that path, the candidate ledger still carries the identical entry, and the embedded
   historical payload for that path is unchanged. No candidate write of any kind is required.

Options 1 and 2 both write inside the protected trust root, so an ordinary pull request cannot
take either: `validate_protected_files` compares the whole trust-root tree and admits no
exemption. Option 3 exists so that the routine case — a Final workspace resolving a new
dependency while the historical archive stays frozen — is decided once, in a reviewed
trust-root change, instead of once per pull request.

A standing entry binds `path`, `base_oid` (provenance only), `snapshot_payload_sha256`,
`snapshot_fingerprint`, and a bounded rationale. It deliberately records no per-change
transition and is deliberately **not** re-bound to `manifest.base`, so the protected base
advancing does not invalidate it and a queue of pending pull requests can land in any order.
It binds archive-side facts only, which is what keeps it narrow:

- coverage is read from the **protected base** ledger and additionally requires the identical
  entry in the candidate ledger, so a candidate can neither mint coverage for itself nor keep
  coverage it edited or dropped;
- coverage requires the embedded payload for that path to be unchanged and to hash to
  `snapshot_payload_sha256`;
- coverage requires `snapshot_fingerprint` to equal the candidate archive's semantic
  fingerprint, so rewriting *any* archived payload voids every standing entry at once and the
  preservations must be re-taken alongside that synchronization.

Standing entries are seeded for the 15 dependency-graph inputs in `BOOTSTRAP_FILES` — every
`Cargo.toml`, every `Cargo.lock`, and `deny.toml`. The remaining 13 inputs (the seven
workflows, `.github/CODEOWNERS`, `.cargo/audit.toml`, `.gitattributes`, `rust-toolchain.toml`,
and `rustfmt.toml`) carry no standing entry and stay fully coupled: changing one still requires
option 1 or option 2 and therefore a reviewed trust-root change.

The schema-v1 ledger starts empty. `standing` is an optional key that is omitted entirely when
there are no standing entries, so the canonical form stays unique. Standing entries use
consecutive integer IDs and strictly ascending unique paths drawn from `BOOTSTRAP_FILES`.

Records use consecutive integer IDs, canonical field order,
lowercase full hashes, and deterministic ID order. The `(base_oid, path)` pair is a stable unique
key, so rebasing or changing the same path again requires a new record bound to the current
protected base. Existing records are an immutable prefix: they cannot be edited, deleted,
reordered, copied under a new ID, or reused for a later change to the same path. Every appended
record must correspond to exactly one changed Bootstrap path choosing preservation; stale,
duplicate, or extraneous records fail. A pull request changing multiple Bootstrap paths may mix
synchronized and preserved decisions independently.

This coupling is deliberately residual. Protected workflow/tree checks, workflow inventory,
Final static policy, the repository transition, actionlint, and metadata validation all run
first and retain their specific diagnostics. Only an otherwise-valid candidate reaches the
missing-decision diagnostic. Because the ledger, archive, and fingerprint source are protected
trust-root files, an ordinary authoritative run still rejects their mutation before this
residual rule and requires the audited bypass described above; direct coupling tests establish
the mechanically valid review decision without weakening that authority boundary.

The snapshot writer remains all-or-nothing over all 28 Bootstrap inputs. Every successful
invocation compares the existing archive with the generated canonical archive and prints this
deterministic contract before the result is accepted:

```text
bootstrap_snapshot_delta changed_count=1 preserved_count=27
changed_path=".github/workflows/upstream-gateway-reference.yml" status=modified
```

Changed paths are sorted. First writes report all 28 paths as `added`, with
`changed_count=28 preserved_count=0`. Inventory differences use `added` and `removed`; payload
differences use `modified`. A malformed or noncanonical existing archive fails closed without
being overwritten.

For an audited, reviewed single-entry Bootstrap update, first materialize the immutable Bootstrap
root byte-for-byte, replace only the reviewed path, run the canonical all-or-nothing writer against
that materialization, and inspect its mandatory delta output. Accept the result only when it says
`changed_count=1 preserved_count=27` and names the exact reviewed path. For example, Git can safely
materialize and replace tree entries without routing binary bytes through a shell text stream:

```text
git worktree add --detach "$MATERIALIZED_ROOT" "$IMMUTABLE_BOOTSTRAP_OID"
git -C "$MATERIALIZED_ROOT" restore --source="$REVIEWED_OID" --worktree -- ".github/workflows/upstream-gateway-reference.yml"
cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- write-bootstrap-snapshot --root "$MATERIALIZED_ROOT" --output "$PWD/.github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"
```

Never generate the historical Bootstrap snapshot from live Final merely because that checkout is
convenient. Binary extraction must remain byte-preserving: do not use PowerShell text redirection
such as `git show > file`, and avoid `cmd.exe` commands whose commit/path syntax is exposed to caret
escaping. There is not yet a first-class single-entry update command; the full materialization and
mandatory delta review above remain required.

After the snapshot delta is accepted, fingerprint the reviewed GTABOOT1 archive directly. The
default output is deliberately human-facing and names the archive subject before the hash:

```text
cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- bootstrap-fingerprint --snapshot "$PWD/.github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"
bootstrap archive /reviewed/GTA-Claw/.github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot fingerprint 96e8c3dabd6d341133ddae8732e90fe088c62f5dc78d1f579eeeac5f9e8497d3
```

Do not run fingerprinting against `--root "$PWD"`. Current Final intentionally differs from
historical Bootstrap, so a live-root hash is not the reviewed archive fingerprint and must never
be copied into `BOOTSTRAP_FINGERPRINT`. Root mode exists only to verify a directory containing
exactly the archive's 28 normalized entries, with no missing or extra files:

```text
cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- bootstrap-fingerprint --root "$EXACT_ARCHIVE_MATERIALIZATION" --snapshot "$PWD/.github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"
```

The command refuses live/Final roots, changed, missing, or extra materialized entries, and a root
invocation without `--snapshot`. Successful output always names either `bootstrap archive <path>`
or `verified materialized Bootstrap root <path>`; it never prints an unlabelled fingerprint.

### Historical Bootstrap decision: 2026-07-26

The coordinator's final, non-reopenable decision accepts the Bootstrap identity for
`.github/workflows/upstream-gateway-reference.yml` that PR #67 Synchronized into
`policy/bootstrap.snapshot`; that merged identity is deliberate. Immediately before PR #67, the
live workflow was 29 lines while the archived payload was 185 lines. Those 156 lines were
accidental drift created after PR #50 replaced the live workflow, when no companion-decision
mechanism existed.

The stale archived payload was the pre-PR #50 Node/pnpm workflow. Synchronization removed
`setup-node`, npm/pnpm, and `node_modules` references from the trust root's own archive and
included the `claw-repo-policy` ratchet entry point. PR #102 now closes that freshness gap by
requiring Synchronize or Preserve for changed Bootstrap source paths.

This note records the accepted historical decision. It does not claim that Bootstrap must mirror
current Final, and it does not authorize regenerating or reverting the archive.

During an audited Final dependency-surface update, copy the reviewed live root deny
policy, desktop manifests, desktop lock, and desktop deny policy into their exact audit
fixtures only through the validator:

```text
cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- write-final-dependency-fixtures --root "$PWD"
```

Hosted bootstrap CI additionally supplies checksum-pinned actionlint and Git binaries,
audits this directory's `Cargo.lock`, checks `deny.toml`, and verifies the exact
build-script/proc-macro allow-list for parser dependencies.
