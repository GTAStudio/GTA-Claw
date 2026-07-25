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
- the three real lockfile locations: root, desktop, and this validator.

The `.github/workflows` directory is a closed inventory. Eight workflow files are
**required** and must be present in every checkout. Two further exact paths,
`.github/workflows/ios-packaging.yml` and `.github/workflows/android-packaging.yml`,
are **admitted** for the shipped mobile platforms: each may be absent or present, and
a present file is subjected to the same tagged-YAML, ASCII-identity, reserved-identity
anti-spoofing, duplicate-name, and isolated-actionlint checks as a required one. No
other path may appear at any depth, and no required path may be removed. Admitting a
further workflow still requires an audited trust-root update.

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
4. Rename cargo-audit data locks to `Cargo.lock.fixture`, because only three real
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

During an audited Bootstrap trust-root update, regenerate the binary snapshot only
through the validator and then copy its printed fingerprint into the reviewed constant:

```text
cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- write-bootstrap-snapshot --root "$PWD" --output "$PWD/.github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"
cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- bootstrap-fingerprint --root "$PWD"
```

During an audited Final dependency-surface update, copy the reviewed live root deny
policy, desktop manifests, desktop lock, and desktop deny policy into their exact audit
fixtures only through the validator:

```text
cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- write-final-dependency-fixtures --root "$PWD"
```

Hosted bootstrap CI additionally supplies checksum-pinned actionlint and Git binaries,
audits this directory's `Cargo.lock`, checks `deny.toml`, and verifies the exact
build-script/proc-macro allow-list for parser dependencies.
