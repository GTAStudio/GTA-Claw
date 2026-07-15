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
paths with trusted Git.

The validator recognizes two base states:

- **Bootstrap:** product-policy files exactly match the fingerprint rooted at
  `8137bccb6e47097f41f016afe5c4b7b2e3d63002`. An unrelated change may pass while that
  exact product-policy fingerprint is retained. Any policy-relevant change must
  establish complete final P04f state in one pull request.
- **Final:** the base satisfies complete final P04f policy. Every candidate must retain
  final policy, including candidates whose changed files are otherwise unrelated.

An unknown non-final base fails. Final state never falls back to bootstrap state.
The head must contain the current base commit; stale pull requests fail even before the
repository's up-to-date rule is considered.

## Frozen and extensible boundaries

The validator exact-freezes:

- both workflow definitions and the complete trusted tree;
- reserved workflow/job/check identities;
- deny, audit, toolchain, and intentional exception policies;
- the desktop workspace's sole app member;
- the desktop package name, manifest, build script, Slint declarations, targets,
  dependencies, smoke test, lock agreement, and Cargo metadata paths;
- the three real lockfile locations: root, desktop, and this validator.

The root headless workspace remains extensible. A new canonical `crates/<name>` or
`apps/<name>` member can pass without changing this trust root when it is explicitly
declared, uses the required workspace inheritance, introduces no nested workspace or
local lock, uses only approved sources, contains no Slint/GUI dependency, and passes
trusted metadata, deny, and audit checks. The root lock contents may evolve under those
same invariants.

## Trust-root updates

An ordinary pull request cannot change either workflow definition or this directory
and still pass the authoritative job. A future update requires:

1. A dedicated trust-root-only pull request.
2. Independent security and full reviews of the complete against-main diff.
3. Explicit use of the narrowly restricted ruleset bypass by an authorized maintainer.
4. Re-verification of the effective required-workflow and branch rules.
5. Subsequent product-policy pull requests based on the new protected main.

No hash stored in a candidate checkout authorizes an update.

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

Hosted bootstrap CI additionally supplies checksum-pinned actionlint and Git binaries,
audits this directory's `Cargo.lock`, checks `deny.toml`, and verifies the exact
build-script/proc-macro allow-list for parser dependencies.
