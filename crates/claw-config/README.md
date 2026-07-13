# `claw-config`

`claw-config` is the strict configuration boundary for the Rust workspace. It
loads UTF-8 JSON5 into immutable typed snapshots, emits a generated JSON Schema,
writes snapshots atomically, classifies transactional reloads, and converts the
frozen GTA legacy environment contract without reading process environment
state.

The version 1 envelope requires `schema_version` and these implemented `core`
domains:

`auth`, `role`, `channels`, `server`, `logging`, `sessions`, `copilot`,
`legacy`, `updates`, `admin`, and `network`.

Unknown envelope, domain, and implemented-field names are rejected. This crate
does not represent or claim the other upstream OpenClaw configuration domains.
Secrets are persisted only as `env:NAME` references; plaintext secret values
cannot be constructed through the public API or loaded from JSON5.

Legacy conversion supports the runtime rows in
`compat/legacy/config/env-mapping.json`, except `COPILOT_CLI_PATH`, because the
production Rust runtime does not execute Copilot CLI. Present deployer, build,
CI, and Copilot CLI rows produce ordered `ManualRequired` diagnostics:

- `COPILOT_CLI_PATH`
- `DOCKER_IMAGE`
- `APP_LANG`
- `COPILOT_CLI_VERSION`
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
- `DOCKERHUB_IMAGE`

The mapping table is generated and validated from the frozen JSON artifact by
`build.rs`. The package-contained `data/env-mapping.json` is the canonical
crate input so `cargo package` verification is independent of the repository
layout. Normal workspace builds compare the complete typed record, including
defaults, conversions, validation, requirements, aliases, targets, and known
quirks, against `compat/legacy/config/env-mapping.json` and fail on any drift.
The generated Rust table embeds every behavioral field so contract changes are
visible to code review; executable conversion remains an explicitly tested,
typed Rust implementation rather than an interpreted rule engine.

Atomic writes require a trusted configuration directory. Existing destination
and parent symlinks/reparse points are rejected, but path-based replacement
cannot eliminate every rename race in a directory writable by an attacker.
Unix flushes the temporary file and directory around atomic rename. When a
Windows destination already exists, the writer flushes the temporary file and
uses `ReplaceFileW` with a recovery backup, preserving destination ACLs and
filesystem metadata. A first write has no destination metadata to preserve and
uses a same-directory rename. Windows does not document a supported
directory-handle flush equivalent, so final directory entry durability across
sudden power loss is not claimed. Post-publication cleanup/durability problems
are returned as `WriteOutcome` warnings rather than falsely reporting that the
atomic replacement failed.
