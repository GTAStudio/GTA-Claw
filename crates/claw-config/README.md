# `claw-config`

`claw-config` is the strict configuration boundary for the Rust workspace. It
loads UTF-8 JSON5 into immutable typed snapshots, emits generated JSON Schemas,
writes snapshots atomically, resolves layered runtime configuration, publishes
tear-free typed reload notifications, and converts the frozen GTA legacy
environment contract without reading process environment state.

`OpenClawConfig` represents all 47 top-level domains in the frozen
`config-domains` inventory. Fixed domains reject unknown keys and
plugin-extensible domains preserve their named extension objects. The original
version 1 runtime envelope remains additive and requires `schema_version` plus
these `core` domains:

`auth`, `role`, `channels`, `server`, `logging`, `sessions`, `copilot`,
`legacy`, `updates`, `admin`, and `network`.

Unknown envelope, top-level domain, and fixed-field names are rejected. Secrets
are persisted only as validated environment or platform-store references.
`SecretRef` and `SecretMaterial` redact Debug, Display, and direct Serde output;
the explicit platform store port is the only API that receives borrowed
plaintext.

Layered runtime resolution uses built-in, system, user, workspace, frozen
legacy environment, then command-line precedence. Nested objects merge
recursively while arrays and scalars replace lower layers. File migrations keep
exact durable backups and expose rollback. `ConfigHub` and `ConfigFileWatcher`
publish complete immutable snapshots and ordered typed notifications.

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

`LEGACY_RUNTIME_CONFIGS` is the public typed disposition registry for the 35
runtime semantic leaves that migrate automatically. Each entry records its
canonical environment name, aliases, JSON5 destination, intended subsystem
owner, current disposition, and routing note. Migration acceptance is not
consumer enforcement: every entry is currently `AcceptedOnly` because no
production crate outside `claw-config` has been established as a consumer.
Future consumer work must attach independent implementation evidence before
changing an entry to `Enforced`.

This distinction is security-relevant. `ALLOWED_SKILL_DOMAINS` does not restrict
skill egress, and `RATE_LIMIT_PER_MIN` does not throttle per-IP requests to
`/api/messages`, until their respective consumers bind and enforce them. A
configured security control must not be presented as active merely because
`claw-config` accepted it.

`SESSION_TTL_MS` (`sessions.ttl_ms`) and `MAX_SESSIONS`
(`sessions.max_entries`) describe only an ephemeral provider-session cache
policy. They are not TTL/LRU controls for durable `claw-memory` data, and must
never cause silent eviction of durable memory.

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
