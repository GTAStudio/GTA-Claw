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
`build.rs`; Rust code does not maintain a second list of canonical names,
aliases, targets, or secret classifications.
