# Oracle provenance for ledger evidence

**Status: proposal.** This document changes nothing that runs. It records a measurement,
names the ceilings that measurement implies, and proposes the smallest schema and validator
change that would make the ledger able to distinguish evidence constrained by an external
oracle from evidence that is only internally consistent.

## 1. What the frozen inventories actually publish

Measured against `compat/upstream/inventories/` at baseline
`b43e832fcc8000ed7287c7accc54e381db607f85`, by reading the key set of every item rather
than the fields any consumer happens to deserialize.

Every item of every inventory publishes the same identity quadruple:
`record_id`, `id`, `classification`, `source_path`.

| inventory | items | fields beyond the identity quadruple |
| --- | ---: | --- |
| `http-sse-endpoints` | 18 | `method`, `path`, `streaming` |
| `gateway-protocol` | 320 | `kind`; `scope` and `advertised` on 278 methods; `protocol_class` on 3 |
| `channels` | 29 | `plugin_id` or `package_name`, `provenance`, `catalog_package`, `catalog_source_path` |
| `plugins` | 137 | `package_name`, `delivery_class` |
| `migrations` | 3 | `kind`, `package_path` |
| `clients` | 10 | `kind` |
| `release-deployment` | 24 | `kind` |
| `skills` | 51 | `license` |
| `providers` | 78 | `plugin_id` |
| `config-domains` | 47 | *(none)* |

Two inventories publish fields that describe **behaviour**: `http-sse-endpoints`
(`method`, `path`, `streaming`) and `gateway-protocol` (`scope`, `advertised`). The other
eight publish identity, packaging provenance, or a taxonomy label, and nothing else.

## 2. Ceilings this implies

A ledger row cannot be arbitrated against a field its inventory does not publish. Where a
row's `acceptance_evidence.required` clause names such a dimension, that dimension is
unfalsifiable against the frozen tree **by construction**, and no amount of test-writing
changes it.

| row | required clause names | published by its inventory | ceiling |
| --- | --- | --- | --- |
| `integration.providers` | IDs, aliases, configuration, auth, capability routing | IDs only | 1 of 5 |
| `integration.channels` | IDs, account routing, inbound/outbound, commands, lifecycle | IDs only | 1 of 5 |
| `interop.clients.native` | each inventoried client completes v4 connection and a platform smoke suite | membership and `kind` | see below |
| `gateway.config.domains` | deserialize every pinned domain, reject unknown contract-breaking shapes | domain names only | names only |

`interop.clients.native` has a second, sharper problem: the inventory it depends on names
ten clients of which only three carry `kind: native_app`. The remainder are a web app, two
terminal clients, a native sidecar, a native helper, a browser extension and a headless
node. The row's membership set and its name disagree, and `kind` is the only field that
can express the disagreement.

`gateway.config.domains` is the weakest of the four: `config-domains.json` publishes the
identity quadruple and nothing else, so the pinned *names* of the 47 domains are
arbitrable and none of their *shapes* are. "Reject unknown contract-breaking shapes" has no
external oracle anywhere in the repository.

The positive result is worth stating too, because it says where effort pays:
**`gateway.protocol.methods` is fully arbitrable.** Its required clause names "every pinned
core method name, scope, and advertised flag", and `gateway-protocol.json` publishes all
three for all 278 methods. `http-sse-endpoints` is likewise fully behavioural for the
surface it covers.

## 3. The governance gap

The evidence gate today establishes that a cited test **exists and is compiled into an
enabled test target**. It does not establish that the test is **constrained by anything
external**. Those are different properties, and the ledger has no field that distinguishes
them, so two rows reading `implemented` can mean:

- a test that fails when a frozen inventory changes, or
- a test that asserts a constant against itself and cannot fail for any value of that constant.

Both render identically in the ledger. Every one of the eight rows currently holding
`implemented` belongs to a feature with **no frozen inventory at all** — there is no
`acp` or `mcp` inventory — so for those rows the second reading is the only one available,
whether or not their tests are good.

This is not an accusation about any particular test. It is a statement that the ledger
cannot currently express the difference, and therefore cannot be audited for it.

## 4. Proposal

Add one required field to each entry of `acceptance_evidence.artifacts`:

```json
{
  "path": "crates/claw-http-api/tests/e2e.rs",
  "test": "observed_response_framing_matches_the_frozen_streaming_modes",
  "oracle": {
    "kind": "inventory",
    "inventory": "inventories/http-sse-endpoints.json",
    "fields": ["method", "path", "streaming"]
  }
}
```

`oracle.kind` is one of:

- `inventory` — the test reads a frozen inventory at runtime and asserts against fields it publishes.
- `external-tool` — the test is arbitrated by something outside the crate under test (a
  compiler, `cargo test -- --list`, a protocol implementation not written here).
- `self-referential` — the test asserts internal consistency only. Legitimate and often
  valuable, but it cannot detect drift from the frozen baseline.

Three validator checks, all mechanically decidable with data `validate.ps1` already parses:

1. **Existence.** For `kind: inventory`, the named inventory must be one of the paths in
   `manifest.json`.
2. **Field subset.** For `kind: inventory`, `oracle.fields` must be non-empty and every
   entry must be a field that inventory actually publishes. *This is the check that would
   have caught the ceilings in section 2*: a row citing `capabilities` against
   `providers.json` fails, because `providers.json` publishes no such field. It converts a
   ceiling from something a session discovers after a day of work into a validation error.
3. **Status floor.** A row whose artifacts are all `self-referential` may not hold
   `implemented`. It may hold `partial`.

Check 2 is the substantive one. Checks 1 and 3 are bookkeeping.

## 5. What this proposal deliberately does not do

- It does not verify that the cited test's assertions *depend* on the cited fields. A
  textual link between a test file and an inventory path proves the file mentions the
  inventory, not that removing the inventory would fail the test. Proving that requires
  mutation, which no static gate can do.
- It does not change any existing row, status, or artifact. Adopting it means backfilling
  `oracle` on the artifacts that exist today, which is a separate, reviewable change.
- It does not touch `compat/upstream/manifest.json` or the frozen inventories. Section 4
  describes a schema change to the ledgers and a validator addition; both are outside the
  authority of the session that wrote this document, which is why this is a proposal and
  not a patch.
- It is orthogonal to, and does not substitute for, verifying that a cited test **name**
  actually registers with the test harness. A citation can name a function that compiles
  and never runs; that is a separate hole in the same gate.
