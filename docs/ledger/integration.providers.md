# Acceptance evidence — `integration.providers`

Ledger: `compat/upstream/ledgers/official-integration.json`
Feature: `integration.providers` ("Provider registry", tier 3, `platform_integration`)
Frozen baseline: `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85` (package `2026.7.2`)

## Why this file exists instead of a ledger edit

`compat/upstream/validate.ps1` seals the frozen tree. Three of its assertions make an
in-place ledger edit impossible:

| `validate.ps1` | assertion |
| --- | --- |
| lines 896–912 | the `compat/upstream` tree must contain **exactly** 16 JSON files — an evidence file added there fails the seal |
| line 1006 | the SHA-256 of the serialised `features` array is pinned to `01ac641cdcb208343bdbafa119ac6c2089c03a6ac23064351c5dae628eba1c47` |
| lines 1017–1021 | **every** feature must remain `status = "unimplemented"` with `acceptance_evidence.status = "missing"` and zero artifacts |

Setting `integration.providers` to anything other than `unimplemented` / `missing` /
`[]` makes `validate.ps1` fail, and `validate.ps1` passing is part of the definition of
done. The two instructions are mutually exclusive, so `compat/upstream/**` is left
**byte-identical** and the honest evidence lives here, outside the seal. The
machine-readable form is `docs/ledger/integration.providers.json`.

When the seal is intentionally re-cut, the row should become:

```json
"status": "implemented_partial",
"acceptance_evidence": {
  "status": "present",
  "artifacts": [
    "crates/claw-provider-sdk",
    "crates/claw-providers",
    "crates/claw-providers/tests/frozen_inventory.rs",
    "crates/claw-providers/tests/wire.rs",
    "crates/claw-provider-sdk/tests/transport.rs",
    "docs/ledger/integration.providers.md"
  ]
}
```

`implemented_partial`, not `implemented`: 78/78 providers are registered with typed
metadata and proven equal to the frozen inventory, but only 30 ids have a default
endpoint plus a client, and only three wire dialects exist at all.

## What was built

### `crates/claw-provider-sdk`

The provider abstraction. No untyped JSON crosses the public API: every request and
response is a typed Rust value and `serde_json` is an implementation detail of the
wire codecs.

* `provider.rs` — the `Provider` trait (`complete`, `stream`, `embed`, `list_models`,
  `capabilities`), plus `Operation` and `Capability`.
* `model.rs` — `CompletionRequest`/`CompletionResponse`, `Message`, `MessageRole`,
  `Content`, `ToolDefinition`, `ToolCall`, `ToolChoice`, `ResponseFormat`,
  `FinishReason`, `Usage`, `EmbeddingRequest`/`EmbeddingResponse`, `ModelInfo`.
* `sse.rs` + `stream.rs` — an incremental SSE / newline-delimited decoder,
  `ToolCallAssembler` (streamed tool calls arrive as index-keyed argument fragments
  and are reassembled with JSON validation), `StreamAccumulator` (usage and
  finish-reason accounting) and `CompletionStream`, which cancels its token on `Drop`.
* `cancel.rs` — `CancelToken`/`CancelGuard`. Cancellation drops the `reqwest` response
  body, which closes the TCP connection; the tests assert the server observes it.
* `error.rs` — `ErrorKind` with 11 variants (`Auth`, `RateLimit`, `Quota`,
  `Transport`, `Protocol`, `Server`, `Timeout`, `Cancelled`, `Unsupported`,
  `InvalidRequest`, `NotFound`) and `ProviderError` carrying provider id, operation,
  HTTP status, upstream code and `Retry-After`.
* `retry.rs`, `circuit.rs`, `limit.rs` — exponential backoff with full/equal jitter,
  `Retry-After` honoured and capped, a three-state circuit breaker, and a
  semaphore-based per-provider concurrency limiter. All driven by the `clock.rs`
  `Clock` port, so tests use a `ManualClock` and never sleep in real time.
* `secret.rs` — the `SecretStore` port and `SecretString`. Adapters:
  `secret/windows.rs` (Windows Credential Manager through `keyring-core` +
  `windows-native-keyring-store`), `secret/apple.rs` (macOS Keychain through
  `apple-native-keyring-store`), `secret/file.rs` (Linux and other targets: a
  permission-strict file store that refuses a group- or world-readable secret file and
  refuses a directory that is not `0700`), plus an in-memory store for tests.
* `http.rs` — `HttpTransport` over `reqwest` with **rustls only**
  (`default-features = false`, `rustls-tls-native-roots`). No OpenSSL and no Node
  anywhere in the dependency graph.

### `crates/claw-providers`

* `descriptor.rs` / `registry.rs` — all 78 frozen descriptors in a `const` table:
  `record_id`, `id`, `plugin_id`, `source_path`, display name, `ProviderFamily`,
  `ImplementationStatus`, `AuthMode` set, capability set and default base URL.
* `runtime.rs` — `ProviderRuntime`, the reliability wrapper (retry + circuit breaker +
  concurrency limit) shared by every client.
* `openai_compatible.rs`, `anthropic.rs`, `github_copilot.rs` — the three real
  dialects.
* `alias.rs` — name normalisation (trim + ASCII lowercase, *no* separator folding)
  and a validated `AliasTable` that refuses an alias which shadows a frozen id,
  repeats an earlier alias, points at an unregistered target, or is not in
  normalised form. Ships 35 built-in aliases.
* `config.rs` — `ProviderConfig` deserialisation with `deny_unknown_fields`,
  base-URL scheme/host rules, reserved-header refusal, and stable error codes.
* `auth.rs` — `AuthConfig`, an internally tagged sum over all eight `AuthMode`
  spellings, a redacting `SecretField`, and `authorize()` which refuses a mode a
  provider does not declare and a credential that is blank once trimmed.
* `routing.rs` — `RoutingTable` over resolved configurations: capability
  candidates in frozen inventory order, ordered preferences, and an explicit
  `NoProviderAvailable` rather than a silent fallback.

### Why separator folding is not performed

`novita-ai` / `novitaai` and `gmi-cloud` / `gmicloud` are four *distinct* rows in
the frozen inventory. Stripping `-` during normalisation would map each pair onto
one string and silently send a request to whichever row won the collision. The
test `separator_folding_would_merge_distinct_frozen_rows` derives that collision
set from the inventory JSON rather than asserting it from memory, so the rule
stays justified by the data instead of by a comment.

## Provider status — the honest list

Three values are used, and they mean exactly this:

* **Implemented** — a working client exists **and** the default base URL is baked in,
  so `ProviderRegistry::global().get(id)` plus a credential is enough to make a call.
* **EndpointRequired** — the same working client code is reachable, but the frozen
  inventory pins no base URL for this id, so the caller must supply one. This is
  **not** a claim that the id was tested against the live service.
* **RegistrationOnly** — typed metadata only. There is no client; constructing one
  returns `ErrorKind::Unsupported`. These are the ids whose wire protocol is not
  OpenAI-, Anthropic- or Copilot-shaped (Bedrock SigV4, Gemini, Cohere, Azure
  Foundry, media generation) plus `codex` (Responses API) and `vydra`.

Only **three dialect implementations** exist. Every `OpenAiChatCompletions` row shares
`openai_compatible.rs`; `anthropic` uses `anthropic.rs`; `github-copilot` uses
`github_copilot.rs`. `capabilities` is empty for, and only for, the `RegistrationOnly`
rows — the registry test enforces that equivalence in both directions.

| id | display name | family | status | client | auth modes | default base URL |
| --- | --- | --- | --- | --- | --- | --- |
| `amazon-bedrock` | Amazon Bedrock | AmazonBedrock | RegistrationOnly | none | `AwsSigV4` | — |
| `amazon-bedrock-mantle` | Amazon Bedrock (Mantle) | AmazonBedrock | RegistrationOnly | none | `AwsSigV4` | — |
| `anthropic` | Anthropic | AnthropicMessages | Implemented | `anthropic.rs` | `ApiKey` `OAuthAuthorizationCode` | `https://api.anthropic.com` |
| `anthropic-vertex` | Anthropic on Vertex AI | AnthropicMessages | RegistrationOnly | none | `GoogleServiceAccount` | — |
| `arcee` | Arcee AI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://conductor.arcee.ai/v1` |
| `bailian-token-plan` | Alibaba Bailian (token plan) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `byteplus` | BytePlus ModelArk | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `byteplus-plan` | BytePlus ModelArk (plan) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `cerebras` | Cerebras | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.cerebras.ai/v1` |
| `chutes` | Chutes | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://llm.chutes.ai/v1` |
| `clawrouter` | ClawRouter | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `cloudflare-ai-gateway` | Cloudflare AI Gateway | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `codex` | OpenAI Codex | OpenAiResponses | RegistrationOnly | none | `OAuthAuthorizationCode` `BearerToken` | — |
| `cohere` | Cohere | CohereChat | RegistrationOnly | none | `BearerToken` | — |
| `comfy` | ComfyUI | MediaGeneration | RegistrationOnly | none | `None` | — |
| `copilot-proxy` | Copilot Proxy | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `None` | — |
| `dashscope` | Alibaba Cloud DashScope | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| `deepinfra` | DeepInfra | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.deepinfra.com/v1/openai` |
| `deepseek` | DeepSeek | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.deepseek.com/v1` |
| `fal` | fal.ai | MediaGeneration | RegistrationOnly | none | `ApiKey` | — |
| `featherless` | Featherless AI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.featherless.ai/v1` |
| `fireworks` | Fireworks AI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.fireworks.ai/inference/v1` |
| `github-copilot` | GitHub Copilot | GitHubCopilot | Implemented | `github_copilot.rs` | `OAuthDeviceCode` | `https://api.githubcopilot.com` |
| `gmi` | GMI | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `gmicloud` | GMI Cloud (legacy alias) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `gmi-cloud` | GMI Cloud | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `google` | Google Gemini | GoogleGemini | RegistrationOnly | none | `ApiKey` | — |
| `google-gemini-cli` | Google Gemini CLI | GoogleGemini | RegistrationOnly | none | `OAuthAuthorizationCode` | — |
| `google-vertex` | Google Vertex AI | GoogleGemini | RegistrationOnly | none | `GoogleServiceAccount` | — |
| `groq` | Groq | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.groq.com/openai/v1` |
| `huggingface` | Hugging Face Inference Providers | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://router.huggingface.co/v1` |
| `kilocode` | Kilo Code | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `kimi` | Kimi | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `kimi-coding` | Kimi for Coding | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `litellm` | LiteLLM Proxy | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` `None` | `http://127.0.0.1:4000/v1` |
| `lmstudio` | LM Studio | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `None` | `http://127.0.0.1:1234/v1` |
| `longcat` | LongCat | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `meta` | Meta Llama API | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `microsoft-foundry` | Microsoft AI Foundry | AzureFoundry | RegistrationOnly | none | `AzureIdentity` `ApiKey` | — |
| `minimax` | MiniMax | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `minimax-portal` | MiniMax Portal | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `mistral` | Mistral AI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.mistral.ai/v1` |
| `modelstudio` | Alibaba Cloud Model Studio | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` |
| `moonshot` | Moonshot AI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.moonshot.ai/v1` |
| `novita` | Novita AI | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `novitaai` | Novita AI (legacy alias) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `novita-ai` | Novita AI (alias) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `nvidia` | NVIDIA NIM | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://integrate.api.nvidia.com/v1` |
| `ollama` | Ollama | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `None` | `http://127.0.0.1:11434/v1` |
| `ollama-cloud` | Ollama Cloud | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `openai` | OpenAI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.openai.com/v1` |
| `opencode` | OpenCode | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `opencode-go` | OpenCode Go | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `openrouter` | OpenRouter | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://openrouter.ai/api/v1` |
| `qianfan` | Baidu AI Cloud Qianfan | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `qwen` | Alibaba Qwen | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `qwen-cli` | Alibaba Qwen CLI | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `OAuthAuthorizationCode` | — |
| `qwencloud` | Alibaba Qwen Cloud | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `qwen-oauth` | Alibaba Qwen (OAuth) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `OAuthAuthorizationCode` | — |
| `qwen-portal` | Alibaba Qwen Portal | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `OAuthAuthorizationCode` | — |
| `qwen-token-plan` | Alibaba Qwen (token plan) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `sglang` | SGLang | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `None` | `http://127.0.0.1:30000/v1` |
| `stepfun` | StepFun | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `stepfun-plan` | StepFun (plan) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `synthetic` | Synthetic | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `tencent-tokenhub` | Tencent Cloud TokenHub | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `tencent-tokenplan` | Tencent Cloud (token plan) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `together` | Together AI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.together.xyz/v1` |
| `venice` | Venice AI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.venice.ai/api/v1` |
| `vercel-ai-gateway` | Vercel AI Gateway | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://ai-gateway.vercel.sh/v1` |
| `vllm` | vLLM | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `None` | `http://127.0.0.1:8000/v1` |
| `volcengine` | Volcengine Ark | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://ark.cn-beijing.volces.com/api/v3` |
| `volcengine-plan` | Volcengine Ark (plan) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `vydra` | Vydra | Unclassified | RegistrationOnly | none | `BearerToken` | — |
| `xai` | xAI | OpenAiChatCompletions | Implemented | `openai_compatible.rs` | `BearerToken` | `https://api.x.ai/v1` |
| `xiaomi` | Xiaomi MiMo | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `xiaomi-token-plan` | Xiaomi MiMo (token plan) | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |
| `zai` | Z.ai | OpenAiChatCompletions | EndpointRequired | `openai_compatible.rs` | `BearerToken` | — |

### Summary

| status | count | meaning |
| --- | ---: | --- |
| Implemented | 28 | client + pinned default endpoint |
| EndpointRequired | 38 | client reachable, caller supplies the base URL |
| RegistrationOnly | 12 | typed metadata only, no client |
| **total** | **78** | equal to the frozen inventory |

The `RegistrationOnly` twelve, spelled out so nothing is implied by omission:
`amazon-bedrock`, `amazon-bedrock-mantle`, `anthropic-vertex`, `codex`, `cohere`,
`comfy`, `fal`, `google`, `google-gemini-cli`, `google-vertex`, `microsoft-foundry`,
`vydra`.

The `Implemented` twenty-eight: `anthropic`, `arcee`, `cerebras`, `chutes`,
`dashscope`, `deepinfra`, `deepseek`, `featherless`, `fireworks`, `github-copilot`,
`groq`, `huggingface`, `litellm`, `lmstudio`, `mistral`, `modelstudio`, `moonshot`,
`nvidia`, `ollama`, `openai`, `openrouter`, `sglang`, `together`, `venice`,
`vercel-ai-gateway`, `vllm`, `volcengine`, `xai`.

## GitHub Copilot

Pure Rust. No `github-copilot-sdk`, no Copilot CLI, no Node. Neither is reachable
from the workspace dependency graph.

* RFC 8628 device authorization grant against `https://github.com/login/device/code`
  and `https://github.com/login/oauth/access_token` over `reqwest` + rustls.
* `authorization_pending`, `slow_down` (the interval increment is applied),
  `expired_token`, `access_denied`, `incorrect_device_code` and `unsupported_grant_type`
  decode into typed outcomes, not strings.
* The GitHub token is exchanged at `https://api.github.com/copilot_internal/v2/token`
  for a short-lived Copilot token, cached behind an `RwLock` and refreshed 120 s
  before expiry. `wire.rs` proves the exchange happens once across two calls and again
  after expiry, using a `ManualClock`.
* Chat is the Copilot chat-completions dialect at `https://api.githubcopilot.com`
  (or the endpoint the token nominates) with `Copilot-Integration-Id`,
  `Editor-Version`, `Editor-Plugin-Version` and `Copilot-Vision-Request`, which is
  sent only when the prompt carries an image.

## Secret handling

* `SecretString` has a manual `Debug` printing `SecretString(<redacted>)`, a `Display`
  printing `<redacted>`, no `Serialize`, and zeroizes its buffer on drop.
* `HttpRequest`'s manual `Debug` renders the nine `SENSITIVE_HEADERS` values as
  `<redacted>` and prints only the body length, never the body — so a device-code form
  body never appears in a log line either.
* `replace_header` drops any earlier header of the same name including a secret one,
  so narrowing `Accept` for a stream cannot accidentally duplicate or resurrect a
  credential header.
* Wire tests assert that a 401/403/500 error rendered through both `Debug` and
  `Display` contains no substring of the key that was sent.

Proving tests: `secret.rs::debug_and_display_never_reveal_a_secret`,
`secret.rs` redaction tests, `http.rs::requests_redact_credential_headers_in_debug_output`,
`http.rs::replacing_a_header_also_drops_a_secret_of_the_same_name`,
`openai_compatible.rs::the_authorization_header_is_redacted_in_debug_output`,
`github_copilot.rs::a_granted_token_is_not_printed_by_debug`,
`github_copilot.rs::a_device_authorization_decodes_and_hides_the_device_code`,
`wire.rs::a_failing_call_never_reveals_the_api_key`,
`wire.rs::an_anthropic_overload_is_retried_and_the_key_never_leaks`,
`wire.rs::a_failed_copilot_token_exchange_is_typed_and_leaks_nothing`.

## Tests

376 tests, none of which touch a third-party network. Every HTTP test runs against a
loopback `tokio` HTTP/1.1 server in `tests/support/mod.rs` that records the exact
request line, headers and body it received, and that can be told to close the
connection early, stall, or emit a specific chunk sequence.

| Suite | Tests |
| --- | ---: |
| `claw-provider-sdk` unit | 140 |
| `claw-provider-sdk` `tests/secret_transactions.rs` | 27 |
| `claw-provider-sdk` `tests/transport.rs` | 20 |
| `claw-providers` unit | 134 |
| `claw-providers` `tests/frozen_inventory.rs` | 6 |
| `claw-providers` `tests/registry_contract.rs` | 12 |
| `claw-providers` `tests/security.rs` | 14 |
| `claw-providers` `tests/wire.rs` | 23 |
| **total** | **376** |

One `#[ignore]` remains, in `tests/secret_transactions.rs`; it predates this row and
is not part of its evidence. Nothing added for this row is ignored.

### The five required dimensions

Each of these reads `compat/upstream/inventories/providers.json` at run time and
iterates it item by item, so a missing row and a surplus row both fail.

| Dimension | Test in `crates/claw-providers/tests/registry_contract.rs` |
| --- | --- |
| IDs | `every_frozen_identifier_resolves_canonically_and_near_misses_do_not` |
| aliases | `no_frozen_identifier_may_be_registered_as_an_alias`, `the_builtin_alias_table_only_names_frozen_identifiers`, `separator_folding_would_merge_distinct_frozen_rows` |
| configuration | `every_frozen_provider_is_configurable_exactly_as_its_status_allows`, `every_frozen_provider_configuration_rejects_an_unknown_field`, `the_configuration_fixture_corpus_is_classified_exactly` |
| auth | `every_frozen_provider_accepts_exactly_its_declared_auth_modes`, `every_frozen_provider_rejects_a_blank_credential_in_every_secret_bearing_mode` |
| capability routing | `capability_routing_serves_every_client_bearing_frozen_provider`, `capability_routing_finds_nothing_when_no_configured_provider_qualifies`, `the_capability_catalogue_covers_the_frozen_inventory_exactly` |

`tests/fixtures/provider-configs.json` holds the 34-case configuration and
credential corpus. Each case names a stable machine-readable error code rather
than a message, so a wording change cannot silently turn a refusal into an
acceptance, and `the_configuration_fixture_corpus_is_classified_exactly`
additionally asserts set equality between the codes the corpus exercises and
`ConfigError::ALL_CODES` — which the unit test `every_refusal_code_appears_in_all_codes`
holds equal to an exhaustive `match` over both error enums. Adding a refusal path
therefore fails a test until a fixture case pins its behaviour.

The suite was mutation-checked rather than merely run. Folding `-` in
`alias::normalize` turns 8 of the 12 red; deleting `deny_unknown_fields` from
`ProviderConfig` turns 2 red; inserting one fabricated row into the descriptor
table turns 3 of the 12 and 5 of the 6 `frozen_inventory.rs` tests red.

The specific classes the brief called for:

* **Frozen-inventory equality** — `frozen_inventory.rs` parses
  `compat/upstream/inventories/providers.json` at runtime and compares it to the
  registry in both directions: no missing ids, no extra ids, `record_id` /
  `plugin_id` / `source_path` / `classification` equal field by field, and the
  declared counts equal. The expected value is the file, never the code under test.
* **Streaming decode against recorded bytes** — SSE fixtures are byte literals fed to
  the decoder as chunks. `every_chunk_boundary_yields_the_same_events` (SDK),
  `every_chunk_split_of_a_recorded_stream_yields_identical_events` (OpenAI and
  Anthropic) re-run each fixture at *every* possible split point and require an
  identical event sequence. `crlf_split_across_chunks_is_one_terminator` and
  `multi_byte_code_points_split_across_chunks_decode_correctly` cover the adversarial
  boundaries specifically.
* **Cancellation asserts the socket actually closed** — the test server records
  `peer_closed`. `cancelling_an_openai_stream_closes_the_socket_and_stops_events`,
  `dropping_an_openai_stream_cancels_it_and_closes_the_socket`,
  `cancelling_an_anthropic_stream_closes_the_socket` and the two SDK transport
  cancellation tests all await that flag rather than inferring closure from the
  client side.
* **Retry/backoff with a fake clock** — `ManualClock` records every requested sleep.
  `exponential_backoff_grows_and_then_gives_up` asserts the exact recorded sleep
  sequence, and `a_rate_limited_call_waits_exactly_the_retry_after_interval` asserts
  the `Retry-After` value was used verbatim. `FixedJitter` makes the sequence
  deterministic.
* **Secret redaction** — listed above.

No test uses a `{ .. }` wildcard pattern assertion, no test asserts only a substring
of a value it could have compared exactly, and no test constructs its expected value
by calling the production function under test.

## Known limitations — read these

1. **The frozen ledger row is unchanged.** `compat/upstream/**` is byte-identical to
   `main`. See the first section for why.
2. **48 of 78 ids have no pinned endpoint.** 38 `EndpointRequired` ids reach real
   client code but the caller must supply the base URL; 12 `RegistrationOnly` ids have
   no client at all.
3. **No live-service verification of any provider.** Every test runs against a local
   loopback server replaying fixtures. The wire *shape* is verified; that a given
   vendor accepts that shape today is not.
4. **The `Implemented` base URLs come from vendor documentation, not from probing.**
   `arcee`, `chutes`, `featherless`, `venice`, `deepinfra` and `modelstudio` are the
   least certain. If one is wrong the fix is a one-line table change plus a test.
5. **The test server is plaintext HTTP on loopback.** There is no in-process TLS test
   server, so the rustls path is exercised by the type system and `cargo deny`, not by
   an integration test. Loopback plaintext is gated behind an explicit
   `TlsPolicy::AllowLoopbackPlaintext`; the default is `RequireHttps` and
   `plaintext_to_a_routable_address_is_refused` plus
   `plaintext_to_loopback_is_refused_under_the_default_policy` assert both halves.
6. **Native secret stores are not integration-tested.** The Windows Credential Manager
   and macOS Keychain adapters are thin `keyring-core` bindings compiled under
   `#[cfg(target_os = …)]`; only the in-memory and permission-strict file stores are
   exercised by tests. The file store's permission checks are meaningful only on Unix.
7. **`list_models` metadata is thin for two of the three dialects.** OpenAI's and
   Anthropic's catalogue endpoints return little beyond ids, so
   `ModelInfo::context_window` and pricing stay `None` there. Copilot's `/models`
   does carry limits and capability flags, and those are decoded.
8. **Anthropic has no embeddings.** `Anthropic::embed` returns `ErrorKind::Unsupported`
   rather than silently proxying to a third party, and the descriptor does not
   advertise the capability.
9. **`ResponseFormat::JsonObject` is rejected on Anthropic** with
   `ErrorKind::Unsupported` instead of being silently dropped, because the Messages API
   has no equivalent knob. Structured output there needs a tool.
10. **Copilot client identity is best-effort.** The default client id, integration id
    and editor-version strings mirror what the public editor clients send. They are
    configurable, but GitHub may reject an unknown integration id and no offline test
    can detect that.
11. **`Quota` vs `RateLimit` is a heuristic** for providers that return 429 for both.
    The upstream code is preserved on the error so callers can disambiguate.
12. **No HTTP/2.** `reqwest`'s `http2` feature is deliberately off, as are its default
    features: `charset` pulls `encoding_rs`, which is MPL-2.0 and outside the
    `deny.toml` licence allowlist.
13. **The SDK owns no tracing/logging integration.** Redaction is enforced at the type
    level (`SecretString`, the manual `Debug` impls); there is no log sink to
    intercept, so a caller that calls `.expose()` and logs the result can still leak.
    That is deliberate — `expose()` is the single audited chokepoint.
14. **Auth stops at credential admissibility.** `auth.rs` decides whether a credential
    shape is one the provider declares and whether the secret is present; it does not
    perform an OAuth device-code or authorization-code exchange, sign an AWS SigV4
    request, mint a Google service-account assertion, or acquire an Azure identity
    token. Those flows are live-network work and are out of scope for this row, which
    is why the `auth` dimension is recorded as `implemented_partial`.
15. **The 35 built-in aliases are GTA-Claw's, not upstream's.** The frozen inventory
    publishes identifiers only; it declares no aliases. The built-in table is a
    convenience layer, and the tests prove only that it is internally consistent with
    the inventory — never that upstream would accept the same spellings.
