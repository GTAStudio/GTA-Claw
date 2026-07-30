//! Native, declarative HTTP, Wasm, and parameter-validation execution tests.

use std::cell::RefCell;
use std::collections::BTreeMap;

use claw_skills::{
    CancellationToken, ExactJsonDocument, HttpBridge, HttpBridgeError, HttpRequest, HttpResponse,
    ManifestError, NativeSkillHandler, NativeSkillRegistry, ParameterValidationError,
    ParameterViolation, ParameterViolationKind, SchemaErrorKind, SkillExecutionError, SkillRuntime,
    WasmHostError, WasmSkillHost, WasmSkillInvocation, load_manifest,
};
use serde_json::{Value, json};

struct Echo;

impl NativeSkillHandler for Echo {
    fn execute(&self, parameters: Value) -> Result<Value, SkillExecutionError> {
        Ok(parameters)
    }
}

#[derive(Default)]
struct CapturingHttp {
    requests: RefCell<Vec<HttpRequest>>,
}

impl HttpBridge for CapturingHttp {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpBridgeError> {
        self.requests.borrow_mut().push(request);
        Ok(HttpResponse {
            status: 200,
            body: br#"{"status":"ok"}"#.to_vec(),
        })
    }
}

#[derive(Default)]
struct CapturingWasm {
    calls: RefCell<Vec<(String, String, Value)>>,
}

impl WasmSkillHost for CapturingWasm {
    fn invoke(&mut self, invocation: WasmSkillInvocation<'_>) -> Result<Value, WasmHostError> {
        self.calls.borrow_mut().push((
            invocation.plugin_id.to_owned(),
            invocation.tool.to_owned(),
            invocation.parameters,
        ));
        Ok(json!({"sandboxed": true}))
    }
}

fn ports() -> (NativeSkillRegistry, CapturingHttp, CapturingWasm) {
    (
        NativeSkillRegistry::new(),
        CapturingHttp::default(),
        CapturingWasm::default(),
    )
}

#[test]
fn native_handler_runs_only_after_exact_parameter_validation() {
    let manifest = load_manifest(
        r#"{
            "id":"native-echo",
            "description":"Echo validated input.",
            "parameters":{
                "type":"object",
                "properties":{"message":{"type":"string","minLength":1}},
                "required":["message"],
                "additionalProperties":false
            },
            "execution":{"kind":"native","handler":"echo"}
        }"#,
    )
    .expect("valid native manifest");
    let (mut native, http, mut wasm) = ports();
    assert_eq!(native.register("echo", Echo), Ok(()));
    let mut runtime = SkillRuntime::new(&native, &http, &mut wasm);
    assert_eq!(
        runtime.execute(&manifest, json!({"message":"hello"})),
        Ok(json!({"message":"hello"}))
    );
    assert_eq!(
        runtime.execute(&manifest, json!({"extra":true})),
        Err(SkillExecutionError::InvalidParameters(
            ParameterValidationError::Violations {
                violations: vec![
                    ParameterViolation {
                        path: "$.message".to_owned(),
                        kind: ParameterViolationKind::MissingRequiredProperty,
                    },
                    ParameterViolation {
                        path: "$.extra".to_owned(),
                        kind: ParameterViolationKind::AdditionalProperty,
                    },
                ],
                limit_reached: false,
            }
        ))
    );
}

#[test]
fn manifest_rejects_unrepresentable_exact_length_bounds() {
    let error = load_manifest(
        r#"{
            "id":"invalid-length",
            "description":"Reject an unusable exact length.",
            "parameters":{"type":"string","minLength":18446744073709551616},
            "execution":{"kind":"native","handler":"echo"}
        }"#,
    )
    .expect_err("the exact bound does not fit the supported length representation");
    assert!(matches!(
        error,
        ManifestError::InvalidParameterSchema(schema)
            if schema.path == "$.minLength"
                && schema.kind == SchemaErrorKind::InvalidLengthBound
    ));
}

#[test]
fn manifest_schema_preflight_rejects_limits_before_exact_tree_construction() {
    let wide_enum = std::iter::repeat_n("0", 4_096)
        .collect::<Vec<_>>()
        .join(",");
    let wide_manifest = format!(
        r#"{{
            "id":"wide-schema",
            "description":"Reject before cloning a wide schema.",
            "parameters":{{"enum":[{wide_enum}]}},
            "execution":{{"kind":"native","handler":"echo"}}
        }}"#
    );
    assert!(matches!(
        load_manifest(&wide_manifest),
        Err(ManifestError::InvalidParameterSchema(error))
            if error.kind == SchemaErrorKind::ResourceLimit
    ));

    let mut deep_schema = "{}".to_owned();
    for _ in 0..64 {
        deep_schema = format!(r#"{{"type":"array","items":{deep_schema}}}"#);
    }
    let deep_manifest = format!(
        r#"{{
            "id":"deep-schema",
            "description":"Reject before recursively cloning a deep schema.",
            "parameters":{deep_schema},
            "execution":{{"kind":"native","handler":"echo"}}
        }}"#
    );
    assert!(matches!(
        load_manifest(&deep_manifest),
        Err(ManifestError::InvalidParameterSchema(error))
            if error.kind == SchemaErrorKind::ResourceLimit
    ));

    let long_name = "x".repeat(1_024);
    let long_path_manifest = format!(
        r#"{{
            "id":"long-schema-path",
            "description":"Reject before allocating an overlong schema path.",
            "parameters":{{"type":"object","properties":{{"{long_name}":{{}}}}}},
            "execution":{{"kind":"native","handler":"echo"}}
        }}"#
    );
    assert!(matches!(
        load_manifest(&long_path_manifest),
        Err(ManifestError::InvalidParameterSchema(error))
            if error.kind == SchemaErrorKind::ResourceLimit
                && error.path == "$"
    ));

    let huge_number = "9".repeat(4_097);
    let huge_number_manifest = format!(
        r#"{{
            "id":"huge-schema-number",
            "description":"Reject an over-budget numeric lexeme before exact parsing.",
            "parameters":{{"minimum":{huge_number}}},
            "execution":{{"kind":"native","handler":"echo"}}
        }}"#
    );
    assert!(matches!(
        load_manifest(&huge_number_manifest),
        Err(ManifestError::InvalidParameterSchema(error))
            if error.kind == SchemaErrorKind::ResourceLimit
    ));
}

#[test]
fn manifest_schema_preflight_rejects_unpaired_surrogate_escapes_without_panicking() {
    for escaped in [r"\ud800", r"\udc00", r"\ud800x", r"\ud800\u0041"] {
        let manifest = format!(
            r#"{{
                "id":"invalid-surrogate",
                "description":"Reject malformed Unicode.",
                "parameters":{{"description":"{escaped}"}},
                "execution":{{"kind":"native","handler":"echo"}}
            }}"#
        );
        assert!(
            matches!(
                load_manifest(&manifest),
                Err(ManifestError::MalformedJson { .. })
            ),
            "escape {escaped} must be rejected as malformed JSON"
        );
    }
}

#[test]
fn exact_parameters_validate_and_encode_without_rounding() {
    let manifest = load_manifest(
        r#"{
            "id":"exact-http",
            "description":"Validate and forward an exact decimal.",
            "parameters":{
                "type":"object",
                "properties":{"value":{"type":"number","minimum":9007199254740993.0}},
                "required":["value"],
                "additionalProperties":false
            },
            "execution":{
                "kind":"http",
                "request":{
                    "method":"POST",
                    "url":"https://example.test/exact",
                    "response":"json"
                }
            }
        }"#,
    )
    .expect("valid exact-number manifest");
    assert_eq!(
        manifest
            .parameters()
            .to_json_vec()
            .expect("serialize the public exact schema"),
        br#"{"type":"object","properties":{"value":{"type":"number","minimum":9007199254740993.0}},"required":["value"],"additionalProperties":false}"#
    );
    assert!(
        manifest.parameters().value().is_none(),
        "the public schema must not expose a rounded serde_json::Value"
    );
    let public_debug = format!("{:?}", manifest.parameters());
    assert!(public_debug.contains("9007199254740993.0"));
    assert!(!public_debug.contains("Number(0)"));
    let native_manifest = load_manifest(
        r#"{
            "id":"exact-native",
            "description":"Refuse lossy conversion to a native handler.",
            "parameters":{"type":"number"},
            "execution":{"kind":"native","handler":"echo"}
        }"#,
    )
    .expect("valid native manifest");
    let (mut native, http, mut wasm) = ports();
    assert_eq!(native.register("echo", Echo), Ok(()));
    {
        let mut runtime = SkillRuntime::new(&native, &http, &mut wasm);
        assert_eq!(
            runtime.execute_exact(
                &manifest,
                ExactJsonDocument::parse(r#"{"value":9007199254740992.9}"#).expect("valid input")
            ),
            Err(SkillExecutionError::InvalidParameters(
                ParameterValidationError::Violations {
                    violations: vec![ParameterViolation {
                        path: "$.value".to_owned(),
                        kind: ParameterViolationKind::NumberTooSmall,
                    }],
                    limit_reached: false,
                }
            ))
        );
        assert_eq!(
            runtime.execute_exact(
                &manifest,
                ExactJsonDocument::parse(r#"{"value":9007199254740993.1}"#).expect("valid input")
            ),
            Ok(json!({"status":"ok"}))
        );
        assert_eq!(
            runtime.execute_exact(
                &manifest,
                ExactJsonDocument::parse(r#"{"value":1,"value":9007199254740993.2}"#)
                    .expect("valid duplicate-key input")
            ),
            Ok(json!({"status":"ok"}))
        );
        assert_eq!(
            runtime.execute_exact(
                &native_manifest,
                ExactJsonDocument::parse("9007199254740993.1").expect("valid input")
            ),
            Err(SkillExecutionError::ParameterEncoding)
        );
    }
    let requests = http.requests.into_inner();
    assert_eq!(requests[0].body, br#"{"value":9007199254740993.1}"#);
    assert_eq!(requests[1].body, br#"{"value":9007199254740993.2}"#);
}

#[test]
fn declarative_http_bridge_receives_exact_request_and_decodes_json() {
    let manifest = load_manifest(
        r#"{
            "id":"fixture-status",
            "description":"Fetch fixture status.",
            "parameters":{"type":"object","additionalProperties":false},
            "execution":{
                "kind":"http",
                "request":{
                    "method":"POST",
                    "url":"http://127.0.0.1:9000/status",
                    "headers":{"x-client":"gta-claw"},
                    "response":"json"
                }
            }
        }"#,
    )
    .expect("valid HTTP manifest");
    let (native, http, mut wasm) = ports();
    let mut runtime = SkillRuntime::new(&native, &http, &mut wasm);
    assert_eq!(
        runtime.execute(&manifest, json!({})),
        Ok(json!({"status":"ok"}))
    );
    assert_eq!(
        http.requests.into_inner(),
        vec![HttpRequest {
            method: claw_skills::HttpMethod::Post,
            url: "http://127.0.0.1:9000/status".to_owned(),
            headers: BTreeMap::from([
                ("content-type".to_owned(), "application/json".to_owned()),
                ("x-client".to_owned(), "gta-claw".to_owned()),
            ]),
            body: b"{}".to_vec(),
        }]
    );
}

#[test]
fn wasm_execution_is_delegated_to_the_sandbox_host_port() {
    let manifest = load_manifest(
        r#"{
            "id":"wasm-example",
            "description":"Invoke a sandboxed component.",
            "parameters":{"type":"array","items":{"type":"integer"}},
            "execution":{"kind":"wasm","plugin_id":"fixture-plugin","export":"run"}
        }"#,
    )
    .expect("valid Wasm manifest");
    let (native, http, mut wasm) = ports();
    {
        let mut runtime = SkillRuntime::new(&native, &http, &mut wasm);
        assert_eq!(
            runtime.execute(&manifest, json!([1, 2])),
            Ok(json!({"sandboxed":true}))
        );
    }
    assert_eq!(
        wasm.calls.into_inner(),
        vec![("fixture-plugin".to_owned(), "run".to_owned(), json!([1, 2]))]
    );
}

#[test]
fn javascript_execution_kind_is_not_representable() {
    let javascript_manifest = r#"{
        "id":"unsafe",
        "description":"Must fail.",
        "parameters":{"type":"object"},
        "execution":{"kind":"javascript","source":"return true"}
    }"#;
    let error = load_manifest(javascript_manifest).expect_err("JavaScript is not representable");
    assert!(
        matches!(error, ManifestError::MalformedJson { .. }),
        "unexpected diagnostic: {error}"
    );
    assert!(
        error.to_string().contains("unknown variant `javascript`"),
        "diagnostic should name the unsupported kind: {error}"
    );
}

#[test]
fn get_parameters_are_percent_encoded_in_an_explicit_query_parameter() {
    let manifest = load_manifest(
        r#"{
            "id":"query-example",
            "description":"Send encoded query input.",
            "parameters":{"type":"object","properties":{"q":{"type":"string"}}},
            "execution":{
                "kind":"http",
                "request":{
                    "method":"GET",
                    "url":"https://example.test/search?fixed=true",
                    "parameters":{"kind":"query_parameter","name":"input"},
                    "response":"json"
                }
            }
        }"#,
    )
    .expect("valid query manifest");
    let (native, http, mut wasm) = ports();
    let mut runtime = SkillRuntime::new(&native, &http, &mut wasm);
    assert_eq!(
        runtime.execute(&manifest, json!({"q":"rust skills"})),
        Ok(json!({"status":"ok"}))
    );
    let requests = http.requests.into_inner();
    assert_eq!(
        requests[0].url,
        "https://example.test/search?fixed=true&input=%7B%22q%22%3A%22rust%20skills%22%7D"
    );
    assert_eq!(
        requests,
        vec![HttpRequest {
            method: claw_skills::HttpMethod::Get,
            url: "https://example.test/search?fixed=true&input=%7B%22q%22%3A%22rust%20skills%22%7D"
                .to_owned(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }]
    );
}

#[test]
fn query_parameters_are_inserted_before_a_url_fragment() {
    let manifest = load_manifest(
        r#"{
            "id":"http-fragment",
            "description":"Append input without moving the fragment.",
            "parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]},
            "execution":{
                "kind":"http",
                "request":{
                    "method":"GET",
                    "url":"https://example.test/search?lang=en#results",
                    "parameters":{"kind":"query_parameter","name":"input"},
                    "response":"json"
                }
            }
        }"#,
    )
    .expect("valid HTTP manifest");
    let (native, http, mut wasm) = ports();

    let output = SkillRuntime::new(&native, &http, &mut wasm)
        .execute(&manifest, json!({"query":"a&b"}))
        .expect("execute");
    assert_eq!(output, json!({"status":"ok"}));
    let calls = http.requests.into_inner();
    assert_eq!(
        calls[0].url,
        "https://example.test/search?lang=en&input=%7B%22query%22%3A%22a%26b%22%7D#results"
    );
}

#[test]
fn an_empty_existing_query_does_not_add_a_leading_ampersand() {
    let manifest = load_manifest(
        r#"{
            "id":"http-empty-query",
            "description":"Append input to an empty query.",
            "parameters":{"type":"object","additionalProperties":false},
            "execution":{
                "kind":"http",
                "request":{
                    "method":"GET",
                    "url":"https://example.test/search?#results",
                    "parameters":{"kind":"query_parameter","name":"input"},
                    "response":"json"
                }
            }
        }"#,
    )
    .expect("valid HTTP manifest");
    let (native, http, mut wasm) = ports();

    SkillRuntime::new(&native, &http, &mut wasm)
        .execute(&manifest, json!({}))
        .expect("execute");

    let calls = http.requests.into_inner();
    assert_eq!(
        calls[0].url,
        "https://example.test/search?input=%7B%7D#results"
    );
    assert!(!calls[0].url.contains("?&"));
}

#[test]
fn every_http_parameter_mode_uses_the_same_canonical_url() {
    let body_manifest = load_manifest(
        r#"{
            "id":"canonical-body",
            "description":"Send a JSON body to a canonical endpoint.",
            "parameters":{"type":"object","additionalProperties":false},
            "execution":{
                "kind":"http",
                "request":{
                    "method":"POST",
                    "url":"HTTPS://Example.TEST:443/old/../status#result",
                    "response":"json"
                }
            }
        }"#,
    )
    .expect("valid body manifest");
    let query_manifest = load_manifest(
        r#"{
            "id":"canonical-query",
            "description":"Send a query parameter to the same canonical endpoint.",
            "parameters":{"type":"object","additionalProperties":false},
            "execution":{
                "kind":"http",
                "request":{
                    "method":"POST",
                    "url":"HTTPS://Example.TEST:443/old/../status#result",
                    "parameters":{"kind":"query_parameter","name":"input"},
                    "response":"json"
                }
            }
        }"#,
    )
    .expect("valid query manifest");
    let (native, http, mut wasm) = ports();
    let mut runtime = SkillRuntime::new(&native, &http, &mut wasm);

    assert_eq!(
        runtime.execute(&body_manifest, json!({})),
        Ok(json!({"status":"ok"}))
    );
    assert_eq!(
        runtime.execute(&query_manifest, json!({})),
        Ok(json!({"status":"ok"}))
    );
    let calls = http.requests.into_inner();
    assert_eq!(calls[0].url, "https://example.test/status#result");
    assert_eq!(
        calls[1].url,
        "https://example.test/status?input=%7B%7D#result"
    );
}

#[test]
fn unknown_manifest_fields_are_rejected_with_source_coordinates() {
    let json = r#"{
        "id":"native-echo",
        "description":"Echo validated input.",
        "parameters":{"type":"object"},
        "execution":{"kind":"native","handler":"echo"},
        "javascript":"forbidden"
    }"#;
    let error = load_manifest(json).expect_err("the manifest model is closed");
    let ManifestError::MalformedJson {
        line,
        column,
        message,
    } = error
    else {
        panic!("expected a JSON diagnostic");
    };
    assert!(line > 0);
    assert!(column > 0);
    assert!(message.contains("unknown field `javascript`"));
}

#[test]
fn unknown_http_parameter_fields_are_rejected() {
    let json = r#"{
        "id":"closed-http-parameters",
        "description":"Reject hidden parameter behavior.",
        "parameters":{"type":"object"},
        "execution":{
            "kind":"http",
            "request":{
                "method":"GET",
                "url":"https://example.test/search",
                "parameters":{"kind":"query_parameter","name":"input","extra":true}
            }
        }
    }"#;

    let error = load_manifest(json).expect_err("HTTP parameter encoding is closed");
    assert!(
        matches!(
            error,
            ManifestError::MalformedJson { ref message, .. }
                if message.contains("unknown field `extra`")
        ),
        "unexpected diagnostic: {error}"
    );
}

#[test]
fn pre_cancelled_execution_never_reaches_a_backend() {
    let manifest = load_manifest(
        r#"{
            "id":"wasm-example",
            "description":"Invoke a sandboxed component.",
            "parameters":{"type":"object","additionalProperties":false},
            "execution":{"kind":"wasm","plugin_id":"fixture-plugin","export":"run"}
        }"#,
    )
    .expect("valid Wasm manifest");
    let (native, http, mut wasm) = ports();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    {
        let mut runtime = SkillRuntime::new(&native, &http, &mut wasm);
        assert_eq!(
            runtime.execute_cancellable(&manifest, json!({}), &cancellation),
            Err(SkillExecutionError::Cancelled)
        );
    }
    assert!(wasm.calls.into_inner().is_empty());
}

#[test]
fn request_debug_redacts_query_values_and_body() {
    let request = HttpRequest {
        method: claw_skills::HttpMethod::Post,
        url: "https://example.test/run?api_key=secret".to_owned(),
        headers: BTreeMap::from([("x-client".to_owned(), "fixture".to_owned())]),
        body: br#"{"password":"secret"}"#.to_vec(),
    };
    assert_eq!(
        format!("{request:?}"),
        "HttpRequest { method: Post, url: \"https://example.test/run?[REDACTED]\", header_names: [\"x-client\"], body: [REDACTED; 21 bytes] }"
    );
}
