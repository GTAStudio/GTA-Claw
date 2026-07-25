//! Native, declarative HTTP, Wasm, and parameter-validation execution tests.

use std::cell::RefCell;
use std::collections::BTreeMap;

use claw_skills::{
    HttpBridge, HttpBridgeError, HttpRequest, HttpResponse, NativeSkillHandler,
    NativeSkillRegistry, ParameterValidationError, ParameterViolation, ParameterViolationKind,
    SkillExecutionError, SkillRuntime, WasmHostError, WasmSkillHost, load_manifest,
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
    fn invoke(
        &self,
        plugin_id: &str,
        export: &str,
        parameters: Value,
    ) -> Result<Value, WasmHostError> {
        self.calls
            .borrow_mut()
            .push((plugin_id.to_owned(), export.to_owned(), parameters));
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
    let (mut native, http, wasm) = ports();
    assert_eq!(native.register("echo", Echo), Ok(()));
    let runtime = SkillRuntime::new(&native, &http, &wasm);
    assert_eq!(
        runtime.execute(&manifest, json!({"message":"hello"})),
        Ok(json!({"message":"hello"}))
    );
    assert_eq!(
        runtime.execute(&manifest, json!({"extra":true})),
        Err(SkillExecutionError::InvalidParameters(
            ParameterValidationError::Violations(vec![
                ParameterViolation {
                    path: "$.message".to_owned(),
                    kind: ParameterViolationKind::MissingRequiredProperty,
                },
                ParameterViolation {
                    path: "$.extra".to_owned(),
                    kind: ParameterViolationKind::AdditionalProperty,
                },
            ])
        ))
    );
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
    let (native, http, wasm) = ports();
    let runtime = SkillRuntime::new(&native, &http, &wasm);
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
    let (native, http, wasm) = ports();
    let runtime = SkillRuntime::new(&native, &http, &wasm);
    assert_eq!(
        runtime.execute(&manifest, json!([1, 2])),
        Ok(json!({"sandboxed":true}))
    );
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
    assert_eq!(
        load_manifest(javascript_manifest),
        Err(claw_skills::ManifestError::MalformedJson)
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
    let (native, http, wasm) = ports();
    let runtime = SkillRuntime::new(&native, &http, &wasm);
    assert_eq!(
        runtime.execute(&manifest, json!({"q":"rust skills"})),
        Ok(json!({"status":"ok"}))
    );
    assert_eq!(
        http.requests.into_inner(),
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
