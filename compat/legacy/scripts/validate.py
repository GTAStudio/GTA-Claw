#!/usr/bin/env python3

import copy
import glob
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    from jsonschema.validators import validator_for
    from referencing import Registry, Resource
except ImportError as exc:
    raise SystemExit(
        "compat/legacy validation requires Python packages jsonschema and referencing"
    ) from exc


BASE = Path(__file__).resolve().parents[1]
REPO = BASE.parents[1]
DISCOVERY_PATTERNS = (
    ".dockerignore",
    ".env.example",
    ".github/workflows/docker-publish.yml",
    "Dockerfile",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "src/**/*.ts",
    "deploy/run.sh",
    "deploy/conf/gta-claw.conf.example",
    "deploy/conf/claw-steward.json",
    "deploy/conf/skills/*.json",
)
AUDITED_SOURCE_COUNT = 38
AUDITED_SOURCE_CATEGORY_TOTALS = {
    "root": 6,
    "ci": 1,
    "typescript": 18,
    "deployment": 3,
    "bundled_skills": 10,
}
HTTP_ENDPOINT_COUNT = 10
HTTP_CASE_COUNT = 28
# Audited from the pinned TypeScript sources; never populate this from examples.json.
HTTP_CASE_CONTRACTS = {
    ("GET", "/", "unauthenticated-no-channels"): (
        200,
        "object{authenticated:boolean,channels:object{discord:boolean,teams:boolean,"
        "telegram:boolean,whatsapp:boolean},deviceFlowEnabled:boolean,endpoints:"
        "object{chat:string,deviceAuth:string,health:string},examples:object{chatCurl:"
        "string},service:string,status:string,tips:array<string>}",
    ),
    ("GET", "/health", "healthy-unauthenticated"): (
        200,
        "object{authenticated:boolean,channels:object{discord:boolean,teams:boolean,"
        "telegram:boolean,whatsapp:boolean},deviceFlowEnabled:boolean,model:string,"
        "sessions:number,skills:number,status:string,uptime:number}",
    ),
    ("GET", "/auth/device", "already-authenticated"): (
        200,
        "object{authenticated:boolean,message:string}",
    ),
    ("GET", "/auth/device", "disabled"): (
        400,
        "object{authenticated:boolean,error:string}",
    ),
    ("GET", "/auth/device", "instructions"): (
        200,
        "object{auth_instructions:string,authenticated:boolean}",
    ),
    ("GET", "/auth/device", "unexpected-error"): (500, "object{error:string}"),
    ("POST", "/chat", "missing-message"): (400, "object{error:string}"),
    ("POST", "/chat", "help-before-auth"): (200, "object{reply:string}"),
    ("POST", "/chat", "unauthenticated-token-mode"): (
        401,
        "object{error:string}",
    ),
    ("POST", "/chat", "unauthenticated-device-flow"): (
        401,
        "object{auth_instructions:string,error:string}",
    ),
    ("POST", "/chat", "success"): (200, "object{reply:string}"),
    ("POST", "/chat", "endpoint-error"): (500, "object{error:string}"),
    ("POST", "/api/messages", "adapter-ack"): (200, "null"),
    ("POST", "/api/messages", "rate-limited"): (429, "object{error:string}"),
    ("GET", "/whatsapp/webhook", "verified"): (200, "string"),
    ("GET", "/whatsapp/webhook", "forbidden"): (403, "object{error:string}"),
    ("POST", "/whatsapp/webhook", "accepted"): (200, "object{ok:boolean}"),
    ("POST", "/whatsapp/webhook", "handling-failed"): (
        500,
        "object{error:string}",
    ),
    ("POST", "/admin/reload", "forbidden"): (403, "object{error:string}"),
    ("POST", "/admin/reload", "reloaded"): (
        200,
        "object{message:string,model:string,skills:number}",
    ),
    ("POST", "/admin/reload", "conflict"): (409, "object{error:string}"),
    ("POST", "/admin/reload", "failed"): (500, "object{error:string}"),
    ("GET", "/admin/system", "forbidden"): (403, "object{error:string}"),
    ("GET", "/admin/system", "system-info"): (
        200,
        "object{node:object{memory_mb:object{heapTotal:number,heapUsed:number,rss:"
        "number},pid:number,uptime_s:number,version:string},os:object{arch:string,"
        "cpus:number,freeMemory_mb:number,hostname:string,loadavg:array<number>,"
        "platform:string,totalMemory_mb:number,uptime_s:number}}",
    ),
    ("POST", "/admin/exec", "forbidden"): (403, "object{error:string}"),
    ("POST", "/admin/exec", "unknown-action"): (
        400,
        "object{allowed:array<string>,error:string}",
    ),
    ("POST", "/admin/exec", "command-success"): (
        200,
        "object{action:string,output:string,success:boolean}",
    ),
    ("POST", "/admin/exec", "command-failure"): (
        200,
        "object{action:string,error:string,stderr:string,success:boolean}",
    ),
}


class ContractError(Exception):
    pass


def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path.relative_to(REPO)}: {exc}") from exc


def ensure(condition: bool, message: str):
    if not condition:
        raise ContractError(message)


def unique(values, label: str):
    values = list(values)
    ensure(len(values) == len(set(values)), f"duplicate {label}")


def expect_contract_error(label: str, operation, message_contains: str = None):
    try:
        operation()
    except ContractError as exc:
        ensure(
            message_contains is None or message_contains in str(exc),
            f"{label} failed for the wrong reason: {exc}",
        )
        return
    raise ContractError(f"regression self-test did not reject {label}")


def run_git(*args: str, check: bool = True):
    result = subprocess.run(
        ["git", *args],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ContractError(f"git {' '.join(args)} failed: {detail}")
    return result


def schema_registry():
    schemas = {}
    resources = []
    for path in sorted((BASE / "schemas").glob("*.json")):
        schema = load_json(path)
        validator = validator_for(schema)
        validator.check_schema(schema)
        schemas[path.name] = schema
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return schemas, Registry().with_resources(resources)


def validate_fixtures(schemas, registry):
    index = load_json(BASE / "fixtures" / "index.json")
    fixtures = index.get("fixtures")
    ensure(isinstance(fixtures, list), "fixtures/index.json must contain fixtures array")
    paths = [entry.get("path") for entry in fixtures]
    unique(paths, "fixture index path")

    indexed_data = set(paths)
    actual_data = {
        path.relative_to(BASE).as_posix()
        for path in BASE.rglob("*.json")
        if "schemas" not in path.parts
        and path != BASE / "fixtures" / "index.json"
    }
    ensure(
        indexed_data == actual_data,
        "fixture index mismatch: "
        f"missing={sorted(actual_data - indexed_data)}, "
        f"extra={sorted(indexed_data - actual_data)}",
    )

    valid_count = 0
    invalid_count = 0
    for entry in fixtures:
        path = BASE / entry["path"]
        schema_name = Path(entry["schema"]).name
        ensure(schema_name in schemas, f"unknown schema for {entry['path']}")
        instance = load_json(path)
        schema = schemas[schema_name]
        validator = validator_for(schema)(schema, registry=registry)
        errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
        expected = entry.get("expected")
        ensure(expected in {"valid", "invalid"}, f"invalid expectation for {entry['path']}")
        if expected == "valid":
            ensure(
                not errors,
                f"{entry['path']} should be valid: "
                + "; ".join(error.message for error in errors[:3]),
            )
            valid_count += 1
        else:
            ensure(errors, f"{entry['path']} should be schema-invalid")
            invalid_count += 1
    return valid_count, invalid_count


def validate_revision(contract, *documents):
    revision = contract["source_revision"]
    ensure(
        run_git("cat-file", "-e", f"{revision}^{{commit}}", check=False).returncode == 0,
        f"source revision does not exist: {revision}",
    )
    for name, document in documents:
        ensure(
            document["source_revision"] == revision,
            f"{name} source_revision does not match contract",
        )


def validate_source_reference(reference, covered_paths):
    path_text = reference["path"]
    ensure(path_text in covered_paths, f"uncovered source reference: {path_text}")
    path = REPO / path_text
    ensure(path.is_file(), f"missing source file: {path_text}")
    lines = path.read_text(encoding="utf-8").splitlines()
    line_count = len(lines)
    start = reference["line_start"]
    end = reference["line_end"]
    ensure(start <= end, f"invalid source range {path_text}:{start}-{end}")
    ensure(end <= line_count, f"source range exceeds {path_text} line count {line_count}")
    meaningful = any(
        re.search(r"[A-Za-z0-9]", stripped)
        and not stripped.startswith(("//", "#", "/*", "*", "*/"))
        for stripped in (line.strip() for line in lines[start - 1:end])
    )
    ensure(meaningful, f"source range has no meaningful content: {path_text}:{start}-{end}")


def source_category(path: str):
    if path.startswith("deploy/conf/skills/"):
        return "bundled_skills"
    if path.startswith("src/"):
        return "typescript"
    if path.startswith("deploy/"):
        return "deployment"
    if path.startswith(".github/"):
        return "ci"
    return "root"


def validate_coverage_definition(coverage):
    include = coverage["discovery"]["include"]
    ensure(
        include == list(DISCOVERY_PATTERNS),
        "source discovery rules differ from the canonical validator rules",
    )

    audited = coverage["audited_sources"]
    ensure(
        len(audited) == AUDITED_SOURCE_COUNT,
        f"expected {AUDITED_SOURCE_COUNT} audited sources, found {len(audited)}",
    )
    category_totals = Counter(source_category(entry["path"]) for entry in audited)
    ensure(
        dict(category_totals) == AUDITED_SOURCE_CATEGORY_TOTALS,
        "audited source category totals mismatch: "
        f"expected={AUDITED_SOURCE_CATEGORY_TOTALS}, actual={dict(category_totals)}",
    )

    discovered = set()
    for pattern in DISCOVERY_PATTERNS:
        for match in glob.glob(str(REPO / pattern), recursive=True):
            path = Path(match)
            if path.is_file():
                discovered.add(path.relative_to(REPO).as_posix())
    covered_paths = {entry["path"] for entry in audited}
    ensure(
        discovered == covered_paths,
        "source coverage mismatch: "
        f"missing={sorted(discovered - covered_paths)}, "
        f"extra={sorted(covered_paths - discovered)}",
    )
    return audited, covered_paths


def validate_ledger(contract, ledger, behaviors, coverage):
    features = ledger["features"]
    feature_ids = [feature["feature_id"] for feature in features]
    unique(feature_ids, "feature_id")
    feature_set = set(feature_ids)

    audited, covered_paths = validate_coverage_definition(coverage)
    unique((entry["path"] for entry in audited), "audited source path")

    revision = contract["source_revision"]
    for entry in audited:
        ensure(entry["classification"] == "fully_classified", f"unclassified {entry['path']}")
        ensure(entry["feature_ids"], f"no feature classification for {entry['path']}")
        unknown = set(entry["feature_ids"]) - feature_set
        ensure(not unknown, f"{entry['path']} references unknown features {sorted(unknown)}")
        ensure(
            run_git("diff", "--quiet", revision, "--", entry["path"], check=False).returncode
            == 0,
            f"audited source changed since {revision}: {entry['path']}",
        )

    feature_source_paths = set()
    for feature in features:
        ensure(feature["status"] != "unclassified", f"unclassified feature {feature['feature_id']}")
        for reference in feature["source"]:
            validate_source_reference(reference, covered_paths)
            feature_source_paths.add(reference["path"])
        for fixture in feature["acceptance_fixture"]:
            ensure((BASE / fixture).is_file(), f"missing acceptance fixture: {fixture}")
    ensure(
        feature_source_paths == covered_paths,
        "audited sources without ledger classification: "
        f"{sorted(covered_paths - feature_source_paths)}",
    )

    inventory = behaviors["behaviors"]
    behavior_ids = [behavior["behavior_id"] for behavior in inventory]
    unique(behavior_ids, "behavior_id")
    behavior_features = set()
    for behavior in inventory:
        ensure(
            behavior["classification"] != "unclassified",
            f"unclassified behavior {behavior['behavior_id']}",
        )
        ensure(
            behavior["feature_id"] in feature_set,
            f"{behavior['behavior_id']} references unknown feature",
        )
        behavior_features.add(behavior["feature_id"])
        validate_source_reference(behavior["source"], covered_paths)
    ensure(
        behavior_features == feature_set,
        f"features without behavior records: {sorted(feature_set - behavior_features)}",
    )
    return len(features), len(inventory), len(audited)


def extract_runtime_env():
    names = set()
    direct = re.compile(r'process\.env\["([^"]+)"\]')
    helper = re.compile(
        r'(?:parseBooleanEnv|parseIntegerEnv|parseOptionalNonEmptyEnv|'
        r'parseDomainList|requireEnv)\(\s*"([^"]+)"'
    )
    for path in (REPO / "src").rglob("*.ts"):
        text = path.read_text(encoding="utf-8")
        names.update(direct.findall(text))
        names.update(helper.findall(text))
    return names


def validate_config(mapping):
    mappings = mapping["mappings"]
    legacy_names = [entry["legacy_env"] for entry in mappings]
    unique(legacy_names, "legacy environment mapping")

    runtime_names = []
    for entry in mappings:
        if entry["scope"] == "runtime":
            runtime_names.append(entry["legacy_env"])
            runtime_names.extend(entry.get("aliases", []))
    unique(runtime_names, "runtime environment name or alias")
    runtime_declared = set(runtime_names)
    runtime_actual = extract_runtime_env()
    ensure(
        runtime_actual == runtime_declared,
        "runtime environment coverage mismatch: "
        f"missing={sorted(runtime_actual - runtime_declared)}, "
        f"extra={sorted(runtime_declared - runtime_actual)}",
    )
    return len(mappings), len(runtime_actual)


def http_response_shape(response):
    if response is None:
        return "null"
    if isinstance(response, bool):
        return "boolean"
    if isinstance(response, (int, float)):
        return "number"
    if isinstance(response, str):
        return "string"
    if isinstance(response, list):
        item_shapes = sorted({http_response_shape(item) for item in response})
        return f"array<{'|'.join(item_shapes) if item_shapes else 'empty'}>"
    if isinstance(response, dict):
        fields = ",".join(
            f"{http_response_shape_key(key)}:{http_response_shape(response[key])}"
            for key in sorted(response)
        )
        return f"object{{{fields}}}"
    return type(response).__name__


def http_response_shape_key(key):
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return key
    return json.dumps(key, ensure_ascii=True)


def validate_http(http_examples):
    endpoints = http_examples["endpoints"]
    endpoint_ids = [endpoint["endpoint_id"] for endpoint in endpoints]
    unique(endpoint_ids, "HTTP endpoint_id")
    pairs = [(endpoint["method"], endpoint["path"]) for endpoint in endpoints]
    unique(pairs, "HTTP method/path")

    server_text = (REPO / "src" / "server.ts").read_text(encoding="utf-8")
    literal_routes = {
        (method.upper(), path)
        for method, path in re.findall(
            r'server\.(get|post)\("([^"]+)"', server_text
        )
    }
    config_text = (REPO / "src" / "config.ts").read_text(encoding="utf-8")
    webhook_match = re.search(
        r'WHATSAPP_WEBHOOK_PATH\s*=\s*.*?\|\|\s*"([^"]+)"',
        config_text,
        re.DOTALL,
    )
    ensure(webhook_match is not None, "cannot derive the default WhatsApp webhook path")
    dynamic_methods = {
        method.upper()
        for method in re.findall(r"server\.(get|post)\(path,", server_text)
    }
    ensure(
        dynamic_methods == {"GET", "POST"},
        f"unexpected dynamic WhatsApp route methods: {sorted(dynamic_methods)}",
    )
    source_routes = literal_routes | {
        (method, webhook_match.group(1)) for method in dynamic_methods
    }
    documented = set(pairs)
    ensure(
        documented == source_routes,
        "HTTP route inventory mismatch: "
        f"undocumented={sorted(source_routes - documented)}, "
        f"invented={sorted(documented - source_routes)}",
    )
    ensure(
        len(endpoints) == HTTP_ENDPOINT_COUNT,
        f"expected {HTTP_ENDPOINT_COUNT} HTTP endpoints, found {len(endpoints)}",
    )
    ensure(
        len(HTTP_CASE_CONTRACTS) == HTTP_CASE_COUNT,
        "validator-owned HTTP case contract count is inconsistent",
    )
    case_ids = []
    documented_cases = []
    for endpoint in endpoints:
        ensure(endpoint["cases"], f"endpoint has no examples: {endpoint['endpoint_id']}")
        for case in endpoint["cases"]:
            case_ids.append(f"{endpoint['endpoint_id']}:{case['case_id']}")
            documented_cases.append(
                (
                    (endpoint["method"], endpoint["path"], case["case_id"]),
                    (case["status"], http_response_shape(case["response"])),
                )
            )
    unique(case_ids, "HTTP case ID")
    unique((key for key, _ in documented_cases), "HTTP method/path/case ID")
    ensure(
        len(case_ids) == HTTP_CASE_COUNT,
        f"expected {HTTP_CASE_COUNT} HTTP cases, found {len(case_ids)}",
    )
    actual_contracts = dict(documented_cases)
    missing = set(HTTP_CASE_CONTRACTS) - set(actual_contracts)
    extra = set(actual_contracts) - set(HTTP_CASE_CONTRACTS)
    changed = {
        key: {
            "expected": HTTP_CASE_CONTRACTS[key],
            "actual": actual_contracts[key],
        }
        for key in set(HTTP_CASE_CONTRACTS) & set(actual_contracts)
        if HTTP_CASE_CONTRACTS[key] != actual_contracts[key]
    }
    ensure(
        not missing and not extra and not changed,
        "HTTP case contract mismatch: "
        f"missing={sorted(missing)}, extra={sorted(extra)}, changed={changed}",
    )
    return len(endpoints), len(case_ids)


def validate_skills(schemas, registry, inventory):
    skills = inventory["skills"]
    source_paths = [skill["source_path"] for skill in skills]
    unique(source_paths, "bundled skill source")
    unique((skill["name"] for skill in skills), "bundled skill name")

    actual_paths = {
        path.relative_to(REPO).as_posix()
        for path in (REPO / "deploy" / "conf" / "skills").glob("*.json")
    }
    ensure(
        set(source_paths) == actual_paths,
        "bundled skill inventory mismatch: "
        f"missing={sorted(actual_paths - set(source_paths))}, "
        f"extra={sorted(set(source_paths) - actual_paths)}",
    )

    schema = schemas["legacy-skill.schema.json"]
    validator = validator_for(schema)(schema, registry=registry)
    bridge_order = ["httpGet", "httpPost", "log"]
    for item in skills:
        source = load_json(REPO / item["source_path"])
        errors = list(validator.iter_errors(source))
        ensure(not errors, f"bundled skill is invalid: {item['source_path']}")
        ensure(source["name"] == item["name"], f"skill name mismatch: {item['source_path']}")
        detected = [
            bridge
            for bridge in bridge_order
            if re.search(rf"\bapi\.{bridge}\b", source["executeCode"])
        ]
        ensure(detected == item["bridges"], f"bridge inventory mismatch: {item['name']}")
        ensure(
            item["migration_decision"] == "manual_rust_wasi_port"
            and item["final_javascript_execution"] is False,
            f"unsafe migration decision for {item['name']}",
        )
    return len(skills)


def role_source_outcome(fixture):
    content_type = fixture["content_type"]
    body = fixture["body"]
    raw = body if isinstance(body, str) else json.dumps(body)
    should_parse = "json" in content_type or raw.lstrip().startswith("{")
    if should_parse:
        try:
            parsed = json.loads(raw) if isinstance(body, str) else body
            content_value = parsed.get("content")
            if not isinstance(content_value, str):
                content_value = parsed.get("prompt")
            if not isinstance(content_value, str) or not content_value:
                raise ValueError('Role JSON must contain a "content" or "prompt" string field')
            model = parsed.get("model") if isinstance(parsed.get("model"), str) else None
            return {"outcome": "loaded_json", "content": content_value, "model": model}
        except (json.JSONDecodeError, ValueError, AttributeError) as exc:
            if "json" in content_type:
                return {"outcome": "error", "error": str(exc)}
    return {"outcome": "loaded_plain_text", "content": raw, "model": None}


def validate_role_sources():
    count = 0
    for path in sorted((BASE / "fixtures" / "role" / "sources").glob("*.json")):
        fixture = load_json(path)
        actual = role_source_outcome(fixture)
        expected = fixture["expected"]
        ensure(actual["outcome"] == expected["outcome"], f"role outcome mismatch: {path.name}")
        if "content" in expected:
            ensure(actual.get("content") == expected["content"], f"role content mismatch: {path.name}")
        if "model" in expected:
            ensure(actual.get("model") == expected["model"], f"role model mismatch: {path.name}")
        if "error_contains" in expected:
            ensure(
                expected["error_contains"].lower() in actual.get("error", "").lower(),
                f"role error mismatch: {path.name}",
            )
        count += 1
    return count


def validate_migration_result_semantics(result):
    kind = result["input"]["kind"]
    status = result["status"]
    exit_code = result["exit_code"]
    remaining = result["remaining_javascript"]
    artifacts = result["artifacts"]
    artifact_kinds = [artifact["kind"] for artifact in artifacts]

    expected_exit_codes = {
        "migrated": 0,
        "manual_port_required": 2,
        "invalid_input": 3,
        "failed": 1,
    }
    ensure(
        exit_code == expected_exit_codes[status],
        f"{status} migration must exit {expected_exit_codes[status]}",
    )
    ensure(not remaining or exit_code != 0, "remaining JavaScript must exit nonzero")

    if kind == "role":
        ensure(status in {"migrated", "invalid_input", "failed"},
               "role migration has an invalid status")
        ensure(not remaining, "role migration cannot report remaining JavaScript")
        ensure(not result["recognized_bridges"], "role migration cannot report bridges")
        expected = ["role"] if status == "migrated" else []
        ensure(artifact_kinds == expected, "role migration artifact mismatch")
    elif kind == "environment":
        ensure(status in {"migrated", "invalid_input", "failed"},
               "environment migration has an invalid status")
        ensure(not remaining, "environment migration cannot report remaining JavaScript")
        ensure(not result["recognized_bridges"],
               "environment migration cannot report bridges")
        expected = ["json5_config"] if status == "migrated" else []
        ensure(artifact_kinds == expected, "environment migration artifact mismatch")
    else:
        ensure(kind == "legacy_skill", f"unknown migration input kind: {kind}")
        if status in {"migrated", "manual_port_required"}:
            ensure(
                sorted(artifact_kinds) == ["wasi_manifest", "wit_scaffold"],
                "legacy skill migration lacks WASI manifest or WIT scaffold",
            )
        else:
            ensure(not artifacts, "failed or invalid legacy skill emitted artifacts")
        if status == "migrated":
            ensure(exit_code == 0 and not remaining,
                   "migrated legacy skill is not fully replaced")
        elif status == "manual_port_required":
            ensure(exit_code == 2 and remaining,
                   "manual legacy skill port lacks remaining-JavaScript evidence")


def validate_migration(contract):
    ensure(
        contract["migration_command"]["silent_success_for_remaining_javascript"] is False,
        "migration contract permits silent JavaScript success",
    )
    decision_ids = {entry["decision_id"] for entry in contract["fixed_decisions"]}
    unique(
        (entry["decision_id"] for entry in contract["fixed_decisions"]),
        "contract decision_id",
    )
    unique(
        (entry["break_id"] for entry in contract["deliberate_breaking_changes"]),
        "contract break_id",
    )
    unique(
        (entry["gap_id"] for entry in contract["evidence_gaps"]),
        "contract gap_id",
    )
    ensure("javascript-execution-removed" in decision_ids, "missing JavaScript removal decision")
    positive_results = [
        load_json(path)
        for path in sorted((BASE / "fixtures" / "migration").glob("*.json"))
    ]
    for result in positive_results:
        validate_migration_result_semantics(result)
        if result["input"]["kind"] == "legacy_skill":
            source_path = REPO / result["input"]["source"]
            ensure(source_path.is_file(), f"missing legacy skill input: {source_path}")
            source = load_json(source_path)
            ensure(
                isinstance(source.get("executeCode"), str),
                f"legacy skill input lacks executeCode: {source_path}",
            )

    manual = load_json(BASE / "fixtures" / "migration" / "manual-port-required.json")
    ensure(manual["status"] == "manual_port_required" and manual["exit_code"] == 2,
           "manual migration fixture must exit 2")
    artifact_kinds = {artifact["kind"] for artifact in manual["artifacts"]}
    ensure(
        {"wasi_manifest", "wit_scaffold"} <= artifact_kinds,
        "manual migration fixture lacks manifest or WIT scaffold",
    )


def run_regression_self_tests(schemas, registry, mapping, coverage, http_examples):
    role_result = role_source_outcome(
        {
            "content_type": "application/json",
            "body": {"content": "role", "model": 7},
        }
    )
    ensure(
        role_result == {"outcome": "loaded_json", "content": "role", "model": None},
        "non-string role model was not ignored",
    )

    unsafe_success = {
        "input": {"kind": "legacy_skill"},
        "status": "migrated",
        "exit_code": 0,
        "recognized_bridges": [],
        "remaining_javascript": [],
        "artifacts": [],
    }
    expect_contract_error(
        "legacy skill success without port evidence",
        lambda: validate_migration_result_semantics(unsafe_success),
    )

    reduced_coverage = copy.deepcopy(coverage)
    reduced_coverage["discovery"]["include"].remove(".env.example")
    reduced_coverage["audited_sources"] = [
        entry
        for entry in reduced_coverage["audited_sources"]
        if entry["path"] != ".env.example"
    ]
    expect_contract_error(
        "coordinated .env.example coverage deletion",
        lambda: validate_coverage_definition(reduced_coverage),
    )

    duplicate_alias = copy.deepcopy(mapping)
    duplicate_alias["mappings"][1]["aliases"] = ["GITHUB_TOKEN"]
    expect_contract_error(
        "runtime alias mapped to multiple targets",
        lambda: validate_config(duplicate_alias),
    )

    invented_route = copy.deepcopy(http_examples)
    invented_route["endpoints"][0]["path"] = "/invented"
    expect_contract_error(
        "invented documented HTTP route",
        lambda: validate_http(invented_route),
        "HTTP route inventory mismatch",
    )

    changed_status = copy.deepcopy(http_examples)
    changed_status["endpoints"][0]["cases"][0]["status"] = 599
    expect_contract_error(
        "changed HTTP case status with stable counts",
        lambda: validate_http(changed_status),
        "HTTP case contract mismatch",
    )

    changed_response_type = copy.deepcopy(http_examples)
    changed_response_type["endpoints"][0]["cases"][0]["response"][
        "authenticated"
    ] = "true"
    http_schema = schemas["http-examples.schema.json"]
    http_validator = validator_for(http_schema)(http_schema, registry=registry)
    schema_errors = list(http_validator.iter_errors(changed_response_type))
    ensure(
        not schema_errors,
        "HTTP response type regression must remain schema-valid: "
        + "; ".join(error.message for error in schema_errors[:3]),
    )
    expect_contract_error(
        "changed schema-valid HTTP response value type",
        lambda: validate_http(changed_response_type),
        "HTTP case contract mismatch",
    )

    changed_nested_shape = copy.deepcopy(http_examples)
    changed_nested_shape["endpoints"][0]["cases"][0]["response"]["channels"][
        "teams"
    ] = "true"
    expect_contract_error(
        "changed nested HTTP response value type",
        lambda: validate_http(changed_nested_shape),
        "HTTP case contract mismatch",
    )

    changed_array_shape = copy.deepcopy(http_examples)
    changed_array_shape["endpoints"][0]["cases"][0]["response"]["tips"][0] = 1
    expect_contract_error(
        "changed nested HTTP response array item type",
        lambda: validate_http(changed_array_shape),
        "HTTP case contract mismatch",
    )

    ensure(
        http_response_shape({"a,b": 1})
        != http_response_shape({"a": 1, "b": 1}),
        "HTTP response-shape key encoding is ambiguous",
    )

    expect_contract_error(
        "structural-only evidence range",
        lambda: validate_source_reference(
            {"path": "package-lock.json", "line_start": 1, "line_end": 1},
            {"package-lock.json"},
        ),
    )


def main():
    try:
        for path in sorted(BASE.rglob("*.json")):
            load_json(path)

        schemas, registry = schema_registry()
        valid_fixtures, invalid_fixtures = validate_fixtures(schemas, registry)

        contract = load_json(BASE / "contract.json")
        ledger = load_json(BASE / "ledger" / "features.json")
        behaviors = load_json(BASE / "ledger" / "behaviors.json")
        mapping = load_json(BASE / "config" / "env-mapping.json")
        http_examples = load_json(BASE / "fixtures" / "http" / "examples.json")
        skills = load_json(BASE / "inventory" / "bundled-skills.json")
        coverage = load_json(BASE / "inventory" / "source-coverage.json")

        validate_revision(
            contract,
            ("features", ledger),
            ("behaviors", behaviors),
            ("config", mapping),
            ("http", http_examples),
            ("skills", skills),
            ("coverage", coverage),
        )
        feature_count, behavior_count, source_count = validate_ledger(
            contract, ledger, behaviors, coverage
        )
        mapping_count, runtime_env_count = validate_config(mapping)
        endpoint_count, http_case_count = validate_http(http_examples)
        skill_count = validate_skills(schemas, registry, skills)
        role_source_count = validate_role_sources()
        validate_migration(contract)
        run_regression_self_tests(
            schemas, registry, mapping, coverage, http_examples
        )

        result = {
            "status": "ok",
            "source_revision": contract["source_revision"],
            "counts": {
                "features": feature_count,
                "behaviors": behavior_count,
                "audited_sources": source_count,
                "environment_mappings": mapping_count,
                "runtime_environment_names": runtime_env_count,
                "http_endpoints": endpoint_count,
                "http_cases": http_case_count,
                "bundled_skills": skill_count,
                "role_source_cases": role_source_count,
                "valid_schema_fixtures": valid_fixtures,
                "negative_schema_fixtures": invalid_fixtures,
            },
            "unclassified_behaviors": 0,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
    except ContractError as exc:
        print(f"legacy contract validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
