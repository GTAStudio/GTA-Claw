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
DUPLICATE_ALIAS_MAPPING_IDENTITY = (
    "DEVICE_FLOW_ENABLED",
    "runtime",
    "auth.github.device.enabled",
)
# Audited from the pinned TypeScript sources; never populate this from examples.json.
HTTP_SHAPE_NULL = '["null"]'
HTTP_SHAPE_STRING = '["string"]'
HTTP_SHAPE_ERROR = '["object",[["error",["string"]]]]'
HTTP_SHAPE_REPLY = '["object",[["reply",["string"]]]]'
HTTP_CASE_CONTRACTS = {
    ("GET", "/", "unauthenticated-no-channels"): (
        200,
        '["object",[["authenticated",["bool"]],["channels",["object",'
        '[["discord",["bool"]],["teams",["bool"]],["telegram",["bool"]],'
        '["whatsapp",["bool"]]]]],["deviceFlowEnabled",["bool"]],["endpoints",'
        '["object",[["chat",["string"]],["deviceAuth",["string"]],'
        '["health",["string"]]]]],["examples",["object",'
        '[["chatCurl",["string"]]]]],["service",["string"]],["status",'
        '["string"]],["tips",["array",[["string"],["string"]]]]]]',
    ),
    ("GET", "/health", "healthy-unauthenticated"): (
        200,
        '["object",[["authenticated",["bool"]],["channels",["object",'
        '[["discord",["bool"]],["teams",["bool"]],["telegram",["bool"]],'
        '["whatsapp",["bool"]]]]],["deviceFlowEnabled",["bool"]],["model",'
        '["string"]],["sessions",["integer"]],["skills",["integer"]],'
        '["status",["string"]],["uptime",["integer"]]]]',
    ),
    ("GET", "/auth/device", "already-authenticated"): (
        200,
        '["object",[["authenticated",["bool"]],["message",["string"]]]]',
    ),
    ("GET", "/auth/device", "disabled"): (
        400,
        '["object",[["authenticated",["bool"]],["error",["string"]]]]',
    ),
    ("GET", "/auth/device", "instructions"): (
        200,
        '["object",[["auth_instructions",["string"]],'
        '["authenticated",["bool"]]]]',
    ),
    ("GET", "/auth/device", "unexpected-error"): (500, HTTP_SHAPE_ERROR),
    ("POST", "/chat", "missing-message"): (400, HTTP_SHAPE_ERROR),
    ("POST", "/chat", "help-before-auth"): (200, HTTP_SHAPE_REPLY),
    ("POST", "/chat", "unauthenticated-token-mode"): (401, HTTP_SHAPE_ERROR),
    ("POST", "/chat", "unauthenticated-device-flow"): (
        401,
        '["object",[["auth_instructions",["string"]],["error",["string"]]]]',
    ),
    ("POST", "/chat", "success"): (200, HTTP_SHAPE_REPLY),
    ("POST", "/chat", "endpoint-error"): (500, HTTP_SHAPE_ERROR),
    ("POST", "/api/messages", "adapter-ack"): (200, HTTP_SHAPE_NULL),
    ("POST", "/api/messages", "rate-limited"): (429, HTTP_SHAPE_ERROR),
    ("GET", "/whatsapp/webhook", "verified"): (200, HTTP_SHAPE_STRING),
    ("GET", "/whatsapp/webhook", "forbidden"): (403, HTTP_SHAPE_ERROR),
    ("POST", "/whatsapp/webhook", "accepted"): (
        200,
        '["object",[["ok",["bool"]]]]',
    ),
    ("POST", "/whatsapp/webhook", "handling-failed"): (500, HTTP_SHAPE_ERROR),
    ("POST", "/admin/reload", "forbidden"): (403, HTTP_SHAPE_ERROR),
    ("POST", "/admin/reload", "reloaded"): (
        200,
        '["object",[["message",["string"]],["model",["string"]],'
        '["skills",["integer"]]]]',
    ),
    ("POST", "/admin/reload", "conflict"): (409, HTTP_SHAPE_ERROR),
    ("POST", "/admin/reload", "failed"): (500, HTTP_SHAPE_ERROR),
    ("GET", "/admin/system", "forbidden"): (403, HTTP_SHAPE_ERROR),
    ("GET", "/admin/system", "system-info"): (
        200,
        '["object",[["node",["object",[["memory_mb",["object",'
        '[["heapTotal",["integer"]],["heapUsed",["integer"]],'
        '["rss",["integer"]]]]],["pid",["integer"]],["uptime_s",'
        '["integer"]],["version",["string"]]]]],["os",["object",'
        '[["arch",["string"]],["cpus",["integer"]],["freeMemory_mb",'
        '["integer"]],["hostname",["string"]],["loadavg",["array",'
        '[["number"],["number"],["number"]]]],["platform",["string"]],'
        '["totalMemory_mb",'
        '["integer"]],["uptime_s",["integer"]]]]]]]',
    ),
    ("POST", "/admin/exec", "forbidden"): (403, HTTP_SHAPE_ERROR),
    ("POST", "/admin/exec", "unknown-action"): (
        400,
        '["object",[["allowed",["array",[["string"],["string"],["string"],'
        '["string"],["string"],["string"],["string"],["string"],["string"],'
        '["string"],["string"],["string"]]]],'
        '["error",["string"]]]]',
    ),
    ("POST", "/admin/exec", "command-success"): (
        200,
        '["object",[["action",["string"]],["output",["string"]],'
        '["success",["bool"]]]]',
    ),
    ("POST", "/admin/exec", "command-failure"): (
        200,
        '["object",[["action",["string"]],["error",["string"]],'
        '["stderr",["string"]],["success",["bool"]]]]',
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


def validator_owned_mapping(mapping, identity):
    ensure(
        identity == DUPLICATE_ALIAS_MAPPING_IDENTITY,
        f"config regression target is not validator-owned: {identity!r}",
    )
    matches = [
        entry
        for entry in mapping["mappings"]
        if (
            entry["legacy_env"],
            entry["scope"],
            entry["target_json5_key"],
        )
        == identity
    ]
    ensure(
        len(matches) == 1,
        f"config regression target {identity!r} must occur exactly once; "
        f"found {len(matches)}",
    )
    return next(iter(matches))


def http_response_shape_descriptor(response):
    if response is None:
        return ("null",)
    if isinstance(response, bool):
        return ("bool",)
    if isinstance(response, int):
        return ("integer",)
    if isinstance(response, float):
        return ("number",)
    if isinstance(response, str):
        return ("string",)
    if isinstance(response, list):
        return (
            "array",
            tuple(http_response_shape_descriptor(item) for item in response),
        )
    if isinstance(response, dict):
        return (
            "object",
            tuple(
                (key, http_response_shape_descriptor(response[key]))
                for key in sorted(response)
            ),
        )
    raise ContractError(f"unsupported JSON response type: {type(response).__name__}")


def http_response_shape(response):
    return json.dumps(
        http_response_shape_descriptor(response),
        ensure_ascii=True,
        separators=(",", ":"),
    )


def validator_owned_http_case(http_examples, contract_key):
    ensure(
        contract_key in HTTP_CASE_CONTRACTS,
        f"HTTP regression target is not validator-owned: {contract_key!r}",
    )
    method, path, case_id = contract_key
    matches = [
        (endpoint, case)
        for endpoint in http_examples["endpoints"]
        if endpoint["method"] == method and endpoint["path"] == path
        for case in endpoint["cases"]
        if case["case_id"] == case_id
    ]
    ensure(
        len(matches) == 1,
        f"HTTP regression target {contract_key!r} must occur exactly once; "
        f"found {len(matches)}",
    )
    return next(iter(matches))


def ensure_schema_valid_fixture(label, instance, validator):
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: list(error.path),
    )
    ensure(
        not errors,
        f"{label} mutation is not schema-valid: "
        f"{next(iter(errors)).message if errors else ''}",
    )


def expect_schema_valid_http_error(label, http_examples, validator, message_contains):
    ensure_schema_valid_fixture(label, http_examples, validator)
    expect_contract_error(
        label,
        lambda: validate_http(http_examples),
        message_contains,
    )


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
    ensure(
        len(case_ids) == HTTP_CASE_COUNT,
        f"expected {HTTP_CASE_COUNT} HTTP cases, found {len(case_ids)}",
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


def run_mapping_regression_self_tests(mapping, mapping_validator):
    missing_target = copy.deepcopy(mapping)
    missing_mapping = validator_owned_mapping(
        missing_target, DUPLICATE_ALIAS_MAPPING_IDENTITY
    )
    missing_target["mappings"].remove(missing_mapping)
    ensure_schema_valid_fixture(
        "missing config regression target", missing_target, mapping_validator
    )
    expect_contract_error(
        "missing config regression target",
        lambda: validator_owned_mapping(
            missing_target, DUPLICATE_ALIAS_MAPPING_IDENTITY
        ),
        "must occur exactly once; found 0",
    )

    duplicate_target = copy.deepcopy(mapping)
    duplicate_mapping = validator_owned_mapping(
        duplicate_target, DUPLICATE_ALIAS_MAPPING_IDENTITY
    )
    duplicate_target["mappings"].append(copy.deepcopy(duplicate_mapping))
    ensure_schema_valid_fixture(
        "duplicate config regression target", duplicate_target, mapping_validator
    )
    expect_contract_error(
        "duplicate config regression target",
        lambda: validator_owned_mapping(
            duplicate_target, DUPLICATE_ALIAS_MAPPING_IDENTITY
        ),
        "must occur exactly once; found 2",
    )

    duplicate_alias = copy.deepcopy(mapping)
    alias_target = validator_owned_mapping(
        duplicate_alias, DUPLICATE_ALIAS_MAPPING_IDENTITY
    )
    alias_target["aliases"] = ["GITHUB_TOKEN"]
    ensure_schema_valid_fixture(
        "runtime alias mapped to multiple targets", duplicate_alias, mapping_validator
    )
    expect_contract_error(
        "runtime alias mapped to multiple targets",
        lambda: validate_config(duplicate_alias),
        "duplicate runtime environment name or alias",
    )


def run_http_regression_self_tests(http_examples, http_validator):
    ensure(
        http_response_shape({"a,b": 1})
        != http_response_shape({"a": 1, "b": 1}),
        "HTTP response-shape encoding loses object key boundaries",
    )
    ensure(
        http_response_shape({"nested": {"authenticated": False}})
        != http_response_shape({"nested": {"authenticated": "false"}}),
        "HTTP response-shape encoding loses nested value types",
    )
    ensure(
        http_response_shape([1, "x"]) != http_response_shape(["x", 1]),
        "HTTP response-shape encoding loses array order",
    )
    ensure(
        http_response_shape([1]) != http_response_shape([1, 1]),
        "HTTP response-shape encoding loses array multiplicity",
    )
    ensure(
        http_response_shape([[1, "x"]]) != http_response_shape([["x", 1]]),
        "HTTP response-shape encoding loses nested array order",
    )
    ensure(
        http_response_shape([[1]]) != http_response_shape([[1, 1]]),
        "HTTP response-shape encoding loses nested array multiplicity",
    )

    root_key = ("GET", "/", "unauthenticated-no-channels")
    already_authenticated_key = ("GET", "/auth/device", "already-authenticated")
    disabled_key = ("GET", "/auth/device", "disabled")
    unexpected_error_key = ("GET", "/auth/device", "unexpected-error")
    endpoint_error_key = ("POST", "/chat", "endpoint-error")

    missing_target = copy.deepcopy(http_examples)
    missing_endpoint, missing_case = validator_owned_http_case(
        missing_target, unexpected_error_key
    )
    missing_endpoint["cases"].remove(missing_case)
    ensure_schema_valid_fixture(
        "missing HTTP regression target", missing_target, http_validator
    )
    expect_contract_error(
        "missing HTTP regression target",
        lambda: validator_owned_http_case(missing_target, unexpected_error_key),
        "must occur exactly once; found 0",
    )

    duplicate_target = copy.deepcopy(http_examples)
    duplicate_endpoint, duplicate_source = validator_owned_http_case(
        duplicate_target, endpoint_error_key
    )
    duplicate_endpoint["cases"].append(copy.deepcopy(duplicate_source))
    ensure_schema_valid_fixture(
        "duplicate HTTP regression target", duplicate_target, http_validator
    )
    expect_contract_error(
        "duplicate HTTP regression target",
        lambda: validator_owned_http_case(duplicate_target, endpoint_error_key),
        "must occur exactly once; found 2",
    )

    invented_route = copy.deepcopy(http_examples)
    route_endpoint, _ = validator_owned_http_case(invented_route, root_key)
    route_endpoint["path"] = "/invented"
    expect_schema_valid_http_error(
        "invented documented HTTP route",
        invented_route,
        http_validator,
        "HTTP route inventory mismatch",
    )

    changed_status = copy.deepcopy(http_examples)
    _, status_case = validator_owned_http_case(changed_status, root_key)
    status_case["status"] = 599
    expect_schema_valid_http_error(
        "changed HTTP case status with stable counts",
        changed_status,
        http_validator,
        "HTTP case contract mismatch",
    )

    changed_shape = copy.deepcopy(http_examples)
    _, shape_case = validator_owned_http_case(changed_shape, root_key)
    response = shape_case["response"]
    ensure(
        isinstance(response, dict)
        and isinstance(response.get("authenticated"), bool),
        f"HTTP regression target {root_key!r} lacks boolean authenticated response",
    )
    response["authenticated"] = "false"
    expect_schema_valid_http_error(
        "changed HTTP response shape with stable counts",
        changed_shape,
        http_validator,
        "HTTP case contract mismatch",
    )

    swapped_cases = copy.deepcopy(http_examples)
    _, already_authenticated = validator_owned_http_case(
        swapped_cases, already_authenticated_key
    )
    _, disabled = validator_owned_http_case(swapped_cases, disabled_key)
    already_authenticated["case_id"], disabled["case_id"] = (
        disabled["case_id"],
        already_authenticated["case_id"],
    )
    expect_schema_valid_http_error(
        "swapped HTTP cases with stable counts",
        swapped_cases,
        http_validator,
        "HTTP case contract mismatch",
    )

    missing_case_fixture = copy.deepcopy(http_examples)
    missing_case_endpoint, missing_case = validator_owned_http_case(
        missing_case_fixture, unexpected_error_key
    )
    missing_case_endpoint["cases"].remove(missing_case)
    expect_schema_valid_http_error(
        "missing HTTP case",
        missing_case_fixture,
        http_validator,
        "HTTP case contract mismatch",
    )

    extra_case_fixture = copy.deepcopy(http_examples)
    extra_case_endpoint, extra_case_source = validator_owned_http_case(
        extra_case_fixture, endpoint_error_key
    )
    invented_case = copy.deepcopy(extra_case_source)
    invented_case["case_id"] = "invented-extra"
    extra_case_endpoint["cases"].append(invented_case)
    expect_schema_valid_http_error(
        "extra HTTP case",
        extra_case_fixture,
        http_validator,
        "HTTP case contract mismatch",
    )

    duplicate_case_fixture = copy.deepcopy(http_examples)
    duplicate_case_endpoint, duplicate_case_source = validator_owned_http_case(
        duplicate_case_fixture, endpoint_error_key
    )
    duplicate_case_endpoint["cases"].append(copy.deepcopy(duplicate_case_source))
    expect_schema_valid_http_error(
        "duplicate HTTP case",
        duplicate_case_fixture,
        http_validator,
        "duplicate HTTP case ID",
    )


def run_regression_self_tests(mapping, coverage, http_examples, schemas, registry):
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

    mapping_schema = schemas["config-mapping.schema.json"]
    mapping_validator = validator_for(mapping_schema)(
        mapping_schema, registry=registry
    )
    run_mapping_regression_self_tests(mapping, mapping_validator)

    reordered_mapping = copy.deepcopy(mapping)
    reordered_mapping["mappings"].reverse()
    ensure_schema_valid_fixture(
        "reordered config mapping", reordered_mapping, mapping_validator
    )
    validate_config(reordered_mapping)
    run_mapping_regression_self_tests(reordered_mapping, mapping_validator)

    http_schema = schemas["http-examples.schema.json"]
    http_validator = validator_for(http_schema)(http_schema, registry=registry)
    run_http_regression_self_tests(http_examples, http_validator)

    reordered_http_examples = copy.deepcopy(http_examples)
    reordered_http_examples["endpoints"].reverse()
    for endpoint in reordered_http_examples["endpoints"]:
        endpoint["cases"].reverse()
    ensure_schema_valid_fixture(
        "reordered HTTP fixture", reordered_http_examples, http_validator
    )
    validate_http(reordered_http_examples)
    run_http_regression_self_tests(reordered_http_examples, http_validator)

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
        run_regression_self_tests(mapping, coverage, http_examples, schemas, registry)

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
