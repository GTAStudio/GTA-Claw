#!/usr/bin/env python3

import argparse
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


DIGEST = re.compile(r"^[0-9a-f]{64}$")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path, template, image):
    text = Path(path).read_text(encoding="utf-8")
    if template:
        if text.count("@OCI_IMAGE_REFERENCE@") != 1:
            raise ValueError(f"{path} must contain exactly one image placeholder")
        text = text.replace("@OCI_IMAGE_REFERENCE@", image)
    elif "@OCI_IMAGE_REFERENCE@" in text:
        raise ValueError(f"{path} retains an image placeholder")
    return json.loads(text, object_pairs_hook=unique_object)


def schema_for(value):
    if isinstance(value, dict):
        return {
            "type": "object",
            "required": list(value),
            "additionalProperties": False,
            "properties": {key: schema_for(item) for key, item in value.items()},
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "prefixItems": [schema_for(item) for item in value],
            "minItems": len(value),
            "maxItems": len(value),
        }
    if value is None:
        return {"type": "null"}
    return {"const": value}


def sandbox_contract():
    return {
        "metadata": {
            "name": "gta-claw-probe",
            "namespace": "gta-claw",
            "uid": "gta-claw-probe",
            "attempt": 0,
        },
        "log_directory": "/var/log/gta-claw-cri-probe",
        "linux": {
            "security_context": {
                "namespace_options": {"network": 2, "pid": 1, "ipc": 1}
            }
        },
    }


def container_contract(image, runtime):
    security = {
        "capabilities": {
            "add_capabilities": [] if runtime else ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
            "drop_capabilities": ["ALL"],
        },
        "privileged": False,
        "run_as_user": {"value": 65532 if runtime else 0},
        "run_as_group": {"value": 65532 if runtime else 0},
        "supplemental_groups": [65532] if runtime else [],
        "no_new_privs": True,
        "readonly_rootfs": True,
    }
    command = (
        [
            "/usr/libexec/gta-claw/gta-claw-daemon",
            "--probe",
            "--state-profile",
            "linux-protected",
            "--state-path",
            "/var/lib/gta-claw-protected",
        ]
        if runtime
        else [
            "/usr/libexec/gta-claw/gta-claw-daemon",
            "--prepare-linux-protected",
            "--state-path",
            "/var/lib/gta-claw-protected",
            "--service-uid",
            "65532",
            "--service-gid",
            "65532",
        ]
    )
    return {
        "metadata": {
            "name": "gta-claw-runtime" if runtime else "gta-claw-init",
            "attempt": 0,
        },
        "image": {"image": image},
        "command": command,
        "mounts": [
            {
                "container_path": "/var/lib",
                "host_path": "/var/lib/gta-claw-cri-probe",
                "readonly": False,
                "selinux_relabel": False,
                "propagation": 0,
            }
        ],
        "log_path": "runtime.log" if runtime else "init.log",
        "stdin": False,
        "stdin_once": False,
        "tty": False,
        "linux": {"security_context": security},
    }


def validate(path, document, expected):
    errors = list(Draft202012Validator(schema_for(expected)).iter_errors(document))
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"{path} violates CRI fixture schema at {location}: {error.message}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", action="store_true")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("sandbox")
    parser.add_argument("initializer")
    parser.add_argument("runtime")
    arguments = parser.parse_args()
    try:
        if not DIGEST.fullmatch(arguments.digest):
            raise ValueError("OCI manifest digest is not lowercase sha256 hex")
        if "/" not in arguments.repository or "." not in arguments.repository.split("/", 1)[0]:
            raise ValueError("OCI image repository is not fully qualified")
        image = f"{arguments.repository}@sha256:{arguments.digest}"
        sandbox = load_json(arguments.sandbox, False, image)
        initializer = load_json(arguments.initializer, arguments.template, image)
        runtime = load_json(arguments.runtime, arguments.template, image)
        validate(arguments.sandbox, sandbox, sandbox_contract())
        validate(arguments.initializer, initializer, container_contract(image, False))
        validate(arguments.runtime, runtime, container_contract(image, True))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"CRI fixture validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
