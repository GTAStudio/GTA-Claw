#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


DIGEST = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY = re.compile(
    r"^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?/"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


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


def compose_contract(image):
    volume = "gta-claw-state:/var/lib"
    return {
        "services": {
            "gta-claw-init": {
                "image": image,
                "user": "0:0",
                "entrypoint": ["/usr/libexec/gta-claw/gta-claw-daemon"],
                "command": [
                    "--prepare-linux-protected",
                    "--state-path",
                    "/var/lib/gta-claw-protected",
                    "--service-uid",
                    "65532",
                    "--service-gid",
                    "65532",
                ],
                "cap_drop": ["ALL"],
                "cap_add": ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
                "security_opt": ["no-new-privileges:true"],
                "restart": "no",
                "volumes": [volume],
            },
            "gta-claw": {
                "image": image,
                "user": "65532:65532",
                "depends_on": {
                    "gta-claw-init": {"condition": "service_completed_successfully"}
                },
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "restart": "unless-stopped",
                "volumes": [volume],
            },
        },
        "volumes": {"gta-claw-state": None},
    }


def kubernetes_contract(image):
    init_security = {
        "runAsUser": 0,
        "runAsGroup": 0,
        "allowPrivilegeEscalation": False,
        "capabilities": {
            "drop": ["ALL"],
            "add": ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
        },
    }
    runtime_security = {
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "runAsGroup": 65532,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    mount = [{"name": "state", "mountPath": "/var/lib"}]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "gta-claw"},
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": {"app": "gta-claw"}},
            "template": {
                "metadata": {"labels": {"app": "gta-claw"}},
                "spec": {
                    "initContainers": [
                        {
                            "name": "linux-protected-init",
                            "image": image,
                            "command": ["/usr/libexec/gta-claw/gta-claw-daemon"],
                            "args": [
                                "--prepare-linux-protected",
                                "--state-path",
                                "/var/lib/gta-claw-protected",
                                "--service-uid",
                                "65532",
                                "--service-gid",
                                "65532",
                            ],
                            "securityContext": init_security,
                            "volumeMounts": mount,
                        }
                    ],
                    "containers": [
                        {
                            "name": "gta-claw",
                            "image": image,
                            "securityContext": runtime_security,
                            "volumeMounts": mount,
                        }
                    ],
                    "volumes": [
                        {
                            "name": "state",
                            "persistentVolumeClaim": {"claimName": "gta-claw-state"},
                        }
                    ],
                },
            },
        },
    }


def load_one(path, template, image):
    text = Path(path).read_text(encoding="utf-8")
    if template:
        if text.count("@OCI_IMAGE_REFERENCE@") != 2:
            raise ValueError(f"{path} must contain exactly two image placeholders")
        text = text.replace("@OCI_IMAGE_REFERENCE@", image)
    elif "@OCI_IMAGE_REFERENCE@" in text:
        raise ValueError(f"{path} retains an image placeholder")
    documents = list(yaml.load_all(text, Loader=UniqueKeyLoader))
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise ValueError(f"{path} must contain exactly one YAML mapping document")
    return documents[0]


def validate(path, document, expected):
    errors = sorted(
        Draft202012Validator(schema_for(expected)).iter_errors(document),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"{path} violates orchestration schema at {location}: {error.message}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", action="store_true")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("compose")
    parser.add_argument("kubernetes")
    arguments = parser.parse_args()
    try:
        if not REPOSITORY.fullmatch(arguments.repository):
            raise ValueError("OCI image repository is not fully qualified")
        if not DIGEST.fullmatch(arguments.digest):
            raise ValueError("OCI manifest digest is not lowercase sha256 hex")
        image = f"{arguments.repository}@sha256:{arguments.digest}"
        compose = load_one(arguments.compose, arguments.template, image)
        kubernetes = load_one(arguments.kubernetes, arguments.template, image)
        validate(arguments.compose, compose, compose_contract(image))
        validate(arguments.kubernetes, kubernetes, kubernetes_contract(image))
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"OCI orchestration validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
