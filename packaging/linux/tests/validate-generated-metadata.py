#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def load_json(path):
    seen = []

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path} contains duplicate key {key!r}")
            result[key] = value
        seen.append(result)
        return result

    with Path(path).open(encoding="utf-8") as source:
        return json.load(source, object_pairs_hook=unique_object)


def digest(path, algorithm):
    hasher = hashlib.new(algorithm)
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def package_version(name):
    return subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", name],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout


def expected_toolchain(arguments):
    return {
        "schemaVersion": 1,
        "image": arguments.build_image,
        "environmentImageId": os.environ["PACKAGING_IMAGE_ID"],
        "debianSnapshot": arguments.debian_snapshot,
        "packages": {
            name: package_version(name)
            for name in (
                "dpkg",
                "rpm",
                "tar",
                "gzip",
                "jq",
                "python3",
                "python3-jsonschema",
                "python3-yaml",
                "cpio",
            )
        },
    }


def expected_provenance(arguments, build_manifest, runtime_manifest, toolchain):
    root = Path(arguments.root)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": arguments.daemon,
                "digest": {"sha256": digest(root / arguments.daemon, "sha256")},
            },
            {
                "name": arguments.cli,
                "digest": {"sha256": digest(root / arguments.cli, "sha256")},
            },
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/GTAStudio/GTA-Claw/packaging/linux/v1",
                "externalParameters": {
                    "architecture": arguments.arch,
                    "rustTarget": arguments.target,
                    "version": arguments.version,
                },
                "internalParameters": {
                    "sourceDateEpoch": int(arguments.source_epoch)
                },
                "resolvedDependencies": [
                    {
                        "uri": (
                            "git+https://github.com/GTAStudio/GTA-Claw.git@"
                            + arguments.source_sha
                        ),
                        "digest": {
                            "gitCommit": arguments.source_sha,
                            "gitTree": arguments.source_tree,
                        },
                    }
                ],
                "buildManifest": {
                    "digest": {
                        "sha256": digest(arguments.build_manifest, "sha256")
                    },
                    "content": build_manifest,
                },
                "runtimeDependencies": runtime_manifest["packages"],
                "packageToolchain": toolchain,
            },
            "runDetails": {
                "builder": {
                    "id": (
                        "https://github.com/GTAStudio/GTA-Claw/blob/"
                        f"{arguments.source_sha}/packaging/linux/package.sh"
                    )
                }
            },
        },
    }


def runtime_owner(path, runtime_manifest, label):
    if label != "oci":
        return "gta-claw"
    owners = [
        package["id"]
        for package in runtime_manifest["packages"]
        if any(item["targetPath"] == path for item in package["files"])
        or any(item["targetPath"] == path for item in package["licenseMaterials"])
    ]
    return owners[0] if owners else "gta-claw"


def verification_code(records, owner):
    values = sorted(
        checksum["checksumValue"]
        for record in records
        if record["owner"] == owner
        for checksum in record["checksums"]
        if checksum["algorithm"] == "SHA1"
    )
    return hashlib.sha1("".join(values).encode("ascii")).hexdigest() if values else ""


def expected_spdx(arguments, runtime_manifest):
    root = Path(arguments.root)
    sbom_relative = f"./{arguments.sbom}"
    checksum_parent = Path(arguments.sbom).parent.as_posix()
    checksum_relative = (
        "./SHA256SUMS"
        if checksum_parent == "."
        else f"./{checksum_parent}/SHA256SUMS"
    )
    excluded = {arguments.sbom, str(Path(arguments.sbom).with_name("SHA256SUMS"))}
    records = []
    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() not in excluded
    ]
    files.sort(key=lambda path: f"./{path.relative_to(root).as_posix()}")
    for index, path in enumerate(
        files,
        start=1,
    ):
        relative = path.relative_to(root).as_posix()
        target = f"/{relative}"
        owner = runtime_owner(target, runtime_manifest, arguments.label)
        license_expression = {
            "libc6": "LGPL-2.1-or-later",
            "libgcc-s1": "GPL-3.0-or-later WITH GCC-exception-3.1",
        }.get(owner, "MIT")
        records.append(
            {
                "SPDXID": f"SPDXRef-File-{index}",
                "owner": owner,
                "fileName": f"./{relative}",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": digest(path, "sha1")},
                    {"algorithm": "SHA256", "checksumValue": digest(path, "sha256")},
                ],
                "licenseConcluded": license_expression,
                "licenseInfoInFiles": [license_expression],
                "copyrightText": "NOASSERTION",
            }
        )

    package_by_id = {package["id"]: package for package in runtime_manifest["packages"]}
    dependency_packages = []
    for package_id, license_expression in (
        ("libc6", "LGPL-2.1-or-later"),
        ("libgcc-s1", "GPL-3.0-or-later WITH GCC-exception-3.1"),
    ):
        package = package_by_id[package_id]
        verification = verification_code(records, package_id)
        item = {
            "SPDXID": f"SPDXRef-Package-{package_id}",
            "name": package_id,
            "versionInfo": package["version"],
            "comment": f"Debian architecture: {package['architecture']}",
            "supplier": "Organization: Debian",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": bool(verification),
            "licenseConcluded": license_expression,
            "licenseDeclared": license_expression,
            "copyrightText": "NOASSERTION",
        }
        if verification:
            item["packageVerificationCode"] = {
                "packageVerificationCodeValue": verification
            }
        dependency_packages.append(item)

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-GTA-Claw",
        },
        {
            "spdxElementId": "SPDXRef-Package-GTA-Claw",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-libc6",
        },
        {
            "spdxElementId": "SPDXRef-Package-GTA-Claw",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-libgcc-s1",
        },
    ]
    relationships.extend(
        {
            "spdxElementId": (
                f"SPDXRef-Package-{record['owner']}"
                if record["owner"] in {"libc6", "libgcc-s1"}
                else "SPDXRef-Package-GTA-Claw"
            ),
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": record["SPDXID"],
        }
        for record in records
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "gta-claw-linux-headless",
        "documentNamespace": (
            "https://github.com/GTAStudio/GTA-Claw/spdx/"
            f"{arguments.source_sha}/{arguments.arch}/{arguments.label}"
        ),
        "creationInfo": {
            "created": arguments.created,
            "creators": ["Tool: packaging/linux/package.sh"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-GTA-Claw",
                "name": "gta-claw",
                "versionInfo": arguments.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": verification_code(
                        records, "gta-claw"
                    ),
                    "packageVerificationCodeExcludedFiles": [
                        sbom_relative,
                        checksum_relative,
                    ],
                },
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": (
                            f"pkg:github/GTAStudio/GTA-Claw@{arguments.source_sha}"
                        ),
                    }
                ],
            },
            *dependency_packages,
        ],
        "files": [{key: value for key, value in record.items() if key != "owner"} for record in records],
        "relationships": relationships,
    }


def expected_artifact_provenance(
    arguments, build_manifest, runtime_manifest, toolchain
):
    artifact_dir = Path(arguments.artifact_dir)
    return {
        "schemaVersion": 1,
        "source": {
            "repository": "https://github.com/GTAStudio/GTA-Claw",
            "revision": arguments.source_sha,
            "tree": arguments.source_tree,
        },
        "buildManifest": {
            "digest": {"sha256": digest(arguments.build_manifest, "sha256")},
            "content": build_manifest,
        },
        "runtimeDependencies": runtime_manifest["packages"],
        "packageToolchain": toolchain,
        "package": {
            "name": "gta-claw",
            "version": arguments.version,
            "architecture": arguments.arch,
        },
        "subjects": [
            {
                "name": name,
                "digest": {"sha256": digest(artifact_dir / name, "sha256")},
            }
            for name in arguments.artifact_subject
        ],
    }


def first_difference(actual, expected, path="<root>"):
    if type(actual) is not type(expected):
        return f"{path}: type {type(actual).__name__} != {type(expected).__name__}"
    if isinstance(actual, dict):
        if actual.keys() != expected.keys():
            return (
                f"{path}: keys {sorted(actual)} != {sorted(expected)}"
            )
        for key in actual:
            difference = first_difference(actual[key], expected[key], f"{path}.{key}")
            if difference:
                return difference
        return None
    if isinstance(actual, list):
        if len(actual) != len(expected):
            return f"{path}: length {len(actual)} != {len(expected)}"
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            difference = first_difference(
                actual_item, expected_item, f"{path}[{index}]"
            )
            if difference:
                return difference
        return None
    if actual != expected:
        return f"{path}: {actual!r} != {expected!r}"
    return None


def compare(actual, expected, label):
    difference = first_difference(actual, expected)
    if difference:
        raise ValueError(
            f"{label} differs from independently reconstructed metadata: {difference}"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--build-manifest", required=True)
    parser.add_argument("--runtime-manifest", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-epoch", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-image", required=True)
    parser.add_argument("--debian-snapshot", required=True)
    parser.add_argument("--artifact-dir")
    parser.add_argument("--artifact-provenance")
    parser.add_argument("--artifact-subject", action="append", default=[])
    arguments = parser.parse_args()
    try:
        root = Path(arguments.root)
        build_manifest = load_json(arguments.build_manifest)
        runtime_manifest = load_json(arguments.runtime_manifest)
        toolchain = expected_toolchain(arguments)
        compare(
            load_json(root / arguments.toolchain),
            toolchain,
            "package toolchain",
        )
        compare(
            load_json(root / arguments.provenance),
            expected_provenance(arguments, build_manifest, runtime_manifest, toolchain),
            "provenance",
        )
        compare(
            load_json(root / arguments.sbom),
            expected_spdx(arguments, runtime_manifest),
            "SPDX SBOM",
        )
        if arguments.artifact_provenance:
            if not arguments.artifact_dir or not arguments.artifact_subject:
                raise ValueError(
                    "artifact provenance validation requires its directory and subjects"
                )
            compare(
                load_json(arguments.artifact_provenance),
                expected_artifact_provenance(
                    arguments, build_manifest, runtime_manifest, toolchain
                ),
                "artifact provenance",
            )
    except (
        KeyError,
        OSError,
        subprocess.CalledProcessError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"generated metadata validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
