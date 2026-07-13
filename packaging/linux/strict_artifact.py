#!/usr/bin/env python3

import json
import gzip
import os
import sys
import tarfile


def fail(message: str) -> None:
    raise SystemExit(f"strict-artifact: {message}")


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_int(value: str) -> int:
    number = int(value)
    if number < 0 or number > 2**63 - 1:
        fail(f"JSON integer is outside the accepted range: {value}")
    return number


def reject_float(value: str):
    fail(f"JSON floating-point value is forbidden: {value}")


def validate_json(path: str) -> None:
    size = os.path.getsize(path)
    if size > 1024 * 1024:
        fail(f"JSON file exceeds 1 MiB: {path}")
    with open(path, "r", encoding="utf-8") as source:
        try:
            value = json.load(
                source,
                object_pairs_hook=strict_pairs,
                parse_int=strict_int,
                parse_float=reject_float,
                parse_constant=reject_float,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            fail(f"invalid strict JSON in {path}: {error}")
    if not isinstance(value, dict):
        fail(f"top-level JSON value is not an object: {path}")
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def normalize_member(name: str) -> str:
    if name in (".", "./"):
        return ""
    if (
        "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in name)
    ):
        fail(f"unsafe archive member name: {name!r}")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name:
        return ""
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail(f"unsafe archive member component: {name!r}")
    if any(part.startswith(".wh.") for part in parts):
        fail(f"OCI whiteout is forbidden: {name!r}")
    return name


def validate_tar(arguments: list[str]) -> None:
    if len(arguments) != 6:
        fail(
            "usage: strict_artifact.py tar ARCHIVE gzip|none "
            "MAX_COMPRESSED MAX_EXPANDED MAX_FILE MAX_MEMBERS"
        )
    path, compression = arguments[:2]
    max_compressed, max_expanded, max_file, max_members = map(int, arguments[2:])
    compressed_size = os.path.getsize(path)
    if compressed_size > max_compressed:
        fail(f"archive compressed size exceeds limit: {compressed_size}")
    if compression == "gzip":
        expanded_stream = 0
        try:
            with gzip.open(path, "rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    expanded_stream += len(chunk)
                    if expanded_stream > max_expanded:
                        fail("raw gzip expansion exceeds archive limit")
        except (gzip.BadGzipFile, EOFError, OSError) as error:
            fail(f"invalid gzip stream {path}: {error}")
    mode = "r:gz" if compression == "gzip" else "r:"
    names = set()
    entries = []
    total = 0
    try:
        with tarfile.open(path, mode) as archive:
            for index, member in enumerate(archive, start=1):
                if index > max_members:
                    fail(f"archive member count exceeds {max_members}")
                name = normalize_member(member.name)
                if not name:
                    continue
                if name in names:
                    fail(f"duplicate normalized archive member: {name}")
                names.add(name)
                if not (member.isfile() or member.isdir()):
                    fail(f"archive member has forbidden type: {name}")
                if member.mode & 0o7000:
                    fail(f"archive member has special permission bits: {name}")
                if member.size < 0 or member.size > max_file:
                    fail(f"archive member size exceeds limit: {name}")
                total += member.size
                if total > max_expanded:
                    fail("archive expanded size exceeds limit")
                entries.append(
                    {
                        "name": name,
                        "type": "file" if member.isfile() else "directory",
                        "size": member.size,
                        "mode": f"{member.mode:04o}",
                        "uid": member.uid,
                        "gid": member.gid,
                    }
                )
    except (tarfile.TarError, EOFError, OSError) as error:
        fail(f"invalid archive {path}: {error}")
    print(json.dumps(entries, sort_keys=True, separators=(",", ":")))


def main() -> None:
    if len(sys.argv) < 3:
        fail("expected json or tar command")
    command = sys.argv[1]
    if command == "json" and len(sys.argv) == 3:
        validate_json(sys.argv[2])
    elif command == "tar":
        validate_tar(sys.argv[2:])
    else:
        fail("invalid command or arguments")


if __name__ == "__main__":
    main()
