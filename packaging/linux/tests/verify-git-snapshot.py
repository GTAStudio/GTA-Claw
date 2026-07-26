#!/usr/bin/env python3

import argparse
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path


def git(repository, *arguments, input_bytes=None):
    return subprocess.run(
        ["git", "-C", repository, *arguments],
        check=True,
        input=input_bytes,
        stdout=subprocess.PIPE,
    ).stdout


def blob_id(repository, content):
    return git(repository, "hash-object", "--stdin", input_bytes=content).decode().strip()


def expected_entries(repository, commit):
    output = git(repository, "ls-tree", "-rz", "--full-tree", "-r", commit)
    entries = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", "strict")
        if object_type != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError(f"unsupported Git tree entry {mode} {object_type} {path}")
        if path in entries:
            raise ValueError(f"duplicate Git tree path: {path}")
        entries[path] = (mode, object_id)
    return entries


def actual_entries(root):
    entries = {}
    for directory, names, files in os.walk(root, followlinks=False):
        for name in sorted((*names, *files)):
            path = Path(directory, name)
            relative = path.relative_to(root).as_posix()
            metadata = os.lstat(path)
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if stat.S_ISLNK(metadata.st_mode):
                content = os.readlink(path).encode("utf-8")
                mode = "120000"
            elif stat.S_ISREG(metadata.st_mode):
                content = path.read_bytes()
                mode = "100755" if metadata.st_mode & 0o111 else "100644"
            else:
                raise ValueError(f"snapshot contains a special file: {relative}")
            entries[relative] = (mode, content)
    return entries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repository")
    parser.add_argument("commit")
    parser.add_argument("tree")
    parser.add_argument("archive")
    parser.add_argument("snapshot")
    arguments = parser.parse_args()
    try:
        repository = Path(arguments.repository).resolve(strict=True)
        archive = Path(arguments.archive).resolve(strict=True)
        snapshot = Path(arguments.snapshot).resolve(strict=True)
        if not snapshot.is_dir() or snapshot.is_symlink():
            raise ValueError("snapshot root is not a physical directory")
        expected_commit = git(repository, "rev-parse", f"{arguments.commit}^{{commit}}").decode().strip()
        expected_tree = git(repository, "rev-parse", f"{expected_commit}^{{tree}}").decode().strip()
        if expected_commit != arguments.commit or expected_tree != arguments.tree:
            raise ValueError("requested Git commit/tree identity changed")
        archived_commit = subprocess.run(
            ["git", "get-tar-commit-id"],
            check=True,
            stdin=archive.open("rb"),
            stdout=subprocess.PIPE,
        ).stdout.decode().strip()
        if archived_commit != expected_commit:
            raise ValueError("Git archive does not bind the requested commit")
        expected = expected_entries(repository, expected_commit)
        actual = actual_entries(snapshot)
        if set(actual) != set(expected):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            raise ValueError(f"snapshot tree paths differ: missing={missing} extra={extra}")
        for path, (expected_mode, expected_id) in expected.items():
            actual_mode, content = actual[path]
            if actual_mode != expected_mode:
                raise ValueError(
                    f"snapshot mode differs for {path}: {actual_mode} != {expected_mode}"
                )
            if blob_id(repository, content) != expected_id:
                raise ValueError(f"snapshot bytes differ from Git blob: {path}")
        tree_receipt = hashlib.sha256(
            b"\0".join(
                f"{path}\t{mode}\t{object_id}".encode()
                for path, (mode, object_id) in sorted(expected.items())
            )
        ).hexdigest()
        print(f"{expected_commit}|{expected_tree}|{tree_receipt}")
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Git snapshot verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
