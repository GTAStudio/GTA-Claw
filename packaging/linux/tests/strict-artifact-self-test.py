#!/usr/bin/env python3

import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def root(name="./", mode=0o755, uid=0, gid=0):
    entry = tarfile.TarInfo(name)
    entry.type = tarfile.DIRTYPE
    entry.mode = mode
    entry.uid = uid
    entry.gid = gid
    entry.size = 0
    return entry


def regular(name="payload", content=b"payload\n"):
    entry = tarfile.TarInfo(name)
    entry.type = tarfile.REGTYPE
    entry.mode = 0o644
    entry.uid = 0
    entry.gid = 0
    entry.size = len(content)
    return entry, content


def write_archive(path, entries):
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            if isinstance(entry, tuple):
                metadata, content = entry
                archive.addfile(metadata, io.BytesIO(content))
            else:
                archive.addfile(entry)


def validate(validator, archive, policy):
    return subprocess.run(
        [
            sys.executable,
            validator,
            "tar",
            archive,
            "none",
            str(1024 * 1024),
            str(1024 * 1024),
            str(1024 * 1024),
            "32",
            policy,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def main():
    validator = Path(__file__).parents[1] / "strict_artifact.py"
    with tempfile.TemporaryDirectory(prefix="gta-claw-strict-root-") as temporary:
        root_path = Path(temporary)
        cases = {
            "missing-root": ([regular()], "required"),
            "duplicate-root": ([root("."), root("./"), regular()], "required"),
            "wrong-mode": ([root(mode=0o777), regular()], "required"),
            "wrong-owner": ([root(uid=1), regular()], "required"),
            "special-bits": ([root(mode=0o4755), regular()], "required"),
            "forbidden-root": ([root(), regular()], "forbidden"),
        }
        valid = root_path / "valid.tar"
        write_archive(valid, [root(), regular()])
        result = validate(validator, valid, "required")
        if result.returncode != 0:
            print(f"valid root archive rejected: {result.stderr}", file=sys.stderr)
            return 1
        for name, (entries, policy) in cases.items():
            archive = root_path / f"{name}.tar"
            write_archive(archive, entries)
            result = validate(validator, archive, policy)
            if result.returncode == 0:
                print(f"strict archive policy accepted {name}", file=sys.stderr)
                return 1
    print(f"Strict archive root self-tests passed ({len(cases) + 1} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
