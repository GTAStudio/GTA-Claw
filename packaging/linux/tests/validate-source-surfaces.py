#!/usr/bin/env python3

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

EXECUTABLE_SURFACES = frozenset(
    {
        "build-container.sh",
        "build-manifest-self-test-container.sh",
        "build-manifest-self-test.sh",
        "build.sh",
        "config.sh",
        "debian/postinst",
        "debian/postrm",
        "debian/preinst.in",
        "debian/prerm",
        "direct/install.sh",
        "direct/uninstall.sh",
        "lib/build-manifest.sh",
        "lib/common.sh",
        "lib/container-mount.sh",
        "lib/oci-validation.sh",
        "lib/worktree-git.sh",
        "libexec/gta-claw-runtime-ready",
        "libexec/gta-claw-state-init",
        "lifecycle-test.sh",
        "oci-self-test-container.sh",
        "oci-self-test.sh",
        "oci/cri-probe.sh",
        "package-container.sh",
        "package.sh",
        "release.sh",
        "rpm/post",
        "rpm/posttrans",
        "rpm/postun",
        "rpm/pre.in",
        "rpm/preun",
        "safeio-self-test.sh",
        "safeio.py",
        "self-test.sh",
        "strict_artifact.py",
        "strict_elf.py",
        "tests/make-malicious-tar.py",
        "tests/reject-javascript-commands-self-test.py",
        "tests/reject-javascript-commands.py",
        "tests/validate-cri-fixtures.py",
        "tests/validate-generated-metadata.py",
        "tests/validate-orchestration.py",
        "tests/validate-source-surfaces.py",
        "validate-oci-artifact.sh",
        "validate.sh",
        "workflow-self-test.sh",
    }
)


def fail(message):
    raise ValueError(message)


def validate_types(root):
    root_metadata = os.lstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode):
        fail(f"Linux packaging root is not a physical directory: {root}")
    for directory, names, files in os.walk(root, followlinks=False):
        for name in sorted((*names, *files)):
            path = Path(directory, name)
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"Linux packaging source must not be a symlink: {path}")
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                fail(f"Linux packaging source has a special file type: {path}")


def git_modes(repository, root):
    result = subprocess.run(
        ["git", "-C", repository, "ls-files", "--stage", "--", root],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    modes = {}
    for line in result.stdout.splitlines():
        metadata, path = line.split("\t", 1)
        mode = metadata.split(" ", 1)[0]
        relative = Path(path).relative_to(root).as_posix()
        modes[relative] = mode
    return modes


def validate_repository(repository, root):
    modes = git_modes(repository, root)
    missing = sorted(EXECUTABLE_SURFACES - modes.keys())
    if missing:
        fail(f"required Linux packaging executables are untracked: {', '.join(missing)}")
    wrong_modes = sorted(
        path for path in EXECUTABLE_SURFACES if modes.get(path) != "100755"
    )
    if wrong_modes:
        fail(
            "required Linux packaging executables are not tracked mode 100755: "
            + ", ".join(wrong_modes)
        )
    unexpected = sorted(path for path, mode in modes.items() if mode == "100755" and path not in EXECUTABLE_SURFACES)
    if unexpected:
        fail(f"unexpected executable Linux packaging sources: {', '.join(unexpected)}")
    for relative in EXECUTABLE_SURFACES:
        path = Path(repository, root, relative)
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
            fail(f"required Linux packaging executable is not a physical executable: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--types-only", action="store_true")
    parser.add_argument("root")
    arguments = parser.parse_args()
    root = Path(arguments.root)
    try:
        validate_types(root)
        if not arguments.types_only:
            repository = subprocess.run(
                ["git", "-C", root, "rev-parse", "--show-toplevel"],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            relative = root.resolve().relative_to(Path(repository).resolve()).as_posix()
            validate_repository(repository, relative)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Linux packaging source policy failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
