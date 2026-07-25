#!/usr/bin/env python3

import argparse
import ctypes
import errno
import os
import re
import stat
import sys
import time
from pathlib import Path


O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0o400000)
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
SYS_OPENAT2 = 437
libc = ctypes.CDLL(None, use_errno=True)
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ulonglong),
        ("mode", ctypes.c_ulonglong),
        ("resolve", ctypes.c_ulonglong),
    ]


def fail(message):
    raise ValueError(message)


def openat2(directory_fd, path, flags, mode=0):
    encoded = os.fsencode(path)
    how = OpenHow(
        flags=flags | O_NOFOLLOW,
        mode=mode,
        resolve=RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    )
    fd = libc.syscall(
        SYS_OPENAT2,
        directory_fd,
        ctypes.c_char_p(encoded),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), path)
    return fd


def validate_directory(fd, label, mode):
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} is not a directory")
    if (metadata.st_uid, metadata.st_gid) != (0, 0):
        fail(f"{label} is not root-owned")
    if stat.S_IMODE(metadata.st_mode) != mode:
        fail(f"{label} mode is not {mode:04o}")


def open_or_create_directory(parent_fd, name, label, mode, create):
    try:
        return openat2(parent_fd, name, os.O_RDONLY | os.O_DIRECTORY)
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
        fd = openat2(parent_fd, name, os.O_RDONLY | os.O_DIRECTORY)
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        os.fsync(parent_fd)
        return fd


def validate_source(path, label):
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} source is not a physical regular file")
    if metadata.st_nlink != 1:
        fail(f"{label} source has multiple hard links")
    return Path(path).read_bytes()


def validate_environment(content):
    text = content.decode("utf-8", "strict")
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ASSIGNMENT.match(stripped):
            fail(
                "gta-claw.env currently permits comments only; "
                f"environment assignment found on line {number}"
            )
        fail(f"invalid gta-claw.env syntax on line {number}")


def validate_file(fd, label, mode):
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} is not a regular file")
    if (metadata.st_uid, metadata.st_gid) != (0, 0):
        fail(f"{label} is not root-owned")
    if stat.S_IMODE(metadata.st_mode) != mode:
        fail(f"{label} mode is not {mode:04o}")
    if metadata.st_nlink != 1:
        fail(f"{label} has multiple hard links")
    return metadata.st_dev, metadata.st_ino


def install_or_open(parent_fd, name, label, mode, content, create):
    try:
        fd = openat2(parent_fd, name, os.O_RDONLY)
    except FileNotFoundError:
        if not create:
            raise
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
            mode,
            dir_fd=parent_fd,
        )
        try:
            os.write(fd, content)
            os.fchmod(fd, mode)
            os.fchown(fd, 0, 0)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        fd = openat2(parent_fd, name, os.O_RDONLY)
    identity = validate_file(fd, label, mode)
    return fd, identity


def verify_path_identity(parent_fd, name, held_fd, expected, label):
    current = openat2(parent_fd, name, os.O_RDONLY)
    try:
        metadata = os.fstat(current)
        if (metadata.st_dev, metadata.st_ino) != expected:
            fail(f"{label} path identity changed during validation")
        validate_file(held_fd, label, stat.S_IMODE(os.fstat(held_fd).st_mode))
    finally:
        os.close(current)


def verify_directory_identity(parent_fd, name, held_fd, label):
    current = openat2(parent_fd, name, os.O_RDONLY | os.O_DIRECTORY)
    try:
        current_metadata = os.fstat(current)
        held_metadata = os.fstat(held_fd)
        if (current_metadata.st_dev, current_metadata.st_ino) != (
            held_metadata.st_dev,
            held_metadata.st_ino,
        ):
            fail(f"{label} identity changed during validation")
    finally:
        os.close(current)


def wait_test_gate():
    entered = os.environ.get("GTA_CLAW_DIRECT_CONFIG_GATE_ENTERED")
    release = os.environ.get("GTA_CLAW_DIRECT_CONFIG_GATE_RELEASE")
    if not entered and not release:
        return
    if not entered or not release:
        fail("direct config test gate is incomplete")
    Path(entered).touch(exist_ok=False)
    while not Path(release).exists():
        time.sleep(0.01)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("install", "verify"))
    parser.add_argument("root")
    parser.add_argument("environment_source")
    parser.add_argument("credential_source")
    arguments = parser.parse_args()
    descriptors = []
    try:
        root = os.path.realpath(arguments.root)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW)
        descriptors.append(root_fd)
        validate_directory(root_fd, "configuration root", 0o755)
        etc_mode = 0o755
        etc_fd = open_or_create_directory(
            root_fd, "etc", "configuration /etc", etc_mode, arguments.operation == "install"
        )
        descriptors.append(etc_fd)
        validate_directory(etc_fd, "configuration /etc", etc_mode)
        config_fd = open_or_create_directory(
            etc_fd,
            "gta-claw",
            "configuration directory",
            0o755,
            arguments.operation == "install",
        )
        descriptors.append(config_fd)
        validate_directory(config_fd, "configuration directory", 0o755)
        credential_dir_fd = open_or_create_directory(
            config_fd,
            "credentials",
            "credential directory",
            0o700,
            arguments.operation == "install",
        )
        descriptors.append(credential_dir_fd)
        validate_directory(credential_dir_fd, "credential directory", 0o700)
        environment_content = validate_source(
            arguments.environment_source, "environment"
        )
        credential_content = validate_source(
            arguments.credential_source, "credential"
        )
        validate_environment(environment_content)
        environment_fd, environment_identity = install_or_open(
            config_fd,
            "gta-claw.env",
            "environment file",
            0o640,
            environment_content,
            arguments.operation == "install",
        )
        descriptors.append(environment_fd)
        environment_length = os.fstat(environment_fd).st_size
        validate_environment(os.pread(environment_fd, environment_length, 0))
        credential_fd, credential_identity = install_or_open(
            credential_dir_fd,
            "daemon.conf",
            "credential file",
            0o600,
            credential_content,
            arguments.operation == "install",
        )
        descriptors.append(credential_fd)
        wait_test_gate()
        verify_path_identity(
            config_fd,
            "gta-claw.env",
            environment_fd,
            environment_identity,
            "environment file",
        )
        verify_path_identity(
            credential_dir_fd,
            "daemon.conf",
            credential_fd,
            credential_identity,
            "credential file",
        )
        verify_directory_identity(root_fd, "etc", etc_fd, "configuration /etc")
        verify_directory_identity(
            etc_fd, "gta-claw", config_fd, "configuration directory"
        )
        verify_directory_identity(
            config_fd,
            "credentials",
            credential_dir_fd,
            "credential directory",
        )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"direct configuration validation failed: {error}", file=sys.stderr)
        return 1
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
