#!/usr/bin/env python3

import argparse
import ctypes
import errno
import ipaddress
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0o400000)
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
SYS_OPENAT2 = 437
libc = ctypes.CDLL(None, use_errno=True)
ALLOWED_ENVIRONMENT_KEYS = {
    "AGENT_ROLE_URL",
    "DEVICE_FLOW_ENABLED",
    "ENABLE_TEAMS",
    "GITHUB_CLIENT_ID",
}
PREDECESSOR_ENVIRONMENT = (
    b"# Non-secret process environment only.\n"
    b"#\n"
    b"# The current daemon accepts no environment-backed runtime configuration.\n"
    b"# Never place tokens, passwords, or private keys here. Future secrets must be\n"
    b"# supplied through /etc/gta-claw/credentials/daemon.conf and consumed from the\n"
    b"# systemd CREDENTIALS_DIRECTORY by a daemon version that explicitly supports it.\n"
)


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
    if any(character != "\n" and not 32 <= ord(character) <= 126 for character in text):
        fail("gta-claw.env permits only visible ASCII and LF line endings")
    assignments = {}
    for number, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if line.endswith("\\"):
                fail(f"gta-claw.env comment continuation is forbidden on line {number}")
            continue
        if stripped != line:
            fail(f"gta-claw.env has surrounding whitespace on line {number}")
        if "=" not in line:
            fail(f"invalid gta-claw.env syntax on line {number}")
        key, value = line.split("=", 1)
        if (
            not key
            or not key[0].isupper()
            or not key.isascii()
            or any(not (character.isupper() or character.isdigit() or character == "_") for character in key)
        ):
            fail(f"invalid gta-claw.env key on line {number}")
        if key not in ALLOWED_ENVIRONMENT_KEYS:
            if any(
                marker in key
                for marker in ("TOKEN", "SECRET", "PASSWORD", "PRIVATE", "PROXY")
            ):
                fail(f"secret-like gta-claw.env key is forbidden on line {number}: {key}")
            fail(f"unknown gta-claw.env key on line {number}: {key}")
        if key in assignments:
            fail(f"duplicate gta-claw.env key on line {number}: {key}")
        if (
            not value
            or any(not 33 <= ord(character) <= 126 or character in "\"'\\" for character in value)
        ):
            fail(f"invalid gta-claw.env value on line {number}: {key}")
        assignments[key] = value

    if assignments.get("ENABLE_TEAMS") != "false":
        fail("gta-claw.env must set ENABLE_TEAMS=false exactly once")
    if "AGENT_ROLE_URL" in assignments:
        role_url = urlsplit(assignments["AGENT_ROLE_URL"])
        try:
            role_port = role_url.port
        except ValueError as error:
            fail(f"invalid AGENT_ROLE_URL port: {error}")
        if (
            role_url.scheme not in ("http", "https")
            or role_url.hostname is None
            or role_url.username is not None
            or role_url.password is not None
            or role_url.fragment
            or role_url.query
            or role_port == 0
        ):
            fail("AGENT_ROLE_URL must be an absolute credential-free HTTP(S) URL without a query")
    has_device_setting = "DEVICE_FLOW_ENABLED" in assignments
    has_client_id = "GITHUB_CLIENT_ID" in assignments
    if has_device_setting != has_client_id:
        fail("DEVICE_FLOW_ENABLED and GITHUB_CLIENT_ID must be configured together")
    if has_device_setting:
        if assignments["DEVICE_FLOW_ENABLED"] != "true":
            fail("DEVICE_FLOW_ENABLED must be true when configured")
        client_id = assignments["GITHUB_CLIENT_ID"]
        if (
            len(client_id) > 128
            or not client_id[0].isalnum()
            or any(
                not (character.isalnum() or character in "_.-")
                for character in client_id
            )
        ):
            fail("GITHUB_CLIENT_ID is not a bounded non-secret identifier")


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


def migrate_predecessor_environment(parent_fd, fd, identity, content):
    metadata = os.fstat(fd)
    current = os.pread(fd, metadata.st_size, 0)
    if current != PREDECESSOR_ENVIRONMENT:
        return fd, identity
    temporary_name = ".gta-claw.env.migrate"
    try:
        temporary = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
            0o640,
            dir_fd=parent_fd,
        )
        try:
            offset = 0
            while offset < len(content):
                written = os.write(temporary, content[offset:])
                if written == 0:
                    fail("environment migration made no write progress")
                offset += written
            os.fchmod(temporary, 0o640)
            os.fchown(temporary, 0, 0)
            os.fsync(temporary)
        finally:
            os.close(temporary)
        os.rename(
            temporary_name,
            "gta-claw.env",
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except Exception:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise
    os.close(fd)
    fd = openat2(parent_fd, "gta-claw.env", os.O_RDONLY)
    return fd, validate_file(fd, "environment file", 0o640)


def verify_path_identity(parent_fd, name, held_fd, expected, label, mode):
    current = openat2(parent_fd, name, os.O_RDONLY)
    try:
        metadata = os.fstat(current)
        if (metadata.st_dev, metadata.st_ino) != expected:
            fail(f"{label} path identity changed during validation")
        validate_file(held_fd, label, mode)
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


def verify_held_content(fd, expected, label):
    metadata = os.fstat(fd)
    if metadata.st_size != len(expected):
        fail(f"{label} length changed during validation")
    if os.pread(fd, metadata.st_size, 0) != expected:
        fail(f"{label} content changed during validation")


def materialize_environment(root_fd, content):
    descriptors = []
    temporary_name = ".gta-claw.env.tmp"
    output_name = "gta-claw.env"
    try:
        run_fd = openat2(root_fd, "run", os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(run_fd)
        runtime_fd = openat2(
            run_fd, "gta-claw-state-init", os.O_RDONLY | os.O_DIRECTORY
        )
        descriptors.append(runtime_fd)
        validate_directory(runtime_fd, "validated environment runtime directory", 0o755)
        try:
            existing = openat2(runtime_fd, output_name, os.O_RDONLY)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            descriptors.append(existing)
            validate_file(existing, "validated environment file", 0o640)
        temporary = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
            0o640,
            dir_fd=runtime_fd,
        )
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(temporary, content[offset:])
            os.fchmod(temporary, 0o640)
            os.fchown(temporary, 0, 0)
            os.fsync(temporary)
        finally:
            os.close(temporary)
        if existing is not None:
            os.unlink(output_name, dir_fd=runtime_fd)
        os.rename(
            temporary_name,
            output_name,
            src_dir_fd=runtime_fd,
            dst_dir_fd=runtime_fd,
        )
        os.fsync(runtime_fd)
    except Exception:
        try:
            os.unlink(temporary_name, dir_fd=runtime_fd)
        except (NameError, FileNotFoundError):
            pass
        raise
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


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


def validate_effective_allowlist(unit):
    if (
        not unit.endswith(".service")
        or not unit.isascii()
        or any(
            not (character.isalnum() or character in "@_.:-") for character in unit
        )
    ):
        fail("network policy unit name is invalid")
    deny_result = subprocess.run(
        (
            "/usr/bin/systemctl",
            "show",
            "-P",
            "IPAddressDeny",
            unit,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        deny_networks = {
            ipaddress.ip_network(value, strict=False)
            for value in deny_result.stdout.split()
        }
    except ValueError as error:
        fail(f"effective systemd IPAddressDeny policy is invalid: {error}")
    if deny_result.returncode != 0 or deny_networks != {
        ipaddress.ip_network("0.0.0.0/0"),
        ipaddress.ip_network("::/0"),
    }:
        fail("effective systemd IPAddressDeny policy is not exactly dual-stack any")
    result = subprocess.run(
        (
            "/usr/bin/systemctl",
            "show",
            "-P",
            "IPAddressAllow",
            unit,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail("effective systemd IPAddressAllow policy is unavailable")
    try:
        networks = [
            ipaddress.ip_network(value, strict=False)
            for value in result.stdout.split()
        ]
    except ValueError as error:
        fail(f"effective systemd IPAddressAllow policy is invalid: {error}")
    if not networks:
        fail("operator-owned IPAddressAllow policy is missing")
    ipv4_canary = ipaddress.ip_address("127.255.255.254")
    ipv6_canary = ipaddress.ip_address("::1")
    for network in networks:
        if network.version == 4:
            if network.prefixlen < 24 or ipv4_canary in network:
                fail(f"operator IPv4 allow is not narrow: {network}")
        elif network.prefixlen < 64 or ipv6_canary in network:
            fail(f"operator IPv6 allow is not narrow: {network}")


def verify_network_denied(unit):
    validate_effective_allowlist(unit)
    targets = (
        (socket.AF_INET, ("127.255.255.254", 9)),
        (socket.AF_INET6, ("::1", 9, 0, 0)),
    )
    for family, target in targets:
        probe = socket.socket(family, socket.SOCK_DGRAM)
        try:
            try:
                probe.connect(target)
                probe.send(b"\0")
            except PermissionError:
                continue
            except OSError as error:
                fail(f"network-denial enforcement could not be proved: {error}")
            fail("network-denial enforcement is unavailable or over-broadly allowed")
        finally:
            probe.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation", choices=("install", "materialize", "network-deny-check", "verify")
    )
    parser.add_argument("root", nargs="?")
    parser.add_argument("environment_source", nargs="?")
    parser.add_argument("credential_source", nargs="?")
    arguments = parser.parse_args()
    if arguments.operation == "network-deny-check":
        if (
            arguments.root is None
            or arguments.environment_source is not None
            or arguments.credential_source is not None
        ):
            parser.error("network-deny-check requires exactly one UNIT argument")
        try:
            verify_network_denied(arguments.root)
        except ValueError as error:
            print(f"direct configuration validation failed: {error}", file=sys.stderr)
            return 1
        return 0
    if any(
        value is None
        for value in (
            arguments.root,
            arguments.environment_source,
            arguments.credential_source,
        )
    ):
        parser.error(f"{arguments.operation} requires ROOT ENVIRONMENT CREDENTIAL")
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
        if arguments.operation == "install":
            environment_fd, environment_identity = migrate_predecessor_environment(
                config_fd,
                environment_fd,
                environment_identity,
                environment_content,
            )
        descriptors.append(environment_fd)
        environment_length = os.fstat(environment_fd).st_size
        held_environment_content = os.pread(environment_fd, environment_length, 0)
        validate_environment(held_environment_content)
        credential_fd, credential_identity = install_or_open(
            credential_dir_fd,
            "daemon.conf",
            "credential file",
            0o600,
            credential_content,
            arguments.operation == "install",
        )
        descriptors.append(credential_fd)
        credential_length = os.fstat(credential_fd).st_size
        held_credential_content = os.pread(credential_fd, credential_length, 0)
        wait_test_gate()
        verify_path_identity(
            config_fd,
            "gta-claw.env",
            environment_fd,
            environment_identity,
            "environment file",
            0o640,
        )
        verify_path_identity(
            credential_dir_fd,
            "daemon.conf",
            credential_fd,
            credential_identity,
            "credential file",
            0o600,
        )
        verify_held_content(
            environment_fd, held_environment_content, "environment file"
        )
        verify_held_content(
            credential_fd, held_credential_content, "credential file"
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
        if arguments.operation == "materialize":
            materialize_environment(root_fd, held_environment_content)
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
