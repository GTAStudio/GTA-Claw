#!/usr/bin/env python3

import ctypes
import errno
import os
import re
import stat
import subprocess
import sys


O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0o400000)
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
SYS_OPENAT2 = 437
COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
libc = ctypes.CDLL(None, use_errno=True)
RETURN_UID = int(os.environ.get("SAFEIO_RETURN_UID", str(os.getuid())))
RETURN_GID = int(os.environ.get("SAFEIO_RETURN_GID", str(os.getgid())))


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ulonglong),
        ("mode", ctypes.c_ulonglong),
        ("resolve", ctypes.c_ulonglong),
    ]


def fail(message: str) -> None:
    raise SystemExit(f"safeio: {message}")


def safe_relative(path: str) -> list[str]:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        fail(f"unsafe relative path: {path!r}")
    parts = path.split("/")
    if any(
        part in ("", ".", "..")
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in part)
        for part in parts
    ):
        fail(f"unsafe relative path component: {path!r}")
    return parts


def validate_component(value: str) -> None:
    if not COMPONENT.fullmatch(value) or ".." in value:
        fail(f"unsafe target component: {value!r}")


def openat2(dir_fd: int, path: str, flags: int, mode: int = 0) -> int:
    safe_relative(path)
    how = OpenHow(
        flags=flags,
        mode=mode,
        resolve=RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    )
    fd = libc.syscall(
        SYS_OPENAT2,
        dir_fd,
        ctypes.c_char_p(os.fsencode(path)),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if fd < 0:
        error = ctypes.get_errno()
        if error == errno.ENOSYS:
            fail("openat2 is unavailable; refusing an unanchored fallback")
        raise OSError(error, os.strerror(error), path)
    return fd


def check_directory(
    fd: int, label: str, mode: int = 0o700, owners: tuple[int, ...] | None = None
) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} is not a directory")
    accepted = owners if owners is not None else (os.getuid(),)
    if info.st_uid not in accepted:
        fail(f"{label} is not owned by the current user")
    if stat.S_IMODE(info.st_mode) != mode:
        fail(f"{label} mode is not {mode:04o}")


def mkdirs(root_fd: int, relative: str, mode: int = 0o700) -> None:
    current = os.dup(root_fd)
    try:
        for part in safe_relative(relative):
            try:
                os.mkdir(part, mode=mode, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW, dir_fd=current)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                os.close(child)
                fail(f"unsafe directory component: {relative!r}")
            os.fchmod(child, mode)
            os.close(current)
            current = child
    finally:
        os.close(current)


def open_repo_target() -> tuple[int, int]:
    repo_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW)
    try:
        try:
            os.mkdir("target", mode=0o700, dir_fd=repo_fd)
        except FileExistsError:
            pass
        target_fd = os.open(
            "target", os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW, dir_fd=repo_fd
        )
        check_directory(target_fd, "repository target", owners=(RETURN_UID, os.getuid()))
        os.fchown(target_fd, os.getuid(), os.getgid())
        os.fchmod(target_fd, 0o700)
        return repo_fd, target_fd
    except BaseException:
        os.close(repo_fd)
        raise


def create_component(target_fd: int, component: str) -> tuple[int, str]:
    validate_component(component)
    lock = f"{component}.lock"
    os.mkdir(lock, mode=0o700, dir_fd=target_fd)
    try:
        os.mkdir(component, mode=0o700, dir_fd=target_fd)
        output_fd = os.open(
            component, os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW, dir_fd=target_fd
        )
        os.fchmod(output_fd, 0o700)
        check_directory(output_fd, "output root")
        return output_fd, lock
    except BaseException:
        os.rmdir(lock, dir_fd=target_fd)
        raise


def open_component(target_fd: int, component: str, label: str) -> int:
    validate_component(component)
    fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW, dir_fd=target_fd)
    check_directory(fd, label, owners=(RETURN_UID, os.getuid()))
    return fd


def chown_tree(root_fd: int, uid: int, gid: int) -> None:
    with os.scandir(root_fd) as entries:
        for entry in entries:
            if entry.is_symlink():
                fail(f"refusing to return ownership across symlink: {entry.name}")
            if entry.is_dir(follow_symlinks=False):
                child = os.open(
                    entry.name,
                    os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW,
                    dir_fd=root_fd,
                )
                try:
                    chown_tree(child, uid, gid)
                    os.fchown(child, uid, gid)
                finally:
                    os.close(child)
            else:
                os.chown(
                    entry.name,
                    uid,
                    gid,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
    os.fchown(root_fd, uid, gid)


def same_inode_at(parent_fd: int, name: str, opened_fd: int) -> bool:
    path_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    opened_info = os.fstat(opened_fd)
    return (path_info.st_dev, path_info.st_ino) == (
        opened_info.st_dev,
        opened_info.st_ino,
    )


def run_child(command: list[str], inherited: dict[str, int], extra: dict[str, str]) -> int:
    environment = os.environ.copy()
    pass_fds = []
    for name, fd in inherited.items():
        os.set_inheritable(fd, True)
        environment[name] = str(fd)
        pass_fds.append(fd)
    environment.update(extra)
    environment["SAFEIO_ACTIVE"] = "1"
    completed = subprocess.run(
        command,
        env=environment,
        pass_fds=tuple(pass_fds),
        check=False,
    )
    return completed.returncode


def command_run_create(arguments: list[str]) -> int:
    if len(arguments) < 3 or arguments[1] != "--":
        fail("usage: safeio.py run-create COMPONENT -- COMMAND...")
    component = arguments[0]
    command = arguments[2:]
    repo_fd, target_fd = open_repo_target()
    output_fd = -1
    lock = ""
    try:
        output_fd, lock = create_component(target_fd, component)
        return run_child(
            command,
            {"SAFEIO_TARGET_FD": target_fd, "SAFEIO_OUTPUT_FD": output_fd},
            {
                "SAFEIO_OUTPUT_COMPONENT": component,
                "OUTPUT_ROOT": f"/proc/self/fd/{output_fd}",
            },
        )
    finally:
        if output_fd >= 0:
            if not same_inode_at(target_fd, component, output_fd):
                fail("output component identity changed during transaction")
            chown_tree(output_fd, RETURN_UID, RETURN_GID)
            os.close(output_fd)
        if lock:
            os.rmdir(lock, dir_fd=target_fd)
        if not same_inode_at(repo_fd, "target", target_fd):
            fail("repository target identity changed during transaction")
        os.fchown(target_fd, RETURN_UID, RETURN_GID)
        os.close(target_fd)
        os.close(repo_fd)


def command_run_package(arguments: list[str]) -> int:
    if len(arguments) < 4 or arguments[2] != "--":
        fail("usage: safeio.py run-package BUILD_COMPONENT OUTPUT_COMPONENT -- COMMAND...")
    build_component, output_component = arguments[:2]
    command = arguments[3:]
    repo_fd, target_fd = open_repo_target()
    build_fd = -1
    output_fd = -1
    lock = ""
    try:
        build_fd = open_component(target_fd, build_component, "build root")
        output_fd, lock = create_component(target_fd, output_component)
        return run_child(
            command,
            {
                "SAFEIO_TARGET_FD": target_fd,
                "SAFEIO_BUILD_FD": build_fd,
                "SAFEIO_OUTPUT_FD": output_fd,
            },
            {
                "BUILD_ROOT": f"/proc/self/fd/{build_fd}",
                "BUILD_MANIFEST": f"/proc/self/fd/{build_fd}/build-manifest.json",
                "SAFEIO_BUILD_COMPONENT": build_component,
                "SAFEIO_OUTPUT_COMPONENT": output_component,
                "OUTPUT_ROOT": f"/proc/self/fd/{output_fd}",
            },
        )
    finally:
        if output_fd >= 0:
            if not same_inode_at(target_fd, output_component, output_fd):
                fail("output component identity changed during transaction")
            chown_tree(output_fd, RETURN_UID, RETURN_GID)
            os.close(output_fd)
        if build_fd >= 0:
            os.close(build_fd)
        if lock:
            os.rmdir(lock, dir_fd=target_fd)
        if not same_inode_at(repo_fd, "target", target_fd):
            fail("repository target identity changed during transaction")
        os.fchown(target_fd, RETURN_UID, RETURN_GID)
        os.close(target_fd)
        os.close(repo_fd)


def command_write(arguments: list[str]) -> int:
    if len(arguments) != 3:
        fail("usage: safeio.py write ROOT_FD RELATIVE MODE")
    root_fd = int(arguments[0])
    relative = arguments[1]
    mode = int(arguments[2], 8)
    fd = openat2(
        root_fd,
        relative,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
        mode,
    )
    try:
        os.fchmod(fd, mode)
        info = os.fstat(fd)
        print(f"READY {info.st_dev}:{info.st_ino}", flush=True)
        while True:
            chunk = sys.stdin.buffer.read(1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        os.fsync(fd)
        if os.fstat(fd).st_nlink != 1:
            fail("written output acquired an unexpected hard link")
    finally:
        os.close(fd)
    return 0


def command_mkdirs(arguments: list[str]) -> int:
    if len(arguments) != 2:
        fail("usage: safeio.py mkdirs ROOT_FD RELATIVE")
    mkdirs(int(arguments[0]), arguments[1])
    return 0


def command_publish(arguments: list[str]) -> int:
    if len(arguments) != 3:
        fail("usage: safeio.py publish ROOT_FD TEMP FINAL")
    root_fd = int(arguments[0])
    temporary, final = arguments[1:]
    temporary_parts = safe_relative(temporary)
    final_parts = safe_relative(final)
    source_fd = openat2(root_fd, temporary, os.O_RDONLY | O_NOFOLLOW)
    source_parent = (
        os.dup(root_fd)
        if len(temporary_parts) == 1
        else openat2(
            root_fd,
            "/".join(temporary_parts[:-1]),
            os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW,
        )
    )
    final_parent = (
        os.dup(root_fd)
        if len(final_parts) == 1
        else openat2(
            root_fd,
            "/".join(final_parts[:-1]),
            os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW,
        )
    )
    try:
        source_info = os.fstat(source_fd)
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1:
            fail("publication source is not a unique regular file")
        os.link(
            temporary_parts[-1],
            final_parts[-1],
            src_dir_fd=source_parent,
            dst_dir_fd=final_parent,
            follow_symlinks=False,
        )
        final_fd = openat2(root_fd, final, os.O_RDONLY | O_NOFOLLOW)
        try:
            final_info = os.fstat(final_fd)
            if (final_info.st_dev, final_info.st_ino) != (
                source_info.st_dev,
                source_info.st_ino,
            ):
                fail("published file is not the reserved inode")
        finally:
            os.close(final_fd)
        os.unlink(temporary_parts[-1], dir_fd=source_parent)
        os.fsync(source_parent)
        if final_parent != source_parent:
            os.fsync(final_parent)
    finally:
        os.close(source_parent)
        os.close(final_parent)
        os.close(source_fd)
    return 0


def command_check(arguments: list[str]) -> int:
    if len(arguments) != 1:
        fail("usage: safeio.py check ROOT_FD")
    check_directory(
        int(arguments[0]),
        "capability root",
        owners=(RETURN_UID, os.getuid()),
    )
    return 0


COMMANDS = {
    "run-create": command_run_create,
    "run-package": command_run_package,
    "write": command_write,
    "mkdirs": command_mkdirs,
    "publish": command_publish,
    "check": command_check,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail(f"expected one of: {', '.join(sorted(COMMANDS))}")
    return COMMANDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    raise SystemExit(main())
