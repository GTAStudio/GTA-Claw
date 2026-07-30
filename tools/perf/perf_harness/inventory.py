"""Exact local host, toolchain, environment, and harness inventories."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from .storage import sha256_file


CHILD_ENVIRONMENT_KEYS = {
    "CARGO_HOME",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "PATH",
    "PATHEXT",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
    "USERPROFILE",
    "WINDIR",
}
SECRET_NAME = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|AUTH)",
    re.IGNORECASE,
)
VERSION_ARGUMENTS = {
    "cargo": ["--version", "--verbose"],
    "git": ["--version"],
    "node": ["--version"],
    "npm": ["--version"],
    "python": ["--version"],
    "rustc": ["--version", "--verbose"],
}


def child_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if name in CHILD_ENVIRONMENT_KEYS
    }
    environment.setdefault("PATH", os.defpath)
    environment.setdefault("LANG", "C.UTF-8")
    host_home = Path(os.environ.get("HOME", str(Path.home())))
    for name, default in (
        ("CARGO_HOME", host_home / ".cargo"),
        ("RUSTUP_HOME", host_home / ".rustup"),
    ):
        if name not in environment and default.exists():
            environment[name] = str(default)
    environment["GTA_CLAW_PERF_LOCAL_ONLY"] = "1"
    if overrides:
        environment.update(overrides)
    return environment


def environment_inventory(repo_root: Path) -> dict[str, Any]:
    all_names = sorted(os.environ)
    safe_values = {
        name: os.environ[name]
        for name in all_names
        if name in CHILD_ENVIRONMENT_KEYS and not SECRET_NAME.search(name)
    }
    redacted = [name for name in all_names if SECRET_NAME.search(name)]
    excluded = [
        name
        for name in all_names
        if name not in safe_values and name not in redacted
    ]
    disk = shutil.disk_usage(repo_root)
    return {
        "host": {
            "system": platform.system(),
            "platform": platform.platform(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "logical_cpu_count": os.cpu_count(),
            "physical_memory_bytes": _physical_memory_bytes(),
            "cpu_model": _cpu_model(),
            "load_average": _load_average(),
            "clocks": {
                "perf_counter": _clock_info("perf_counter"),
                "monotonic": _clock_info("monotonic"),
            },
            "disk": {
                "path": str(repo_root),
                "total_bytes": disk.total,
                "free_bytes": disk.free,
            },
        },
        "variables": safe_values,
        "redacted_variable_names": redacted,
        "excluded_variable_names": excluded,
        "child_base": child_environment(),
    }


def toolchain_inventory(tool_names: Iterable[str]) -> list[dict[str, Any]]:
    names = sorted(set(tool_names) | {"git", "python"})
    return [_tool_inventory(name) for name in names]


def file_tool_inventory(
    name: str, path: Path, *, version_file: Path | None = None
) -> dict[str, Any]:
    if not path.exists():
        return {
            "name": name,
            "status": "BLOCKED",
            "path": str(path),
            "reason": "local tool file does not exist",
        }
    realpath = path.resolve()
    version: str | None = None
    if version_file is not None and version_file.is_file():
        try:
            import json

            parsed = json.loads(version_file.read_text(encoding="utf-8"))
            if isinstance(parsed, dict) and isinstance(parsed.get("version"), str):
                version = parsed["version"]
        except (OSError, json.JSONDecodeError):
            version = None
    return {
        "name": name,
        "status": "available",
        "path": str(path.absolute()),
        "realpath": str(realpath),
        "sha256": sha256_file(realpath),
        "launcher_sha256": sha256_file(path) if path.is_file() else None,
        "version": version,
    }


def harness_inventory(perf_root: Path, version: str) -> dict[str, Any]:
    files = []
    for path in sorted(perf_root.rglob("*")):
        relative = path.relative_to(perf_root)
        if (
            not path.is_file()
            or "__pycache__" in relative.parts
            or "results" in relative.parts
            or path.suffix == ".pyc"
        ):
            continue
        files.append(
            {
                "path": relative.as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {
        "version": version,
        "python_executable": str(Path(sys.executable).resolve()),
        "files": files,
    }


def platform_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def _tool_inventory(name: str) -> dict[str, Any]:
    executable = sys.executable if name == "python" else shutil.which(name)
    if executable is None:
        return {"name": name, "status": "BLOCKED", "reason": "tool is not on PATH"}
    path = Path(executable).resolve()
    command = [str(path), *VERSION_ARGUMENTS.get(name, ["--version"])]
    try:
        result = subprocess.run(
            command,
            check=False,
            timeout=10,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment(),
        )
        version = (result.stdout.strip() or result.stderr.strip()).replace("\r\n", "\n")
        status = "available" if result.returncode == 0 else "error"
    except (OSError, subprocess.TimeoutExpired) as error:
        version = str(error)
        status = "error"
    return {
        "name": name,
        "status": status,
        "path": str(Path(executable).absolute()),
        "realpath": str(path),
        "sha256": sha256_file(path),
        "version": version,
    }


def _physical_memory_bytes() -> int | None:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
        return None
    if not isinstance(pages, int) or not isinstance(page_size, int):
        return None
    return pages * page_size


def _cpu_model() -> str | None:
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                check=True,
                timeout=5,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            return result.stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            return platform.processor() or None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name"):
                return line.partition(":")[2].strip() or None
    return platform.processor() or None


def _load_average() -> list[float] | None:
    try:
        return list(os.getloadavg())
    except (AttributeError, OSError):
        return None


def _clock_info(name: str) -> dict[str, Any]:
    info = time.get_clock_info(name)
    return {
        "implementation": info.implementation,
        "monotonic": info.monotonic,
        "adjustable": info.adjustable,
        "resolution_seconds": info.resolution,
    }
