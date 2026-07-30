"""Hash declared benchmark artifacts without broad tree scans."""

from __future__ import annotations

import glob
import os
from pathlib import Path
from typing import Any, Iterable

from .storage import sha256_file
from .templates import render_template


def collect_artifacts(
    definitions: Iterable[dict[str, Any]],
    context: dict[str, str],
    *,
    checkout: Path,
    target_dir: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    missing: list[str] = []
    seen: set[Path] = set()
    for definition in definitions:
        pattern = render_template(definition["path"], context)
        matches = sorted(Path(match) for match in glob.glob(pattern, recursive=True))
        files = [
            path
            for path in matches
            if path.is_file()
            and path not in seen
            and (
                not definition.get("executable_only")
                or _is_executable_artifact(path)
            )
        ]
        if definition.get("required") and not files:
            missing.append(pattern)
        for path in files:
            seen.add(path)
            stat = path.stat()
            artifacts.append(
                {
                    "path": _logical_path(path, checkout, target_dir),
                    "size_bytes": stat.st_size,
                    "mode": stat.st_mode,
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": sha256_file(path),
                }
            )
    return artifacts, missing


def _is_executable_artifact(path: Path) -> bool:
    if os.name == "nt":
        return path.suffix.lower() in {".exe", ".com", ".bat", ".cmd"}
    return os.access(path, os.X_OK)


def _logical_path(path: Path, checkout: Path, target_dir: Path) -> str:
    resolved = path.resolve()
    for prefix, root in (("checkout", checkout.resolve()), ("target", target_dir.resolve())):
        if resolved == root or root in resolved.parents:
            return f"{prefix}:{resolved.relative_to(root).as_posix()}"
    return str(resolved)
