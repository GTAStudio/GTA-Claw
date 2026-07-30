"""Atomic retained-run storage and interruption recovery."""

from __future__ import annotations

import hashlib
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .processes import process_exists
from .schema import validate_run_document


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    encoded = (
        json.dumps(
            value,
            allow_nan=False,
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    with temporary.open("wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def recover_interrupted_document(document: dict[str, Any]) -> dict[str, Any]:
    recovered = json.loads(json.dumps(document))
    recovered["status"] = "running"
    recovered["updated_at"] = utc_now()
    recovered["summary"] = {"status": "NOT_COMPARED", "workloads": []}
    for sample in recovered.get("raw_samples", []):
        if sample.get("status") == "running":
            sample["status"] = "interrupted"
            sample["ended_at"] = recovered["updated_at"]
            sample["error_reason"] = "recovered after an interrupted harness process"
    validate_run_document(recovered)
    return recovered


class RunStore:
    """Owns one output directory and its partial/final documents."""

    def __init__(self, output: Path) -> None:
        self.output = output.resolve()
        self.partial_path = self.output / "run.partial.json"
        self.final_path = self.output / "run.json"
        self.lock = OutputLock(self.output / "run.lock")

    def begin(self, *, resume: bool) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        self.lock.acquire(allow_stale=resume)
        if self.final_path.exists():
            raise FileExistsError(f"completed run already exists: {self.final_path}")
        if self.partial_path.exists() and not resume:
            raise FileExistsError(
                f"partial run exists; pass --resume to recover: {self.partial_path}"
            )
        if resume and not self.partial_path.exists():
            raise FileNotFoundError(
                f"cannot resume because no partial run exists: {self.partial_path}"
            )

    def load_partial(self) -> dict[str, Any]:
        value = json.loads(self.partial_path.read_text(encoding="utf-8"))
        validate_run_document(value)
        return value

    def save_partial(self, document: dict[str, Any]) -> None:
        document["updated_at"] = utc_now()
        validate_run_document(document)
        atomic_write_json(self.partial_path, document)

    def complete(self, document: dict[str, Any]) -> None:
        document["updated_at"] = utc_now()
        validate_run_document(document)
        atomic_write_json(self.final_path, document)
        if self.partial_path.exists():
            self.partial_path.unlink()
            _fsync_directory(self.output)

    def close(self) -> None:
        self.lock.release()


class OutputLock:
    """A local PID lock that can reclaim a demonstrably stale run."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.held = False

    def acquire(self, *, allow_stale: bool) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "created_at": utc_now(),
        }
        for attempt in range(2):
            try:
                descriptor = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
            except FileExistsError:
                if attempt or not allow_stale or not self._is_stale():
                    raise RuntimeError(f"performance output is locked: {self.path}")
                self.path.unlink()
                continue
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self.held = True
            return
        raise RuntimeError(f"could not acquire output lock: {self.path}")

    def release(self) -> None:
        if self.held and self.path.exists():
            self.path.unlink()
            _fsync_directory(self.path.parent)
        self.held = False

    def _is_stale(self) -> bool:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            pid = int(payload["pid"])
            hostname = payload["hostname"]
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False
        return hostname == socket.gethostname() and not process_exists(pid)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            pass
    finally:
        os.close(descriptor)
