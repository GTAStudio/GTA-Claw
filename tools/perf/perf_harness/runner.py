"""Retained command execution through the isolated measurement child."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from .storage import atomic_write_json, sha256_file


class CommandRunner:
    def __init__(self, output: Path) -> None:
        self.output = output.resolve()
        self.control = self.output / "control"
        self.logs = self.output / "logs"
        self.helper = Path(__file__).with_name("_measure_child.py").resolve()

    def run(
        self,
        *,
        sample_id: str,
        argv: list[str],
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: float,
        terminate_grace_seconds: float = 5.0,
    ) -> dict[str, Any]:
        safe_id = "".join(
            character if character.isalnum() or character in "-_" else "-"
            for character in sample_id
        )
        stdout_path = self.logs / f"{safe_id}.stdout.log"
        stderr_path = self.logs / f"{safe_id}.stderr.log"
        spec_path = self.control / f"{safe_id}.spec.json"
        result_path = self.control / f"{safe_id}.result.json"
        spec = {
            "argv": argv,
            "cwd": str(cwd),
            "environment": environment,
            "parent_pid": os.getpid(),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "timeout_seconds": timeout_seconds,
            "terminate_grace_seconds": terminate_grace_seconds,
        }
        atomic_write_json(spec_path, spec)
        helper = subprocess.Popen(
            [sys.executable, str(self.helper), str(spec_path), str(result_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            ),
        )
        interrupted = False
        try:
            helper.wait(timeout=timeout_seconds + terminate_grace_seconds + 30)
        except KeyboardInterrupt:
            interrupted = True
            _stop_helper(helper, terminate_grace_seconds + 10)
        except subprocess.TimeoutExpired:
            _stop_helper(helper, terminate_grace_seconds + 10)

        if not result_path.exists():
            result = {
                "status": "interrupted" if interrupted else "error",
                "error_reason": "measurement child exited without a result",
                "exit_code": None,
                "signal": None,
                "started_at": None,
                "ended_at": None,
                "wall_time_seconds": None,
                "max_rss_bytes": None,
                "rss_support": {
                    "supported": False,
                    "reason": "measurement child did not report resource usage",
                },
            }
        else:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        result["stdout"] = _log_descriptor(stdout_path, self.output)
        result["stderr"] = _log_descriptor(stderr_path, self.output)
        result["command"] = {
            "argv": argv,
            "cwd": str(cwd),
            "environment": environment,
            "shell": False,
        }
        if interrupted:
            result["status"] = "interrupted"
            result["error_reason"] = "harness interrupted while command was running"
        return result


def _signal_helper(helper: subprocess.Popen[bytes]) -> None:
    if helper.poll() is not None:
        return
    try:
        helper.send_signal(signal.SIGINT if os.name != "nt" else signal.CTRL_BREAK_EVENT)
    except (OSError, ValueError):
        helper.terminate()


def _stop_helper(helper: subprocess.Popen[bytes], timeout: float) -> None:
    _signal_helper(helper)
    try:
        helper.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        helper.kill()
        helper.wait()


def _log_descriptor(path: Path, output: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "path": path.relative_to(output).as_posix(),
            "size_bytes": 0,
            "sha256": None,
        }
    return {
        "path": path.relative_to(output).as_posix(),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
