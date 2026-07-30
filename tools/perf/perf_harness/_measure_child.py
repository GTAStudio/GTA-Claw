"""Isolated command process used to obtain per-sample child resource usage."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if __package__:
    from .processes import process_exists
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from perf_harness.processes import process_exists


class Interrupted(Exception):
    pass


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: _measure_child.py SPEC RESULT", file=sys.stderr)
        return 2
    spec_path = Path(sys.argv[1])
    result_path = Path(sys.argv[2])
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    started_at = _utc_now()
    started = time.perf_counter_ns()
    process: subprocess.Popen[bytes] | None = None
    status = "error"
    reason: str | None = None
    returncode: int | None = None

    def interrupt(_signum: int, _frame: object) -> None:
        raise Interrupted()

    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, signal_name):
            signal.signal(getattr(signal, signal_name), interrupt)

    Path(spec["stdout_path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(spec["stderr_path"]).parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(spec["stdout_path"], "wb") as stdout, open(
            spec["stderr_path"], "wb"
        ) as stderr:
            process = subprocess.Popen(
                spec["argv"],
                cwd=spec["cwd"],
                env=spec["environment"],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=os.name != "nt",
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )
            deadline = time.monotonic() + spec["timeout_seconds"]
            while True:
                if not process_exists(spec["parent_pid"]):
                    status = "interrupted"
                    reason = "harness parent exited while command was running"
                    _terminate(process, spec["terminate_grace_seconds"])
                    returncode = process.returncode
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    reason = f"command exceeded {spec['timeout_seconds']} seconds"
                    _terminate(process, spec["terminate_grace_seconds"])
                    returncode = process.returncode
                    break
                try:
                    returncode = process.wait(timeout=min(0.25, remaining))
                except subprocess.TimeoutExpired:
                    continue
                status = "success" if returncode == 0 else "error"
                break
    except Interrupted:
        status = "interrupted"
        reason = "command interrupted"
        if process is not None:
            _terminate(process, spec["terminate_grace_seconds"])
            returncode = process.returncode
    except OSError as error:
        status = "error"
        reason = f"{type(error).__name__}: {error}"

    ended = time.perf_counter_ns()
    result = {
        "status": status,
        "error_reason": reason,
        "exit_code": returncode if returncode is not None and returncode >= 0 else None,
        "signal": -returncode if returncode is not None and returncode < 0 else None,
        "started_at": started_at,
        "ended_at": _utc_now(),
        "wall_time_seconds": (ended - started) / 1_000_000_000,
        "max_rss_bytes": _max_rss_bytes(),
        "rss_support": _rss_support(),
    }
    temporary = result_path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(result, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, result_path)
    return 130 if status == "interrupted" else 0


def _terminate(process: subprocess.Popen[bytes], grace_seconds: float) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=grace_seconds)
        return
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                timeout=grace_seconds,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _max_rss_bytes() -> int | None:
    try:
        import resource
    except ImportError:
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return int(usage if sys.platform == "darwin" else usage * 1024)


def _rss_support() -> dict[str, Any]:
    if os.name == "nt":
        return {
            "supported": False,
            "reason": "Python resource.getrusage is unavailable on Windows",
        }
    return {
        "supported": True,
        "scope": "maximum resident set of the measured child process",
    }


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


if __name__ == "__main__":
    raise SystemExit(main())
