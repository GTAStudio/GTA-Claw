"""End-to-end local performance run orchestration."""

from __future__ import annotations

import copy
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable

from . import HARNESS_VERSION, SCHEMA_VERSION
from .artifacts import collect_artifacts
from .comparison import compare_document
from .git_repo import DetachedWorktrees, GitRepository, Revision
from .inventory import (
    child_environment,
    environment_inventory,
    file_tool_inventory,
    harness_inventory,
    platform_name,
    toolchain_inventory,
)
from .runner import CommandRunner
from .schedule import build_schedule, remaining_slots
from .schema import RUN_SCHEMA_URI, validate_run_document
from .storage import (
    RunStore,
    recover_interrupted_document,
    sha256_json,
    utc_now,
)
from .templates import render_template


class HarnessInterrupted(RuntimeError):
    """Raised after an interrupted sample has been retained."""


class LocalPerfHarness:
    def __init__(
        self,
        repo_root: Path,
        catalog: dict[str, Any],
        thresholds: dict[str, Any],
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.catalog = catalog
        self.thresholds = thresholds
        self.repository = GitRepository(self.repo_root)
        self.perf_root = Path(__file__).resolve().parents[1]

    def list_workloads(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for suite in self.catalog["suites"]:
            for workload in suite["workloads"]:
                reasons = self._host_blockers(workload)
                enabled = suite.get("enabled_by_default", False) and workload.get(
                    "enabled_by_default", suite.get("enabled_by_default", False)
                )
                entries.append(
                    {
                        "suite_id": suite["id"],
                        "suite_name": suite["name"],
                        "workload_id": workload["id"],
                        "description": workload["description"],
                        "default": enabled,
                        "status": "BLOCKED"
                        if reasons
                        else "ENABLED"
                        if enabled
                        else "DISABLED",
                        "reasons": reasons,
                        "capacity": workload["capacity"],
                        "network_policy": workload["network_policy"],
                    }
                )
        return entries

    def dry_run(
        self,
        reference_name: str,
        candidate_name: str,
        workloads: list[dict[str, Any]],
    ) -> dict[str, Any]:
        reference = self.repository.resolve(reference_name)
        candidate = self.repository.resolve(candidate_name)
        schedule = build_schedule(workloads)
        planned = []
        for workload in workloads:
            availability = {
                variant: self._dry_availability(workload, revision)
                for variant, revision in (
                    ("reference", reference),
                    ("candidate", candidate),
                )
            }
            planned.append(
                {
                    **copy.deepcopy(workload),
                    "availability": availability,
                    "rendered_commands": {
                        variant: self._dry_command(workload, variant, revision)
                        for variant, revision in (
                            ("reference", reference),
                            ("candidate", candidate),
                        )
                    },
                }
            )
        return {
            "dry_run": True,
            "local_only": True,
            "repository": {
                "root": str(self.repo_root),
                "reference": reference.as_dict(),
                "candidate": candidate.as_dict(),
                "merge_base": self.repository.merge_base(reference, candidate),
            },
            "workloads": planned,
            "schedule": schedule,
            "thresholds": self.thresholds,
        }

    def run(
        self,
        *,
        reference_name: str,
        candidate_name: str,
        workloads: list[dict[str, Any]],
        output: Path,
        compare: bool,
        resume: bool,
        keep_worktrees: bool,
    ) -> tuple[dict[str, Any], int]:
        reference = self.repository.resolve(reference_name)
        candidate = self.repository.resolve(candidate_name)
        schedule = build_schedule(workloads)
        plan_hash = self._plan_hash(reference, candidate, workloads, schedule)
        store = RunStore(output)
        document: dict[str, Any] | None = None
        try:
            store.begin(resume=resume)
            if resume:
                document = recover_interrupted_document(store.load_partial())
                actual_plan = document["metadata"]["configuration"]["plan_sha256"]
                if actual_plan != plan_hash:
                    raise ValueError(
                        "resume arguments do not match the retained run plan "
                        f"({plan_hash} != {actual_plan})"
                    )
                if document["metadata"]["configuration"]["compare"] != compare:
                    raise ValueError(
                        "resume must use the same --compare choice as the retained run"
                    )
                document["metadata"].setdefault("recoveries", []).append(
                    {
                        "recovered_at": utc_now(),
                        "environment": environment_inventory(self.repo_root),
                        "harness": harness_inventory(
                            self.perf_root, HARNESS_VERSION
                        ),
                        "toolchains": self._toolchains(workloads),
                    }
                )
            else:
                document = self._new_document(
                    reference,
                    candidate,
                    workloads,
                    schedule,
                    plan_hash,
                    compare=compare,
                )
            store.save_partial(document)

            with self.repository.worktrees(
                document["run_id"],
                reference,
                candidate,
                keep=keep_worktrees,
            ) as worktrees:
                self._preflight_all(document, workloads, worktrees, store)
                self._prepare_all(
                    document,
                    workloads,
                    worktrees,
                    store,
                    resumed=resume,
                )
                self._run_schedule(
                    document,
                    workloads,
                    schedule,
                    worktrees,
                    store,
                )
            document["status"] = "completed"
            document["summary"] = (
                compare_document(document, self.thresholds)
                if compare
                else _uncompared_summary(document)
            )
            store.complete(document)
            return document, _summary_exit_code(document["summary"]["status"])
        except HarnessInterrupted:
            if document is None:
                raise
            document["status"] = "interrupted"
            document["summary"] = {"status": "INTERRUPTED", "workloads": []}
            store.save_partial(document)
            return document, 130
        except Exception:
            if document is not None:
                document["status"] = "failed"
                document["summary"] = {"status": "FAIL", "workloads": []}
                store.save_partial(document)
            raise
        finally:
            store.close()

    def compare_retained(
        self, document: dict[str, Any], thresholds: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        validate_run_document(document)
        compared = copy.deepcopy(document)
        compared["summary"] = compare_document(
            compared, thresholds if thresholds is not None else self.thresholds
        )
        comparison_thresholds = (
            thresholds if thresholds is not None else self.thresholds
        )
        compared["metadata"]["comparison"] = {
            "compared_at": utc_now(),
            "thresholds": comparison_thresholds,
            "thresholds_sha256": sha256_json(comparison_thresholds),
        }
        compared["updated_at"] = utc_now()
        validate_run_document(compared)
        return compared

    def _new_document(
        self,
        reference: Revision,
        candidate: Revision,
        workloads: list[dict[str, Any]],
        schedule: list[dict[str, Any]],
        plan_hash: str,
        *,
        compare: bool,
    ) -> dict[str, Any]:
        created = utc_now()
        snapshots = []
        for workload in workloads:
            snapshot = copy.deepcopy(workload)
            snapshot["availability"] = {
                "reference": {"status": "PENDING"},
                "candidate": {"status": "PENDING"},
            }
            snapshots.append(snapshot)
        document = {
            "$schema": RUN_SCHEMA_URI,
            "schema_version": SCHEMA_VERSION,
            "run_id": f"{created[:10]}-{uuid.uuid4().hex[:12]}",
            "status": "running",
            "created_at": created,
            "updated_at": created,
            "metadata": {
                "harness": harness_inventory(self.perf_root, HARNESS_VERSION),
                "repository": {
                    "root": str(self.repo_root),
                    "reference": reference.as_dict(),
                    "candidate": candidate.as_dict(),
                    "merge_base": self.repository.merge_base(reference, candidate),
                    "checkout_strategy": "detached git worktrees",
                    "source_branches_mutated": False,
                },
                "toolchains": self._toolchains(workloads),
                "environment": environment_inventory(self.repo_root),
                "configuration": {
                    "local_only": True,
                    "compare": compare,
                    "plan_sha256": plan_hash,
                    "catalog_sha256": sha256_json(self.catalog),
                    "thresholds_sha256": sha256_json(self.thresholds),
                    "suite_ids": sorted({workload["suite_id"] for workload in workloads}),
                    "schedule": schedule,
                },
                "thresholds": copy.deepcopy(self.thresholds),
            },
            "workloads": snapshots,
            "raw_samples": [],
            "summary": {"status": "NOT_COMPARED", "workloads": []},
        }
        validate_run_document(document)
        return document

    def _toolchains(self, workloads: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        required = {
            tool
            for workload in workloads
            for tool in workload.get("required_tools", [])
        }
        if "cargo" in required:
            required.add("rustc")
        tools = toolchain_inventory(required)
        if "node" in required:
            tools.append(
                file_tool_inventory(
                    "typescript",
                    self.repo_root / "node_modules" / "typescript" / "bin" / "tsc",
                    version_file=self.repo_root
                    / "node_modules"
                    / "typescript"
                    / "package.json",
                )
            )
        return tools

    def _preflight_all(
        self,
        document: dict[str, Any],
        workloads: list[dict[str, Any]],
        worktrees: DetachedWorktrees,
        store: RunStore,
    ) -> None:
        snapshots = {workload["id"]: workload for workload in document["workloads"]}
        for workload in workloads:
            snapshot = snapshots[workload["id"]]
            availability = {}
            for variant in ("reference", "candidate"):
                target = worktrees.target_for(
                    variant, workload["id"], None, "workload"
                )
                context = self._context(
                    variant,
                    worktrees.paths[variant],
                    target,
                    target,
                    store.output,
                )
                link_reasons = self._prepare_links(
                    workload, worktrees.paths[variant], context
                )
                reasons = link_reasons + self._checkout_blockers(
                    workload, worktrees.paths[variant], context
                )
                availability[variant] = (
                    {"status": "BLOCKED", "reason": "; ".join(reasons)}
                    if reasons
                    else {"status": "SUPPORTED"}
                )
            snapshot["availability"] = availability
            if any(value["status"] != "SUPPORTED" for value in availability.values()):
                for variant, value in availability.items():
                    self._retain_blocked_sample(
                        document,
                        workload,
                        variant,
                        value.get("reason", "peer variant is blocked"),
                        worktrees,
                        store.output,
                    )
            store.save_partial(document)

    def _prepare_all(
        self,
        document: dict[str, Any],
        workloads: list[dict[str, Any]],
        worktrees: DetachedWorktrees,
        store: RunStore,
        *,
        resumed: bool,
    ) -> None:
        snapshots = {workload["id"]: workload for workload in document["workloads"]}
        runner = CommandRunner(store.output)
        for workload in workloads:
            snapshot = snapshots[workload["id"]]
            if any(
                value["status"] != "SUPPORTED"
                for value in snapshot["availability"].values()
            ):
                continue
            for variant in ("reference", "candidate"):
                if workload.get("prepare_command"):
                    suffix = (
                        f":resume:{len(document['metadata'].get('recoveries', []))}"
                        if resumed
                        else ""
                    )
                    slot = {
                        "slot_id": f"{workload['id']}:prepare:{variant}{suffix}",
                        "order_index": -1,
                        "phase": "prepare",
                        "phase_index": 0,
                        "variant": variant,
                        "suite_id": workload["suite_id"],
                        "workload_id": workload["id"],
                    }
                    if self._slot_is_terminal(document, slot["slot_id"]):
                        continue
                    sample = self._execute(
                        document,
                        workload,
                        slot,
                        worktrees,
                        store,
                        runner,
                        command_key="prepare_command",
                    )
                    if sample["status"] != "success":
                        snapshot["availability"][variant] = {
                            "status": (
                                "BLOCKED"
                                if sample["status"] == "blocked"
                                else "ERROR"
                            ),
                            "reason": sample.get(
                                "error_reason", "preparation command failed"
                            ),
                        }
                        store.save_partial(document)
            if resumed and workload["target_scope"] == "workload" and not workload.get(
                "prepare_command"
            ):
                for variant in ("reference", "candidate"):
                    if snapshot["availability"][variant]["status"] != "SUPPORTED":
                        continue
                    slot = {
                        "slot_id": (
                            f"{workload['id']}:recovery-warmup:"
                            f"{len(document['metadata'].get('recoveries', []))}:{variant}"
                        ),
                        "order_index": -1,
                        "phase": "warmup",
                        "phase_index": -1,
                        "variant": variant,
                        "suite_id": workload["suite_id"],
                        "workload_id": workload["id"],
                    }
                    sample = self._execute(
                        document,
                        workload,
                        slot,
                        worktrees,
                        store,
                        runner,
                        command_key="command",
                    )
                    if sample["status"] != "success":
                        snapshot["availability"][variant] = {
                            "status": (
                                "BLOCKED"
                                if sample["status"] == "blocked"
                                else "ERROR"
                            ),
                            "reason": sample.get(
                                "error_reason", "recovery warmup failed"
                            ),
                        }
                        store.save_partial(document)

    def _run_schedule(
        self,
        document: dict[str, Any],
        workloads: list[dict[str, Any]],
        schedule: list[dict[str, Any]],
        worktrees: DetachedWorktrees,
        store: RunStore,
    ) -> None:
        by_id = {workload["id"]: workload for workload in workloads}
        snapshots = {workload["id"]: workload for workload in document["workloads"]}
        runner = CommandRunner(store.output)
        for slot in remaining_slots(schedule, document["raw_samples"]):
            workload = by_id[slot["workload_id"]]
            availability = snapshots[workload["id"]]["availability"]
            if any(
                value["status"] != "SUPPORTED" for value in availability.values()
            ):
                continue
            sample = self._execute(
                document,
                workload,
                slot,
                worktrees,
                store,
                runner,
                command_key="command",
            )
            if sample["phase"] == "warmup" and sample["status"] != "success":
                availability[slot["variant"]] = {
                    "status": (
                        "BLOCKED"
                        if sample["status"] == "blocked"
                        else "ERROR"
                    ),
                    "reason": sample.get(
                        "error_reason",
                        f"warmup command ended with {sample['status']}",
                    ),
                }
                store.save_partial(document)
            elif sample["status"] == "blocked":
                availability[slot["variant"]] = {
                    "status": "BLOCKED",
                    "reason": sample.get(
                        "error_reason", "local dependency is unavailable"
                    ),
                }
                store.save_partial(document)

    def _execute(
        self,
        document: dict[str, Any],
        workload: dict[str, Any],
        slot: dict[str, Any],
        worktrees: DetachedWorktrees,
        store: RunStore,
        runner: CommandRunner,
        *,
        command_key: str,
    ) -> dict[str, Any]:
        variant = slot["variant"]
        target = worktrees.target_for(
            variant,
            workload["id"],
            slot["slot_id"],
            workload["target_scope"],
        )
        sample_dir = target / "sample"
        target.mkdir(parents=True, exist_ok=True)
        temporary = target / "tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        home = target / "home"
        home.mkdir(parents=True, exist_ok=True)
        context = self._context(
            variant,
            worktrees.paths[variant],
            target,
            sample_dir,
            store.output,
        )
        argv, cwd, environment = self._render_command(
            workload, command_key, context, worktrees.paths[variant]
        )
        attempts = sum(
            sample.get("slot_id") == slot["slot_id"]
            for sample in document["raw_samples"]
        )
        sample_id = f"{slot['slot_id']}:attempt-{attempts + 1}"
        sample = {
            "sample_id": sample_id,
            **slot,
            "status": "running",
            "operations": workload["operations_per_sample"],
            "capacity": workload["capacity"],
            "network_policy": workload["network_policy"],
            "command": {
                "argv": argv,
                "cwd": str(cwd),
                "environment": environment,
                "shell": False,
            },
            "artifacts": [],
        }
        document["raw_samples"].append(sample)
        store.save_partial(document)
        result = runner.run(
            sample_id=sample_id,
            argv=argv,
            cwd=cwd,
            environment=environment,
            timeout_seconds=workload["timeout_seconds"],
        )
        sample.update(result)
        environmental_block = self._environmental_block_reason(sample, store.output)
        if environmental_block is not None:
            sample["status"] = "blocked"
            sample["error_reason"] = environmental_block
        if sample["status"] == "success":
            artifacts, missing = collect_artifacts(
                workload.get("artifacts", []),
                context,
                checkout=worktrees.paths[variant],
                target_dir=target,
            )
            sample["artifacts"] = artifacts
            if missing:
                sample["status"] = "error"
                sample["error_reason"] = (
                    "required artifacts were not produced: " + ", ".join(missing)
                )
        store.save_partial(document)
        if sample["status"] == "interrupted":
            raise HarnessInterrupted(sample_id)
        return sample

    def _prepare_links(
        self,
        workload: dict[str, Any],
        checkout: Path,
        context: dict[str, str],
    ) -> list[str]:
        reasons: list[str] = []
        for link in workload.get("links", []):
            source = Path(render_template(link["source"], context)).resolve()
            target = checkout / link["target"]
            target_parent = target.parent.resolve()
            checkout_resolved = checkout.resolve()
            if (
                target_parent != checkout_resolved
                and checkout_resolved not in target_parent.parents
            ):
                reasons.append(f"unsafe link target outside checkout: {target}")
                continue
            if not source.exists():
                if link.get("required"):
                    reasons.append(f"required host path is unavailable: {source}")
                continue
            if target.exists() or target.is_symlink():
                if target.is_symlink() and target.resolve() == source:
                    continue
                reasons.append(f"link target already exists and is not the expected link: {target}")
                continue
            try:
                target.symlink_to(source, target_is_directory=source.is_dir())
            except OSError as error:
                reasons.append(f"cannot link {source} into detached checkout: {error}")
        return reasons

    def _checkout_blockers(
        self,
        workload: dict[str, Any],
        checkout: Path,
        context: dict[str, str],
    ) -> list[str]:
        reasons = self._host_blockers(workload, include_links=False)
        for relative in workload.get("required_paths", []):
            if not (checkout / relative).exists():
                reasons.append(f"required path is absent: {relative}")
        for relative in workload.get("required_link_paths", []):
            if not (checkout / relative).exists():
                reasons.append(f"required linked path is absent: {relative}")
        for command_key in ("prepare_command", "command"):
            if command_key not in workload:
                continue
            argv, cwd, _environment = self._render_command(
                workload, command_key, context, checkout
            )
            executable = Path(argv[0])
            if ("/" in argv[0] or "\\" in argv[0]) and not executable.is_absolute():
                executable = cwd / executable
            if executable.is_absolute() and not executable.exists():
                reasons.append(f"{command_key} executable is absent: {executable}")
        return reasons

    def _host_blockers(
        self, workload: dict[str, Any], *, include_links: bool = True
    ) -> list[str]:
        reasons: list[str] = []
        platforms = workload.get("platforms")
        if platforms and platform_name() not in platforms:
            reasons.append(
                f"platform {platform_name()} is unsupported; requires {', '.join(platforms)}"
            )
        environment = child_environment()
        for tool in workload.get("required_tools", []):
            if shutil.which(tool, path=environment["PATH"]) is None:
                reasons.append(f"required tool is not on PATH: {tool}")
        if include_links:
            context = {
                "repo": str(self.repo_root),
                "checkout": str(self.repo_root),
                "target_dir": "<isolated-target>",
                "sample_dir": "<isolated-sample>",
                "run_dir": "<output>",
                "variant": "<variant>",
                "python": sys.executable,
                "exe_suffix": ".exe" if os.name == "nt" else "",
            }
            for link in workload.get("links", []):
                source = Path(render_template(link["source"], context))
                if link.get("required") and not source.exists():
                    reasons.append(f"required host path is unavailable: {source}")
            for relative in workload.get("required_link_paths", []):
                source = self.repo_root / relative
                if not source.exists():
                    reasons.append(f"required host path is unavailable: {source}")
        return reasons

    def _dry_availability(
        self, workload: dict[str, Any], revision: Revision
    ) -> dict[str, str]:
        reasons = self._host_blockers(workload)
        for path in workload.get("required_paths", []):
            if not self.repository.tracked_path_exists(revision, path):
                reasons.append(
                    f"required path is absent from {revision.commit[:12]}: {path}"
                )
        return (
            {"status": "BLOCKED", "reason": "; ".join(reasons)}
            if reasons
            else {"status": "SUPPORTED"}
        )

    def _dry_command(
        self, workload: dict[str, Any], variant: str, revision: Revision
    ) -> dict[str, Any]:
        context = {
            "repo": str(self.repo_root),
            "checkout": f"<detached-{variant}-{revision.commit[:12]}>",
            "target_dir": f"<isolated-target-{variant}-{workload['id']}>",
            "sample_dir": f"<isolated-sample-{variant}-{workload['id']}>",
            "run_dir": "<output>",
            "variant": variant,
            "python": sys.executable,
            "exe_suffix": ".exe" if os.name == "nt" else "",
        }
        overrides = {
            name: render_template(value, context)
            for name, value in workload.get("environment", {}).items()
        }
        target = Path(context["target_dir"])
        overrides.update(
            {
                "HOME": str(target / "home"),
                "USERPROFILE": str(target / "home"),
                "TMPDIR": str(target / "tmp"),
                "TMP": str(target / "tmp"),
                "TEMP": str(target / "tmp"),
            }
        )
        cwd_value = render_template(workload.get("cwd", "."), context)
        cwd = (
            str(Path(context["checkout"]) / cwd_value)
            if not Path(cwd_value).is_absolute()
            else cwd_value
        )
        return {
            "prepare_argv": [
                render_template(argument, context)
                for argument in workload.get("prepare_command", [])
            ],
            "argv": [
                render_template(argument, context)
                for argument in workload["command"]
            ],
            "cwd": cwd,
            "environment": child_environment(overrides),
            "shell": False,
        }

    def _render_command(
        self,
        workload: dict[str, Any],
        command_key: str,
        context: dict[str, str],
        checkout: Path,
    ) -> tuple[list[str], Path, dict[str, str]]:
        argv = [
            render_template(argument, context)
            for argument in workload[command_key]
        ]
        cwd_value = render_template(workload.get("cwd", "."), context)
        cwd = Path(cwd_value)
        if not cwd.is_absolute():
            cwd = checkout / cwd
        cwd = cwd.resolve()
        checkout_resolved = checkout.resolve()
        if cwd != checkout_resolved and checkout_resolved not in cwd.parents:
            raise ValueError(f"workload cwd escapes detached checkout: {cwd}")
        overrides = {
            name: render_template(value, context)
            for name, value in workload.get("environment", {}).items()
        }
        temporary = str(Path(context["target_dir"]) / "tmp")
        home = str(Path(context["target_dir"]) / "home")
        overrides.update(
            {
                "HOME": home,
                "USERPROFILE": home,
                "TMPDIR": temporary,
                "TMP": temporary,
                "TEMP": temporary,
            }
        )
        return argv, cwd, child_environment(overrides)

    def _context(
        self,
        variant: str,
        checkout: Path,
        target: Path,
        sample_dir: Path,
        output: Path,
    ) -> dict[str, str]:
        return {
            "repo": str(self.repo_root),
            "checkout": str(checkout),
            "target_dir": str(target),
            "sample_dir": str(sample_dir),
            "run_dir": str(output),
            "variant": variant,
            "python": sys.executable,
            "exe_suffix": ".exe" if os.name == "nt" else "",
        }

    def _retain_blocked_sample(
        self,
        document: dict[str, Any],
        workload: dict[str, Any],
        variant: str,
        reason: str,
        worktrees: DetachedWorktrees,
        output: Path,
    ) -> None:
        slot_id = f"{workload['id']}:blocked:{variant}"
        if self._slot_is_terminal(document, slot_id):
            return
        target = worktrees.target_for(variant, workload["id"], None, "workload")
        context = self._context(
            variant, worktrees.paths[variant], target, target, output
        )
        argv, cwd, environment = self._render_command(
            workload, "command", context, worktrees.paths[variant]
        )
        document["raw_samples"].append(
            {
                "sample_id": f"{slot_id}:attempt-1",
                "slot_id": slot_id,
                "order_index": -1,
                "phase": "prepare",
                "phase_index": -1,
                "variant": variant,
                "suite_id": workload["suite_id"],
                "workload_id": workload["id"],
                "status": "blocked",
                "error_reason": reason,
                "operations": workload["operations_per_sample"],
                "capacity": workload["capacity"],
                "network_policy": workload["network_policy"],
                "command": {
                    "argv": argv,
                    "cwd": str(cwd),
                    "environment": environment,
                    "shell": False,
                },
                "artifacts": [],
            }
        )

    def _slot_is_terminal(self, document: dict[str, Any], slot_id: str) -> bool:
        return any(
            sample.get("slot_id") == slot_id
            and sample.get("status")
            in {"success", "error", "timeout", "blocked"}
            for sample in document["raw_samples"]
        )

    def _environmental_block_reason(
        self, sample: dict[str, Any], output: Path
    ) -> str | None:
        if sample.get("status") != "error":
            return None
        stderr = sample.get("stderr")
        if not isinstance(stderr, dict) or not isinstance(stderr.get("path"), str):
            return None
        path = output / stderr["path"]
        try:
            message = path.read_text(encoding="utf-8", errors="replace")[:131072]
        except OSError:
            return None
        offline_markers = (
            "attempting to make an http request, but --offline was specified",
            "no matching package named",
            "failed to download",
        )
        if (
            "offline" in message.lower()
            and any(marker in message.lower() for marker in offline_markers)
        ):
            return "required Cargo dependency is not available in the local offline cache"
        return None

    def _plan_hash(
        self,
        reference: Revision,
        candidate: Revision,
        workloads: list[dict[str, Any]],
        schedule: list[dict[str, Any]],
    ) -> str:
        return sha256_json(
            {
                "schema_version": SCHEMA_VERSION,
                "reference": reference.as_dict(),
                "candidate": candidate.as_dict(),
                "workloads": workloads,
                "schedule": schedule,
                "thresholds": self.thresholds,
            }
        )


def _summary_exit_code(status: str) -> int:
    if status == "FAIL":
        return 1
    if status == "BLOCKED":
        return 3
    return 0


def _uncompared_summary(document: dict[str, Any]) -> dict[str, Any]:
    availability = [
        value
        for workload in document["workloads"]
        for value in workload.get("availability", {}).values()
    ]
    sample_statuses = {
        sample.get("status")
        for sample in document["raw_samples"]
        if sample.get("phase") in {"prepare", "warmup", "measure"}
    }
    if any(value.get("status") == "ERROR" for value in availability) or (
        {"error", "timeout"} & sample_statuses
    ):
        status = "FAIL"
    elif any(value.get("status") == "BLOCKED" for value in availability) or (
        "blocked" in sample_statuses
    ):
        status = "BLOCKED"
    else:
        status = "NOT_COMPARED"
    return {"status": status, "workloads": []}
