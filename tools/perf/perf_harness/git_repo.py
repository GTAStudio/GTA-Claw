"""Read-only revision resolution and detached worktree materialization."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class GitError(RuntimeError):
    """Raised when a repository operation cannot be completed safely."""


@dataclass(frozen=True)
class Revision:
    requested: str
    commit: str
    tree: str

    def as_dict(self) -> dict[str, str]:
        return {
            "requested": self.requested,
            "commit": self.commit,
            "tree": self.tree,
        }


class GitRepository:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        discovered = self._git("rev-parse", "--show-toplevel")
        if Path(discovered).resolve() != self.root:
            raise GitError(f"repository root mismatch: {discovered} != {self.root}")

    def resolve(self, requested: str) -> Revision:
        commit = self._git(
            "rev-parse", "--verify", "--end-of-options", f"{requested}^{{commit}}"
        )
        tree = self._git("show", "-s", "--format=%T", commit)
        return Revision(requested=requested, commit=commit, tree=tree)

    def merge_base(self, left: Revision, right: Revision) -> dict[str, str]:
        commit = self._git("merge-base", left.commit, right.commit)
        tree = self._git("show", "-s", "--format=%T", commit)
        return {"commit": commit, "tree": tree}

    def tracked_path_exists(self, revision: Revision, relative_path: str) -> bool:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "cat-file",
                "-e",
                f"{revision.commit}:{relative_path}",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0

    def worktrees(
        self,
        run_id: str,
        reference: Revision,
        candidate: Revision,
        *,
        keep: bool,
    ) -> "DetachedWorktrees":
        return DetachedWorktrees(self, run_id, reference, candidate, keep=keep)

    def _git(self, *arguments: str, check: bool = True) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if check and result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise GitError(f"git {' '.join(arguments)} failed: {detail}")
        return result.stdout.strip()


class DetachedWorktrees:
    """Two detached checkouts plus isolated build targets."""

    def __init__(
        self,
        repository: GitRepository,
        run_id: str,
        reference: Revision,
        candidate: Revision,
        *,
        keep: bool,
    ) -> None:
        self.repository = repository
        self.revisions = {"reference": reference, "candidate": candidate}
        safe_id = "".join(
            character if character.isalnum() or character in "-_" else "-"
            for character in run_id
        )
        base = Path(tempfile.gettempdir()).resolve() / "gta-claw-perf"
        self.root = (base / safe_id).resolve()
        if base not in self.root.parents:
            raise GitError(f"unsafe performance worktree root: {self.root}")
        self.paths = {
            "reference": self.root / "reference",
            "candidate": self.root / "candidate",
        }
        self.targets = self.root / "targets"
        self.keep = keep

    def __enter__(self) -> "DetachedWorktrees":
        self._clear_previous()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            for variant in ("reference", "candidate"):
                self.repository._git(
                    "worktree",
                    "add",
                    "--detach",
                    "--force",
                    str(self.paths[variant]),
                    self.revisions[variant].commit,
                )
            self.targets.mkdir(parents=True, exist_ok=True)
        except BaseException:
            self.cleanup()
            raise
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if not self.keep:
            self.cleanup()

    def target_for(
        self, variant: str, workload_id: str, slot_id: str | None, scope: str
    ) -> Path:
        base = self.targets / variant / workload_id
        if scope == "sample":
            if slot_id is None:
                raise GitError(f"sample-scoped target requires a slot: {workload_id}")
            safe_slot = "".join(
                character if character.isalnum() or character in "-_" else "-"
                for character in slot_id
            )
            return base / safe_slot
        if scope != "workload":
            raise GitError(f"unknown target scope: {scope}")
        return base

    def cleanup(self) -> None:
        for variant in ("candidate", "reference"):
            path = self.paths[variant]
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repository.root),
                    "worktree",
                    "remove",
                    "--force",
                    str(path),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode and path.exists():
                shutil.rmtree(path)
        self.repository._git("worktree", "prune", check=False)
        if self.root.exists():
            shutil.rmtree(self.root)

    def _clear_previous(self) -> None:
        if not self.root.exists():
            return
        self.cleanup()
