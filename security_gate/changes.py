"""Work out WHAT CHANGED between two commits: which files, and which new lines.

Every check uses this so it only looks at the push/PR, never the whole repo.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

# git's built-in ID for "an empty folder": comparing against it = every file is new (first push)
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_ZERO_SHA = "0" * 40  # what GitHub sends as "before" on a branch's very first push
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GitError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str  # "added" | "modified" | "deleted" | "renamed"
    added_lines: frozenset[int]  # line numbers (in the new version) this change wrote

    def touches(self, start: int, end: int | None = None) -> bool:
        """Did this change write any line between start and end?"""
        return any(start <= n <= (end or start) for n in self.added_lines)


@dataclass(frozen=True)
class ChangeSet:
    repo: Path
    base: str
    head: str
    files: tuple[ChangedFile, ...]

    @property
    def current_files(self) -> tuple[ChangedFile, ...]:
        """Changed files that still exist (deleted files can't be scanned)."""
        return tuple(f for f in self.files if f.status != "deleted")

    def get(self, path: str) -> ChangedFile | None:
        return next((f for f in self.files if f.path == path), None)


def git(repo: Path, *args: str) -> str:
    """Run git safely: arguments as a list (no shell), a timeout, clear errors."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out") from exc
    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def resolve(repo: Path, ref: str | None) -> str:
    """Turn a branch / tag / SHA into a full commit SHA. Empty or all-zero = first push."""
    if not ref or ref == _ZERO_SHA:
        return EMPTY_TREE
    if ref.startswith("-"):  # a ref must never be read as a git option
        raise GitError(f"refusing unsafe ref {ref!r}")
    try:
        return git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").strip()
    except GitError as exc:
        raise GitError(f"unknown git ref {ref!r} (is it fetched? use fetch-depth: 0)") from exc


def collect_changes(repo: str | Path, base: str | None, head: str = "HEAD") -> ChangeSet:
    repo = Path(repo).resolve()
    head_sha = resolve(repo, head)
    base_sha = resolve(repo, base)
    if base_sha != EMPTY_TREE:
        # Compare against where the branch split off (like GitHub's PR view), so commits
        # added to main later are never blamed on this change.
        base_sha = git(repo, "merge-base", base_sha, head_sha).strip()

    files = []
    for status, path in _changed_paths(repo, base_sha, head_sha):
        lines = frozenset() if status == "deleted" else _added_lines(repo, base_sha, head_sha, path)
        files.append(ChangedFile(path, status, lines))
    return ChangeSet(repo, base_sha, head_sha, tuple(files))


def _changed_paths(repo: Path, base: str, head: str) -> list[tuple[str, str]]:
    # -z = NUL-separated output, so paths with spaces/unicode are never mangled
    out = git(repo, "diff", "--name-status", "-z", "--find-renames", base, head)
    parts = [p for p in out.split("\0") if p]
    names = {"A": "added", "M": "modified", "D": "deleted", "R": "renamed", "T": "modified"}
    result, i = [], 0
    while i < len(parts):
        code = parts[i][0]
        if code in ("R", "C"):  # renames/copies list old path then new path
            result.append(("renamed" if code == "R" else "added", parts[i + 2]))
            i += 3
        else:
            result.append((names.get(code, "modified"), parts[i + 1]))
            i += 2
    return result


def _added_lines(repo: Path, base: str, head: str, path: str) -> frozenset[int]:
    """Read '@@ -a,b +c,d @@' headers: the change wrote lines c .. c+d-1 of the new file."""
    out = git(repo, "diff", "--unified=0", "--no-color", "--no-ext-diff", base, head, "--", path)
    lines: set[int] = set()
    for row in out.splitlines():
        if match := _HUNK.match(row):
            start, count = int(match.group(1)), int(match.group(2) or 1)
            lines.update(range(start, start + count))
    return frozenset(lines)
