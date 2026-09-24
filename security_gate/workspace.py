"""Copy ONLY the changed files into a temporary folder for the scanners.

Why not scan the checkout directly?
  * guarantees only the push/PR is scanned, never the whole repo
  * drops scanner-settings files a PR could add to switch scanning off
    (e.g. a .gitleaks.toml that allow-lists everything)
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from security_gate.changes import ChangeSet, GitError, git

# A PR must never be able to configure its own scan.
SCANNER_SETTINGS_FILES = frozenset({".gitleaks.toml", ".gitleaksignore", ".semgrepignore"})


@dataclass(frozen=True)
class Workspace:
    root: Path
    files: tuple[str, ...]  # repo-relative paths copied into root
    skipped_settings_files: tuple[str, ...]

    def read(self, path: str) -> str | None:
        return (self.root / path).read_text(errors="replace") if path in self.files else None


@contextmanager
def make_workspace(changes: ChangeSet) -> Iterator[Workspace]:
    with tempfile.TemporaryDirectory(prefix="security-gate-") as tmp:
        root = Path(tmp).resolve()
        copied, skipped = [], []
        for changed in changes.current_files:
            if PurePosixPath(changed.path).name in SCANNER_SETTINGS_FILES:
                skipped.append(changed.path)
                continue
            try:
                content = git(changes.repo, "show", f"{changes.head}:{changed.path}")
            except GitError:
                continue  # e.g. a submodule entry: nothing to scan
            target = (root / changed.path).resolve()
            if not target.is_relative_to(root):  # never write outside the temp folder
                raise GitError(f"refusing unsafe path {changed.path!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            copied.append(changed.path)
        # Our own EMPTY .semgrepignore: Semgrep then scans every copied file
        # (its built-in default silently skips folders like tests/).
        (root / ".semgrepignore").write_text("")
        yield Workspace(root, tuple(sorted(copied)), tuple(skipped))
