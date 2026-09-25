"""Build what the AI reviewers are shown: changed code + the local files it imports.

  * lines are numbered and lines written by this change are marked '+'
  * every line containing a secret is REDACTED before anything leaves the machine
    (Gitleaks scans all context files; if it can't run, nothing is sent: fail closed)
  * total size is capped (changed files first, then imports) so cost stays predictable
"""

from __future__ import annotations

import json
import posixpath
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from security_gate.changes import ChangeSet, GitError, git
from security_gate.tools import ToolError, find_tool, run_tool

CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php", ".cs"}
REDACTED = "[REDACTED BY SECURITY-GATE: line contained a secret]"
MAX_TOTAL_CHARS = 60_000  # ~15k tokens
MAX_FILE_CHARS = 20_000

_PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.MULTILINE)
_JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*)['"](\.{1,2}/[^'"]+)['"]""")


class ContextError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContextFile:
    path: str
    content: str  # already redacted
    role: str  # "changed" | "imported by <path>"
    added_lines: frozenset[int]


@dataclass(frozen=True)
class Context:
    files: tuple[ContextFile, ...]
    truncated: bool

    @property
    def contents(self) -> dict[str, str]:
        """{path: content}: exactly what the AI saw (the validator checks citations against it)."""
        return {f.path: f.content for f in self.files}

    def render(self) -> str:
        blocks = []
        for f in self.files:
            lines = [
                f"{n:>5}{'+' if n in f.added_lines else ' '}| {text}"
                for n, text in enumerate(f.content.splitlines(), 1)
            ]
            blocks.append(f"=== FILE: {f.path}  ({f.role}) ===\n" + "\n".join(lines))
        return "\n\n".join(blocks)


def build_context(changes: ChangeSet) -> Context:
    repo_files = set(git(changes.repo, "ls-tree", "-r", "--name-only", changes.head).splitlines())
    changed = [f for f in changes.current_files if PurePosixPath(f.path).suffix in CODE_EXTENSIONS]

    selected: list[tuple[str, str, frozenset[int]]] = []  # (path, role, added_lines)
    for f in changed:
        selected.append((f.path, "changed", f.added_lines))
    seen = {f.path for f in changed}
    for f in changed:
        for target in _local_imports(f.path, _show(changes, f.path), repo_files):
            if target not in seen:
                seen.add(target)
                selected.append((target, f"imported by {f.path}", frozenset()))

    raw = {path: _show(changes, path) for path, _, _ in selected}
    raw = redact_secrets(raw)

    files, total, truncated = [], 0, False
    for path, role, added in selected:
        content = raw[path]
        if len(content) > MAX_FILE_CHARS:
            content = content[:MAX_FILE_CHARS].rsplit("\n", 1)[0] + "\n# ... [file truncated]"
            truncated = True
        if total + len(content) > MAX_TOTAL_CHARS:
            truncated = True
            continue  # deterministic: later (lower-priority) files are the ones dropped
        total += len(content)
        files.append(ContextFile(path, content, role, added))
    return Context(tuple(files), truncated)


def redact_secrets(files: dict[str, str]) -> dict[str, str]:
    """Replace every line Gitleaks flags with a marker. No Gitleaks = no context (fail closed)."""
    exe = find_tool("gitleaks")
    if exe is None:
        raise ContextError("gitleaks not available: refusing to send code to the AI unscanned")
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
        root = Path(tmp).resolve()
        for path, content in files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        report = Path(out) / "r.json"
        try:
            r = run_tool([exe, "dir", str(root), "--report-format=json", f"--report-path={report}",
                          "--no-banner", "--exit-code=0", "--log-level=error", "--redact=100"], 120)  # fmt: skip
        except ToolError as exc:
            raise ContextError(f"secret scan of AI context failed: {exc}") from exc
        if r.returncode != 0 or not report.exists():
            raise ContextError("secret scan of AI context failed: refusing to send code to the AI")
        hits = json.loads(report.read_text() or "[]")

    flagged: dict[str, set[int]] = {}
    for h in hits:
        path = Path(h["File"]).resolve().relative_to(root).as_posix()
        flagged.setdefault(path, set()).update(range(int(h["StartLine"]), int(h["EndLine"]) + 1))
    cleaned = {}
    for path, content in files.items():
        lines = content.splitlines()
        for n in flagged.get(path, ()):
            if 0 < n <= len(lines):
                indent = lines[n - 1][: len(lines[n - 1]) - len(lines[n - 1].lstrip())]
                lines[n - 1] = indent + REDACTED
        cleaned[path] = "\n".join(lines) + ("\n" if content.endswith("\n") else "")
    return cleaned


def _local_imports(path: str, content: str, repo_files: set[str]) -> list[str]:
    """Resolve imports to files IN this repo (third-party packages are skipped). One hop only."""
    found = []
    if path.endswith(".py"):
        for m in _PY_IMPORT.finditer(content):
            module = (m.group(1) or m.group(2)).lstrip(".")
            if not module:
                continue
            base = module.replace(".", "/")
            for candidate in (f"{base}.py", f"{base}/__init__.py", f"src/{base}.py"):
                if candidate in repo_files:
                    found.append(candidate)
                    break
    elif PurePosixPath(path).suffix in {".js", ".jsx", ".ts", ".tsx"}:
        for m in _JS_IMPORT.finditer(content):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(path), m.group(1)))
            for ext in ("", ".js", ".ts", ".jsx", ".tsx", "/index.js", "/index.ts"):
                if base + ext in repo_files:
                    found.append(base + ext)
                    break
    return found


def _show(changes: ChangeSet, path: str) -> str:
    try:
        return git(changes.repo, "show", f"{changes.head}:{path}")
    except GitError:
        return ""
