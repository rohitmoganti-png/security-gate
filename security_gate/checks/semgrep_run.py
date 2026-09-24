"""ONE Semgrep run shared by check 2 (risky code) and check 3 (AI code smells).

Loads Semgrep's curated ruleset AND our own AI-smell pack in a single invocation,
then each check picks its half of the results (by `metadata.source`).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from security_gate.changes import ChangeSet
from security_gate.result import Finding, Severity
from security_gate.tools import ToolError, find_tool, run_tool
from security_gate.workspace import Workspace

REGISTRY_RULES = "p/default"  # Semgrep's curated multi-language security rules
AI_SMELL_RULES = Path(__file__).resolve().parent.parent / "rules" / "ai-smells.yml"

_SEVERITY = {"CRITICAL": Severity.CRITICAL, "ERROR": Severity.HIGH, "HIGH": Severity.HIGH,
             "WARNING": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
             "INFO": Severity.LOW, "LOW": Severity.LOW}  # fmt: skip


@dataclass(frozen=True)
class SemgrepOutput:
    registry: tuple[Finding, ...]  # found by p/default
    ai_smells: tuple[Finding, ...]  # found by our pack
    error: str = ""
    seconds: float = 0.0
    notes: tuple[str, ...] = ()


_cache: dict[Path, SemgrepOutput] = {}  # one run per workspace, reused by both checks


def run_once(changes: ChangeSet, workspace: Workspace) -> SemgrepOutput:
    if workspace.root not in _cache:
        _cache.clear()
        _cache[workspace.root] = _run(changes, workspace)
    return _cache[workspace.root]


def _run(changes: ChangeSet, workspace: Workspace) -> SemgrepOutput:
    started = time.monotonic()
    exe = find_tool("semgrep")
    if exe is None:
        return SemgrepOutput((), (), error="semgrep not installed (run scripts/install-tools.sh)")
    cmd = [exe, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
           "--timeout=30", f"--config={REGISTRY_RULES}", f"--config={AI_SMELL_RULES}", "."]  # fmt: skip
    try:
        r = run_tool(cmd, timeout=600, cwd=workspace.root)
    except ToolError as exc:
        return SemgrepOutput((), (), error=str(exc))
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return SemgrepOutput((), (), error=f"semgrep failed: {r.stderr.strip()[:300]}")
    fatal = [e for e in data.get("errors", []) if e.get("level") == "error"]
    if r.returncode not in (0, 1) or (fatal and not data.get("results")):
        detail = "; ".join(e.get("message", "")[:150] for e in fatal) or r.stderr[:300]
        return SemgrepOutput((), (), error=f"semgrep error: {detail}")

    registry, smells = [], []
    for item in data.get("results", []):
        rule_id = item["check_id"]
        if ".secrets." in rule_id:
            continue  # secrets are Gitleaks' job (check 1); avoids duplicates + printing the value
        extra = item.get("extra", {})
        is_smell = extra.get("metadata", {}).get("source") == "ai-smell-pack"
        path = item["path"].removeprefix("./")
        line = item["start"]["line"]
        changed = changes.get(path)
        finding = Finding(
            rule=_short_id(rule_id),
            severity=_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
            path=path,
            line=line,
            message=" ".join(extra.get("message", "").split())[:240],
            evidence=_line(workspace, path, line),
            new=bool(changed and changed.touches(line, item["end"]["line"])),
        )
        (smells if is_smell else registry).append(finding)
    # Files Semgrep could not fully parse get less coverage: say so rather than stay silent.
    unparsed = sorted(
        {e.get("path", "?").removeprefix("./") for e in data.get("errors", [])
         if "Pars" in str(e.get("type")) or "Syntax error" in str(e.get("message"))}
    )  # fmt: skip
    notes = tuple(f"could not fully parse {p}: coverage reduced for that file" for p in unparsed)
    return SemgrepOutput(tuple(registry), tuple(smells), seconds=time.monotonic() - started, notes=notes)


def _short_id(rule_id: str) -> str:
    """Semgrep prefixes local-rule IDs with their folder path; keep a stable, readable ID."""
    if "ai-smell." in rule_id:
        return "ai-smell." + rule_id.split("ai-smell.", 1)[1]
    return rule_id.rsplit(".", 1)[-1]  # python.x.y.sql-injection -> sql-injection


def _line(workspace: Workspace, path: str, line: int) -> str:
    content = workspace.read(path) or ""
    lines = content.splitlines()
    return f"code: {lines[line - 1].strip()[:160]}" if 0 < line <= len(lines) else ""
