"""Check 2: risky code patterns (SQL injection, TLS off, shell injection, ...) via Semgrep p/default."""

from security_gate.changes import ChangeSet
from security_gate.checks.semgrep_run import run_once
from security_gate.result import CheckResult
from security_gate.workspace import Workspace

NAME, TOOL = "Risky code", "semgrep"


def run(changes: ChangeSet, workspace: Workspace) -> CheckResult:
    if not workspace.files:
        return CheckResult(NAME, TOOL, not_applicable="no text files changed")
    out = run_once(changes, workspace)
    return CheckResult(NAME, TOOL, out.registry, error=out.error, seconds=out.seconds, notes=out.notes)
