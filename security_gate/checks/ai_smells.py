"""Check 3: AI code smells: our own Semgrep rule pack (security_gate/rules/ai-smells.yml).

Runs in the SAME Semgrep invocation as check 2; this check reports only the pack's hits.
"""

from security_gate.changes import ChangeSet
from security_gate.checks.semgrep_run import run_once
from security_gate.result import CheckResult
from security_gate.workspace import Workspace

NAME, TOOL = "AI code smells", "semgrep+pack"


def run(changes: ChangeSet, workspace: Workspace) -> CheckResult:
    if not workspace.files:
        return CheckResult(NAME, TOOL, not_applicable="no text files changed")
    out = run_once(changes, workspace)
    return CheckResult(NAME, TOOL, out.ai_smells, error=out.error)
