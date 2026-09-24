"""Check 1: hardcoded secrets (Gitleaks).

* The full secret never reaches our code: Gitleaks masks it at the source (--redact),
  and we mask again before printing (defense in depth).
* A `gitleaks:allow` comment on a line silences a known-safe example value.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from security_gate.changes import ChangeSet
from security_gate.result import CheckResult, Finding, Severity
from security_gate.tools import ToolError, find_tool, run_tool
from security_gate.workspace import Workspace

NAME, TOOL = "Secrets", "gitleaks"


def mask(value: str) -> str:
    """Show at most 6 characters: 'sk_live_51Hq...' -> 'sk_liv****'."""
    prefix = value.split("...", 1)[0][:6]
    return f"{prefix}****" if prefix else "****"


def run(changes: ChangeSet, workspace: Workspace) -> CheckResult:
    started = time.monotonic()
    exe = find_tool("gitleaks")
    if exe is None:
        return CheckResult(NAME, TOOL, error="gitleaks not installed (run scripts/install-tools.sh)")
    if not workspace.files:
        return CheckResult(NAME, TOOL, not_applicable="no text files changed")

    # The report goes OUTSIDE the scanned folder so Gitleaks never scans its own output.
    with tempfile.TemporaryDirectory() as out:
        report = Path(out) / "gitleaks.json"
        cmd = [exe, "dir", str(workspace.root), "--report-format=json", f"--report-path={report}",
               "--no-banner", "--exit-code=0", "--log-level=error", "--redact=85"]  # fmt: skip
        try:
            r = run_tool(cmd, timeout=120)
        except ToolError as exc:
            return CheckResult(NAME, TOOL, error=str(exc))
        if r.returncode != 0 or not report.exists():
            return CheckResult(NAME, TOOL, error=f"gitleaks failed: {r.stderr.strip()[:300]}")
        raw = json.loads(report.read_text() or "[]")

    findings = []
    for item in raw:
        path = Path(item["File"]).resolve().relative_to(workspace.root).as_posix()
        line = int(item["StartLine"])
        changed = changes.get(path)
        findings.append(
            Finding(
                rule=item.get("RuleID", "secret"),
                severity=Severity.HIGH,
                path=path,
                line=line,
                message=item.get("Description", "Possible hardcoded secret").split(",")[0],
                evidence=f"secret: {mask(item.get('Secret', ''))}",
                new=bool(changed and changed.touches(line)),
            )
        )
    return CheckResult(NAME, TOOL, tuple(findings), seconds=time.monotonic() - started)
