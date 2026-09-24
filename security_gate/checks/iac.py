"""Check 6: infrastructure-as-code misconfigurations (Checkov).

Runs ONLY when the push changed infra files: Terraform, Kubernetes, CloudFormation,
Dockerfiles, or GitHub Actions workflows. Otherwise the result is N/A (not a pass).

Checkov's free edition reports no severities, so we keep a short curated list of
high-risk rules that BLOCK; everything else is a warning.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import PurePosixPath

from security_gate.changes import ChangeSet
from security_gate.result import CheckResult, Finding, Severity
from security_gate.tools import ToolError, find_tool, run_tool
from security_gate.workspace import Workspace

NAME, TOOL = "Infrastructure", "checkov"
FRAMEWORKS = "terraform,kubernetes,cloudformation,dockerfile,github_actions"

HIGH_RISK = {  # exposed to the internet / credentials / container escape
    "CKV_AWS_24": "SSH (22) open to the internet",
    "CKV_AWS_25": "RDP (3389) open to the internet",
    "CKV_AWS_41": "hardcoded AWS keys in provider",
    "CKV_AWS_20": "S3 bucket publicly readable",
    "CKV_AWS_57": "S3 bucket publicly writable",
    "CKV_AWS_17": "database publicly accessible",
    "CKV_K8S_16": "privileged container",
    "CKV_K8S_17": "shares host PID namespace",
    "CKV_K8S_18": "shares host IPC namespace",
    "CKV_K8S_19": "shares host network",
    "CKV2_GHA_1": "workflow token has write-all permissions",
}
MEDIUM_RISK = {"CKV_DOCKER_8", "CKV_K8S_20", "CKV_K8S_23", "CKV_K8S_14", "CKV_DOCKER_7", "CKV_DOCKER_4"}

_K8S = re.compile(r"^\s*apiVersion:.*$[\s\S]*^\s*kind:", re.MULTILINE)
_CFN = re.compile(r"AWSTemplateFormatVersion|\bAWS::[A-Za-z0-9]+::")


def infra_files(workspace: Workspace) -> list[str]:
    found = []
    for path in workspace.files:
        p = PurePosixPath(path)
        name = p.name.lower()
        is_yaml_json = p.suffix in (".yml", ".yaml", ".json")
        text = workspace.read(path) or "" if is_yaml_json else ""
        if (
            p.suffix == ".tf"
            or name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")
            or (path.startswith(".github/workflows/") and p.suffix in (".yml", ".yaml"))
            or (is_yaml_json and (_K8S.search(text) or _CFN.search(text)))
        ):  # fmt: skip
            found.append(path)
    return found


def run(changes: ChangeSet, workspace: Workspace) -> CheckResult:
    started = time.monotonic()
    files = infra_files(workspace)
    if not files:
        return CheckResult(NAME, TOOL, not_applicable="no infrastructure files changed")
    exe = find_tool("checkov")
    if exe is None:
        return CheckResult(NAME, TOOL, error="checkov not installed (run scripts/install-tools.sh)")

    cmd = [exe, "-d", str(workspace.root), "--framework", FRAMEWORKS, "--output", "json",
           "--quiet", "--compact", "--soft-fail", "--skip-download"]  # fmt: skip
    try:
        r = run_tool(cmd, timeout=600)
    except ToolError as exc:
        return CheckResult(NAME, TOOL, error=str(exc))
    try:
        data = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        return CheckResult(NAME, TOOL, error=f"checkov failed: {r.stderr.strip()[:300]}")

    findings = []
    for block in data if isinstance(data, list) else [data]:
        for item in block.get("results", {}).get("failed_checks", []):
            findings.append(_to_finding(item, changes))
    findings += pull_request_target_checks(changes, workspace, files)
    note = f"scanned {len(files)} infra file(s): {', '.join(files)}"
    return CheckResult(NAME, TOOL, tuple(findings), seconds=time.monotonic() - started, notes=(note,))


def _to_finding(item: dict, changes: ChangeSet) -> Finding:
    check_id = item["check_id"]
    path = item["file_path"].lstrip("/")
    start, end = (max(1, n) for n in (item.get("file_line_range") or [1, 1]))
    if check_id in HIGH_RISK:
        severity, message = Severity.HIGH, f"{HIGH_RISK[check_id]}: {item['check_name']}"
    else:
        severity = Severity.MEDIUM if check_id in MEDIUM_RISK else Severity.LOW
        message = item["check_name"]
    changed = changes.get(path)
    return Finding(
        rule=check_id,
        severity=severity,
        path=path,
        line=start,
        message=message,
        evidence=item.get("guideline") or "",
        new=bool(changed and changed.touches(start, end)),
    )


def pull_request_target_checks(changes: ChangeSet, workspace: Workspace, files: list[str]) -> list[Finding]:
    """Our own rule (ENG-384): pull_request_target + checking out the PR's code = untrusted code
    running with the repo's secrets. This is how the Trivy supply-chain attack worked."""
    findings = []
    for path in files:
        if not path.startswith(".github/workflows/"):
            continue
        text = workspace.read(path) or ""
        if "pull_request_target" in text and re.search(r"github\.event\.pull_request\.head\.(sha|ref)", text):
            line = next((i for i, row in enumerate(text.splitlines(), 1) if "pull_request_target" in row), 1)
            changed = changes.get(path)
            findings.append(
                Finding(
                    rule="gha-pull-request-target-checkout",
                    severity=Severity.CRITICAL,
                    path=path,
                    line=line,
                    message="Workflow runs on pull_request_target AND checks out the PR's code: untrusted "
                    "code runs with this repo's secrets. Use the pull_request trigger instead.",
                    new=bool(changed and changed.added_lines),
                )
            )
    return findings
