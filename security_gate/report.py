"""Turn check results into what people read.

  * log: one collapsible section per check (GitHub '::group::'), ending in PASS/WARN/FAIL/N/A/ERROR
  * inline annotations on the changed files ('::error file=..,line=..::')
  * a summary table + final RESULT line
  * the same table on the run's Summary page ($GITHUB_STEP_SUMMARY)
  * security-report.json for machines
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from security_gate import __version__
from security_gate.changes import ChangeSet
from security_gate.result import CheckResult, Status

EXIT_PASS, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2
_IN_GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"


def print_header(changes: ChangeSet, mode: str) -> None:
    print(f"Security Gate v{__version__}  |  mode: {mode}  |  {changes.base[:8]} → {changes.head[:8]}")
    print(f"{len(changes.files)} changed file(s):")
    for f in changes.files:
        print(f"   {f.status:<9} {f.path}")
    print()


def print_check(number: int, result: CheckResult) -> None:
    title = f"{number}. {result.name} ({result.tool})"
    summary = f"{title} {'.' * max(3, 42 - len(title))} {result.status}  {_count(result)}"
    print(f"::group::{summary}" if _IN_GITHUB else f"▶ {summary}")
    if result.error:
        print(f"   ERROR: {result.error}")
    if result.not_applicable:
        print(f"   Not applicable: {result.not_applicable}")
    for note in result.notes:
        print(f"   note: {note}")
    for f in sorted(result.findings, key=lambda f: (-f.severity.rank, f.path, f.line)):
        scope = "NEW" if f.new else "pre-existing"
        flag = "BLOCKING" if f.blocking else "warning"
        print(f"   [{f.severity.upper()}] {f.path}:{f.line}  {f.rule}  ({scope}, {flag})")
        print(f"        {f.message}")
        if f.evidence:
            print(f"        {f.evidence}")
    if not result.findings and not result.error and not result.not_applicable:
        print("   No issues found.")
    if _IN_GITHUB:
        print("::endgroup::")
        for f in result.findings:  # shows the problem inline on the file in the PR / commit view
            level = "error" if f.blocking else "warning"
            print(f"::{level} file={f.path},line={f.line},title={result.name}: {f.rule}::{f.message}")


def verdict(results: list[CheckResult], mode: str) -> tuple[int, str]:
    errors = [r.name for r in results if r.status is Status.ERROR]
    blocking = sum(1 for r in results for f in r.findings if f.blocking)
    if errors:  # fail closed: a check that couldn't run is never treated as a pass
        return EXIT_ERROR, f"ERROR: check(s) could not run: {', '.join(errors)} (failing closed)"
    if blocking and mode == "enforce":
        return EXIT_BLOCKED, f"BLOCKED: {blocking} blocking issue(s)"
    if blocking:
        return EXIT_PASS, f"REPORT ONLY: {blocking} blocking issue(s) found (mode=report, not blocking)"
    return EXIT_PASS, "PASSED: no blocking issues"


def print_summary(results: list[CheckResult], final: str) -> None:
    labels = [f"{r.name} ({r.tool})" for r in results]
    width = max([len(label) for label in labels] + [5]) + 2  # fit the longest check name
    line = "─" * (width + 40)
    print("\n" + line)
    print(f"{'#':<3}{'Check':<{width}}{'Result':<8}Details")
    for i, (r, label) in enumerate(zip(results, labels, strict=True), 1):
        print(f"{i:<3}{label:<{width}}{r.status:<8}{_count(r)}")
    print(line)
    print(f"RESULT: {final}")


def write_github_summary(results: list[CheckResult], final: str) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "N/A": "➖", "ERROR": "🛑"}
    rows = ["## Security Check", "", "| # | Check | Result | Details |", "|---|---|---|---|"]
    rows += [
        f"| {i} | {r.name} ({r.tool}) | {icon[r.status]} {r.status} | {_count(r)} |"
        for i, r in enumerate(results, 1)
    ]
    findings = [(r.name, f) for r in results for f in r.findings]
    if findings:
        rows += ["", "### Findings", "", "| Check | Severity | Location | Rule | Blocking |",
                 "|---|---|---|---|---|"]  # fmt: skip
        rows += [
            f"| {name} | {f.severity} | `{f.path}:{f.line}` | {f.rule} | {'yes' if f.blocking else 'no'} |"
            for name, f in findings
        ]
    rows += ["", f"**{final}**"]
    with open(target, "a") as fh:
        fh.write("\n".join(rows) + "\n")


def run_metadata(changes: ChangeSet) -> dict:
    """Where/when this ran, from the variables GitHub Actions sets (empty when run locally)."""
    env = os.environ
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    repo = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    ref = env.get("GITHUB_REF", "")
    pr = ref.split("/")[2] if ref.startswith("refs/pull/") else None
    return {
        "repository": repo,
        "server_url": server,
        "event": env.get("GITHUB_EVENT_NAME", "local"),
        "branch": env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME", ""),
        "pull_request": int(pr) if pr and pr.isdigit() else None,
        "head_sha": changes.head,
        "base_sha": changes.base,
        "actor": env.get("GITHUB_ACTOR", ""),
        "run_id": run_id,
        "run_url": f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else "",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def build_report(
    changes: ChangeSet, results: list[CheckResult], final: str, mode: str, exit_code: int
) -> dict:
    """Everything a person or a dashboard needs about one run (secrets are already masked)."""
    blocking = sum(1 for r in results for f in r.findings if f.blocking)
    return {
        "version": __version__,
        "result": final,
        "exit_code": exit_code,
        "mode": mode,
        "blocking_count": blocking,
        "duration_seconds": round(sum(r.seconds for r in results), 1),
        "run": run_metadata(changes),
        "changed_files": [
            {"path": f.path, "status": f.status, "lines_changed": len(f.added_lines)}
            for f in changes.files
        ],
        "checks": [
            {
                **asdict(r),
                "status": r.status,
                "findings": [{**asdict(f), "blocking": f.blocking} for f in r.findings],
            }
            for r in results
        ],
    }


def write_json(path: str, report: dict) -> None:
    Path(path).write_text(json.dumps(report, indent=2, default=str))


def _count(r: CheckResult) -> str:
    if r.error:
        return "could not run"
    if r.not_applicable:
        return r.not_applicable
    blocking = sum(1 for f in r.findings if f.blocking)
    if not r.findings:
        return "no issues"
    return f"{len(r.findings)} finding(s), {blocking} blocking"
