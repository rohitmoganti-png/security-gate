"""The `security-gate` command.

    security-gate scan --base <commit-or-branch> [--head HEAD] [--repo .] [--mode enforce|report]

Exit codes: 0 = passed (or report-only), 1 = blocked, 2 = a check could not run (fail closed).
"""

from __future__ import annotations

import argparse
import os
import sys

from security_gate import __version__, report
from security_gate.changes import GitError, collect_changes
from security_gate.checks import ALL_CHECKS
from security_gate.workspace import make_workspace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-gate")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan what changed between two commits")
    scan.add_argument("--repo", default=".", help="path to the git repository")
    scan.add_argument("--base", default="", help="compare against this (empty = first push)")
    scan.add_argument("--head", default="HEAD", help="the new commit (default: HEAD)")
    scan.add_argument(
        "--mode",
        choices=["enforce", "report"],
        default=os.environ.get("SECURITY_GATE_MODE") or "enforce",
        help="enforce = block on serious new issues; report = never block",
    )
    scan.add_argument("--output", default="security-report.json", help="JSON report path")
    args = parser.parse_args(argv)

    try:
        changes = collect_changes(args.repo, args.base, args.head)
    except GitError as exc:
        print(f"security-gate: error: {exc}", file=sys.stderr)
        return report.EXIT_ERROR

    report.print_header(changes, args.mode)
    results = []
    with make_workspace(changes) as workspace:
        if workspace.skipped_settings_files:
            print(f"Ignored scanner-settings files from this change: {workspace.skipped_settings_files}")
        for number, check in enumerate(ALL_CHECKS, 1):
            result = check.run(changes, workspace)
            report.print_check(number, result)
            results.append(result)

    code, final = report.verdict(results, args.mode)
    report.print_summary(results, final)
    report.write_github_summary(results, final)
    report.write_json(args.output, changes, results, final)
    print(f"Full report: {args.output}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
