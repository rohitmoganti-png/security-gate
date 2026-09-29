"""The `security-gate` command.

    security-gate scan --base <commit-or-branch> [--head HEAD] [--repo .] [--mode enforce|report]
    security-gate upload --bucket <s3-bucket> [--json security-report.json] [--html security-report.html]

Exit codes: 0 = passed (or report-only), 1 = blocked, 2 = a check could not run (fail closed).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from security_gate import __version__, html_report, report
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
    scan.add_argument("--html", default="security-report.html", help="HTML report path")
    upload = sub.add_parser("upload", help="file the JSON + HTML reports in S3")
    upload.add_argument("--bucket", required=True, help="S3 bucket (the stack's ReportsBucketName)")
    upload.add_argument("--json", default="security-report.json", help="JSON report path")
    upload.add_argument("--html", default="security-report.html", help="HTML report path")
    args = parser.parse_args(argv)

    if args.command == "upload":
        return _upload(args)

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
    data = report.build_report(changes, results, final, args.mode, code)
    report.write_json(args.output, data)
    Path(args.html).write_text(html_report.render(data))
    print(f"Full report: {args.output} and {args.html}")
    return code


def _upload(args: argparse.Namespace) -> int:
    from security_gate.storage import upload_reports

    try:
        for uri in upload_reports(args.bucket, args.json, args.html):
            print(f"Saved {uri}")
    except Exception as exc:  # the verdict is already decided; report the storage problem clearly
        print(f"security-gate: could not save the reports to S3: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
