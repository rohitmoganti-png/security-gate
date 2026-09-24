"""The `security-gate` command.

    security-gate scan --base <commit-or-branch> [--head HEAD] [--repo .]
"""

from __future__ import annotations

import argparse
import sys

from security_gate import __version__
from security_gate.changes import GitError, collect_changes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-gate")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan what changed between two commits")
    scan.add_argument("--repo", default=".", help="path to the git repository")
    scan.add_argument("--base", default="", help="compare against this (empty = first push)")
    scan.add_argument("--head", default="HEAD", help="the new commit (default: HEAD)")
    args = parser.parse_args(argv)

    try:
        changes = collect_changes(args.repo, args.base, args.head)
    except GitError as exc:
        print(f"security-gate: error: {exc}", file=sys.stderr)
        return 1

    print(f"Security Gate v{__version__}: comparing {changes.base[:8]} → {changes.head[:8]}")
    print(f"{len(changes.files)} changed file(s):")
    for f in changes.files:
        print(f"  {f.status:<9} {f.path}  ({len(f.added_lines)} new/changed lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
