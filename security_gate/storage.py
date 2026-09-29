"""File a run's reports in S3 (the Security Gate's report cabinet).

    s3://<bucket>/reports-raw/org=<org>/repo=<repo>/year=YYYY/month=MM/day=DD/<who>_run-<id>-<attempt>_<result>.json
    s3://<bucket>/reports-html/…same path….html

<who> = pr-<number> or branch-<name>; <result> = passed | blocked | error.
The `key=value` folders let Athena query by repo or date later. Uses the standard AWS
credential chain (on CodeBuild: the machine's role, which may only write these prefixes).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

RESULTS = {0: "passed", 1: "blocked"}  # anything else = error (fail closed)


def _safe(text: str) -> str:
    """Keep S3 keys to plain characters: branch names can contain '/', spaces, etc."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "unknown"


def report_key(report: dict, prefix: str, extension: str) -> str:
    run = report.get("run", {})
    org, _, repo = (run.get("repository") or "local/local").partition("/")
    day = (run.get("generated_at") or "0000-00-00")[:10]
    year, month, date = day.split("-")
    who = f"pr-{run['pull_request']}" if run.get("pull_request") else f"branch-{_safe(run.get('branch') or 'unknown')}"
    result = RESULTS.get(report.get("exit_code"), "error")
    name = f"{who}_run-{_safe(str(run.get('run_id') or 'local'))}-{_safe(str(run.get('run_attempt') or '1'))}_{result}"
    return (
        f"{prefix}/org={_safe(org)}/repo={_safe(repo or 'local')}/"
        f"year={year}/month={month}/day={date}/{name}.{extension}"
    )


def upload_reports(bucket: str, json_path: str, html_path: str, client=None) -> list[str]:
    """Upload both reports; returns the S3 URIs written. Raises on any failure."""
    report = json.loads(Path(json_path).read_text())
    if client is None:
        import boto3

        client = boto3.client("s3")
    written = []
    for path, prefix, ext, content_type in (
        (json_path, "reports-raw", "json", "application/json"),
        (html_path, "reports-html", "html", "text/html; charset=utf-8"),
    ):
        key = report_key(report, prefix, ext)
        client.put_object(Bucket=bucket, Key=key, Body=Path(path).read_bytes(), ContentType=content_type)
        written.append(f"s3://{bucket}/{key}")
    return written
