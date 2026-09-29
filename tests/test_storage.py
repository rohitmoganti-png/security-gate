"""Tests for filing reports in S3 (security_gate/storage.py). No AWS calls."""

import json

from security_gate import storage


def report(**run):
    base = {"repository": "moring-ai/security-gate-demo", "generated_at": "2026-10-02T10:14:03+00:00",
            "run_id": "36472189038", "run_attempt": "1", "pull_request": 12, "branch": "fail-7"}  # fmt: skip
    return {"exit_code": 1, "run": {**base, **run}}


def test_pr_report_key_follows_the_naming_convention():
    assert storage.report_key(report(), "reports-raw", "json") == (
        "reports-raw/org=moring-ai/repo=security-gate-demo/year=2026/month=10/day=02/"
        "pr-12_run-36472189038-1_blocked.json"
    )


def test_push_report_key_uses_a_safe_branch_name_and_result():
    r = report(pull_request=None, branch="feature/new login")
    r["exit_code"] = 0
    assert storage.report_key(r, "reports-html", "html").endswith("/branch-feature-new-login_run-36472189038-1_passed.html")
    r["exit_code"] = 2
    assert storage.report_key(r, "reports-html", "html").endswith("_error.html")


def test_local_run_without_github_metadata_still_gets_a_key():
    key = storage.report_key({"exit_code": 0, "run": {"generated_at": "2026-10-02T00:00:00"}}, "reports-raw", "json")
    assert key == "reports-raw/org=local/repo=local/year=2026/month=10/day=02/branch-unknown_run-local-1_passed.json"


def test_upload_writes_json_and_html(tmp_path):
    (tmp_path / "r.json").write_text(json.dumps(report()))
    (tmp_path / "r.html").write_text("<html></html>")
    calls = []

    class FakeS3:
        def put_object(self, **kw):
            calls.append(kw)

    uris = storage.upload_reports("my-bucket", str(tmp_path / "r.json"), str(tmp_path / "r.html"), client=FakeS3())
    assert [c["Key"].split("/")[0] for c in calls] == ["reports-raw", "reports-html"]
    assert calls[0]["ContentType"] == "application/json" and calls[1]["ContentType"].startswith("text/html")
    assert uris[0].startswith("s3://my-bucket/reports-raw/org=moring-ai/")
