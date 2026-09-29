"""Tests for the HTML dashboard report (security_gate/html_report.py)."""

import re

from security_gate.html_report import render

RUN = {
    "repository": "acme/shop", "server_url": "https://github.com", "event": "pull_request",
    "branch": "feature-x", "pull_request": 7, "head_sha": "abc123def456", "base_sha": "000",
    "actor": "maya", "run_id": "99", "run_url": "https://github.com/acme/shop/actions/runs/99",
    "generated_at": "2026-09-25T12:00:00+00:00",
}  # fmt: skip


def report(checks, exit_code=1, mode="enforce"):
    blocking = sum(1 for c in checks for f in c["findings"] if f["blocking"])
    return {"version": "0.2.0", "result": "BLOCKED" if blocking else "PASSED", "exit_code": exit_code,
            "mode": mode, "blocking_count": blocking, "duration_seconds": 3.2, "run": RUN,
            "changed_files": [{"path": "app/tokens.py", "status": "added", "lines_changed": 6}],
            "checks": checks}  # fmt: skip


def check(name, status, findings=(), **extra):
    return {"name": name, "tool": "t", "status": status, "findings": list(findings), "error": "",
            "not_applicable": "", "seconds": 1.0, "notes": [], "details": {}, **extra}  # fmt: skip


def finding(**kw):
    base = {"rule": "jwt-python-hardcoded-secret", "severity": "high", "path": "app/tokens.py", "line": 6,
            "message": "Hardcoded JWT secret", "evidence": "code: jwt.encode(...)", "new": True, "blocking": True}
    return {**base, **kw}


AI_DETAILS = {
    "provider": "litellm", "model": "security-review", "calls": 2, "input_tokens": 3500, "output_tokens": 900,
    "cost_usd": 0.024, "files_reviewed": ["app/routes.py"], "candidates": 2, "rejected_by_validator": [],
    "ai_calls": [{"call_id": "call-1", "model": "bedrock/global.anthropic.claude-sonnet-4-6", "cost_usd": 0.0137, "fallback_used": False},
                 {"call_id": "call-2", "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", "cost_usd": 0.0103, "fallback_used": True}],
    "verdicts": [{"title": "Any user can read any invoice", "category": "broken-access-control",
                  "location": "app/routes.py:33", "trace": ["app/routes.py:25", "app/routes.py:33"],
                  "verdict": "confirmed", "reasoning": "no ownership check", "likelihood": "high",
                  "impact": "high", "severity": "high", "blockers": None,
                  "suggested_fix": "call require_owner", "fingerprint": "ai1:x"},
                 {"title": "Maybe a race", "category": "race", "location": "app/db.py:9", "trace": [],
                  "verdict": "rejected", "reasoning": "single writer", "likelihood": None, "impact": None,
                  "severity": None, "blockers": None, "suggested_fix": "", "fingerprint": "ai1:y"}],
}  # fmt: skip


def test_blocked_dashboard_verdict_counts_and_links():
    html = render(report([check("Secrets", "PASS"), check("Risky code", "FAIL", [finding()]),
                          check("Infrastructure", "N/A", not_applicable="no infra files")]))  # fmt: skip
    assert ">BLOCKED<" in html and "1 blocking issue: fix before merging." in html
    assert re.search(r'sev-high"><div class="knum">1<', html)  # HIGH tile = 1
    assert re.search(r'sev-critical"><div class="knum">0<', html)
    assert 'href="https://github.com/acme/shop/blob/abc123def456/app/tokens.py#L6"' in html
    assert 'href="https://github.com/acme/shop/pull/7"' in html
    assert "no infra files" in html and "Load it from an environment variable" not in html  # fix text is per check
    assert "use the safe API" in html  # Risky code's how-to-fix, inside the finding row


def test_passed_and_error_verdicts():
    passed = render(report([check("Secrets", "PASS")], exit_code=0))
    assert ">PASSED<" in passed and "No blocking issues." in passed and "No findings in this change." in passed
    errored = render(report([check("Secrets", "ERROR", error="gitleaks crashed")], exit_code=2))
    assert ">ERROR<" in errored and "failed closed" in errored and "gitleaks crashed" in errored


def test_blocking_findings_are_listed_first_then_by_severity():
    low = finding(severity="low", blocking=False, new=False, message="LOW-ONE")
    medium = finding(severity="medium", blocking=False, message="MEDIUM-ONE")
    high = finding(severity="high", blocking=True, message="HIGH-ONE")
    html = render(report([check("Risky code", "FAIL", [low, medium, high])]))
    assert html.index("HIGH-ONE") < html.index("MEDIUM-ONE") < html.index("LOW-ONE")


def test_untrusted_text_is_escaped_never_executed():
    evil = finding(message="<script>alert(1)</script>", evidence="<img src=x onerror=alert(1)>",
                   path='app/"><script>x</script>.py')  # fmt: skip
    html = render(report([check("Risky code", "FAIL", [evil])]))
    assert "<script" not in html.lower()  # no script tags at all (the page itself uses none)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html


def test_page_is_self_contained():
    html = render(report([check("Secrets", "PASS")], exit_code=0))
    assert "<script" not in html and "<link" not in html
    assert not re.search(r'(src|href)="(?!https://github\.com/)[a-z]+://', html)  # only links to the repo


def test_ai_dashboard_shows_funnel_calls_cost_and_fallback():
    ai = check("AI review", "FAIL", [finding(rule="ai.broken-access-control", path="app/routes.py", line=33,
               message="Any user can read any invoice CONFIRMED by independent verifier: no ownership check")],
               details=AI_DETAILS)  # fmt: skip
    html = render(report([ai]))
    assert "Proposed by Hunter" in html and "Rejected by Verifier" in html
    assert "call-1" in html and "call-2" in html and "fallback used" in html
    assert "2 call(s) · $0.024" in html
    assert "likelihood high × impact high → high" in html and "call require_owner" in html
    assert "single writer" in html  # the rejected candidate's reason, in AI review details
    assert "CONFIRMED by independent verifier" not in html  # the row title is just the issue


def test_skipped_ai_review_tile():
    html = render(report([check("AI review", "N/A", not_applicable="no code files changed")], exit_code=0))
    assert ">Skipped<" in html and "no code files changed" in html


def test_local_run_without_github_metadata_still_renders():
    data = report([check("Secrets", "FAIL", [finding()])], exit_code=1)
    data["run"] = {"head_sha": "abc", "event": "local"}
    html = render(data)
    assert "local run" in html and "<code>app/tokens.py:6</code>" in html
