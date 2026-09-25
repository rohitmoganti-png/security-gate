"""Tests for the HTML report (security_gate/html_report.py)."""

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


def test_blocked_report_shows_verdict_stages_fix_first_and_line_links():
    html = render(report([check("Secrets", "PASS"), check("Risky code", "FAIL", [finding()]),
                          check("Infrastructure", "N/A", not_applicable="no infra files")]))  # fmt: skip
    assert "BLOCKED: 1 blocking issue" in html
    assert "The 7 security stages" in html and "Fix these first" in html
    assert 'href="https://github.com/acme/shop/blob/abc123def456/app/tokens.py#L6"' in html
    assert 'href="https://github.com/acme/shop/pull/7"' in html
    assert "no infra files" in html and "How to fix:" in html


def test_passed_report_has_no_fix_section():
    html = render(report([check("Secrets", "PASS")], exit_code=0))
    assert "PASSED: no blocking issues" in html and "Fix these first" not in html


def test_untrusted_text_is_escaped_never_executed():
    evil = finding(message="<script>alert(1)</script>", evidence="<img src=x onerror=alert(1)>",
                   path='app/"><script>x</script>.py')  # fmt: skip
    html = render(report([check("Risky code", "FAIL", [evil])]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html


def test_ai_section_shows_funnel_verdicts_and_cost():
    details = {"model": "gpt-6-luna", "calls": 2, "input_tokens": 3500, "output_tokens": 900, "cost_usd": 0.0008,
               "files_reviewed": ["app/routes.py"], "candidates": 1, "rejected_by_validator": [],
               "verdicts": [{"title": "Any user can read any invoice", "category": "broken-access-control",
                             "location": "app/routes.py:33", "trace": ["app/routes.py:25", "app/routes.py:33"],
                             "verdict": "confirmed", "reasoning": "no ownership check", "likelihood": "high",
                             "impact": "high", "severity": "high", "blockers": None,
                             "suggested_fix": "call require_owner", "fingerprint": "ai1:x"}]}  # fmt: skip
    ai = check("AI review", "FAIL", [finding(rule="ai.broken-access-control", path="app/routes.py", line=33)],
               details=details)  # fmt: skip
    html = render(report([ai]))
    assert "AI review in detail" in html and "proposed by the Hunter" in html
    assert "likelihood <b>high</b> × impact <b>high</b>" in html
    assert "$0.0008" in html and "call require_owner" in html


def test_local_run_without_github_metadata_still_renders():
    data = report([check("Secrets", "PASS")], exit_code=0)
    data["run"] = {"head_sha": "abc", "event": "local"}
    html = render(data)
    assert "local repository" in html and "<code>app/tokens.py</code>" in html
