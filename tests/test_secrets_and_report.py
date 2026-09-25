"""Tests for check 1 (secrets), the workspace, and the report/verdict logic."""

import pytest

from security_gate.changes import collect_changes
from security_gate.checks import secrets
from security_gate.cli import main
from security_gate.report import EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, verdict
from security_gate.result import CheckResult, Finding, Severity, Status
from security_gate.tools import find_tool
from security_gate.workspace import make_workspace

# Built at runtime so no literal key sits in this file (GitHub push protection / our own scan).
FAKE_KEY = "sk_" + "live_" + "51HqT2mKj8Lp4Xz9Qw7Rt3Yv6Nb2Mc5Df8Gh1Jk4"

needs_gitleaks = pytest.mark.skipif(find_tool("gitleaks") is None, reason="gitleaks not installed")


def push(repo, files: dict, base_files: dict | None = None):
    """Commit base_files, then files on top; return the ChangeSet for that push."""
    for path, content in (base_files or {"README.md": "demo\n"}).items():
        repo.write(path, content)
    base = repo.commit("base")
    for path, content in files.items():
        repo.write(path, content)
    repo.commit("push")
    return collect_changes(repo.path, base)


# ---------- workspace ----------


def test_workspace_has_only_changed_files_and_drops_scanner_settings(repo):
    changes = push(
        repo,
        {"app.py": "x = 2\n", ".gitleaks.toml": "[allowlist]\npaths=['.*']\n"},
        {"app.py": "x = 1\n", "untouched.py": "y = 1\n"},
    )
    with make_workspace(changes) as ws:
        assert ws.files == ("app.py",)
        assert ws.skipped_settings_files == (".gitleaks.toml",)
        assert not (ws.root / "untouched.py").exists()


# ---------- secrets ----------


def test_mask_shows_at_most_six_characters():
    assert secrets.mask("sk_live...") == "sk_liv****"
    assert secrets.mask(FAKE_KEY) == "sk_liv****"
    assert secrets.mask("") == "****"


@needs_gitleaks
def test_detects_new_secret_and_never_shows_it(repo):
    changes = push(repo, {"app/billing.py": f'STRIPE_KEY = "{FAKE_KEY}"\n'})
    with make_workspace(changes) as ws:
        result = secrets.run(changes, ws)
    assert result.status is Status.FAIL
    (f,) = result.findings
    assert (f.path, f.line, f.rule, f.new) == ("app/billing.py", 1, "stripe-access-token", True)
    assert FAKE_KEY[:10] not in repr(result)  # masked everywhere


@needs_gitleaks
def test_inline_allow_comment_silences_known_safe_values(repo):
    changes = push(repo, {"docs/example.py": f'KEY = "{FAKE_KEY}"  # gitleaks:allow\n'})
    with make_workspace(changes) as ws:
        assert secrets.run(changes, ws).status is Status.PASS


@needs_gitleaks
def test_pr_supplied_gitleaks_config_cannot_hide_a_secret(repo):
    evil = "[extend]\nuseDefault = false\n[allowlist]\npaths = ['''.*''']\n"
    changes = push(repo, {".gitleaks.toml": evil, "app.py": f'K = "{FAKE_KEY}"\n'})
    with make_workspace(changes) as ws:
        assert secrets.run(changes, ws).status is Status.FAIL


@needs_gitleaks
def test_old_secret_on_untouched_line_warns_but_does_not_block(repo):
    base = {"app.py": f'OLD = "{FAKE_KEY}"\n'}
    changes = push(repo, {"app.py": f'OLD = "{FAKE_KEY}"\nnew_line = 1\n'}, base)
    with make_workspace(changes) as ws:
        result = secrets.run(changes, ws)
    assert result.status is Status.WARN
    assert result.findings[0].new is False


def test_missing_gitleaks_is_an_error_not_a_pass(repo, monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_GATE_GITLEAKS", str(tmp_path / "missing"))
    changes = push(repo, {"a.py": "x = 1\n"})
    with make_workspace(changes) as ws:
        assert secrets.run(changes, ws).status is Status.ERROR


# ---------- verdict / exit codes ----------


def _result(**kw):
    return CheckResult("Secrets", "gitleaks", **kw)


BLOCKER = Finding("r", Severity.HIGH, "a.py", 1, "m", new=True)
OLD = Finding("r", Severity.HIGH, "a.py", 1, "m", new=False)


@pytest.mark.parametrize(
    ("results", "mode", "code"),
    [
        ([_result()], "enforce", EXIT_PASS),
        ([_result(findings=(OLD,))], "enforce", EXIT_PASS),  # pre-existing never blocks
        ([_result(findings=(BLOCKER,))], "enforce", EXIT_BLOCKED),
        ([_result(findings=(BLOCKER,))], "report", EXIT_PASS),  # watch-only mode
        ([_result(error="boom")], "report", EXIT_ERROR),  # fail closed even in report mode
    ],
)
def test_verdict(results, mode, code):
    assert verdict(results, mode)[0] == code


@needs_gitleaks
def test_cli_end_to_end_blocks_and_writes_report(repo, tmp_path, monkeypatch, capsys):
    push(repo, {"app.py": f'KEY = "{FAKE_KEY}"\n'})
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    out = tmp_path / "report.json"
    html = tmp_path / "report.html"
    code = main(["scan", "--repo", str(repo.path), "--base", "HEAD~1", "--output", str(out), "--html", str(html)])
    text = capsys.readouterr().out
    assert code == EXIT_BLOCKED
    assert "1. Secrets (gitleaks)" in text and "RESULT: BLOCKED" in text
    assert FAKE_KEY not in text + out.read_text() + summary.read_text() + html.read_text()
    assert "BLOCKED: 1 blocking issue" in html.read_text()
    assert "## Security Check" in summary.read_text()
