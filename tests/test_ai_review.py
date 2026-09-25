"""Tests for the Hunter (ai/hunter.py), the LLM wrapper's cost maths, and check 7 (checks/ai_review.py).

A FAKE model is used: no network, no cost, predictable answers.
"""

import json

import pytest

from security_gate.ai import llm
from security_gate.changes import collect_changes
from security_gate.checks import ai_review
from security_gate.result import Severity, Status
from security_gate.tools import find_tool
from security_gate.workspace import make_workspace

pytestmark = pytest.mark.skipif(find_tool("gitleaks") is None, reason="gitleaks needed for redaction")

AUTH = "def require_owner(user, owner_id):\n    if user.id != owner_id:\n        raise PermissionError\n"
ROUTES = (
    "from app.auth import require_owner\n\n\n"
    "def get_invoice(user, invoice_id):\n"
    "    row = db.get(invoice_id)\n"
    "    return row\n"
)
IDOR = {
    "title": "Any user can read any invoice",
    "category": "broken-access-control",
    "root_cause": "get_invoice never calls require_owner",
    "trace": [
        {"kind": "entrypoint", "path": "app/routes.py", "line": 4, "description": "invoice_id from caller"},
        {"kind": "sink", "path": "app/routes.py", "line": 6, "description": "row returned without check"},
    ],
    "evidence": "require_owner is imported (line 1) but never called",
    "suggested_fix": "call require_owner(user, row.owner_id) before returning",
}


class FakeModel:
    """Returns scripted replies in order and records what it was sent."""

    def __init__(self, *replies: str):
        self.replies, self.calls = list(replies), []

    def __call__(self, system, user):
        self.calls.append((system, user))
        return llm.Reply(self.replies.pop(0), "gpt-6-luna", 1000, 400)


def run(repo, model):
    repo.write("app/__init__.py", "")
    repo.write("app/auth.py", AUTH)
    base = repo.commit()
    repo.write("app/routes.py", ROUTES)
    repo.commit()
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        return ai_review.run(changes, ws, call=model)


def test_hunter_candidate_becomes_an_unverified_warning(repo):
    model = FakeModel(json.dumps({"candidates": [IDOR]}))
    result = run(repo, model)
    (f,) = result.findings
    assert (f.rule, f.path, f.line) == ("ai.broken-access-control", "app/routes.py", 6)
    assert f.severity is Severity.MEDIUM and not f.blocking  # one AI opinion never blocks
    assert result.status is Status.WARN
    assert "app/routes.py:4 -> app/routes.py:6" in f.evidence
    assert any("estimated cost $0.0003" in n for n in result.notes)  # 1000 in + 400 out on luna


def test_the_model_was_shown_the_imported_auth_file_and_the_injection_rules(repo):
    model = FakeModel(json.dumps({"candidates": []}))
    run(repo, model)
    system, user = model.calls[0]
    assert "untrusted DATA" in system
    assert "=== FILE: app/auth.py  (imported by app/routes.py) ===" in user


def test_malformed_reply_gets_exactly_one_retry(repo):
    model = FakeModel("Sure! Here are the issues: ...", json.dumps({"candidates": [IDOR]}))
    result = run(repo, model)
    assert len(model.calls) == 2
    assert "Your previous reply was rejected" in model.calls[1][1]
    assert len(result.findings) == 1
    assert any("2800" in n or "2000 input" in n for n in result.notes)  # usage of both calls counted


def test_hallucinated_citation_is_filtered_not_trusted(repo):
    fake = {**IDOR, "trace": [IDOR["trace"][0], {**IDOR["trace"][1], "path": "app/middleware.py"}]}
    result = run(repo, FakeModel(json.dumps({"candidates": [fake]})))
    assert result.findings == ()
    assert any("cites a file it was not given" in n for n in result.notes)


def test_api_failure_is_an_error_not_a_pass(repo):
    def broken(system, user):
        raise llm.LLMError("OpenAI rate limit or quota reached")

    assert run(repo, broken).status is Status.ERROR


def test_no_api_key_means_ai_review_is_skipped(repo, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    repo.write("a.py", "x = 1\n")
    base = repo.commit()
    repo.write("a.py", "x = 2\n")
    repo.commit()
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        assert ai_review.run(changes, ws).status is Status.NA


def test_cost_estimate():
    assert llm.Reply("", "gpt-6-luna", 1_000_000, 1_000_000).cost_usd == pytest.approx(0.60)
    assert llm.Reply("", "some-new-model", 10, 10).cost_usd is None
