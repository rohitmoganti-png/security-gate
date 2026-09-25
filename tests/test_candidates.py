"""Tests for the Hunter candidate format + plain-code validator (security_gate/ai/candidates.py)."""

import copy
import json

import pytest

from security_gate.ai.candidates import parse_candidates

ROUTES = """from flask import Blueprint, jsonify
from app.auth import current_user
bp = Blueprint("api", __name__)


@bp.get("/invoices/<invoice_id>")
def get_invoice(invoice_id):
    current_user()
    row = get_db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return jsonify(dict(row))
"""
FILES = {"app/routes.py": ROUTES, "app/auth.py": "def require_owner(user, owner_id):\n    ...\n"}

GOOD = {
    "title": "Any logged-in user can read any invoice (IDOR)",
    "category": "broken-access-control",
    "root_cause": "get_invoice never checks the invoice belongs to the requesting user",
    "trace": [
        {"kind": "entrypoint", "path": "app/routes.py", "line": 6, "description": "GET /invoices/<id>"},
        {"kind": "propagation", "path": "app/routes.py", "line": 9, "description": "id used as-is"},
        {"kind": "sink", "path": "app/routes.py", "line": 10, "description": "row returned to caller"},
    ],
    "evidence": "current_user() is called but require_owner() from app/auth.py never is",
    "suggested_fix": "call require_owner(user, row['owner_id']) before returning",
}


def reply(*candidates):
    return json.dumps({"candidates": list(candidates)})


def test_well_formed_candidate_passes():
    (c,), rejected = parse_candidates(reply(GOOD), FILES)
    assert rejected == []
    assert c.category == "broken-access-control"
    assert c.sink.line == 10
    assert c.fingerprint.startswith("ai1:")


def test_no_findings_is_valid():
    assert parse_candidates(reply(), FILES) == ([], [])


def mutated(**changes):
    item = copy.deepcopy(GOOD)
    item.update(changes)
    return item


@pytest.mark.parametrize(
    ("bad", "reason"),
    [
        ({k: v for k, v in GOOD.items() if k != "evidence"}, "wrong fields"),  # missing field
        (mutated(verdict="confirmed"), "wrong fields"),  # Hunter tries to give a verdict
        (mutated(category="scary-stuff"), "unknown category"),
        (mutated(evidence="   "), "evidence must be a non-empty string"),
        (mutated(trace=[GOOD["trace"][0]]), "needs at least one 'entrypoint' and one 'sink'"),
        (
            mutated(trace=[*GOOD["trace"][:2], {**GOOD["trace"][2], "path": "app/middleware.py"}]),
            "cites a file it was not given",  # hallucinated file
        ),
        (
            mutated(trace=[*GOOD["trace"][:2], {**GOOD["trace"][2], "line": 999}]),
            "cites a line that doesn't exist",  # hallucinated line
        ),
        (mutated(trace=[{**GOOD["trace"][0], "line": "6"}, GOOD["trace"][2]]), "line that doesn't exist"),
    ],
)
def test_bad_candidates_are_rejected_by_plain_code(bad, reason):
    valid, rejected = parse_candidates(reply(GOOD, bad), FILES)
    assert len(valid) == 1  # the good one still gets through
    assert len(rejected) == 1 and reason in rejected[0]


@pytest.mark.parametrize("text", ["not json", '["a list"]', '{"candidates": [], "extra": 1}'])
def test_malformed_replies_are_rejected(text):
    valid, rejected = parse_candidates(text, FILES)
    assert valid == [] and rejected


def test_fingerprint_ignores_ai_wording_and_line_moves():
    (a,), _ = parse_candidates(reply(GOOD), FILES)
    reworded = mutated(title="Totally different title", evidence="other words")
    (b,), _ = parse_candidates(reply(reworded), FILES)
    assert a.fingerprint == b.fingerprint  # same bug in the same code = same ID

    shifted_files = {**FILES, "app/routes.py": "# new comment\n" + ROUTES}
    moved = copy.deepcopy(GOOD)
    for step in moved["trace"]:
        step["line"] += 1
    (c,), _ = parse_candidates(reply(moved), shifted_files)
    assert c.fingerprint == a.fingerprint  # survives the code moving down a line
