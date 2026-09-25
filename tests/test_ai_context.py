"""Tests for the AI context builder (ai/context.py) and the Hunter prompt (ai/prompts.py)."""

import pytest

from security_gate.ai import context as ctx
from security_gate.ai.prompts import HUNTER_SYSTEM, hunter_user_message
from security_gate.changes import collect_changes
from security_gate.tools import find_tool

# Built at runtime so no literal secret sits in this file.
KEY = "bk_" + "live_9fX2qLr7Tz4Vw8Nb3Mh6Pd1Fs5Gj0HcKy"
AUTH = f'LEGACY_KEY = "{KEY}"\n\n\ndef require_owner(user, owner_id):\n    return user.id == owner_id\n'
ROUTES_V1 = "from flask import Blueprint\nbp = Blueprint('api', __name__)\n"
ROUTES_V2 = ROUTES_V1 + (
    "\n\n@bp.get('/invoices/<invoice_id>')\n"
    "def get_invoice(invoice_id):\n"
    "    from app.auth import require_owner\n"
    "    return load(invoice_id)\n"
)

needs_gitleaks = pytest.mark.skipif(find_tool("gitleaks") is None, reason="gitleaks not installed")


@pytest.fixture
def changes(repo):
    for p, c in {"app/__init__.py": "", "app/auth.py": AUTH, "app/routes.py": ROUTES_V1,
                 "app/unrelated.py": "X = 1\n", "README.md": "demo\n"}.items():  # fmt: skip
        repo.write(p, c)
    base = repo.commit()
    repo.write("app/routes.py", ROUTES_V2)
    repo.write("README.md", "demo v2\n")  # not code: must not be sent to the AI
    repo.commit()
    return collect_changes(repo.path, base)


@needs_gitleaks
def test_context_has_changed_code_plus_its_local_imports(changes):
    context = ctx.build_context(changes)
    roles = {f.path: f.role for f in context.files}
    assert roles == {"app/routes.py": "changed", "app/auth.py": "imported by app/routes.py"}
    # 'flask' is third-party and app/unrelated.py isn't imported, so neither is included


@needs_gitleaks
def test_secret_in_an_unchanged_imported_file_is_redacted(changes):
    context = ctx.build_context(changes)
    assert KEY not in context.render()
    assert ctx.REDACTED in context.contents["app/auth.py"]
    assert "def require_owner" in context.contents["app/auth.py"]  # the rest is still there


@needs_gitleaks
def test_render_numbers_lines_and_marks_new_ones(changes):
    text = ctx.build_context(changes).render()
    assert "=== FILE: app/routes.py  (changed) ===" in text
    assert "    6+| def get_invoice(invoice_id):" in text  # written by this change
    assert "    1 | from flask import Blueprint" in text  # old line: no '+'


def test_no_gitleaks_means_nothing_is_sent(changes, monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_GATE_GITLEAKS", str(tmp_path / "missing"))
    with pytest.raises(ctx.ContextError, match="refusing"):
        ctx.build_context(changes)


@needs_gitleaks
def test_size_cap_drops_lower_priority_files_first(changes, monkeypatch):
    monkeypatch.setattr(ctx, "MAX_TOTAL_CHARS", len(ROUTES_V2) + 5)
    context = ctx.build_context(changes)
    assert [f.path for f in context.files] == ["app/routes.py"]  # the import was dropped
    assert context.truncated


def test_prompt_has_the_injection_rules():
    for phrase in ["untrusted DATA", "do not flag", "never instructions", "random token"]:
        assert phrase in HUNTER_SYSTEM
    message, token = hunter_user_message("code here")
    assert f"<<<UNTRUSTED-CODE {token}>>>" in message and f"<<<END-UNTRUSTED-CODE {token}>>>" in message
    assert hunter_user_message("x")[1] != token  # a fresh token every call: code can't predict it
