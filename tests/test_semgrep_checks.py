"""Tests for check 2 (risky code) and check 3 (AI code smells)."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from security_gate.changes import collect_changes
from security_gate.checks import ai_smells, code, semgrep_run
from security_gate.result import Status
from security_gate.tools import find_tool
from security_gate.workspace import make_workspace

FIXTURES = Path(__file__).parent / "fixtures" / "ai_smells"
CATEGORIES = {
    "placeholder-credentials", "tls-disabled", "sql-string-building", "shell-injection",
    "silent-failure", "cors-wildcard", "debug-enabled", "jwt-no-verify", "unfinished-scaffolding",
}  # fmt: skip

pytestmark = pytest.mark.skipif(find_tool("semgrep") is None, reason="semgrep not installed")


def run_pack_on_fixtures(tmp_path):
    """Run ONLY our rule pack on the fixture files -> {filename: {category, ...}}."""
    for f in FIXTURES.iterdir():
        shutil.copy(f, tmp_path)  # outside git: Semgrep only scans tracked files inside a repo
    out = subprocess.run(
        [find_tool("semgrep"), "scan", "--json", "--metrics=off", "--disable-version-check",
         "--quiet", f"--config={semgrep_run.AI_SMELL_RULES}", str(tmp_path)],  # fmt: skip
        capture_output=True, text=True, check=False,
    )
    hits: dict[str, set[str]] = {}
    for r in json.loads(out.stdout)["results"]:
        hits.setdefault(Path(r["path"]).name, set()).add(r["extra"]["metadata"]["category"])
    return hits


def test_ai_smell_pack_every_category_has_a_positive_case(tmp_path):
    hits = run_pack_on_fixtures(tmp_path)
    assert hits["bad.py"] == CATEGORIES  # all 9 categories caught in Python
    assert len(hits["bad.js"]) == 6  # the categories that have JavaScript rules


def test_ai_smell_pack_safe_code_triggers_nothing(tmp_path):
    hits = run_pack_on_fixtures(tmp_path)
    assert "good.py" not in hits and "good.js" not in hits


def test_every_rule_is_tagged_as_ai_smell_pack():
    text = semgrep_run.AI_SMELL_RULES.read_text()
    assert text.count("- id: ") == text.count("metadata: {source: ai-smell-pack")


def scan(repo, head_files, base_files=None, offline_rules=None, monkeypatch=None):
    for p, c in (base_files or {"README.md": "demo\n"}).items():
        repo.write(p, c)
    base = repo.commit("base")
    for p, c in head_files.items():
        repo.write(p, c)
    repo.commit("push")
    if offline_rules:  # swap the registry download for a local rule file (fast, offline)
        monkeypatch.setattr(semgrep_run, "REGISTRY_RULES", str(offline_rules))
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        return code.run(changes, ws), ai_smells.run(changes, ws)


OFFLINE_REGISTRY = """rules:
  - id: python.test.sql-injection
    languages: [python]
    severity: ERROR
    message: SQL injection
    pattern: $DB.execute(f"...")
"""


def test_one_run_split_into_two_checks_new_vs_old(repo, tmp_path, monkeypatch):
    rules = tmp_path / "registry.yml"
    rules.write_text(OFFLINE_REGISTRY)
    old = 'import requests\nrequests.get("https://x", verify=False)\n'
    new = old + 'def f(db, u):\n    return db.execute(f"SELECT {u}")\n'
    risky, smells = scan(repo, {"app.py": new}, {"app.py": old}, rules, monkeypatch)

    assert risky.status is Status.FAIL
    assert [(f.rule, f.line, f.new) for f in risky.findings] == [("sql-injection", 4, True)]
    by_rule = {f.rule: f for f in smells.findings}
    assert by_rule["ai-smell.sql-string-building"].new is True  # this push wrote it: blocks
    assert by_rule["ai-smell.tls-verification-disabled"].new is False  # old line: warn only
    assert "verify=False" in by_rule["ai-smell.tls-verification-disabled"].evidence


def test_real_registry_rules_end_to_end(repo):
    """Downloads Semgrep's p/default: this is exactly what runs in CI."""
    app = (
        "import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/u')\ndef u():\n"
        "    conn = sqlite3.connect('x.db')\n"
        "    return str(conn.execute(f\"SELECT * FROM t WHERE id = {request.args['id']}\"))\n"
        "app.run(debug=True)\n"
    )
    risky, smells = scan(repo, {"app.py": app})
    assert risky.status is Status.FAIL and risky.findings
    assert {"ai-smell.sql-string-building", "ai-smell.debug-enabled"} <= {f.rule for f in smells.findings}


def test_unparseable_file_is_reported_not_silently_skipped(repo, tmp_path, monkeypatch):
    rules = tmp_path / "registry.yml"
    rules.write_text(OFFLINE_REGISTRY)
    broken = 'def f(db):\n    return db.execute(f"SELECT {x["id"]}"\n'  # unbalanced: not valid Python
    risky, _ = scan(repo, {"broken.py": broken}, offline_rules=rules, monkeypatch=monkeypatch)
    assert any("could not fully parse broken.py" in n for n in risky.notes)
