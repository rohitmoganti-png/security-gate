"""Tests for check 6, infrastructure (checks/iac.py)."""

import pytest

from security_gate.changes import collect_changes
from security_gate.checks import iac
from security_gate.result import Severity, Status
from security_gate.tools import find_tool
from security_gate.workspace import make_workspace

OPEN_SSH_TF = """resource "aws_security_group" "web" {
  description = "web"
  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
UNSAFE_WORKFLOW = """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - run: make test
"""
DOCKERFILE = 'FROM python:3.12-slim\nUSER root\nCMD ["python", "app.py"]\n'


def run_check(repo, files):
    repo.write("README.md", "x\n")
    base = repo.commit()
    for p, c in files.items():
        repo.write(p, c)
    repo.commit()
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        return iac.run(changes, ws)


def test_not_applicable_without_infra_files(repo):
    result = run_check(repo, {"app.py": "x = 1\n", "config.yaml": "name: demo\n"})
    assert result.status is Status.NA


def test_detects_infra_file_types(repo):
    repo.write("README.md", "x\n")
    base = repo.commit()
    for p, c in {
        "infra/main.tf": "x",
        "Dockerfile": "FROM x",
        "k8s/app.yaml": "apiVersion: v1\nkind: Pod\n",
        "cfn/stack.yaml": "Resources:\n  B:\n    Type: AWS::S3::Bucket\n",
        ".github/workflows/ci.yml": "on: push\n",
        "app/settings.yaml": "debug: false\n",  # ordinary YAML: not infra
    }.items():
        repo.write(p, c)
    repo.commit()
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        assert sorted(iac.infra_files(ws)) == sorted(
            ["infra/main.tf", "Dockerfile", "k8s/app.yaml", "cfn/stack.yaml", ".github/workflows/ci.yml"]
        )


def test_pull_request_target_checkout_is_critical(repo):
    """Our own rule: no Checkov needed for it."""
    repo.write("README.md", "x\n")
    base = repo.commit()
    repo.write(".github/workflows/ci.yml", UNSAFE_WORKFLOW)
    repo.commit()
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        (f,) = iac.pull_request_target_checks(changes, ws, iac.infra_files(ws))
    assert (f.rule, f.severity, f.blocking, f.line) == (
        "gha-pull-request-target-checkout", Severity.CRITICAL, True, 1,
    )


@pytest.mark.skipif(find_tool("checkov") is None, reason="checkov not installed")
def test_checkov_blocks_open_ssh_and_warns_on_hygiene(repo):
    result = run_check(repo, {"infra/main.tf": OPEN_SSH_TF, "Dockerfile": DOCKERFILE})
    assert result.status is Status.FAIL
    by_rule = {f.rule: f for f in result.findings}
    assert by_rule["CKV_AWS_24"].severity is Severity.HIGH and by_rule["CKV_AWS_24"].blocking
    assert by_rule["CKV_DOCKER_8"].severity is Severity.MEDIUM  # USER root: warn only
    assert not by_rule["CKV_DOCKER_2"].blocking  # missing HEALTHCHECK: low, warn only
