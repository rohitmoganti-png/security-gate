"""Tests for check 5, dependency CVEs (checks/cves.py)."""

from security_gate.changes import collect_changes
from security_gate.checks import cves
from security_gate.registry import Registry, Vulnerability
from security_gate.result import Severity, Status
from security_gate.workspace import make_workspace


class FakeRegistry:
    def __init__(self, vulns_by_package: dict):
        self.vulns = vulns_by_package

    def vulnerabilities(self, ecosystem, name, version):
        return self.vulns.get((name, version), [])


GHSA = Vulnerability("GHSA-x", ("CVE-2018-18074",), "Leaks auth header on redirect", "high", ("2.20.0",))
PYSEC = Vulnerability("PYSEC-y", ("CVE-2018-18074",), "Leaks auth header", "medium", ("2.20.0",))
LOW = Vulnerability("GHSA-z", ("CVE-2024-1",), "Minor issue", "low", ("2.32.0",))


def run_check(repo, before, after, registry):
    repo.write("requirements.txt", before)
    base = repo.commit()
    repo.write("requirements.txt", after)
    repo.commit()
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        return cves.run(changes, ws, registry)


def test_new_vulnerable_version_blocks_with_cve_fix_and_link(repo):
    fake = FakeRegistry({("requests", "2.19.0"): [GHSA, PYSEC, LOW]})
    result = run_check(repo, "flask==3.0.3\n", "flask==3.0.3\nrequests==2.19.0\n", fake)
    assert result.status is Status.FAIL
    by_cve = {f.rule: f for f in result.findings}
    assert set(by_cve) == {"CVE-2018-18074", "CVE-2024-1"}  # GHSA + PYSEC merged into one
    high = by_cve["CVE-2018-18074"]
    assert (high.severity, high.blocking, high.line) == (Severity.HIGH, True, 2)
    assert "upgrade to 2.20.0" in high.message
    assert high.evidence == "https://www.cve.org/CVERecord?id=CVE-2018-18074"
    assert by_cve["CVE-2024-1"].blocking is False  # low severity only warns


def test_unchanged_dependency_is_never_rechecked(repo):
    fake = FakeRegistry({("requests", "2.19.0"): [GHSA]})
    result = run_check(repo, "requests==2.19.0\n", "requests==2.19.0\nflask==3.0.3\n", fake)
    assert result.status is Status.PASS  # the old vulnerable pin is not this push's fault


def test_unpinned_dependencies_are_listed_not_guessed(repo):
    result = run_check(repo, "", "flask>=3\n", FakeRegistry({}))
    assert any("not pinned" in n and "flask" in n for n in result.notes)


def test_lowest_fix_above_current():
    assert cves.lowest_fix_above(("2.0.1", "2.20.0", "2.31.0"), "2.19.0") == "2.20.0"
    assert cves.lowest_fix_above(("1.0",), "2.0") is None


def test_live_osv_lookup(repo):
    """Real network call: requests 2.19.0 has the well-known CVE-2018-18074."""
    result = run_check(repo, "", "requests==2.19.0\n", Registry())
    assert "CVE-2018-18074" in {f.rule for f in result.findings}
    assert result.status is Status.FAIL
