"""Tests for the dependency parser (deps.py) and check 4, fake packages (checks/packages.py)."""

from datetime import UTC, datetime, timedelta

from security_gate.changes import collect_changes
from security_gate.checks import packages
from security_gate.deps import Dependency, new_or_changed, parse
from security_gate.registry import PackageInfo, Registry, Vulnerability
from security_gate.result import Severity, Status
from security_gate.workspace import make_workspace

NOW = datetime(2026, 9, 24, tzinfo=UTC)


class FakeRegistry:
    """Same interface as Registry, answers from a dict. No network."""

    def __init__(self, packages: dict, malicious: tuple = ()):
        self.packages, self.malicious = packages, malicious

    def package(self, ecosystem, name):
        return self.packages.get(name)

    def vulnerabilities(self, ecosystem, name, version):
        return [Vulnerability("MAL-2026-1", (), "malware", "critical")] if name in self.malicious else []


def info(age_days=3000, versions=("1.0", "1.1", "2.0"), weekly=None):
    return PackageInfo(NOW - timedelta(days=age_days), frozenset(versions), weekly)


def dep(name, version=None, ecosystem="PyPI"):
    return Dependency(ecosystem, name, version, "requirements.txt", 3)


# ---------- parsing: only NEW or CHANGED dependencies ----------


def test_parse_all_three_manifest_types():
    req = "flask==3.0.3\nFlask_Cors>=4  # comment\n-r other.txt\ngit+https://x/y.git\n"
    assert [(d.name, d.version) for d in parse("requirements.txt", req)] == [
        ("flask", "3.0.3"),
        ("flask-cors", None),  # names are normalized the way PyPI does
    ]
    pyproject = '[project]\ndependencies = ["requests==2.32.3", "rich"]\n'
    assert [d.name for d in parse("pyproject.toml", pyproject)] == ["requests", "rich"]
    pkg = '{"dependencies": {"express": "4.19.2", "lodash": "^4.17.0"}, "devDependencies": {"jest": "29.7.0"}}'
    assert [(d.name, d.version, d.line) for d in parse("package.json", pkg)] == [
        ("express", "4.19.2", 1),
        ("lodash", None, 1),
        ("jest", "29.7.0", 1),
    ]


def test_only_added_or_version_changed_deps_are_checked(repo):
    repo.write("requirements.txt", "flask==3.0.3\nrequests==2.31.0\n")
    base = repo.commit()
    repo.write("requirements.txt", "flask==3.0.3\nrequests==2.32.3\nnew-lib==1.0\n")
    repo.commit()
    found = new_or_changed(collect_changes(repo.path, base))
    assert [(d.name, d.version, d.line) for d in found] == [("requests", "2.32.3", 2), ("new-lib", "1.0", 3)]


# ---------- the SlopGuard layers ----------


def test_nonexistent_package_blocks():
    (f,) = packages.assess(dep("flask-invoice-helpers"), FakeRegistry({}), NOW)
    assert (f.rule, f.severity, f.blocking) == ("package-does-not-exist", Severity.CRITICAL, True)


def test_known_malicious_package_blocks():
    (f,) = packages.assess(dep("evil-pkg"), FakeRegistry({"evil-pkg": info()}, ("evil-pkg",)), NOW)
    assert f.rule == "known-malicious-package" and f.blocking


def test_single_weak_signal_only_warns():
    new_but_unique = packages.assess(dep("brand-new-tool"), FakeRegistry({"brand-new-tool": info(5)}), NOW)
    assert [(f.rule, f.blocking) for f in new_but_unique] == [("low-trust-package", False)]
    old_lookalike = packages.assess(dep("reqeusts"), FakeRegistry({"reqeusts": info()}), NOW)
    assert [(f.rule, f.blocking) for f in old_lookalike] == [("lookalike-name", False)]


def test_lookalike_plus_new_is_a_typosquat_and_blocks():
    (f,) = packages.assess(dep("reqeusts"), FakeRegistry({"reqeusts": info(age_days=2, versions=("0.1",))}), NOW)
    assert (f.rule, f.severity, f.blocking) == ("possible-typosquat", Severity.HIGH, True)
    assert "requests" in f.message


def test_npm_low_downloads_signal():
    fake = FakeRegistry({"expres": info(weekly=12)})
    (f,) = packages.assess(dep("expres", ecosystem="npm"), fake, NOW)
    assert f.rule == "possible-typosquat"  # looks like 'express' AND 12 downloads/week


def test_healthy_popular_package_is_clean():
    assert packages.assess(dep("flask", "3.0.3"), FakeRegistry({"flask": info(versions=("3.0.3",))}), NOW) == []


def test_hallucinated_version_warns():
    (f,) = packages.assess(dep("flask", "9.9.9"), FakeRegistry({"flask": info()}), NOW)
    assert f.rule == "version-does-not-exist" and not f.blocking


def test_edit_distance_counts_swaps_as_one():
    assert packages.edit_distance("reqeusts", "requests") == 1
    assert packages.closest_popular("reqeusts", "PyPI") == "requests"
    assert packages.closest_popular("requests", "PyPI") is None  # the real one is not a look-alike
    assert packages.closest_popular("my-internal-lib", "PyPI") is None


# ---------- whole check ----------


def run_check(repo, files, registry):
    repo.write("README.md", "x\n")
    base = repo.commit()
    for p, c in files.items():
        repo.write(p, c)
    repo.commit()
    changes = collect_changes(repo.path, base)
    with make_workspace(changes) as ws:
        return packages.run(changes, ws, registry)


def test_no_manifest_change_is_not_applicable(repo):
    assert run_check(repo, {"app.py": "x = 1\n"}, FakeRegistry({})).status is Status.NA


def test_unreachable_registry_fails_closed(repo):
    class Down(FakeRegistry):
        def package(self, ecosystem, name):
            from security_gate.registry import RegistryError

            raise RegistryError("could not reach pypi.org")

    assert run_check(repo, {"requirements.txt": "flask\n"}, Down({})).status is Status.ERROR


def test_live_pypi_lookup(repo):
    """Real network call: exactly what CI does."""
    result = run_check(repo, {"requirements.txt": "flask==3.0.3\nflask-invoice-helpers==1.0.2\n"}, Registry())
    assert result.status is Status.FAIL
    assert [(f.rule, f.line) for f in result.findings] == [("package-does-not-exist", 2)]
