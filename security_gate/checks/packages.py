"""Check 4: fake / hallucinated / suspicious packages (SlopGuard-style layers).

  Layer 0  exists?            not on PyPI/npm                      -> BLOCK (critical)
  Layer 2  known malicious?   OSV.dev MAL- advisory                -> BLOCK (critical)
  Layer 1  look-alike name?   1-2 edits from a popular package     -> warning
  Layer 3  suspicious history brand new (<30 days) / barely used   -> warning
  Combined look-alike AND (new or barely used) = typosquat pattern -> BLOCK (high)

No single weak signal ever blocks on its own. Read-only lookups: nothing is installed.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from security_gate.changes import ChangeSet
from security_gate.deps import Dependency, new_or_changed
from security_gate.popular import popular_for
from security_gate.registry import Registry, RegistryError
from security_gate.result import CheckResult, Finding, Severity
from security_gate.workspace import Workspace

NAME, TOOL = "Fake packages", "PyPI/npm/OSV"
NEW_PACKAGE_DAYS = 30
FEW_RELEASES = 3  # PyPI adoption proxy (its API has no download counts)
FEW_WEEKLY_DOWNLOADS = 100  # npm


def run(changes: ChangeSet, workspace: Workspace, registry: Registry | None = None) -> CheckResult:
    started = time.monotonic()
    deps = new_or_changed(changes)
    if not deps:
        return CheckResult(NAME, TOOL, not_applicable="no dependencies added or changed")
    registry = registry or Registry()
    findings: list[Finding] = []
    try:
        for dep in deps:
            findings += assess(dep, registry)
    except RegistryError as exc:  # fail closed: an unreachable registry is not "all clear"
        return CheckResult(NAME, TOOL, error=str(exc))
    note = f"checked {len(deps)} new/changed dependenc{'y' if len(deps) == 1 else 'ies'}"
    return CheckResult(NAME, TOOL, tuple(findings), seconds=time.monotonic() - started, notes=(note,))


def assess(dep: Dependency, registry: Registry, now: datetime | None = None) -> list[Finding]:
    def finding(rule: str, severity: Severity, message: str) -> Finding:
        return Finding(rule, severity, dep.path, dep.line, message, evidence=f"package: {dep.name}")

    info = registry.package(dep.ecosystem, dep.name)
    if info is None:  # Layer 0
        return [finding("package-does-not-exist", Severity.CRITICAL,
                        f"'{dep.name}' does not exist on {dep.ecosystem}. Likely an AI-hallucinated "
                        "name; an attacker could register it with malware (slopsquatting).")]  # fmt: skip

    malicious = [v.id for v in registry.vulnerabilities(dep.ecosystem, dep.name, None) if v.id.startswith("MAL-")]
    if malicious:  # Layer 2
        return [finding("known-malicious-package", Severity.CRITICAL,
                        f"'{dep.name}' is flagged as malware by OSV.dev ({', '.join(malicious)}).")]  # fmt: skip

    signals = []  # Layer 3 (skipped for well-known packages: these signals target unknown names)
    if dep.name.lower() in popular_for(dep.ecosystem):
        return _version_check(dep, info.versions, finding)
    age_days = (now or datetime.now(UTC)) - info.first_published if info.first_published else None
    if age_days is not None and age_days.days < NEW_PACKAGE_DAYS:
        signals.append(f"first published only {age_days.days} day(s) ago")
    if dep.ecosystem == "PyPI" and len(info.versions) < FEW_RELEASES:
        signals.append(f"only {len(info.versions)} release(s) ever")
    if info.weekly_downloads is not None and info.weekly_downloads < FEW_WEEKLY_DOWNLOADS:
        signals.append(f"only {info.weekly_downloads} downloads last week")

    lookalike = closest_popular(dep.name, dep.ecosystem)  # Layer 1
    findings = []
    if lookalike and signals:
        findings.append(finding("possible-typosquat", Severity.HIGH,
                                f"'{dep.name}' looks like popular '{lookalike}' AND is suspicious: "
                                f"{'; '.join(signals)}. Classic typosquat pattern."))  # fmt: skip
    elif lookalike:
        findings.append(finding("lookalike-name", Severity.MEDIUM,
                                f"'{dep.name}' is very close to popular '{lookalike}'. Check the spelling."))  # fmt: skip
    elif signals:
        findings.append(finding("low-trust-package", Severity.MEDIUM,
                                f"'{dep.name}' exists but: {'; '.join(signals)}. Review before trusting it."))  # fmt: skip

    return findings + _version_check(dep, info.versions, finding)


def _version_check(dep: Dependency, versions: frozenset[str], finding) -> list[Finding]:
    if dep.version and versions and dep.version not in versions:
        return [finding("version-does-not-exist", Severity.MEDIUM,
                        f"{dep.name}=={dep.version} was never published (hallucinated version?).")]  # fmt: skip
    return []


def closest_popular(name: str, ecosystem: str) -> str | None:
    """A popular package 1-2 edits away (but not the same name), if any."""
    name = name.lower()
    if len(name) < 4 or name in popular_for(ecosystem):
        return None
    limit = 1 if len(name) < 7 else 2
    best = min(
        ((edit_distance(name, p), p) for p in popular_for(ecosystem) if abs(len(p) - len(name)) <= limit),
        default=None,
    )
    return best[1] if best and best[0] <= limit else None


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment): swaps count as 1 edit ('reqeusts')."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]
