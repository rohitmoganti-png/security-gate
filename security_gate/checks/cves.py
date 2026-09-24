"""Check 5: known vulnerabilities (CVEs) in dependencies this push added or upgraded.

Source: OSV.dev, which aggregates the official CVE list (github.com/CVEProject/cvelistV5)
with GitHub Security Advisories and PyPI/npm advisories, indexed by package + version.
Only NEW or CHANGED dependency versions are checked: old ones never block this push.
"""

from __future__ import annotations

import re
import time

from security_gate.changes import ChangeSet
from security_gate.deps import new_or_changed
from security_gate.registry import Registry, RegistryError, Vulnerability
from security_gate.result import CheckResult, Finding, Severity
from security_gate.workspace import Workspace

NAME, TOOL = "Dependency CVEs", "OSV.dev"
_SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
             "low": Severity.LOW, "unknown": Severity.MEDIUM}  # fmt: skip


def run(changes: ChangeSet, workspace: Workspace, registry: Registry | None = None) -> CheckResult:
    started = time.monotonic()
    deps = new_or_changed(changes)
    if not deps:
        return CheckResult(NAME, TOOL, not_applicable="no dependencies added or changed")
    pinned = [d for d in deps if d.version]
    unpinned = [d.name for d in deps if not d.version]
    notes = [f"checked {len(pinned)} pinned dependenc{'y' if len(pinned) == 1 else 'ies'}"]
    if unpinned:
        notes.append(f"not pinned to an exact version, so not checked: {', '.join(unpinned)}")

    registry = registry or Registry()
    findings = []
    try:
        for dep in pinned:
            vulns = [v for v in registry.vulnerabilities(dep.ecosystem, dep.name, dep.version)
                     if not v.id.startswith("MAL-")]  # malware is check 4's job  # fmt: skip
            for vuln in merge_duplicates(vulns):
                cve = vuln.aliases[0] if vuln.aliases else vuln.id
                fix = lowest_fix_above(vuln.fixed_in, dep.version)
                findings.append(
                    Finding(
                        rule=cve,
                        severity=_SEVERITY.get(vuln.severity, Severity.MEDIUM),
                        path=dep.path,
                        line=dep.line,
                        message=f"{dep.name} {dep.version}: {vuln.summary or vuln.id}"
                        + (f". Fix: upgrade to {fix}" if fix else ". No fixed version published yet"),
                        evidence=_link(cve),
                    )
                )
    except RegistryError as exc:  # fail closed
        return CheckResult(NAME, TOOL, error=str(exc))
    return CheckResult(NAME, TOOL, tuple(findings), seconds=time.monotonic() - started, notes=tuple(notes))


def merge_duplicates(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """The same CVE often appears as a GitHub advisory AND a PyPI advisory: keep one (the most severe)."""
    rank = {"critical": 4, "high": 3, "medium": 2, "unknown": 2, "low": 1}
    best: dict[str, Vulnerability] = {}
    for v in vulns:
        key = v.aliases[0] if v.aliases else v.id
        if key not in best or rank.get(v.severity, 0) > rank.get(best[key].severity, 0):
            fixes = tuple(dict.fromkeys((*best.get(key, v).fixed_in, *v.fixed_in)))
            best[key] = Vulnerability(v.id, v.aliases, v.summary, v.severity, fixes)
    return list(best.values())


def lowest_fix_above(fixed_in: tuple[str, ...], current: str) -> str | None:
    """Smallest 'fixed' version that is newer than the current one."""
    newer = [f for f in fixed_in if _key(f) > _key(current)]
    return min(newer, key=_key) if newer else None


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version)[:4])


def _link(vuln_id: str) -> str:
    if vuln_id.startswith("CVE-"):
        return f"https://www.cve.org/CVERecord?id={vuln_id}"
    return f"https://osv.dev/vulnerability/{vuln_id}"
