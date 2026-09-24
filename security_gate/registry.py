"""Read-only lookups against public package registries and OSV.dev.

Nothing is ever installed or executed: these are plain HTTPS GET/POST JSON calls.
Any failure other than "not found" raises RegistryError, so the check fails closed.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime

from security_gate import __version__

_TIMEOUT = 20
_HEADERS = {"User-Agent": f"security-gate/{__version__}", "Accept": "application/json"}


class RegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class PackageInfo:
    first_published: datetime | None
    versions: frozenset[str]
    weekly_downloads: int | None = None  # npm only (PyPI's JSON API has no download counts)


@dataclass(frozen=True)
class Vulnerability:
    id: str  # OSV ID, e.g. GHSA-..., PYSEC-..., MAL-...
    aliases: tuple[str, ...]  # e.g. ("CVE-2018-18074",)
    summary: str
    severity: str  # "critical" | "high" | "medium" | "low" | "unknown"
    fixed_in: tuple[str, ...] = field(default_factory=tuple)


class Registry:
    """Real network client. Tests swap in a fake with the same three methods."""

    def package(self, ecosystem: str, name: str) -> PackageInfo | None:
        return _pypi(name) if ecosystem == "PyPI" else _npm(name)

    def vulnerabilities(self, ecosystem: str, name: str, version: str | None) -> list[Vulnerability]:
        query: dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            query["version"] = version
        vulns, token = [], None
        while True:  # OSV pages large result sets
            body = {**query, **({"page_token": token} if token else {})}
            data = _request("https://api.osv.dev/v1/query", body) or {}
            vulns += [_to_vuln(v, name) for v in data.get("vulns", [])]
            token = data.get("next_page_token")
            if not token:
                return vulns


def _pypi(name: str) -> PackageInfo | None:
    data = _request(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if data is None:
        return None
    uploads = [
        f["upload_time_iso_8601"]
        for files in data.get("releases", {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    first = min((_parse_time(t) for t in uploads), default=None)
    return PackageInfo(first, frozenset(data.get("releases", {})))


def _npm(name: str) -> PackageInfo | None:
    data = _request(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
    if data is None:
        return None
    created = data.get("time", {}).get("created")
    downloads = _request(
        f"https://api.npmjs.org/downloads/point/last-week/{urllib.parse.quote(name, safe='@')}"
    )
    return PackageInfo(
        _parse_time(created) if created else None,
        frozenset(data.get("versions", {})),
        (downloads or {}).get("downloads"),
    )


def _request(url: str, body: dict | None = None) -> dict | None:
    """GET (or POST JSON). Returns None on 404; raises RegistryError on anything else."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {**_HEADERS, **({"Content-Type": "application/json"} if body is not None else {})}
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RegistryError(f"{url} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RegistryError(f"could not reach {urllib.parse.urlparse(url).netloc}: {exc}") from exc


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _to_vuln(v: dict, package: str) -> Vulnerability:
    fixed = []
    for affected in v.get("affected", []):
        for r in affected.get("ranges", []):
            fixed += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return Vulnerability(
        id=v["id"],
        aliases=tuple(a for a in v.get("aliases", []) if a.startswith("CVE-")),
        summary=(v.get("summary") or v.get("details", "")[:120] or "").strip(),
        severity=_severity(v),
        fixed_in=tuple(dict.fromkeys(fixed)),
    )


def _severity(v: dict) -> str:
    """OSV entries from GitHub carry database_specific.severity (LOW/MODERATE/HIGH/CRITICAL)."""
    label = str(v.get("database_specific", {}).get("severity", "")).lower()
    return {"moderate": "medium"}.get(label, label) or "unknown"
