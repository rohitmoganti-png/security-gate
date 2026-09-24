"""Find the dependencies a push ADDED or CHANGED (shared by check 4 packages and check 5 CVEs).

Supported manifests:
  PyPI: requirements*.txt, pyproject.toml ([project] dependencies)
  npm:  package.json (dependencies, devDependencies)
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath

from security_gate.changes import EMPTY_TREE, ChangeSet, GitError, git


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # "PyPI" | "npm" (the names OSV.dev uses)
    name: str
    version: str | None  # exact pinned version if there is one (==1.2.3 / "1.2.3"), else None
    path: str  # manifest file
    line: int  # line in the manifest (for the report / annotations)


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==\s*([A-Za-z0-9.+!*-]+))?")


def is_manifest(path: str) -> bool:
    name = PurePosixPath(path).name
    return (name.startswith("requirements") and name.endswith(".txt")) or name in (
        "pyproject.toml",
        "package.json",
    )


def new_or_changed(changes: ChangeSet) -> list[Dependency]:
    """Dependencies in the new version of each manifest that weren't there (same version) before."""
    result: list[Dependency] = []
    for changed in changes.current_files:
        if not is_manifest(changed.path):
            continue
        head = parse(changed.path, _read(changes, changes.head, changed.path))
        base = parse(changed.path, _read(changes, changes.base, changed.path))
        before = {(d.name, d.version) for d in base}
        result += [d for d in head if (d.name, d.version) not in before]
    return result


def parse(path: str, text: str) -> list[Dependency]:
    if not text:
        return []
    name = PurePosixPath(path).name
    if name == "package.json":
        return _parse_package_json(path, text)
    if name == "pyproject.toml":
        return _parse_pyproject(path, text)
    return _parse_requirements(path, text)


def normalize_pypi(name: str) -> str:
    """PyPI treats Flask_Cors, flask.cors and flask-cors as the same name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(path: str, text: str) -> list[Dependency]:
    deps = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue  # options (-r, -e, --hash...) and direct URLs are not registry packages
        if m := _REQ.match(line):
            deps.append(Dependency("PyPI", normalize_pypi(m.group(1)), m.group(2), path, number))
    return deps


def _parse_pyproject(path: str, text: str) -> list[Dependency]:
    try:
        specs = tomllib.loads(text).get("project", {}).get("dependencies", [])
    except tomllib.TOMLDecodeError:
        return []
    lines = text.splitlines()
    deps = []
    for spec in specs:
        if m := _REQ.match(spec):
            number = next((i for i, row in enumerate(lines, 1) if spec in row), 1)
            deps.append(Dependency("PyPI", normalize_pypi(m.group(1)), m.group(2), path, number))
    return deps


def _parse_package_json(path: str, text: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    lines = text.splitlines()
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str) or spec.startswith(("file:", "git", "http", "link:", "workspace:")):
                continue
            version = spec if re.fullmatch(r"\d+\.\d+\.\d+[\w.-]*", spec) else None
            number = next((i for i, row in enumerate(lines, 1) if f'"{name}"' in row), 1)
            deps.append(Dependency("npm", name, version, path, number))
    return deps


def _read(changes: ChangeSet, commit: str, path: str) -> str:
    if commit == EMPTY_TREE:
        return ""
    try:
        return git(changes.repo, "show", f"{commit}:{path}")
    except GitError:
        return ""  # the file didn't exist in that commit
