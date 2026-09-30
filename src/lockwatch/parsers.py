"""Parsers for dependency manifests and lockfiles.

The parsers only read data.  They never import, install, or execute a project
dependency, which makes scanning suitable for untrusted source trees.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .models import Package

try:  # Python 3.11+
    import tomllib  # type: ignore
except ImportError:  # pragma: no cover - exercised only on older Pythons
    tomllib = None  # type: ignore

try:
    from packaging.requirements import Requirement
except ImportError:  # pragma: no cover
    Requirement = None  # type: ignore


class ParseError(ValueError):
    """Raised when a supported lockfile cannot be decoded."""


def _dedupe(packages: Iterable[Package]) -> List[Package]:
    result: Dict[str, Package] = {}
    for package in packages:
        if package.name and package.version:
            result.setdefault(package.key(), package)
    return sorted(result.values(), key=lambda item: (item.ecosystem, item.name.lower(), item.version))


def parse_package_lock(path: Path) -> List[Package]:
    """Read npm package-lock v1, v2, and v3 files."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ParseError("cannot read package-lock.json %s: %s" % (path, exc)) from exc
    packages: List[Package] = []
    package_map = document.get("packages")
    if isinstance(package_map, dict):
        for location, value in package_map.items():
            if location == "" or not isinstance(value, dict):
                continue
            version = value.get("version")
            if not isinstance(version, str):
                continue
            name = _npm_name_from_location(location)
            if not name:
                continue
            dev = bool(value.get("dev"))
            packages.append(Package(name, version, "npm", str(path), "dev" if dev else "runtime"))
    # npm lockfile v1 stores a nested dependencies tree.
    def visit(tree: Any, prefix: str = "") -> None:
        if not isinstance(tree, dict):
            return
        for name, value in tree.items():
            if not isinstance(value, dict):
                continue
            version = value.get("version")
            if isinstance(version, str):
                packages.append(Package(str(name), version, "npm", str(path), "dev" if value.get("dev") else "runtime"))
            visit(value.get("dependencies"), prefix + "node_modules/")

    visit(document.get("dependencies"))
    return _dedupe(packages)


def _npm_name_from_location(location: str) -> str:
    marker = "node_modules/"
    if marker not in location:
        return ""
    tail = location.rsplit(marker, 1)[1].strip("/")
    if not tail:
        return ""
    if tail.startswith("@"):
        bits = tail.split("/")
        return "/".join(bits[:2]) if len(bits) >= 2 else tail
    return tail.split("/", 1)[0]


_REQ_OPTION = re.compile(r"^(?:-r|--requirement|-c|--constraint|-f|--find-links|--index-url|--extra-index-url|--trusted-host)\b", re.I)


def parse_requirements(path: Path) -> List[Package]:
    """Parse pinned and versioned requirements without resolving/installing them.

    A requirement without an exact version is retained with its specifier as a
    version marker.  OSV queries are only attempted for exact versions.
    """

    packages: List[Package] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ParseError("cannot read requirements file %s: %s" % (path, exc)) from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";") or _REQ_OPTION.match(line):
            continue
        # Strip an inline comment only when separated by whitespace.
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line:
            continue
        name = version = ""
        if Requirement is not None:
            try:
                requirement = Requirement(line)
                name = requirement.name
                if requirement.specifier:
                    exact = [str(spec.version) for spec in requirement.specifier if spec.operator in ("==", "===") and "*" not in spec.version]
                    version = exact[0] if exact else str(requirement.specifier)
                # VCS/path requirements have no version suitable for OSV.
                if requirement.url and not version:
                    version = requirement.url
            except Exception:
                name = ""
        if not name:
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s*(==|===|~=|>=|<=|!=|>|<)\s*([^;\s]+))?", line)
            if not match:
                continue
            name = match.group(1)
            version = match.group(3) or ""
        if not version:
            # Preserve unresolved specs as a marker but do not ask OSV about it.
            version = "*"
        packages.append(Package(name, version, "PyPI", str(path), "runtime"))
    return _dedupe(packages)


def parse_poetry_lock(path: Path) -> List[Package]:
    """Parse Poetry's TOML lockfile when tomllib/tomli is available."""

    try:
        text = path.read_bytes()
    except (OSError, IOError) as exc:
        raise ParseError("cannot read poetry.lock %s: %s" % (path, exc)) from exc
    parser = tomllib
    if parser is None:
        try:
            import tomli as parser  # type: ignore
        except ImportError as exc:
            raise ParseError("parsing poetry.lock requires Python 3.11+ or tomli") from exc
    try:
        document = parser.loads(text.decode("utf-8"))
    except Exception as exc:
        raise ParseError("invalid poetry.lock %s: %s" % (path, exc)) from exc
    packages: List[Package] = []
    for item in document.get("package", []) if isinstance(document, dict) else []:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("version"), str):
            continue
        category = str(item.get("category", "main"))
        packages.append(Package(item["name"], item["version"], "PyPI", str(path), "dev" if category == "dev" else "runtime"))
    return _dedupe(packages)


def parse_files(paths: Sequence[Path]) -> List[Package]:
    """Parse files based on their names, returning a de-duplicated inventory."""

    packages: List[Package] = []
    for path in paths:
        lower = path.name.lower()
        if lower == "package-lock.json":
            packages.extend(parse_package_lock(path))
        # A caller may pass a generated file with a different basename (for
        # example ``req.txt``); text/in files use requirements syntax.
        elif lower in {"requirements.txt", "requirements-dev.txt", "requirements.in"} or lower.endswith((".requirements", ".txt", ".in")):
            packages.extend(parse_requirements(path))
        elif lower == "poetry.lock":
            packages.extend(parse_poetry_lock(path))
        else:
            raise ParseError("unsupported dependency file: %s" % path)
    return _dedupe(packages)
