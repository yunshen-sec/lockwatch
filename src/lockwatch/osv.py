"""Optional OSV.dev client with a small, transparent JSON cache."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import Finding, Package, severity_from_osv

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvError(RuntimeError):
    """A recoverable OSV query failure."""


class OsvCache:
    """On-disk cache keyed by ecosystem/name/version.

    Cache data is untrusted input and is parsed as JSON only; it is never
    deserialised as Python objects.
    """

    def __init__(self, path: Optional[Path], max_age: float = 86400.0):
        self.path = Path(path) if path else None
        self.max_age = max_age
        self._entries: Dict[str, Dict[str, Any]] = {}
        if self.path:
            try:
                parsed = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    self._entries = parsed.get("entries", parsed) if isinstance(parsed.get("entries", parsed), dict) else {}
            except (OSError, UnicodeError, json.JSONDecodeError):
                self._entries = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        entry = self._entries.get(key)
        if not isinstance(entry, dict):
            return None
        try:
            if self.max_age >= 0 and time.time() - float(entry.get("timestamp", 0)) > self.max_age:
                return None
        except (TypeError, ValueError):
            return None
        response = entry.get("response")
        return response if isinstance(response, dict) else None

    def put(self, key: str, response: Dict[str, Any]) -> None:
        self._entries[key] = {"timestamp": time.time(), "response": response}
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"version": 1, "entries": self._entries}, sort_keys=True)
        fd, temporary = tempfile.mkstemp(prefix=".lockwatch-cache-", dir=str(self.path.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
            os.replace(temporary, self.path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _cache_key(package: Package) -> str:
    return package.key()


def query_package(package: Package, timeout: float = 5.0, cache: Optional[OsvCache] = None, endpoint: str = OSV_QUERY_URL) -> Dict[str, Any]:
    """Query one exact version.  Raises :class:`OsvError` on network errors."""

    key = _cache_key(package)
    if cache:
        cached = cache.get(key)
        if cached is not None:
            return cached
    if package.version in {"", "*"} or package.version.startswith(("http://", "https://", "git+")):
        response: Dict[str, Any] = {"vulns": [], "skipped": "version is not exact"}
        if cache:
            cache.put(key, response)
        return response
    payload = {"package": {"name": package.name, "ecosystem": package.ecosystem}, "version": package.version}
    request = Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response_stream:  # nosec B310 - endpoint is explicit/configurable
            response_data = response_stream.read()
        decoded = json.loads(response_data.decode("utf-8"))
    except (OSError, ValueError, HTTPError, URLError) as exc:
        raise OsvError("OSV query failed for %s: %s" % (package.key(), exc)) from exc
    if not isinstance(decoded, dict):
        raise OsvError("OSV returned a non-object response for %s" % package.key())
    if cache:
        cache.put(key, decoded)
    return decoded


def findings_for_package(package: Package, response: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    vulnerabilities = response.get("vulns", [])
    if not isinstance(vulnerabilities, list):
        return findings
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        identifier = vulnerability.get("id")
        if not isinstance(identifier, str) or not identifier:
            continue
        aliases = [str(value) for value in vulnerability.get("aliases", []) if isinstance(value, (str, int))]
        references = [str(item.get("url")) for item in vulnerability.get("references", []) if isinstance(item, dict) and item.get("url")]
        findings.append(Finding(package=package, vulnerability_id=identifier, severity=severity_from_osv(vulnerability), summary=str(vulnerability.get("summary") or ""), details=str(vulnerability.get("details") or ""), aliases=aliases, references=references))
    return findings


def scan_packages(packages: Iterable[Package], timeout: float = 5.0, cache: Optional[OsvCache] = None, endpoint: str = OSV_QUERY_URL) -> tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    errors: List[str] = []
    for package in packages:
        try:
            findings.extend(findings_for_package(package, query_package(package, timeout=timeout, cache=cache, endpoint=endpoint)))
        except OsvError as exc:
            errors.append(str(exc))
    return findings, errors
