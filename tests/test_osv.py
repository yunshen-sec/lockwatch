import json

import lockwatch.osv as osv
from lockwatch.models import Package


class _Response:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


def test_osv_cache_avoids_second_request(tmp_path, monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return _Response(json.dumps({"vulns": [{"id": "GHSA-test", "database_specific": {"severity": "HIGH"}}]}).encode())

    monkeypatch.setattr(osv, "urlopen", fake_urlopen)
    package = Package("requests", "2.31.0", "PyPI", "requirements.txt")
    cache = osv.OsvCache(tmp_path / "cache.json")
    first = osv.query_package(package, timeout=1, cache=cache, endpoint="https://example.invalid")
    second = osv.query_package(package, timeout=1, cache=osv.OsvCache(tmp_path / "cache.json"), endpoint="https://example.invalid")
    assert first == second
    assert len(calls) == 1
    assert osv.findings_for_package(package, first)[0].severity.name == "HIGH"


def test_osv_skips_unpinned_ranges(monkeypatch):
    monkeypatch.setattr(osv, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network should not be used")))
    response = osv.query_package(Package("urllib3", ">=2.0", "PyPI", "requirements.txt"), timeout=1)
    assert response["skipped"] == "version is not exact"
