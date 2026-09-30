import json

from lockwatch.parsers import parse_package_lock, parse_poetry_lock, parse_requirements


def test_package_lock_v3_and_scoped_names(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "demo"}, "node_modules/lodash": {"version": "4.17.21"}, "node_modules/@scope/pkg": {"version": "1.2.3", "dev": True}}}))
    packages = parse_package_lock(path)
    assert {(item.name, item.version, item.dependency_type) for item in packages} == {
        ("lodash", "4.17.21", "runtime"), ("@scope/pkg", "1.2.3", "dev")
    }


def test_requirements_are_read_without_installing(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("# comment\nrequests==2.31.0\nurllib3>=2.0\n--index-url https://example.invalid/simple\n")
    packages = parse_requirements(path)
    assert [(item.name, item.version) for item in packages] == [("requests", "2.31.0"), ("urllib3", ">=2.0")]


def test_poetry_lock(tmp_path):
    path = tmp_path / "poetry.lock"
    path.write_text('[[package]]\nname = "requests"\nversion = "2.31.0"\ncategory = "main"\n\n[[package]]\nname = "pytest"\nversion = "8.0.0"\ncategory = "dev"\n')
    packages = parse_poetry_lock(path)
    assert [(item.name, item.dependency_type) for item in packages] == [("pytest", "dev"), ("requests", "runtime")]
