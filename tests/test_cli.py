import json

from lockwatch.cli import main


def test_cli_offline_json(tmp_path, capsys):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n")
    assert main(["scan", str(requirements), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["metadata"]["osv_queried"] is False
    assert report["packages"][0]["name"] == "requests"


def test_typed_option_accepts_generated_filename(tmp_path, capsys):
    lock = tmp_path / "npm-deps.json"
    lock.write_text('{"packages":{"node_modules/demo":{"version":"1.0.0"}}}')
    assert main(["scan", "--package-lock", str(lock), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["packages"][0]["name"] == "demo"
