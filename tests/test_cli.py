import json

from lockwatch.cli import main


def test_cli_offline_json(tmp_path, capsys):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n")
    assert main(["scan", str(requirements), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["metadata"]["osv_queried"] is False
    assert report["packages"][0]["name"] == "requests"
