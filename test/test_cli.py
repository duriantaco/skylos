import subprocess, pathlib, sys, json

SAMPLE = pathlib.Path(__file__).parent / "sample_project"

def test_cli_runs_and_json_ok(tmp_path):
    res = subprocess.run(
        ["skylos", str(SAMPLE), "--json"],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(res.stdout)
    assert any(d["name"] == "module1.unused_function" for d in data)