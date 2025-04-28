import json, pathlib, skylos

SAMPLE = pathlib.Path(__file__).parent / "sample_project"

def test_analyze_returns_dead():
    out = json.loads(skylos.analyze(str(SAMPLE)))
    names = {d["name"] for d in out}
    assert "module1.unused_function" in names
    assert "live" not in names
