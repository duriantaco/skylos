import json
from pathlib import Path

from skylos.analyzer import analyze


def test_same_named_arrow_sites_survive_without_rescuing_unrelated_dead_code(tmp_path):
    (tmp_path / "package.json").write_text('{"private":true,"main":"index.js"}')
    (tmp_path / "index.js").write_text(
        "const callback = () => {};\n"
        "function first() { const callback = () => {}; consume(callback); }\n"
        "function second() { const callback = () => {}; consume(callback); }\n"
        "const unrelated = () => 1;\n"
        "consume(callback); first(); second();\n"
    )
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    sites = [
        d
        for d in report["definitions"].values()
        if d["name"] == "callback" and Path(d["file"]).name == "index.js"
    ]
    assert {d["line"] for d in sites} == {1, 2, 3}
    assert all(d["dead"] is False for d in sites)
    dead = {d["name"] for d in report.get("unused_functions", [])}
    assert "callback" not in dead
    assert "unrelated" in dead
