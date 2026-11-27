import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript.core import TypeScriptCore


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


@pytest.mark.parametrize("descending", [False, True])
def test_duplicate_callers_own_their_calls_regardless_of_capture_order(
    tmp_path, monkeypatch, descending
):
    (tmp_path / "package.json").write_text('{"private":true,"main":"index.js"}')
    script = tmp_path / "index.js"
    script.write_text(
        "function targetA() {} function targetB() {} function targetC() {}\n"
        "function first() { const open = () => targetA(); return open; }\n"
        "function second() { const open = () => targetB(); return open; } "
        "function third() { const open = () => targetC(); return open; }\n"
        "first(); second(); third();\n"
    )
    run_batch = TypeScriptCore._run_batch

    # Tree-sitter can return captures in either order across processes.
    def ordered_captures(self, key, pattern):
        captures = run_batch(self, key, pattern)
        if key == "defs":
            for nodes in captures.values():
                nodes.sort(key=lambda node: node.start_byte, reverse=descending)
        return captures

    monkeypatch.setattr(TypeScriptCore, "_run_batch", ordered_captures)
    definitions = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))[
        "definitions"
    ]
    callbacks = {k: v for k, v in definitions.items() if v["name"] == "open"}
    assert len(callbacks) == 3
    assert callbacks[f"{script}:open"]["calls"] == ["targetA"]
    assert callbacks[f"{script}:open:function:3"]["calls"] == ["targetB"]
    assert [row["calls"] for row in callbacks.values()].count(["targetC"]) == 1
    for outer, target in (
        ("first", "targetA"),
        ("second", "targetB"),
        ("third", "targetC"),
    ):
        # Preserve the existing accounting of nested calls by the outer body.
        assert definitions[f"{script}:{outer}"]["calls"] == [target]
        assert set(definitions[f"{script}:{target}"]["called_by"]) == {outer, "open"}
