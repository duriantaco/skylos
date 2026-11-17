import json

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript.core import TypeScriptCore


def test_top_level_var_declarations_extracted_without_function_locals():
    core = TypeScriptCore(
        "app.js",
        b"var RGX = /x/;\nvar retired = /y/;\n"
        b"function match(value) { var local = 1; return RGX.test(value); }\n",
    )
    core.scan()
    definitions = {(d.name, d.type, d.line) for d in core.defs}
    assert ("RGX", "variable", 1) in definitions
    assert ("retired", "variable", 2) in definitions
    assert not any(name == "local" for name, _, _ in definitions)
    assert ("RGX", "app.js") in core.refs


def test_ts_module_variables_have_definition_context_and_unused_controls(tmp_path):
    (tmp_path / "package.json").write_text('{"private":true,"main":"app.js"}')
    (tmp_path / "app.js").write_text(
        "var RGX = /x/;\nconst MAP = { GET: 1 };\n"
        "var retiredPattern = /unused/;\nconst retiredMap = { POST: 2 };\n"
        'console.log(RGX.test("x"), MAP.GET);\n'
    )
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    definitions = {d["name"]: d for d in report["definitions"].values()}
    assert definitions["RGX"]["line"] == 1
    assert definitions["MAP"]["line"] == 2
    assert definitions["RGX"]["dead"] is False
    assert definitions["MAP"]["dead"] is False
    dead = {d["name"] for d in report.get("unused_variables", [])}
    assert {"retiredPattern", "retiredMap"} <= dead
    assert not {"RGX", "MAP"} & dead


def test_python_variable_context_volume_is_unchanged(tmp_path):
    (tmp_path / "app.py").write_text("module_value = 1\nprint(module_value)\n")
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not any(
        d["type"] in {"variable", "constant"} for d in report["definitions"].values()
    )
