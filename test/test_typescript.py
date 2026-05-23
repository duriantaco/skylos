import pickle

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file

TS_CODE = """
// 1. DEAD CODE
function unusedLegacyFunction() {
    return "delete me";
}

// 2. DANGER
function runUnsafe(input: string) {
    eval(input);
}

// 3. QUALITY (Complexity ~3)
function simpleFunction(x: number) {
    if (x > 10) { return true; } else { return false; }
}

runUnsafe("test");
"""

JS_CODE = """
// 1. DEAD CODE
function unusedLegacyFunction() {
    return "delete me";
}

// 2. DANGER
function runUnsafe(input) {
    eval(input);
}

// 3. QUALITY (Complexity ~3)
function simpleFunction(x) {
    if (x > 10) { return true; } else { return false; }
}

runUnsafe("test");
"""


@pytest.mark.parametrize(
    ("filename", "code"),
    [("app.ts", TS_CODE), ("app.js", JS_CODE)],
)
def test_typescript_scanner_defaults(tmp_path, filename, code):
    d = tmp_path / "src"
    d.mkdir()
    p = d / filename
    p.write_text(code, encoding="utf-8")

    results = scan_typescript_file(str(p))
    defs, refs, _, _, _, _, quality, danger, _, _, _, _, _ = results

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert "unusedLegacyFunction" in def_names
    assert "unusedLegacyFunction" not in ref_names
    assert "runUnsafe" in ref_names

    eval_findings = [f for f in danger if f["rule_id"] == "SKY-D201"]
    assert len(eval_findings) == 1

    assert len(quality) == 0


def test_typescript_config_override(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    p = d / "app.ts"
    p.write_text(TS_CODE, encoding="utf-8")

    strict_config = {"languages": {"typescript": {"complexity": 1}}}

    results = scan_typescript_file(str(p), config=strict_config)
    _, _, _, _, _, _, quality, _, _, _, _, _, _ = results

    assert len(quality) > 0
    assert quality[0]["rule_id"] == "SKY-Q301"


def test_jsx_scanner_parses_component_file(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    p = d / "widget.jsx"
    p.write_text(
        'export default function Widget() { return <div className="card">hi</div>; }\n',
        encoding="utf-8",
    )

    defs, refs, _, _, _, _, quality, danger, _, _, _, _, _ = scan_typescript_file(
        str(p)
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert "Widget" in def_names
    assert "div" not in ref_names
    assert quality == []
    assert danger == []


def test_typescript_scan_result_is_parallel_worker_picklable(tmp_path):
    p = tmp_path / "app.ts"
    p.write_text("export function run(input: string) { return eval(input); }\n")

    result = scan_typescript_file(str(p), {}, enable_quality_rules=False)

    pickle.dumps(result)
