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


def test_typescript_scanner_defaults(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    p = d / "app.ts"
    p.write_text(TS_CODE, encoding="utf-8")

    results = scan_typescript_file(str(p))
    defs, refs, _, _, _, _, quality, danger, _ = results

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert "unusedLegacyFunction" in def_names
    assert "unusedLegacyFunction" not in ref_names
    assert "runUnsafe" in ref_names

    eval_findings = [f for f in danger if f["rule_id"] == "SKY-D501"]
    assert len(eval_findings) == 1

    assert len(quality) == 0


def test_typescript_config_override(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    p = d / "app.ts"
    p.write_text(TS_CODE, encoding="utf-8")

    strict_config = {"languages": {"typescript": {"complexity": 1}}}

    results = scan_typescript_file(str(p), config=strict_config)
    _, _, _, _, _, _, quality, _, _ = results

    assert len(quality) > 0
    assert quality[0]["rule_id"] == "SKY-Q501"
