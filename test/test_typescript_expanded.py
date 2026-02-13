from skylos.visitors.languages.typescript import scan_typescript_file


def _scan_ts(tmp_path, code):
    p = tmp_path / "test.ts"
    p.write_text(code, encoding="utf-8")
    results = scan_typescript_file(str(p))
    defs, refs, _, _, _, _, quality, danger, _, _, _, _ = results
    return defs, refs, quality, danger


class TestTSDangerRules:
    def test_eval_detected(self, tmp_path):
        _, _, _, danger = _scan_ts(tmp_path, 'eval("alert(1)");')
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D501" in ids

    def test_innerhtml_detected(self, tmp_path):
        code = 'document.getElementById("x")!.innerHTML = "<b>xss</b>";'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D502" in ids

    def test_new_function_detected(self, tmp_path):
        code = 'const f = new Function("return 1");'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D504" in ids

    def test_settimeout_string_detected(self, tmp_path):
        code = 'setTimeout("alert(1)", 1000);'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D505" in ids

    def test_setinterval_string_detected(self, tmp_path):
        code = 'setInterval("document.write(1)", 5000);'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D505" in ids

    def test_outerhtml_detected(self, tmp_path):
        code = 'document.getElementById("x")!.outerHTML = "<div>replaced</div>";'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D507" in ids

    def test_settimeout_callback_safe(self, tmp_path):
        code = 'setTimeout(() => { console.log("ok"); }, 100);'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D505" not in ids


class TestTSQualityRules:
    def test_cyclomatic_complexity(self, tmp_path):
        code = (
            "function complex(x: number) {\n"
            "    if (x > 0) {\n"
            "        if (x > 1) { return 1; }\n"
            "        else { return 2; }\n"
            "    } else if (x < -5) {\n"
            "        switch(x) {\n"
            "            case -6: return 6;\n"
            "            case -7: return 7;\n"
            "            case -8: return 8;\n"
            "            default: return 0;\n"
            "        }\n"
            "    }\n"
            "    for (let i = 0; i < 10; i++) {\n"
            "        while (x > 0) {\n"
            "            if (x % 2 === 0) { break; }\n"
            "            if (x % 3 === 0) { continue; }\n"
            "            x--;\n"
            "        }\n"
            "    }\n"
            "    return -1;\n"
            "}\n"
            "complex(1);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in quality}
        assert "SKY-Q601" in ids

    def test_nesting_depth(self, tmp_path):
        code = (
            "function deep(x: number) {\n"
            "    if (x > 0) {\n"
            "        for (let i = 0; i < 10; i++) {\n"
            "            while (i < 5) {\n"
            "                if (i % 2 === 0) {\n"
            "                    try { console.log(i); } catch (e) { }\n"
            "                }\n"
            "                break;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "deep(1);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        nesting = [f for f in quality if f["rule_id"] == "SKY-Q602"]
        assert len(nesting) > 0

    def test_too_many_params(self, tmp_path):
        code = (
            "function many(a: number, b: number, c: string, d: boolean, e: any, f: object) {\n"
            "    return a;\n"
            "}\n"
            "many(1, 2, 'x', true, null, {});\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        param_findings = [f for f in quality if f["rule_id"] == "SKY-Q604"]
        assert len(param_findings) == 1
        assert "6 parameters" in param_findings[0]["message"]

    def test_small_function_no_findings(self, tmp_path):
        code = (
            "function small(x: number): number {\n"
            "    return x + 1;\n"
            "}\n"
            "small(1);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        assert len(quality) == 0


class TestTSImports:
    def test_named_imports(self, tmp_path):
        code = (
            "import { foo, bar } from './helpers';\n"
            "foo();\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        def_names = {d.name for d in defs}
        assert "foo" in def_names
        assert "bar" in def_names
        import_defs = [d for d in defs if d.type == "import"]
        assert len(import_defs) == 2

    def test_default_import(self, tmp_path):
        code = (
            "import React from 'react';\n"
            "React.createElement('div');\n"
        )
        defs, _, _, _ = _scan_ts(tmp_path, code)
        import_defs = [d for d in defs if d.type == "import"]
        names = {d.name for d in import_defs}
        assert "React" in names

    def test_namespace_import(self, tmp_path):
        code = (
            "import * as utils from './utils';\n"
            "utils.doThing();\n"
        )
        defs, _, _, _ = _scan_ts(tmp_path, code)
        import_defs = [d for d in defs if d.type == "import"]
        names = {d.name for d in import_defs}
        assert "utils" in names

    def test_unused_import_detectable(self, tmp_path):
        code = (
            "import { unused } from './lib';\n"
            "function usedFunc() { return 42; }\n"
            "usedFunc();\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        def_names = {d.name for d in defs}
        ref_names = {r[0] for r in refs}
        assert "unused" in def_names
        assert "unused" not in ref_names
