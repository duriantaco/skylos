import ast

from skylos.analysis import file_worker
from skylos.analysis.file_processing import scan_python_quality
from skylos.analysis.file_worker import process_file
from skylos.config import load_config


_EVAL_SOURCE = "def run(text):\n    return eval(text)\n"


def _fail_quality(*args, **kwargs):
    raise RecursionError("forced quality rule failure")


def test_quality_rule_failure_keeps_security_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(file_worker, "scan_python_quality", _fail_quality)
    source = tmp_path / "mod.py"
    source.write_text(_EVAL_SOURCE, encoding="utf-8")

    result = process_file(str(source), "mod", project_root=tmp_path)

    assert [(f["rule_id"], f["line"]) for f in result[7]] == [("SKY-D201", 2)]
    assert result[6] == []
    assert result[25]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert result[25]["kind"] == "quality_scan_error"
    assert result[25]["error_type"] == "RecursionError"


def test_quality_and_security_failures_are_both_reported(tmp_path, monkeypatch):
    from skylos.rules.danger import danger

    def fail_taint(*args, **kwargs):
        raise RuntimeError("forced taint failure")

    monkeypatch.setattr(file_worker, "scan_python_quality", _fail_quality)
    monkeypatch.setattr(danger, "scan_file_with_tree", fail_taint)
    source = tmp_path / "mod.py"
    source.write_text(_EVAL_SOURCE, encoding="utf-8")

    result = process_file(str(source), "mod", project_root=tmp_path)

    assert [error["kind"] for error in result[25]] == [
        "quality_scan_error",
        "security_scan_error",
    ]


def test_long_expressions_do_not_exhaust_quality_rules():
    terms = "+".join(["v"] * 700)
    source = (
        "v = 1\n"
        f"TOTAL = {terms}\n"
        f"def f(a, flag={terms}):\n"
        "    return a\n"
        "class A:\n"
        f"    Y = {terms}\n"
        "    def first(self):\n"
        "        return self.x\n"
        "    def second(self):\n"
        "        return self.y\n"
    )
    cfg = dict(load_config("."))

    findings = scan_python_quality(ast.parse(source), source, "mod.py", cfg)

    assert isinstance(findings, list)
