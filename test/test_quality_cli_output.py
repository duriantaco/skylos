"""CLI output should not be mistaken for an abandoned debug print."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.quality.logic_security import DebugLeftoverRule


def _print_findings(source: str) -> list[dict]:
    visitor = LinterVisitor([DebugLeftoverRule()], "app.py")
    visitor.context["source"] = source
    visitor.visit(ast.parse(source))
    return [item for item in visitor.findings if item["rule_id"] == "SKY-L009"]


def test_main_guard_output_does_not_hide_unrelated_runtime_print() -> None:
    source = """
def service():
    print("debug")

if __name__ == "__main__":
    print("ready")
    service()
"""
    findings = _print_findings(source)
    assert [(item["name"], item["line"]) for item in findings] == [("print", 3)]


def test_cli_entry_output_is_accepted_but_debug_output_is_flagged() -> None:
    source = """
import sys

def _run_cli(args):
    print("result")
    print("invalid input", file=sys.stderr)

def main():
    return _run_cli(sys.argv)

def service():
    print("debug")

if __name__ == "__main__":
    raise SystemExit(main())
"""
    findings = _print_findings(source)
    assert [(item["name"], item["line"]) for item in findings] == [("print", 12)]


def test_service_stderr_and_json_are_output_but_debug_marker_is_reported() -> None:
    source = """
import json
import sys

def run(args):
    print("failed", file=sys.stderr)
    print(json.dumps({"status": "ok"}), flush=True)
    print("debug")

def main():
    run(sys.argv)

if __name__ == "__main__":
    main()
"""
    findings = _print_findings(source)
    assert [(item["name"], item["line"]) for item in findings] == [("print", 8)]


def test_decorated_main_route_print_is_reported() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/status")
def main():
    print("DEBUG: route dump")
    return {"status": "ok"}

if __name__ == "__main__":
    main()
"""
    findings = _print_findings(source)
    assert [(item["name"], item["line"]) for item in findings] == [("print", 7)]


def test_undecorated_main_with_argv_is_cli_output() -> None:
    source = """
import sys

def main():
    command = sys.argv[1]
    print(command)

if __name__ == "__main__":
    main()
"""
    assert _print_findings(source) == []


def test_stderr_output_does_not_require_a_main_guard() -> None:
    source = """
import sys

def service():
    print("failed", file=sys.stderr)
"""
    assert _print_findings(source) == []


def test_breakpoint_inside_main_guard_still_reports() -> None:
    source = """
if __name__ == "__main__":
    print("running")
    breakpoint()
"""
    findings = _print_findings(source)
    assert [(item["name"], item["line"]) for item in findings] == [("breakpoint", 4)]


@pytest.mark.parametrize(
    "source",
    [
        'print(f"  Plan: {plan_display_name(result.plan)}")',
        'print(f"  Organization: {result.org_name}")',
        'print("Connected to Skylos Cloud!")',
        'print("Debug mode disabled")',
        'print("Set DEBUG in your config")',
        'print("Debugger ready")',
        'print("Debug documentation", file=destination)',
        'print(json.dumps({"status": "ok"}))',
        'print(json.dumps(vars(options)))',
        'print(value)',
        'print(repr(value))',
        'print(f"Plan: {plan!r}")',
        'print(f"value={value!r}")',
        'print(f"{left == right}")',
        'print(f"{value:=10}")',
        'print(f"{(value := 10)}")',
        'print(f"{format_value(value=1)}")',
        'print(len(locals()))',
        'print(f"Count: {len(locals())}")',
        'print(json.dumps({"debug": False}))',
        'print("Use --debug for details")',
        'print(f"DEBUG{version}")',
        'print(f"DBG{serial}")',
        'print("Debug mode {}".format(mode))',
        'print("Use --debug %s" % option)',
        'pprint(data)',
        'pprint.pprint(data)',
    ],
)
def test_ordinary_output_is_not_debugging_evidence(source: str) -> None:
    assert _print_findings(source) == []


@pytest.mark.parametrize(
    "source",
    [
        'print("DEBUG:", payload)',
        'print("[DEBUG]", payload)',
        'print("DBG: checkpoint")',
        'print(f"DEBUG: {payload}")',
        'print(locals())',
        'print(globals())',
        'print(vars(request))',
        'print(request.__dict__)',
        'pprint(locals())',
        'pprint.pprint(vars(request))',
        'builtins.print("DEBUG:", payload)',
        'print(f"{payload=}")',
        'print(f"{payload = }")',
        'print(f"{payload=:.2f}")',
        'print(f"{payload=!s}")',
        'print(f"é: {payload=}")',
        'print(f"{(payload)=!r}")',
        'print(f"{format_value(value=1)=}")',
        'print(f"{payload = !s:>10}")',
        'print(f"State: {vars(request)}")',
        'print(f"{request.__dict__}")',
        'print("DEBUG: {}".format(payload))',
        'print("DBG: %s" % payload)',
    ],
)
def test_print_diagnostics_require_evidence_and_are_advisory(source: str) -> None:
    findings = _print_findings(source)
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert "Possible debug output" in findings[0]["message"]
    assert "Remove before shipping" not in findings[0]["message"]


@pytest.mark.parametrize("filename", ["cli.py", "__main__.py", "scripts/run.py", "test_app.py"])
@pytest.mark.parametrize("source", ['print("DEBUG:", payload)', 'pprint(locals())', 'breakpoint()'])
def test_filenames_do_not_hide_debugging_evidence(filename: str, source: str) -> None:
    visitor = LinterVisitor([DebugLeftoverRule()], filename)
    visitor.context["source"] = source
    visitor.visit(ast.parse(source))
    assert len(visitor.findings) == 1


def test_cli_handler_preserves_debug_findings_between_normal_messages() -> None:
    source = '''
import sys
def main():
    print(f"Plan: {plan}")
    print("DEBUG:", payload)
    print(f"{payload=}")
    breakpoint()
    print("Ready", file=sys.stderr)
if __name__ == "__main__":
    main()
'''
    assert [(item["name"], item["line"]) for item in _print_findings(source)] == [
        ("print", 5), ("print", 6), ("breakpoint", 7)
    ]


def test_fallback_renderer_does_not_hide_extra_debug_calls() -> None:
    source = '''
def show(result, writer=None):
    if writer:
        writer.print(f"Plan: {result.plan}")
    else:
        print(f"Plan: {result.plan}")
        print("DEBUG:", vars(result))
        breakpoint()
'''
    assert [(item["name"], item["line"]) for item in _print_findings(source)] == [
        ("print", 7), ("breakpoint", 8)
    ]


def test_ast_without_source_does_not_guess_fstring_debug_syntax() -> None:
    visitor = LinterVisitor([DebugLeftoverRule()], "app.py")
    visitor.visit(ast.parse('print(f"value={value!r}")'))
    assert visitor.findings == []


def test_multiline_debug_expression_uses_source_coordinates() -> None:
    source = 'print(f"""{(value)\n = }""")'
    findings = _print_findings(source)
    assert len(findings) == 1
    assert "f-string debug expression" in findings[0]["message"]
