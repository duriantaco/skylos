"""CLI output should not be mistaken for an abandoned debug print."""

import ast

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


def test_cli_entry_output_is_accepted_but_service_output_is_flagged() -> None:
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


def test_reachable_service_helper_keeps_diagnostic_style_findings() -> None:
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
    assert [(item["name"], item["line"]) for item in findings] == [
        ("print", 6),
        ("print", 7),
        ("print", 8),
    ]


def test_decorated_main_route_print_is_reported() -> None:
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/status")
def main():
    print("debug route dump")
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


def test_diagnostic_style_without_main_guard_still_reports() -> None:
    source = """
import sys

def service():
    print("failed", file=sys.stderr)
"""
    findings = _print_findings(source)
    assert [(item["name"], item["line"]) for item in findings] == [("print", 5)]


def test_breakpoint_inside_main_guard_still_reports() -> None:
    source = """
if __name__ == "__main__":
    print("running")
    breakpoint()
"""
    findings = _print_findings(source)
    assert [(item["name"], item["line"]) for item in findings] == [("breakpoint", 4)]
