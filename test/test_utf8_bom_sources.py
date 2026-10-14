"""Files that start with a UTF-8 byte-order mark (U+FEFF).

Windows editors write one in any file type. Python, Node, npm and pip skip it,
so Skylos must read such files as if it were not there, without hiding a
U+FEFF that appears anywhere else.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from skylos.analysis.ast_cache import (
    MODE_STRICT,
    load_python_module,
    python_ast_cache_session,
)
from skylos.analyzer import analyze
from skylos.core.js_api_surface_utils import read_package_json
from skylos.core.safe_cache_io import strip_utf8_bom, write_text_no_symlink
from skylos.done.base import open_comparison
from skylos.rules.sca.vulnerability_scanner import (
    _manifest_text_is_valid,
    _read_manifest_text,
    parse_package_json,
    parse_requirements_txt,
)
from skylos.security.injection_scanner import scan_file
from skylos.visitors.languages.typescript.workspace import (
    discover_workspace_inventory,
)

BOM = "\ufeff"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)
    return path


def _scan(root: Path, **flags) -> dict:
    return json.loads(
        analyze(str(root), conf=0, grep_verify=False, trace_file=False, **flags)
    )


def test_strip_utf8_bom_drops_only_one_leading_mark():
    assert strip_utf8_bom(BOM + "x = 1\n") == "x = 1\n"
    assert strip_utf8_bom(BOM + BOM + "x") == BOM + "x"
    assert strip_utf8_bom("x = 1  # " + BOM) == "x = 1  # " + BOM
    assert strip_utf8_bom("") == ""


def test_bom_python_file_is_analysed_not_a_syntax_error(tmp_path):
    _write(
        tmp_path / "app.py",
        BOM + "def used():\n    return 1\n\n\ndef unused():\n    return 2\n\n\n"
        "print(used())\n",
    )

    result = _scan(tmp_path)

    assert result["analysis_errors"] == []
    assert [item["simple_name"] for item in result["unused_functions"]] == ["unused"]


def test_bom_python_danger_finding_keeps_line_and_column(tmp_path):
    _write(tmp_path / "plain" / "first.py", "eval(input())\n")
    _write(tmp_path / "bom" / "first.py", BOM + "eval(input())\n")

    plain = _scan(tmp_path / "plain", enable_danger=True)["danger"]
    marked = _scan(tmp_path / "bom", enable_danger=True)["danger"]

    def where(items):
        return [(i["rule_id"], i["line"], i["col"]) for i in items]

    assert where(marked) == where(plain)
    assert ("SKY-D201", 1, 0) in where(marked)


def test_ast_cache_parses_a_bom_python_file(tmp_path):
    path = _write(tmp_path / "mod.py", BOM + "VALUE = 1\n")

    with python_ast_cache_session():
        source, tree = load_python_module(path, MODE_STRICT)

    assert source == "VALUE = 1\n"
    assert tree is not None


def test_leading_bom_is_not_hidden_text_but_later_ones_are(tmp_path):
    path = _write(tmp_path / "zw.py", BOM + "x = 1\ny = 2  # a\u200bb\n")

    hidden = [
        (f["line"], f["simple_name"])
        for f in scan_file(path)
        if f["type"] == "hidden_char"
    ]

    assert hidden == [(2, "U+200B")]


def test_second_feff_on_the_first_line_is_still_reported(tmp_path):
    path = _write(tmp_path / "zw.py", BOM + "x = 1  # " + BOM + "hidden\n")

    hidden = [f for f in scan_file(path) if f["type"] == "hidden_char"]

    assert [(f["line"], f["simple_name"]) for f in hidden] == [(1, "U+FEFF")]


def test_leading_bom_in_agent_instruction_file_stays_reported(tmp_path):
    path = _write(tmp_path / ".cursor" / "BUGBOT.md", BOM + "# Bugbot\nBe strict.\n")

    hidden = [f for f in scan_file(path) if f["type"] == "hidden_char"]

    assert [(f["rule_id"], f["line"]) for f in hidden] == [("SKY-D266", 1)]


def test_leading_bom_in_yaml_reviewer_config_stays_reported(tmp_path):
    path = _write(tmp_path / ".coderabbit.yaml", BOM + "language: en\n")

    hidden = [
        f
        for f in scan_file(path, scan_path=".coderabbit.yaml")
        if f["type"] == "hidden_char"
    ]

    assert [(f["rule_id"], f["line"]) for f in hidden] == [("SKY-D266", 1)]


def test_bom_manifests_are_parsed_by_dependency_scanning(tmp_path):
    package = _write(
        tmp_path / "package.json",
        BOM + '{"name": "demo", "dependencies": {"lodash": "4.17.20"}}\n',
    )
    requirements = _write(tmp_path / "requirements.txt", BOM + "requests==2.19.0\n")

    # The scanner validates each manifest's text before parsing it.
    text = _read_manifest_text(package, max_bytes=100_000, encoding="utf-8")
    assert _manifest_text_is_valid("package.json", text)
    assert [d["name"] for d in parse_package_json(package)] == ["lodash"]
    assert [d["name"] for d in parse_requirements_txt(requirements)] == ["requests"]


def test_bom_package_json_names_the_workspace_and_its_type(tmp_path):
    _write(tmp_path / "package.json", BOM + '{"name": "demo", "type": "module"}\n')

    inventory = discover_workspace_inventory(tmp_path)

    assert inventory.root_package is not None
    assert inventory.root_package.name == "demo"
    assert read_package_json(tmp_path / "package.json")["type"] == "module"


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def test_done_comparison_strips_the_bom_from_python_only(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    _write(tmp_path / "app.py", BOM + "x = 1\n")
    _write(tmp_path / "pyproject.toml", BOM + "[tool.x]\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    _write(tmp_path / "app.py", BOM + "x = 2\n")

    comparison = open_comparison(tmp_path, "main")

    assert comparison.base_text("app.py") == "x = 1\n"
    assert comparison.head_text("app.py") == "x = 2\n"
    # Not Python: unchanged (TOML readers reject a byte-order mark).
    assert comparison.base_text("pyproject.toml") == BOM + "[tool.x]\n"
    assert comparison.head_text("pyproject.toml") == BOM + "[tool.x]\n"
