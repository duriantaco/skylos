"""Dead-code confidence comes from evidence instead of a flat 100%."""

from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.generated_files import (
    REASON_GENERATED_SOURCE,
    classify_generated_file,
)
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.deadcode.confidence import (
    CONFIDENCE_CAPS,
    calibrate_dead_code_confidence,
    confidence_detail,
    experimental_hidden_counts,
)
from skylos.ui.scope_notes import scope_note_lines
from skylos.visitors.base import Definition


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _scan(root: Path, conf: int = 60, **kwargs) -> dict:
    return json.loads(analyze(str(root), conf=conf, grep_cache=False, **kwargs))


def _by_name(result: dict, key: str) -> dict[str, dict]:
    return {item.get("name"): item for item in result.get(key) or []}


def _definition(name, kind, filename, **attrs) -> Definition:
    definition = Definition(name, kind, filename, 1)
    for key, value in attrs.items():
        setattr(definition, key, value)
    return definition


def test_caps_follow_the_weakest_evidence():
    defs = {
        "m.os": _definition("os", "import", "m.py"),
        "m._helper": _definition("m._helper", "function", "m.py"),
        "m.public": _definition("m.public", "function", "m.py"),
        "m.Model": _definition("m.Model", "class", "m.py"),
        "m.Model.field": _definition("m.Model.field", "variable", "m.py"),
        "m.Model.run": _definition("m.Model.run", "method", "m.py"),
        "m.f.arg": _definition("m.f.arg", "parameter", "m.py"),
        "page": _definition(
            "Page", "function", "page.tsx", confidence_factors=["default_export"]
        ),
        "lib": _definition("helper", "function", "lib.ts"),
        "rs": _definition("walk", "function", "lib.rs"),
        "used": _definition("used", "function", "m.py", references=2),
    }
    defs["m.Model"].references = 1

    calibrate_dead_code_confidence(defs, demoted_exports=[defs["lib"]])

    confidence = {key: d.confidence for key, d in defs.items()}
    assert confidence["m.os"] == 100
    assert confidence["m._helper"] == 100
    assert confidence["m.public"] == CONFIDENCE_CAPS["public_name"]
    assert confidence["m.Model.field"] == CONFIDENCE_CAPS["class_attribute"]
    assert confidence["m.Model.run"] == CONFIDENCE_CAPS["public_method"]
    assert confidence["m.f.arg"] == CONFIDENCE_CAPS["signature_parameter"]
    assert confidence["page"] == CONFIDENCE_CAPS["default_export"]
    assert confidence["lib"] == CONFIDENCE_CAPS["exported_symbol"]
    assert confidence["rs"] == CONFIDENCE_CAPS["experimental_language"]
    # Referenced definitions are not candidates and are left alone.
    assert confidence["used"] == 100


def test_calibration_never_raises_existing_confidence_and_is_idempotent():
    definition = _definition("m.public", "function", "m.py", confidence=70)
    defs = {"m.public": definition}

    calibrate_dead_code_confidence(defs)
    calibrate_dead_code_confidence(defs)

    assert definition.confidence == 70
    assert definition.confidence_factors == ["public_name"]


def test_only_parameters_and_experimental_languages_fall_below_the_default():
    for factor, cap in CONFIDENCE_CAPS.items():
        if factor in {"experimental_language", "signature_parameter"}:
            assert cap < 60, factor
        else:
            assert cap >= 60, factor
    assert (
        CONFIDENCE_CAPS["experimental_language"]
        < CONFIDENCE_CAPS["signature_parameter"]
    )


def test_confidence_detail_names_the_weakest_factor():
    assert (
        confidence_detail(
            {
                "confidence": 60,
                "confidence_factors": ["exported_symbol", "default_export"],
            }
        )
        == "Confidence: 60% (default export (frameworks load modules by it))"
    )
    assert confidence_detail({"confidence": 100}) == "Confidence: 100%"
    assert confidence_detail({"name": "x"}) is None


def test_scan_reports_varied_confidence_and_threshold_filters_weak_findings(tmp_path):
    _write(tmp_path / "package.json", '{"name": "app"}')
    _write(tmp_path / "src/index.ts", "import { used } from './lib';\nused();\n")
    _write(
        tmp_path / "src/lib.ts",
        "export function used() { return 1; }\n"
        "export function neverImported() { return 2; }\n",
    )
    _write(tmp_path / "src/orphan.ts", "export default function Orphan() {}\n")
    _write(tmp_path / "app.py", "import os\n\n\ndef public_helper():\n    return 1\n")

    result = _scan(tmp_path)
    functions = _by_name(result, "unused_functions")
    files = {Path(f["file"]).name: f for f in result.get("unused_files") or []}

    assert functions["neverImported"]["confidence"] == 85
    assert functions["Orphan"]["confidence"] == 60
    assert functions["public_helper"]["confidence"] == 90
    assert _by_name(result, "unused_imports")["os"]["confidence"] == 100
    assert files["orphan.ts"]["confidence"] == 80
    assert files["orphan.ts"]["confidence_factors"] == ["unimported_file"]
    low, high = result["assessment"]["dead_code"]["confidence_range"]
    assert low < high

    strict = _scan(tmp_path, conf=90)
    strict_functions = _by_name(strict, "unused_functions")
    assert "Orphan" not in strict_functions
    assert "neverImported" not in strict_functions
    assert "public_helper" in strict_functions
    # File-level findings carry a confidence for sorting; ``skylos done``
    # compares unused-file sets across revisions, so the threshold does not
    # filter them.
    assert {Path(f["file"]).name for f in strict.get("unused_files") or []} == {
        "orphan.ts"
    }


def test_file_only_imported_by_unused_files_is_labelled_and_weaker(tmp_path):
    _write(tmp_path / "package.json", '{"name": "app"}')
    _write(tmp_path / "src/index.ts", "export const x = 1;\n")
    _write(tmp_path / "src/dead-root.ts", "import { leaf } from './leaf';\nleaf();\n")
    _write(tmp_path / "src/leaf.ts", "export function leaf() {}\n")

    files = {Path(f["file"]).name: f for f in _scan(tmp_path).get("unused_files") or []}

    assert files["dead-root.ts"]["confidence"] == 80
    assert files["leaf.ts"]["confidence"] == 65
    assert (
        "only imported by files that are themselves unused"
        in files["leaf.ts"]["message"]
    )


def test_rust_dead_code_is_experimental_and_hidden_by_default(tmp_path):
    _write(tmp_path / "Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\n')
    _write(
        tmp_path / "src/main.rs",
        "fn main() {}\n\nfn never_called() -> u32 { 1 }\n",
    )
    _write(tmp_path / "app.py", "def py_dead():\n    return 1\n")

    default = _scan(tmp_path)
    names = set(_by_name(default, "unused_functions"))
    assert "py_dead" in names
    assert "never_called" not in names
    hidden = default["analysis_summary"]["dead_code_experimental"]["rust"]
    assert hidden == {"listed": False, "show_with": "--confidence 40"}
    assert any(
        "Rust dead code is experimental" in line for line in scope_note_lines(default)
    )

    opted_in = _scan(tmp_path, conf=40)
    rust = _by_name(opted_in, "unused_functions")["never_called"]
    assert rust["confidence"] == 40
    assert "experimental_language" in rust["confidence_factors"]
    assert "dead_code_experimental" not in opted_in["analysis_summary"]


def test_experimental_hidden_counts_respect_the_threshold():
    definition = _definition("walk", "function", "lib.rs")
    defs = {"walk": definition}
    calibrate_dead_code_confidence(defs)

    assert experimental_hidden_counts(defs, 60) == {"rust": 1}
    assert experimental_hidden_counts(defs, 40) == {}


def test_generated_headers_are_report_only(tmp_path):
    tanstack = _write(
        tmp_path / "src/routeTree.gen.ts",
        "/* eslint-disable */\n\n// @ts-nocheck\n\n"
        "// This file was automatically generated by TanStack Router.\n"
        "import type { Unused } from './x'\n",
    )
    openapi = _write(
        tmp_path / "src/client/utils.gen.ts",
        "// This file is auto-generated by @hey-api/openapi-ts\n\nexport const a = 1;\n",
    )
    protobuf = _write(
        tmp_path / "pkg/thing_pb2.py",
        "# -*- coding: utf-8 -*-\n"
        "# Generated by the protocol buffer compiler.  DO NOT EDIT!\nimport os\n",
    )
    go = _write(
        tmp_path / "gen.go",
        "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage x\n",
    )
    handwritten = _write(
        tmp_path / "src/ids.ts",
        "// Returns an auto-generated id for each row.\nexport const id = 1;\n",
    )
    later = _write(
        tmp_path / "src/later.ts",
        "export const x = 1;\n// This file was automatically generated by hand.\n",
    )

    for path in (tanstack, openapi, protobuf, go):
        assert classify_generated_file(path, tmp_path) == REASON_GENERATED_SOURCE
    assert classify_generated_file(handwritten, tmp_path) is None
    assert classify_generated_file(later, tmp_path) is None


def test_generated_source_findings_are_dropped_but_its_references_count(tmp_path):
    _write(tmp_path / "package.json", '{"name": "app"}')
    _write(
        tmp_path / "src/routeTree.gen.ts",
        "// This file was automatically generated by TanStack Router.\n"
        "import { Home } from './routes/home';\n"
        "import { createStart } from '@tanstack/react-start';\n"
        "export const routeTree = [Home];\n",
    )
    _write(
        tmp_path / "src/routes/home.tsx", "export function Home() { return null; }\n"
    )
    _write(tmp_path / "src/stale.ts", "export function stale() {}\n")

    result = _scan(tmp_path, skip_generated=True)
    reported = {
        (Path(item["file"]).name, item.get("name"))
        for key in ("unused_functions", "unused_imports", "unused_files")
        for item in result.get(key) or []
    }

    assert not any(name == "routeTree.gen.ts" for name, _ in reported)
    assert ("home.tsx", "Home") not in reported
    assert ("stale.ts", "stale") in reported
    generated = result["analysis_summary"]["generated_files"]["by_reason"]
    assert generated.get(REASON_GENERATED_SOURCE) == 1


def test_unused_parameters_are_hidden_by_default_with_a_count(tmp_path):
    _write(
        tmp_path / "app.py",
        "def calculate(first, unused_second):\n"
        "    return first\n\n\n"
        "def stale():\n"
        "    return 1\n\n\n"
        "print(calculate(1, 2))\n",
    )

    default = _scan(tmp_path)
    assert not default.get("unused_parameters")
    assert "stale" in _by_name(default, "unused_functions")
    below = default["analysis_summary"]["dead_code_below_threshold"]
    assert below == {"unused_parameters": {"count": 1, "show_with": "--confidence 50"}}
    assert any(
        line.startswith("1 unused parameter is below the default confidence")
        and "--confidence 50" in line
        for line in scope_note_lines(default)
    )

    opted_in = _scan(tmp_path, conf=50)
    parameter = _by_name(opted_in, "unused_parameters")["unused_second"]
    assert parameter["confidence"] == 50
    assert parameter["confidence_factors"] == ["signature_parameter"]
    assert "dead_code_below_threshold" not in opted_in["analysis_summary"]
