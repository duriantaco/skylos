#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from skylos.analysis import implicit_refs
from skylos.analysis.penalties import _check_abstract_overrides
from skylos.analyzer import Skylos, analyze
from skylos.visitors.base import Definition


class _CountingDefinition(Definition):
    __slots__ = ()
    name_reads = 0

    def __getattribute__(self, attribute):
        if attribute == "name":
            type(self).name_reads += 1
        return super().__getattribute__(attribute)


class _CountingDefinitions(dict):
    def __init__(self, definitions):
        super().__init__(definitions)
        self.items_calls = 0
        self.values_calls = 0

    def items(self):
        self.items_calls += 1
        return super().items()

    def values(self):
        self.values_calls += 1
        return super().values()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_fixture(root: Path, *, per_language: int) -> int:
    """Create a deterministic mixed-language fixture for analyzer timing."""
    _write(
        root / "pyproject.toml",
        "[tool.skylos]\n"
        "ignore = []\n"
        "complexity = 10\n"
        "nesting = 3\n"
        "max_args = 5\n"
        "max_lines = 50\n",
    )
    _write(
        root / "package.json",
        json.dumps(
            {
                "name": "@speed/root",
                "workspaces": ["packages/*"],
                "dependencies": {"@speed/lib": "workspace:*"},
            }
        ),
    )
    _write(
        root / "packages" / "lib" / "package.json",
        json.dumps(
            {
                "name": "@speed/lib",
                "exports": {
                    ".": {
                        "types": "./dist/index.d.ts",
                        "import": "./dist/index.js",
                    }
                },
            }
        ),
    )
    _write(root / "Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n')

    for i in range(per_language):
        _write(
            root / "python" / f"module_{i}.py",
            "\n".join(
                [
                    f"def live_{i}(value):",
                    f"    return helper_{i}(value) + 1",
                    "",
                    f"def helper_{i}(value):",
                    "    if value > 10:",
                    "        return value - 1",
                    "    return value + 1",
                    "",
                    f"def unused_{i}():",
                    "    return 'unused'",
                    "",
                ]
            ),
        )

        _write(
            root / "packages" / "lib" / "src" / f"file_{i}.ts",
            "\n".join(
                [
                    f"export function lib{i}(value: number) {{",
                    "  return value + 1;",
                    "}",
                    "",
                    f"function internal{i}() {{",
                    "  return 'unused';",
                    "}",
                    "",
                ]
            ),
        )

        _write(
            root / "javascript" / f"component_{i}.jsx",
            "\n".join(
                [
                    f"export function Component{i}(props) {{",
                    "  return <div>{props.title}</div>;",
                    "}",
                    "",
                    f"function unusedComponent{i}() {{",
                    "  return null;",
                    "}",
                    "",
                ]
            ),
        )

        _write(
            root / "rust" / "src" / f"module_{i}.rs",
            "\n".join(
                [
                    f"pub fn live_{i}(value: i32) -> i32 {{",
                    f"    helper_{i}(value) + 1",
                    "}",
                    "",
                    f"fn helper_{i}(value: i32) -> i32 {{",
                    "    if value > 10 { value - 1 } else { value + 1 }",
                    "}",
                    "",
                    f"fn unused_{i}() -> &'static str {{",
                    '    "unused"',
                    "}",
                    "",
                ]
            ),
        )

        _write(
            root / "php" / f"service_{i}.php",
            "\n".join(
                [
                    "<?php",
                    f"function live_{i}($value) {{",
                    f"    return helper_{i}($value) + 1;",
                    "}",
                    f"function helper_{i}($value) {{",
                    "    return $value > 10 ? $value - 1 : $value + 1;",
                    "}",
                    f"function unused_{i}() {{",
                    "    return 'unused';",
                    "}",
                    "",
                ]
            ),
        )

    _write(
        root / "packages" / "app" / "src" / "index.ts",
        "\n".join(
            [
                "import { lib0 } from '@speed/lib';",
                "export function run() {",
                "  return lib0(41);",
                "}",
                "",
            ]
        ),
    )
    _write(
        root / "packages" / "lib" / "src" / "index.ts",
        "export { lib0 } from './file_0';\n",
    )
    _write(
        root / "rust" / "src" / "lib.rs",
        "\n".join([f"pub mod module_{i};" for i in range(min(per_language, 16))]),
    )

    return (per_language * 5) + 4


def _count_result_items(result: dict[str, Any]) -> int:
    total = 0
    for key in (
        "unused_functions",
        "unused_imports",
        "unused_classes",
        "unused_variables",
        "unused_parameters",
        "unused_files",
        "danger",
        "quality",
        "secrets",
    ):
        value = result.get(key)
        if isinstance(value, list):
            total += len(value)
    return total


def run_once(root: Path) -> tuple[float, int]:
    started = time.perf_counter()
    analyze_options = {
        "enable_danger": True,
        "enable_quality": True,
        "grep_verify": False,
    }
    payload = analyze(str(root), **analyze_options)
    elapsed = time.perf_counter() - started
    data = json.loads(payload)
    return elapsed, _count_result_items(data)


def run_scale_probe(*, size: int) -> dict[str, Any]:
    """Guard indexed analyzer lookups without relying on wall-clock timing."""
    if size < 1:
        raise ValueError("scale probe size must be at least 1")

    qualified_definitions = [
        _CountingDefinition(
            f"pkg.{index:04d}.Owner.target",
            "function",
            Path("definitions.py"),
            index + 1,
        )
        for index in range(size)
    ]
    qualified_analyzer = Skylos()
    qualified_analyzer.defs = {
        definition.name: definition for definition in qualified_definitions
    }
    qualified_analyzer.refs = [
        (f"pkg.{index:04d}.target", Path("caller.py")) for index in range(size)
    ]
    qualified_analyzer._global_type_map = {}
    _CountingDefinition.name_reads = 0

    original_pattern_tracker = implicit_refs.pattern_tracker
    implicit_refs.pattern_tracker = implicit_refs.ImplicitRefTracker()
    try:
        qualified_analyzer._mark_refs()
    finally:
        implicit_refs.pattern_tracker = original_pattern_tracker

    qualified_name_reads = _CountingDefinition.name_reads
    qualified_name_read_limit = size * ((2 * size.bit_length()) + 2)
    marked_references = sum(
        definition.references for definition in qualified_definitions
    )
    qualified_passed = (
        marked_references == size
        and all(definition.references == 1 for definition in qualified_definitions)
        and qualified_name_reads <= qualified_name_read_limit
    )

    classes = []
    methods = []
    for index in range(size):
        filename = Path(f"child_{index:04d}.py")
        class_name = f"models.Child{index:04d}"
        class_definition = Definition(class_name, "class", filename, 1)
        class_definition.base_classes = ["framework.ExternalBase"]
        classes.append(class_definition)
        methods.append(
            Definition(
                f"{class_name}.external_hook_{index:04d}",
                "method",
                filename,
                2,
            )
        )

    abstract_definitions = _CountingDefinitions(
        {definition.name: definition for definition in (*classes, *methods)}
    )
    abstract_analyzer = Skylos()
    abstract_analyzer.defs = abstract_definitions
    abstract_analyzer._global_abstract_methods = {}
    abstract_analyzer._global_protocol_classes = set()
    framework = SimpleNamespace(abstract_methods={}, protocol_classes=set())

    abstract_outcomes = [
        _check_abstract_overrides(method, abstract_analyzer, framework)
        for method in methods
    ]
    external_override_count = sum(outcome == -40 for outcome in abstract_outcomes)
    abstract_passed = (
        external_override_count == size
        and abstract_definitions.values_calls == 1
        and abstract_definitions.items_calls == 0
    )

    return {
        "size": size,
        "qualified_references": {
            "name_reads": qualified_name_reads,
            "name_read_limit": qualified_name_read_limit,
            "marked_references": marked_references,
            "passed": qualified_passed,
        },
        "abstract_overrides": {
            "values_calls": abstract_definitions.values_calls,
            "items_calls": abstract_definitions.items_calls,
            "external_override_count": external_override_count,
            "passed": abstract_passed,
        },
        "passed": qualified_passed and abstract_passed,
    }


def run_speed_check(
    *,
    root: Path,
    per_language: int,
    warmups: int,
    iterations: int,
    max_seconds: float,
    scale_size: int = 256,
) -> dict[str, Any]:
    """
    Measure analyzer runtime on a generated fixture.

    Calls: scripts/analyzer_speed_check.py build_fixture;
        scripts/analyzer_speed_check.py run_once.
        
    Called from: scripts/analyzer_speed_check.py main.
    """
    file_count = build_fixture(root, per_language=per_language)

    # Keep this deterministic enough for CI and avoid progress-log overhead.
    os.environ.setdefault("SKYLOS_JOBS", "1")
    os.environ.setdefault("SKYLOS_MARKREFS_TICK", "1000000")

    for _ in range(warmups):
        run_once(root)

    timings: list[float] = []
    finding_count = 0
    for _ in range(iterations):
        elapsed, finding_count = run_once(root)
        timings.append(elapsed)

    median_seconds = statistics.median(timings)
    scale = run_scale_probe(size=scale_size)
    timing_passed = median_seconds <= max_seconds
    return {
        "file_count": file_count,
        "finding_count": finding_count,
        "iterations": iterations,
        "warmups": warmups,
        "timings": timings,
        "median_seconds": median_seconds,
        "max_seconds": max_seconds,
        "timing_passed": timing_passed,
        "scale": scale,
        "passed": timing_passed and scale["passed"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a deterministic analyzer speed smoke check."
    )
    parser.add_argument("--per-language", type=int, default=24)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--max-seconds", type=float, default=8.0)
    parser.add_argument("--scale-size", type=int, default=256)
    parser.add_argument(
        "--fixture-root",
        type=Path,
        default=None,
        help="Optional existing directory for debugging. It must be empty.",
    )
    args = parser.parse_args()

    if args.per_language < 1:
        parser.error("--per-language must be at least 1")
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    if args.warmups < 0:
        parser.error("--warmups must be non-negative")
    if args.max_seconds <= 0:
        parser.error("--max-seconds must be positive")
    if args.scale_size < 1:
        parser.error("--scale-size must be at least 1")

    if args.fixture_root is not None:
        args.fixture_root.mkdir(parents=True, exist_ok=True)
        if any(args.fixture_root.iterdir()):
            parser.error("--fixture-root must be empty")
        summary = run_speed_check(
            root=args.fixture_root,
            per_language=args.per_language,
            warmups=args.warmups,
            iterations=args.iterations,
            max_seconds=args.max_seconds,
            scale_size=args.scale_size,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="skylos-speed-") as tmp:
            summary = run_speed_check(
                root=Path(tmp),
                per_language=args.per_language,
                warmups=args.warmups,
                iterations=args.iterations,
                max_seconds=args.max_seconds,
                scale_size=args.scale_size,
            )

    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["passed"]:
        failures = []
        if not summary["timing_passed"]:
            failures.append(
                f"median {summary['median_seconds']:.3f}s exceeds "
                f"budget {summary['max_seconds']:.3f}s"
            )
        if not summary["scale"]["passed"]:
            failures.append("deterministic scale probe exceeded its work bounds")
        print("Analyzer speed check failed: " + "; ".join(failures))
        return 1

    print(
        "Analyzer speed check passed: "
        f"median {summary['median_seconds']:.3f}s <= "
        f"budget {summary['max_seconds']:.3f}s "
        f"for {summary['file_count']} files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
