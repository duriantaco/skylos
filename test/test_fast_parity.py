from __future__ import annotations

import ast
import os
import json
import subprocess
import sys
import textwrap
import pytest
from difflib import SequenceMatcher
from pathlib import Path

skylos_fast = pytest.importorskip("skylos_fast")

from skylos_fast import (
    compute_similarity,
    discover_files,
    find_cycles,
    analyze_coupling as fast_analyze_coupling,
)
from skylos.rules.quality.coupling import analyze_coupling as py_analyze_coupling
from skylos.circular_deps import CircularDependencyAnalyzer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SKYLOS_PKG = PROJECT_ROOT / "skylos"

_REAL_FILES: list[Path] = []
for f in sorted(SKYLOS_PKG.rglob("*.py")):
    if "__pycache__" in str(f) or "venv" in str(f):
        continue
    _REAL_FILES.append(f)


def _run_dead_code_parity_scans_in_subprocess(target: Path) -> tuple[dict, dict]:
    code = textwrap.dedent(
        """
        import json
        import shutil
        import sys
        from pathlib import Path
        import skylos.analyzer as mod
        from skylos.analyzer import Skylos

        target = sys.argv[1]
        exclude = ["venv", "__pycache__", ".git", "node_modules"]
        cache_dir = Path(".skylos") / "cache"

        if cache_dir.exists():
            shutil.rmtree(cache_dir)

        result_fast = json.loads(Skylos().analyze(target, exclude_folders=exclude))

        if cache_dir.exists():
            shutil.rmtree(cache_dir)

        mod._fast_discover = None

        import skylos.rules.quality.clones as clones_mod
        clones_mod._fast_similarity = None

        import skylos.rules.quality.coupling as coupling_mod
        coupling_mod._fast_analyze_coupling = None

        import skylos.circular_deps as circ_mod
        circ_mod._fast_find_cycles = None

        result_py = json.loads(Skylos().analyze(target, exclude_folders=exclude))
        print(json.dumps({"fast": result_fast, "python": result_py}))
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", code, str(target)],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    return payload["fast"], payload["python"]


def _py_similarity(a: str, b: str) -> float:
    return SequenceMatcher(a=a, b=b).ratio()


def _py_discover(root: str, extensions: list[str], exclude_dirs: list[str]) -> set[str]:
    ext_set = {"." + e for e in extensions}
    exclude_set = set(exclude_dirs)
    found = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_set]
        for f in filenames:
            fpath = os.path.join(dirpath, f)
            if Path(fpath).suffix.lower() in ext_set:
                found.add(fpath)
    return found


def _py_find_cycles(edges, modules):
    analyzer = CircularDependencyAnalyzer()
    for m in modules:
        analyzer.modules[m] = f"{m}.py"
    for frm, to in edges:
        analyzer.dependencies[frm].add(to)
    return analyzer._find_cycles_py()


def _compare_coupling_dicts(py_result, rs_result, label=""):
    """Deep compare two coupling result dicts. Returns list of diff strings."""
    diffs = []
    py_classes = set(py_result.get("classes", {}).keys())
    rs_classes = set(rs_result.get("classes", {}).keys())

    if py_classes != rs_classes:
        diffs.append(f"{label} class sets differ: PY={py_classes} RS={rs_classes}")
        return diffs

    for cls_name in sorted(py_classes):
        pc = py_result["classes"][cls_name]
        rc = rs_result["classes"][cls_name]

        for key in [
            "efferent_coupling",
            "afferent_coupling",
            "total_coupling",
            "instability",
            "efferent_classes",
            "afferent_classes",
            "is_protocol",
            "is_abc",
            "is_dataclass",
            "methods",
            "line",
        ]:
            pv = pc.get(key)
            rv = rc.get(key)
            if pv != rv:
                diffs.append(f"{label} {cls_name}.{key}: PY={pv!r} RS={rv!r}")

        pb = pc.get("breakdown", {})
        rb = rc.get("breakdown", {})
        for bk in sorted(set(list(pb.keys()) + list(rb.keys()))):
            if pb.get(bk) != rb.get(bk):
                diffs.append(
                    f"{label} {cls_name}.breakdown.{bk}: PY={pb.get(bk)} RS={rb.get(bk)}"
                )

    py_graph = py_result.get("coupling_graph", {})
    rs_graph = rs_result.get("coupling_graph", {})
    for name in sorted(set(list(py_graph.keys()) + list(rs_graph.keys()))):
        if py_graph.get(name) != rs_graph.get(name):
            diffs.append(
                f"{label} graph.{name}: PY={py_graph.get(name)} RS={rs_graph.get(name)}"
            )

    return diffs


class TestSimilarityParity:
    PAIRS = [
        ("def foo(x): return x + 1", "def foo(x): return x + 1"),
        ("def foo(x): return x + 1", "def bar(y): return y + 1"),
        ("def foo(x): return x + 1", "def foo(x): return x * 2 + 1"),
        ("def foo(x): return x + 1", "class Bar: pass"),
        ("", ""),
        ("def f(x):  return   x+1", "def f(x): return x+1"),
        (
            "def process(data):\n    result = []\n    for item in data:\n        if item > 0:\n            result.append(item * 2)\n    return result",
            "def transform(values):\n    output = []\n    for val in values:\n        if val > 0:\n            output.append(val * 2)\n    return output",
        ),
        ("café = 'hello'", "cafe = 'hello'"),
        ("x = 100\ny = 200\nz = x + y", "a = 999\nb = 888\nc = a + b"),
        ("abcdefghij", "abcdefghik"),
        ("aaaaaaaaaa", "zzzzzzzzzz"),
        ("hello world", ""),
        (
            "class Foo:\n    def bar(self):\n        return 42\n",
            "class Baz:\n    def qux(self):\n        return 42\n",
        ),
    ]

    @pytest.mark.parametrize("a,b", PAIRS)
    def test_similarity_exact_match(self, a, b):
        py_val = _py_similarity(a, b)
        rs_val = compute_similarity(a, b)
        assert py_val == rs_val, (
            f"Similarity drift!\n  a={a!r}\n  b={b!r}\n  Python={py_val}\n  Rust={rs_val}"
        )

    def test_similarity_symmetry(self):
        for a, b in self.PAIRS:
            py_ab = _py_similarity(a, b)
            py_ba = _py_similarity(b, a)
            rs_ab = compute_similarity(a, b)
            rs_ba = compute_similarity(b, a)
            assert py_ab == py_ba
            assert rs_ab == rs_ba
            assert py_ab == rs_ab

    def test_similarity_on_real_code_fragments(self):
        lines = []
        for f in _REAL_FILES[:10]:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                file_lines = [l for l in content.splitlines() if l.strip()]
                lines.extend(file_lines[:20])
            except Exception:
                continue

        import random

        random.seed(42)
        pairs = [(random.choice(lines), random.choice(lines)) for _ in range(100)]

        for a, b in pairs:
            py_val = _py_similarity(a, b)
            rs_val = compute_similarity(a, b)
            assert py_val == rs_val, (
                f"Real code drift!\n  a={a!r}\n  b={b!r}\n  Python={py_val}\n  Rust={rs_val}"
            )


class TestFileDiscoveryParity:
    EXCLUDES = [
        "__pycache__",
        ".git",
        ".tox",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        "node_modules",
        ".venv",
        "venv",
        ".eggs",
    ]

    def test_python_files_match(self):
        root = str(SKYLOS_PKG)
        rs_files = set(discover_files(root, ["py"], self.EXCLUDES))
        py_files = _py_discover(root, ["py"], self.EXCLUDES)
        assert rs_files == py_files, (
            f"File discovery drift!\n"
            f"  Rust-only ({len(rs_files - py_files)}): {sorted(rs_files - py_files)[:5]}\n"
            f"  Python-only ({len(py_files - rs_files)}): {sorted(py_files - rs_files)[:5]}"
        )

    def test_multi_extension_match(self):
        root = str(SKYLOS_PKG)
        exts = ["py", "go", "ts", "tsx"]
        rs_files = set(discover_files(root, exts, self.EXCLUDES))
        py_files = _py_discover(root, exts, self.EXCLUDES)
        assert rs_files == py_files

    def test_empty_directory(self, tmp_path):
        rs = discover_files(str(tmp_path), ["py"], [])
        py = _py_discover(str(tmp_path), ["py"], [])
        assert set(rs) == py == set()

    def test_single_file_directory(self, tmp_path):
        (tmp_path / "hello.py").write_text("x = 1")
        (tmp_path / "readme.md").write_text("# hi")
        rs = set(discover_files(str(tmp_path), ["py"], []))
        py = _py_discover(str(tmp_path), ["py"], [])
        assert rs == py

    def test_nested_excludes(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1")
        (tmp_path / "src" / "__pycache__").mkdir()
        (tmp_path / "src" / "__pycache__" / "app.cpython-313.pyc").write_text("")
        (tmp_path / "venv").mkdir()
        (tmp_path / "venv" / "lib.py").write_text("y = 2")

        excludes = ["__pycache__", "venv"]
        rs = set(discover_files(str(tmp_path), ["py"], excludes))
        py = _py_discover(str(tmp_path), ["py"], excludes)
        assert rs == py
        assert len(rs) == 1


class TestCycleDetectionParity:
    CASES = [
        ("triangle", [("a", "b"), ("b", "c"), ("c", "a")], ["a", "b", "c"]),
        (
            "two_pairs",
            [("a", "b"), ("b", "a"), ("c", "d"), ("d", "c")],
            ["a", "b", "c", "d"],
        ),
        ("no_cycle", [("a", "b"), ("b", "c")], ["a", "b", "c"]),
        ("self_loop", [("a", "a")], ["a"]),
        (
            "diamond_back",
            [("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("d", "a")],
            ["a", "b", "c", "d"],
        ),
        (
            "chain",
            [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("e", "a")],
            ["a", "b", "c", "d", "e"],
        ),
        ("isolated", [("a", "b"), ("b", "a")], ["a", "b", "c"]),
        ("empty", [], ["a", "b"]),
        (
            "complex",
            [("x", "y"), ("y", "z"), ("z", "x"), ("z", "w"), ("w", "y")],
            ["w", "x", "y", "z"],
        ),
    ]

    @pytest.mark.parametrize("name,edges,modules", CASES, ids=[c[0] for c in CASES])
    def test_same_cycles_found(self, name, edges, modules):
        py_cycles = _py_find_cycles(edges, modules)
        rs_cycles = find_cycles(edges, modules)

        py_set = {tuple(sorted(c)) for c in py_cycles}
        rs_set = {tuple(sorted(c)) for c in rs_cycles}

        assert py_set == rs_set, (
            f"Cycle drift in '{name}'!\n"
            f"  Python: {py_cycles}\n"
            f"  Rust:   {rs_cycles}\n"
            f"  PY-only: {py_set - rs_set}\n"
            f"  RS-only: {rs_set - py_set}"
        )

    @pytest.mark.parametrize("name,edges,modules", CASES, ids=[c[0] for c in CASES])
    def test_same_cycle_count(self, name, edges, modules):
        py_cycles = _py_find_cycles(edges, modules)
        rs_cycles = find_cycles(edges, modules)
        assert len(py_cycles) == len(rs_cycles), (
            f"Cycle count drift in '{name}': PY={len(py_cycles)} RS={len(rs_cycles)}"
        )

    @pytest.mark.parametrize("name,edges,modules", CASES, ids=[c[0] for c in CASES])
    def test_cycle_normalization(self, name, edges, modules):
        rs_cycles = find_cycles(edges, modules)
        for cycle in rs_cycles:
            if len(cycle) > 1:
                assert cycle[0] == min(cycle), (
                    f"Rust cycle not normalized: {cycle} (min={min(cycle)})"
                )

        py_cycles = _py_find_cycles(edges, modules)
        for cycle in py_cycles:
            if len(cycle) > 1:
                assert cycle[0] == min(cycle), (
                    f"Python cycle not normalized: {cycle} (min={min(cycle)})"
                )


class TestCouplingParity:
    SYNTHETIC_SOURCES = {
        "basic_inheritance": """
class Animal:
    name: str

class Dog(Animal):
    owner: str

    def bark(self) -> str:
        return "woof"
""",
        "type_hints_and_instantiation": """
from typing import List, Optional

class Config:
    debug: bool

class Logger:
    config: Config

    def log(self, msg: str) -> None:
        c = Config()
        print(msg, c)

class App:
    logger: Logger
    config: Config

    def run(self) -> None:
        self.logger.log("started")
""",
        "protocol_and_abc": """
from abc import ABC, abstractmethod
from typing import Protocol

class Drawable(Protocol):
    def draw(self) -> None: ...

class Shape(ABC):
    @abstractmethod
    def area(self) -> float: ...

class Circle(Shape, Drawable):
    radius: float

    def area(self) -> float:
        return 3.14 * self.radius ** 2

    def draw(self) -> None:
        print("circle")
""",
        "dataclass": """
from dataclasses import dataclass

@dataclass
class Point:
    x: float
    y: float

@dataclass
class Line:
    start: Point
    end: Point

    def length(self) -> float:
        return ((self.end.x - self.start.x) ** 2) ** 0.5
""",
        "decorator_deps": """
class Validator:
    pass

class Serializer:
    @Validator
    def serialize(self, data):
        return str(data)
""",
        "attribute_access": """
class Database:
    def query(self, sql: str):
        return []

class Repository:
    db: Database

    def find_all(self):
        return Database.query("SELECT *")
""",
        "no_classes": """
def hello():
    return "world"

x = 42
""",
        "single_class": """
class Lonely:
    def method(self):
        pass
""",
        "nested_types": """
from typing import Dict, List, Optional, Union

class Error:
    message: str

class Result:
    data: Optional[Dict[str, List[Error]]]
    status: Union[str, int]
""",
    }

    @pytest.mark.parametrize("name", sorted(SYNTHETIC_SOURCES.keys()))
    def test_synthetic_parity(self, name):
        source = self.SYNTHETIC_SOURCES[name]
        tree = ast.parse(source)
        py_result = py_analyze_coupling(tree, f"{name}.py")
        rs_result = fast_analyze_coupling(source, f"{name}.py")

        diffs = _compare_coupling_dicts(py_result, rs_result, label=name)
        assert not diffs, f"Coupling drift in '{name}':\n" + "\n".join(
            f"  {d}" for d in diffs
        )

    def test_real_codebase_files(self):
        files_with_classes = []
        for f in _REAL_FILES:
            try:
                source = f.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)
                classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
                if len(classes) >= 2:
                    files_with_classes.append(f)
            except Exception:
                continue

        assert len(files_with_classes) > 0, "No files with classes found"

        all_diffs = []
        for f in files_with_classes[:20]:
            source = f.read_text(encoding="utf-8", errors="ignore")
            try:
                tree = ast.parse(source)
                py_result = py_analyze_coupling(tree, str(f))
                rs_result = fast_analyze_coupling(source, str(f))
                diffs = _compare_coupling_dicts(py_result, rs_result, label=f.name)
                all_diffs.extend(diffs)
            except SyntaxError:
                continue

        assert not all_diffs, (
            f"Coupling drift on real files ({len(all_diffs)} diffs):\n"
            + "\n".join(f"  {d}" for d in all_diffs[:20])
        )


class TestEndToEndParity:
    def test_dead_code_findings_match(self):
        result_rust, result_py = _run_dead_code_parity_scans_in_subprocess(SKYLOS_PKG)

        def _finding_set(result, key):
            return {f"{f['file']}:{f['name']}:{f['line']}" for f in result.get(key, [])}

        rust_funcs = _finding_set(result_rust, "unused_functions")
        py_funcs = _finding_set(result_py, "unused_functions")
        assert rust_funcs == py_funcs, (
            f"Unused functions drift!\n"
            f"  Rust-only ({len(rust_funcs - py_funcs)}): {sorted(rust_funcs - py_funcs)[:5]}\n"
            f"  Python-only ({len(py_funcs - rust_funcs)}): {sorted(py_funcs - rust_funcs)[:5]}"
        )

        rust_classes = _finding_set(result_rust, "unused_classes")
        py_classes = _finding_set(result_py, "unused_classes")
        assert rust_classes == py_classes, (
            f"Unused classes drift!\n"
            f"  Rust-only ({len(rust_classes - py_classes)}): {sorted(rust_classes - py_classes)[:5]}\n"
            f"  Python-only ({len(py_classes - rust_classes)}): {sorted(py_classes - rust_classes)[:5]}"
        )

        rust_imports = _finding_set(result_rust, "unused_imports")
        py_imports = _finding_set(result_py, "unused_imports")
        assert rust_imports == py_imports, (
            f"Unused imports drift!\n"
            f"  Rust-only ({len(rust_imports - py_imports)}): {sorted(rust_imports - py_imports)[:5]}\n"
            f"  Python-only ({len(py_imports - rust_imports)}): {sorted(py_imports - rust_imports)[:5]}"
        )
