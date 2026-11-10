"""Source-backed consumers that do not use ordinary module imports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.rules.quality import unused_deps
from skylos.visitors.languages.typescript.file_references import _shell_load_paths


def _write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scan(root):
    result = json.loads(
        analyze(
            str(root),
            conf=60,
            grep_verify=False,
            enable_dependency_hallucinations=False,
            trace_file=False,
        )
    )
    assert not result.get("analysis_errors")
    return result


@pytest.mark.parametrize(
    "command",
    [
        "npx tsx src/run.ts argument.ts",
        "npx --yes tsx src/run.ts",
        "npx --no-install ts-node --project tsconfig.json src/run.ts",
        "npx --package=tsx tsx src/run.ts",
    ],
)
def test_npx_known_runtime_has_one_script_operand(command):
    assert list(_shell_load_paths(command)) == ["src/run.ts"]


@pytest.mark.parametrize(
    "command",
    [
        "echo npx tsx src/dead.ts",
        "npx arbitrary-tool src/dead.ts",
        "npx --package=unrelated tsx src/dead.ts",
        "npx --unknown tsx src/dead.ts",
        "npx tsx --eval 'require(\"./src/dead.ts\")'",
    ],
)
def test_npx_prose_unknown_package_or_eval_is_not_script_evidence(command):
    assert list(_shell_load_paths(command)) == []


def test_shell_runtime_root_preserves_real_entry_and_reports_orphan(tmp_path):
    _write(tmp_path, "run.sh", "npx tsx src/simulator.ts --mode test\n")
    _write(tmp_path, "src/simulator.ts", "console.log('simulation'); export {};\n")
    _write(tmp_path, "src/orphan.ts", "console.log('retired'); export {};\n")
    report = _scan(tmp_path)
    dead = {Path(row["file"]).name for row in report.get("unused_files", [])}
    assert "simulator.ts" not in dead
    assert "orphan.ts" in dead


def _exercise_sources(root, loader):
    _write(root, "package.json", '{"dependencies":{"next":"15.0.0"}}')
    _write(
        root,
        "app/page.tsx",
        "import { getExercise } from '../lib/exercises';\n"
        "export default async function Page() { return getExercise('one'); }\n",
    )
    _write(root, "lib/exercises.ts", loader)
    for name in ("starter", "tests", "solution", "orphan"):
        _write(
            root,
            f"content/exercises/one/{name}.js",
            f"export function {name}() {{ return '{name}'; }}\n",
        )
    _write(root, "other/exercises/one/solution.js", "export function unrelated() {}\n")


LOADER = """import fs from "node:fs/promises";
import path from "node:path";
const ROOT = path.join(process.cwd(), "content", "exercises");
const EXT = { vanilla: "js", typed: "ts" };
export async function getExercise(slug: string) {
  const dir = path.join(ROOT, slug);
  const ext = EXT["vanilla"];
  const [starter, solution, tests] = await Promise.all([
    fs.readFile(path.join(dir, `starter.${ext}`), "utf8"),
    fs.readFile(path.join(dir, `solution.${ext}`), "utf8"),
    fs.readFile(path.join(dir, `tests.${ext}`), "utf8"),
  ]);
  return { starter, solution, tests };
}
"""


def test_live_node_source_reads_keep_only_exact_assets_and_public_exports(tmp_path):
    _exercise_sources(tmp_path, LOADER)
    _write(
        tmp_path,
        "content/exercises/one/solution.ts",
        "export function unselected() {}\n",
    )
    report = _scan(tmp_path)
    dead = {
        Path(row["file"]).relative_to(tmp_path).as_posix()
        for row in report.get("unused_files", [])
    }
    assert (
        not {
            f"content/exercises/one/{name}.js"
            for name in ("starter", "tests", "solution")
        }
        & dead
    )
    assert "content/exercises/one/orphan.js" in dead
    assert "other/exercises/one/solution.js" in dead
    assert "content/exercises/one/solution.ts" in dead
    unused = {
        row["name"].rsplit(".", 1)[-1] for row in report.get("unused_functions", [])
    }
    assert not {"starter", "solution", "tests"} & unused
    assert "orphan" in unused
    assert "unrelated" in unused
    assert "unselected" in unused


@pytest.mark.parametrize(
    "replace",
    [
        ("node:fs/promises", "./fake-fs"),
        (
            "export async function getExercise(slug: string)",
            "export async function getExercise(slug: string, fs: any)",
        ),
        (
            "const dir = path.join(ROOT, slug);",
            "const dir = path.join(ROOT, slug); fs.readFile = fake;",
        ),
        (
            "const dir = path.join(ROOT, slug);",
            "const dir = path.join(ROOT, slug); configure(fs);",
        ),
    ],
)
def test_unproved_filesystem_provider_does_not_rescue_assets(tmp_path, replace):
    _exercise_sources(tmp_path, LOADER.replace(*replace))
    report = _scan(tmp_path)
    dead = {Path(row["file"]).name for row in report.get("unused_files", [])}
    assert {"starter.js", "tests.js", "solution.js", "orphan.js"} <= dead


def test_source_read_in_uncalled_owner_does_not_rescue_assets(tmp_path):
    _exercise_sources(tmp_path, LOADER.replace("getExercise", "retiredLoader"))
    report = _scan(tmp_path)
    dead = {Path(row["file"]).name for row in report.get("unused_files", [])}
    assert {"starter.js", "tests.js", "solution.js", "orphan.js"} <= dead


def test_unused_import_of_reader_is_not_a_live_source_consumer(tmp_path):
    _exercise_sources(tmp_path, LOADER)
    _write(
        tmp_path,
        "app/page.tsx",
        "import { getExercise } from '../lib/exercises';\n"
        "export default function Page() { return 'hello'; }\n",
    )
    report = _scan(tmp_path)
    dead = {Path(row["file"]).name for row in report.get("unused_files", [])}
    assert {"starter.js", "tests.js", "solution.js", "orphan.js"} <= dead


@pytest.mark.parametrize(
    "replacement",
    [
        "const alias = fs; alias.readFile = fake;",
        'const alias = EXT; alias.vanilla = "jsx";',
        'EXT.vanilla = "jsx";',
        'process.chdir("other");',
        "configure(path);",
    ],
)
def test_source_reader_dependency_mutation_does_not_invent_loads(tmp_path, replacement):
    _exercise_sources(
        tmp_path,
        LOADER.replace(
            "const dir = path.join(ROOT, slug);",
            "const dir = path.join(ROOT, slug); " + replacement,
        ),
    )
    report = _scan(tmp_path)
    dead = {Path(row["file"]).name for row in report.get("unused_files", [])}
    assert {"starter.js", "tests.js", "solution.js", "orphan.js"} <= dead


@pytest.mark.parametrize(
    "body",
    [
        'return null;\n  const text = await fs.readFile(path.join(ROOT, slug, "solution.js"), "utf8");',
        'if (false) { return fs.readFile(path.join(ROOT, slug, "solution.js"), "utf8"); }',
        'while (false) { return fs.readFile(path.join(ROOT, slug, "solution.js"), "utf8"); }',
        'for (;;) { break; return fs.readFile(path.join(ROOT, slug, "solution.js"), "utf8"); }',
        'for (;;) { continue; return fs.readFile(path.join(ROOT, slug, "solution.js"), "utf8"); }',
    ],
)
def test_unreachable_source_read_does_not_rescue_assets(tmp_path, body):
    source = LOADER[: LOADER.index("  const dir =")]
    _exercise_sources(tmp_path, source + "  " + body + "\n}\n")
    report = _scan(tmp_path)
    dead = {Path(row["file"]).name for row in report.get("unused_files", [])}
    assert "solution.js" in dead


def test_conditional_jump_still_allows_reachable_source_read(tmp_path):
    source = LOADER[: LOADER.index("  const dir =")]
    body = 'for (let i = 0; i < 2; i++) { if (i === 0) continue; return fs.readFile(path.join(ROOT, slug, "solution.js"), "utf8"); }'
    _exercise_sources(tmp_path, source + "  " + body + "\n}\n")
    report = _scan(tmp_path)
    dead = {
        Path(row["file"]).relative_to(tmp_path).as_posix()
        for row in report.get("unused_files", [])
    }
    assert "content/exercises/one/solution.js" not in dead
    assert "content/exercises/one/orphan.js" in dead


def _dependency_scan(root, source):
    _write(root, "requirements.txt", "backend-engine\nretired-package\n")
    path = _write(root, "verify.py", source)
    return {row["name"] for row in unused_deps.scan_unused_dependencies(root, [path])}


def test_finite_native_find_spec_list_counts_dependency_exposure(tmp_path, monkeypatch):
    monkeypatch.setattr(unused_deps, "_build_import_to_dist", lambda: {})
    monkeypatch.setattr(unused_deps, "_load_import_to_dist", lambda: {})
    source = """import importlib.util
def check_dependencies():
    modules = ["backend_engine"]
    for module in modules:
        if importlib.util.find_spec(module):
            print("available")
check_dependencies()
"""
    assert _dependency_scan(tmp_path, source) == {"retired-package"}


@pytest.mark.parametrize(
    "source",
    [
        "class Fake:\n    def find_spec(self, name): pass\n"
        'fake = Fake()\nfake.find_spec("backend_engine")\n',
        "import importlib.util\nimportlib.util.find_spec = fake\n"
        'importlib.util.find_spec("backend_engine")\n',
        "import importlib.util\ndef check(importlib):\n"
        '    return importlib.util.find_spec("backend_engine")\n',
        "import importlib.util\ndef check():\n"
        '    modules = ["backend_engine"]\n    modules = ["different"]\n'
        "    for module in modules:\n        importlib.util.find_spec(module)\n",
        "import importlib.util\ndef check():\n"
        '    modules = ["backend_engine"]\n    modules.append("different")\n'
        "    for module in modules:\n        importlib.util.find_spec(module)\n",
        "import importlib.util\nfinder = importlib.util\n"
        'finder.find_spec = fake\nimportlib.util.find_spec("backend_engine")\n',
        "import importlib.util\nconfigure(provider=importlib.util)\n"
        'importlib.util.find_spec("backend_engine")\n',
        "import importlib.util\nproviders = {'finder': importlib.util}\nconfigure(providers)\n"
        'importlib.util.find_spec("backend_engine")\n',
        'import importlib.util\nprobe = lambda *importlib: importlib.util.find_spec("backend_engine")\n',
        'import importlib.util\nprobe = lambda **importlib: importlib.util.find_spec("backend_engine")\n',
    ],
)
def test_find_spec_lookalikes_or_rebound_values_do_not_credit_dependency(
    tmp_path, monkeypatch, source
):
    monkeypatch.setattr(unused_deps, "_build_import_to_dist", lambda: {})
    monkeypatch.setattr(unused_deps, "_load_import_to_dist", lambda: {})
    assert "backend-engine" in _dependency_scan(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        'from importlib.util import find_spec as locate\nlocate("backend_engine")\n',
        'from importlib import util as finder\nfinder.find_spec(name="backend_engine")\n',
        'import importlib.util as finder\nfinder.find_spec("backend_engine")\n',
    ],
)
def test_native_finder_aliases_keep_exact_dependency_only(
    tmp_path, monkeypatch, source
):
    monkeypatch.setattr(unused_deps, "_build_import_to_dist", lambda: {})
    monkeypatch.setattr(unused_deps, "_load_import_to_dist", lambda: {})
    assert _dependency_scan(tmp_path, source) == {"retired-package"}


def test_local_importlib_lookalike_is_not_native_dependency_exposure(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(unused_deps, "_build_import_to_dist", lambda: {})
    monkeypatch.setattr(unused_deps, "_load_import_to_dist", lambda: {})
    _write(tmp_path, "importlib.py", "util = object()\n")
    findings = _dependency_scan(
        tmp_path, 'import importlib.util\nimportlib.util.find_spec("backend_engine")\n'
    )
    assert findings == {"backend-engine", "retired-package"}


@pytest.mark.parametrize(
    "declaration, loaded",
    [
        (
            'class Retired { source = fs.readFileSync(path.join(process.cwd(), "asset.ts"), "utf8"); }',
            False,
        ),
        (
            'class Active { static source = fs.readFileSync(path.join(process.cwd(), "asset.ts"), "utf8"); }',
            True,
        ),
        (
            'const source = fs.readFileSync(path.join(process.cwd(), "asset.ts"), "utf8");',
            True,
        ),
    ],
)
def test_source_read_class_fields_require_eager_execution(
    tmp_path, declaration, loaded
):
    _write(
        tmp_path,
        "index.ts",
        'import fs from "node:fs";\nimport path from "node:path";\n'
        + declaration
        + "\nexport const value = 1;\n",
    )
    _write(tmp_path, "asset.ts", "export function payload() { return 1; }\n")
    report = _scan(tmp_path)
    dead = {Path(row["file"]).name for row in report.get("unused_files", [])}
    assert ("asset.ts" not in dead) is loaded
