"""Path construction is evidence of a load only until its consumer is disproved.

All fixtures are statically scanned and never imported or executed.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


def scan(root, *, provider="module.exports = { run() {} };", extra=""):
    files = {
        "package.json": '{"private":true,"main":"index.js"}',
        "index.js": 'const path = require("node:path");\n'
        'const shared = require(path.join(__dirname, "lib", "shared.js"));\n'
        'const input = path.join(__dirname, "tools", "input.ts");\n'
        'const entry = path.resolve(__dirname, "src", "bundle.ts");\n'
        + extra
        + "\nshared.run(input, entry);\n",
        "lib/shared.js": provider,
        "tools/input.ts": 'console.log("input");',
        "src/bundle.ts": 'console.log("bundle");',
        "src/orphan.ts": 'console.log("orphan");',
    }
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    report = json.loads(analyze(str(root), conf=0, grep_verify=False))
    dead = {
        Path(f["file"]).relative_to(root).as_posix()
        for f in report.get("unused_files", [])
    }
    return report, dead


def test_paths_passed_only_to_source_proven_empty_method_do_not_load_files(tmp_path):
    _, dead = scan(tmp_path)
    assert {"tools/input.ts", "src/bundle.ts", "src/orphan.ts"} <= dead
    assert "lib/shared.js" not in dead  # require(path.join(...)) really loads it


@pytest.mark.parametrize(
    "provider",
    [
        "module.exports = { run(file) { return require(file); } };",
        'module.exports = require("external-loader");',
        'module.exports = { run(file = require("../tools/input.ts")) {} };',
    ],
)
def test_real_or_unknown_consumers_preserve_path_targets(tmp_path, provider):
    _, dead = scan(tmp_path, provider=provider)
    assert "tools/input.ts" not in dead
    assert "src/bundle.ts" not in dead
    assert "src/orphan.ts" in dead


@pytest.mark.parametrize(
    "extra",
    [
        "shared.run = externalLoader;",
        "configure(shared);",
        "const escaped = shared;",
        "const escapedPath = input; useUnknown(escapedPath);",
        "function inspect(shared) { return shared.run(input); }",
    ],
)
def test_mutated_escaped_or_shadowed_proof_keeps_conservative_paths(tmp_path, extra):
    _, dead = scan(tmp_path, extra=extra)
    assert "tools/input.ts" not in dead
    assert "src/orphan.ts" in dead


def test_unused_and_directly_ignored_path_values_do_not_create_file_edges(tmp_path):
    files = {
        "package.json": '{"private":true,"main":"index.js"}',
        "index.js": 'const path = require("node:path");\n'
        "function discard(value) {}\n"
        'discard(path.join(__dirname, "ignored.js"));\n'
        'const unusedPath = path.resolve(__dirname, "unread.js");\n'
        'external(path.join(__dirname, "opaque.js"));\n',
        "ignored.js": 'console.log("ignored");',
        "unread.js": 'console.log("unread");',
        "opaque.js": 'console.log("opaque");',
    }
    for name, source in files.items():
        (tmp_path / name).write_text(source)
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    dead = {Path(f["file"]).name for f in report.get("unused_files", [])}
    assert {"ignored.js", "unread.js"} <= dead
    assert "opaque.js" not in dead


@pytest.mark.parametrize(
    "extra",
    [
        'require("external-patcher");',
        "const pathAlias = path; configure(pathAlias);",
        "path.join = loadAndReturnPath;",
        'function shadow(path) { return path.join("tools", "input.ts"); }',
    ],
)
def test_opaque_dependencies_or_unstable_path_provider_preserve_targets(
    tmp_path, extra
):
    _, dead = scan(tmp_path, extra=extra)
    assert "tools/input.ts" not in dead
    assert "src/bundle.ts" not in dead


def test_other_module_can_replace_an_empty_export_through_its_own_alias(tmp_path):
    (tmp_path / "patch.js").write_text(
        'const shared = require("./lib/shared.js"); shared.run = externalLoader;'
    )
    _, dead = scan(tmp_path, extra='require("./patch.js");')
    assert "tools/input.ts" not in dead
    assert "src/bundle.ts" not in dead


@pytest.mark.parametrize(
    "patch",
    [
        'require("external-path-patcher");',
        'require("./patch-path.js");',
        'const execute = eval; execute("patch native provider");',
    ],
)
def test_local_empty_consumer_also_requires_stable_dependency_effects(tmp_path, patch):
    (tmp_path / "package.json").write_text('{"private":true,"main":"index.js"}')
    (tmp_path / "index.js").write_text(
        patch + '\nconst path = require("node:path");\n'
        "function discard(value) {}\n"
        'discard(path.join(__dirname, "feature.js"));\n'
    )
    (tmp_path / "patch-path.js").write_text(
        'require("node:path").join = unknownLoader;'
    )
    (tmp_path / "feature.js").write_text('console.log("feature");')
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    dead = {Path(f["file"]).name for f in report.get("unused_files", [])}
    assert "feature.js" not in dead
