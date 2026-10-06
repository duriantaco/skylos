import json
import os

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript.core import TypeScriptCore
from skylos.visitors.languages.typescript.quality import scan_quality


def _write_fixture(root, filename, source):
    root = root.resolve()
    path = root / filename
    path.resolve().relative_to(root)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(source)
    return path


def _write_source(root, suffix, source):
    return _write_fixture(root, f"entry{suffix}", source)


@pytest.mark.parametrize("suffix", [".ts", ".js", ".tsx", ".jsx"])
@pytest.mark.parametrize(
    "read",
    [
        "if (usedFlag) console.log(1);",
        "while (usedFlag) { break; }",
        "do { break; } while (usedFlag);",
        "for (; usedFlag;) { break; }",
        "console.log(usedFlag ? 1 : 2);",
        "switch (usedFlag) { default: break; }",
        "console.log((usedFlag));",
    ],
)
def test_condition_and_parenthesized_reads_keep_only_used_variable(
    tmp_path, suffix, read
):
    source = "const usedFlag = true; const unusedFlag = true;\n" + read
    path = _write_source(tmp_path, suffix, source)
    result = json.loads(analyze(str(path), conf=0, grep_verify=False))

    unused = {item["name"] for item in result.get("unused_variables", [])}
    assert "usedFlag" not in unused
    assert "unusedFlag" in unused


@pytest.mark.parametrize("suffix", [".ts", ".js"])
@pytest.mark.parametrize(
    "read",
    [
        'job["tick"]();',
        "job['tick']();",
        'job?.["tick"]();',
        'console.log(job["tick"]);',
    ],
)
def test_literal_bracket_member_reads_keep_only_referenced_method(
    tmp_path, suffix, read
):
    path = _write_source(
        tmp_path,
        suffix,
        "class Jobs { tick() { return 1; } unused() { return 0; } }\n"
        "const job = new Jobs();\n" + read,
    )
    result = json.loads(analyze(str(path), conf=0, grep_verify=False))

    unused = {item["name"] for item in result.get("unused_functions", [])}
    assert "Jobs.tick" not in unused
    assert "Jobs.unused" in unused


def test_ordinary_string_does_not_rescue_method(tmp_path):
    path = _write_source(
        tmp_path,
        ".ts",
        "class Jobs { tick() { return 1; } }\n"
        'const job = new Jobs(); console.log(job, "tick");\n',
    )
    result = json.loads(analyze(str(path), conf=0, grep_verify=False))
    unused = {item["name"] for item in result.get("unused_functions", [])}
    assert "Jobs.tick" in unused


def _unreachable_findings(source, suffix=".ts"):
    core = TypeScriptCore(f"entry{suffix}", source.encode())
    assert core.root_node is not None and not core.root_node.has_error
    return [
        finding
        for finding in scan_quality(
            core.root_node, core.source, core.file_path, lang=core.lang
        )
        if finding["rule_id"] == "SKY-UC002"
    ]


@pytest.mark.parametrize("suffix", [".ts", ".js"])
@pytest.mark.parametrize(
    "helper",
    [
        "function helper() { return 1; }",
        "async function helper() { return 1; }",
        "function* helper() { yield 1; }",
    ],
)
def test_hoisted_helpers_after_return_are_not_unreachable_statements(suffix, helper):
    # TypeScript v5.9.3 program.ts returns a program object before declaring
    # getResolvedModule and its other helpers. Declarations are hoisted.
    source = f"function run() {{\n  return helper();\n  {helper}\n}}\nrun();\n"
    assert _unreachable_findings(source, suffix) == []


@pytest.mark.parametrize(
    "declaration",
    ["type Result = number;", "interface Result { value: number; }"],
)
def test_erased_type_declarations_after_return_are_not_unreachable(declaration):
    assert (
        _unreachable_findings(f"function run() {{\n  return 1;\n  {declaration}\n}}\n")
        == []
    )


@pytest.mark.parametrize("suffix", [".ts", ".js"])
@pytest.mark.parametrize("declaration", ["var value;", "var value, other;"])
def test_hoisted_uninitialized_var_after_return_is_not_unreachable(suffix, declaration):
    assert (
        _unreachable_findings(
            f"function run() {{\n  return value;\n  {declaration}\n}}\n", suffix
        )
        == []
    )


@pytest.mark.parametrize(
    "statement",
    [
        'console.log("unreachable");',
        "const result = helper();",
        "var result = helper();",
        "let result;",
        "class Result {}",
        "enum Result { Success }",
    ],
)
def test_real_unreachable_statement_after_hoisted_helper_remains_reported(statement):
    findings = _unreachable_findings(
        "function run() {\n  return helper();\n"
        "  function helper() { return 1; }\n"
        f"  {statement}\n}}\n"
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 4


def test_unreachable_code_inside_hoisted_helper_remains_reported():
    findings = _unreachable_findings(
        "function run() {\n  return helper();\n"
        "  function helper() {\n    return 1;\n    console.log(2);\n  }\n}\n"
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 5


def test_empty_statement_does_not_hide_real_unreachable_call():
    findings = _unreachable_findings(
        "function run() {\n  return 1;\n  ;\n  console.log(2);\n}\n"
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 4


def _package_test_files(tmp_path, package, paths):
    _write_fixture(tmp_path, "package.json", json.dumps(package))
    files = []
    for filename in paths:
        parent = tmp_path / os.path.dirname(filename)
        parent.mkdir(parents=True, exist_ok=True)
        source = (
            "export default 1;\n" if filename == "index.js" else "console.log(1);\n"
        )
        if filename.endswith(".d.ts"):
            source = "export declare const value: number;\n"
        files.append(str(_write_fixture(tmp_path, filename, source)))
    return files


def _dead_test_files(tmp_path, files):
    from skylos.visitors.languages.typescript.analysis import find_dead_ts_files

    return {
        os.path.relpath(finding["file"], tmp_path)
        for finding in find_dead_ts_files(files, [], {}, {}, project_root=str(tmp_path))
    }


@pytest.mark.parametrize("command", ["ava", "xo && ava", "npx ava", "env CI=1 ava"])
def test_ava_default_test_entry_is_grounded_in_active_package_runner(tmp_path, command):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": command},
            "devDependencies": {"ava": "^6.4.1"},
        },
        ["index.js", "test.js", "orphan.js"],
    )
    dead = _dead_test_files(tmp_path, files)
    assert "test.js" not in dead
    assert "orphan.js" in dead


@pytest.mark.parametrize(
    "tool,test_file", [("ava", "test.js"), ("tsd", "index.test-d.ts")]
)
@pytest.mark.parametrize("missing", ["dependency", "command"])
def test_test_runner_names_alone_do_not_create_entrypoints(
    tmp_path, tool, test_file, missing
):
    package = {
        "main": "index.js",
        "scripts": {"test": tool},
        "devDependencies": {tool: "*"},
    }
    package.pop("devDependencies" if missing == "dependency" else "scripts")
    files = _package_test_files(
        tmp_path, package, ["index.js", "index.d.ts", test_file]
    )
    assert test_file in _dead_test_files(tmp_path, files)


def test_ava_package_patterns_replace_defaults_and_keep_excluded_files_dead(tmp_path):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": "ava"},
            "devDependencies": {"ava": "*"},
            "ava": {"files": ["checks/*.js", "!checks/excluded.js"]},
        },
        [
            "index.js",
            "test.js",
            "checks/live.js",
            "checks/excluded.js",
            "checks/nested/dead.js",
        ],
    )
    dead = _dead_test_files(tmp_path, files)
    assert "checks/live.js" not in dead
    assert {"test.js", "checks/excluded.js", "checks/nested/dead.js"} <= dead


def test_ava_external_configuration_does_not_invent_default_test_roots(tmp_path):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": "ava"},
            "devDependencies": {"ava": "*"},
        },
        ["index.js", "test.js"],
    )
    _write_fixture(
        tmp_path, "ava.config.mjs", "export default {files: dynamicFiles()};\n"
    )
    assert "test.js" in _dead_test_files(tmp_path, files)


def test_ava_unsupported_extension_does_not_create_test_root(tmp_path):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": "ava"},
            "devDependencies": {"ava": "*"},
        },
        ["index.js", "test.js", "source/test.ts"],
    )
    dead = _dead_test_files(tmp_path, files)
    assert "test.js" not in dead
    assert "source/test.ts" in dead


@pytest.mark.parametrize(
    "tool,test_file", [("ava", "test.js"), ("tsd", "index.test-d.ts")]
)
def test_runner_after_changing_directory_does_not_rescue_package_default(
    tmp_path, tool, test_file
):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": f"cd elsewhere && {tool}"},
            "devDependencies": {tool: "*"},
        },
        ["index.js", "index.d.ts", test_file],
    )
    assert test_file in _dead_test_files(tmp_path, files)


@pytest.mark.parametrize("files_config", [None, [], 1, ["{a,b}.js"], ["!@(all)"]])
def test_unknown_ava_file_configuration_does_not_crash_or_invent_roots(
    tmp_path, files_config
):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": "ava"},
            "devDependencies": {"ava": "*"},
            "ava": {"files": files_config},
        },
        ["index.js", "test.js"],
    )
    assert "test.js" in _dead_test_files(tmp_path, files)


def test_tsd_default_corresponding_type_test_does_not_rescue_unrelated_file(tmp_path):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": "xo && ava && tsd"},
            "devDependencies": {"tsd": "^0.33.0"},
        },
        [
            "index.js",
            "index.d.ts",
            "index.test-d.ts",
            "other.test-d.ts",
            "type-checks/other.ts",
        ],
    )
    dead = _dead_test_files(tmp_path, files)
    assert "index.test-d.ts" not in dead
    assert {"other.test-d.ts", "type-checks/other.ts"} <= dead


def test_tsd_configured_directory_is_only_used_as_fallback(tmp_path):
    files = _package_test_files(
        tmp_path,
        {
            "main": "index.js",
            "scripts": {"test": "tsd"},
            "devDependencies": {"tsd": "*"},
            "tsd": {"directory": "type-checks"},
        },
        [
            "index.js",
            "index.d.ts",
            "type-checks/live.ts",
            "type-checks/live.tsx",
            "orphan.ts",
        ],
    )
    dead = _dead_test_files(tmp_path, files)
    assert "type-checks/live.ts" not in dead
    assert "type-checks/live.tsx" not in dead
    assert "orphan.ts" in dead


@pytest.mark.parametrize(
    "tool, test_file", [("ava", "test.js"), ("tsd", "index.test-d.ts")]
)
def test_package_test_roots_do_not_become_production_entrypoints(
    tmp_path, tool, test_file
):
    from skylos.visitors.languages.typescript.analysis import (
        _discover_ts_reachability_entry_files,
    )

    files = _package_test_files(
        tmp_path,
        {"main": "index.js", "scripts": {"test": tool}, "devDependencies": {tool: "*"}},
        ["index.js", "index.d.ts", test_file],
    )
    all_entries = _discover_ts_reachability_entry_files(
        files, project_root=str(tmp_path)
    )
    assert str(tmp_path / test_file) in all_entries
    entries = _discover_ts_reachability_entry_files(
        files, project_root=str(tmp_path), include_dev_roots=False
    )
    assert str(tmp_path / test_file) not in entries
