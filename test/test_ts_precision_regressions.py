"""Static controls for evidenced JS/TS loads and accurate function metrics."""

import json
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.analysis import find_dead_ts_files
from skylos.visitors.languages.typescript.build_configs import (
    _compile_jest_pattern,
    load_jest_configs,
    resolve_jest_mapping,
)


def _write(root, relative, source):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source, encoding="utf-8")
    return path


def _unused(root, files):
    for relative, source in files.items():
        _write(root, relative, source)
    paths = [path for path in root.rglob("*") if path.suffix in {".js", ".ts"}]
    rows = find_dead_ts_files(paths, set(), {}, {}, project_root=str(root.resolve()))
    return {Path(row["file"]).relative_to(root.resolve()).as_posix() for row in rows}


@pytest.mark.parametrize(
    "mention",
    [
        "console.log('legacy.js was deleted');",
        "const removed = 'legacy.js';",
        "function Worker(value) {} new Worker('legacy.js');",
        "const importScripts = console.log; importScripts('legacy.js');",
        "new Worker('active.js', { name: 'legacy.js' });",
        "new Worker(`legacy.js ${suffix}`);",
        "new Worker('legacy.js was deleted');",
    ],
)
def test_js_mentions_and_shadowed_loader_lookalikes_keep_unused_file(tmp_path, mention):
    unused = _unused(
        tmp_path,
        {
            "src/index.js": mention,
            "src/legacy.js": "console.log('unused');",
            "src/active.js": "console.log('worker');",
        },
    )
    assert "src/legacy.js" in unused


@pytest.mark.parametrize(
    "loader",
    [
        "new Worker('legacy.js');",
        "new SharedWorker(new URL('./legacy.js', import.meta.url));",
        "navigator.serviceWorker.register('legacy.js');",
        "importScripts('legacy.js');",
    ],
)
def test_actual_browser_loads_keep_the_named_file_live(tmp_path, loader):
    assert "src/legacy.js" not in _unused(
        tmp_path,
        {
            "src/index.js": loader,
            "src/legacy.js": "console.log('used');",
        },
    )


@pytest.mark.parametrize(
    "reference,source",
    [
        ("tools/build.py", "MESSAGE = 'src/legacy.js was deleted'\nprint(MESSAGE)\n"),
        (
            "tools/build.py",
            "import subprocess\nsubprocess.run(['node', '-e', \"console.log('src/legacy.js')\"])\n",
        ),
        (
            "tools/build.py",
            "subprocess = object()\nsubprocess.run(['node', 'src/legacy.js'])\n",
        ),
        ("tsconfig.jsonc", '// src/legacy.js was removed\n{"files": []}\n'),
        (
            "tsconfig.jsonc",
            '{"notes": "src/legacy.js", "exclude": ["src/legacy.js"]}\n',
        ),
        ("data.json", '{"files": ["src/legacy.js"]}\n'),
        ("notes.yml", 'notes: "node src/legacy.js"\n'),
        ("run.sh", "echo 'node src/legacy.js'\n"),
        ("page.html", "<p>src/legacy.js was deleted</p>"),
        ("page.html", '<script data-src="src/legacy.js"></script>'),
        ("page.html", "<script data-help=\"src='src/legacy.js'\"></script>"),
        ("page.html", '<script src="src/legacy.js was deleted"></script>'),
    ],
)
def test_prose_comments_and_non_loading_fields_do_not_create_roots(
    tmp_path, reference, source
):
    assert "src/legacy.js" in _unused(
        tmp_path,
        {
            "src/index.ts": "console.log('entry');",
            "src/legacy.js": "console.log('unused');",
            reference: source,
        },
    )


@pytest.mark.parametrize(
    "reference,source",
    [
        (
            "tools/build.py",
            "from subprocess import run as launch\nlaunch(['node', 'src/legacy.js'])\n",
        ),
        (
            "tools/build.py",
            "import subprocess\nfrom pathlib import Path\nENTRY = Path(__file__).parent / 'src' / 'legacy.js'\nsubprocess.run(['node', str(ENTRY)])\n",
        ),
        ("tsconfig.jsonc", '// compiler roots\n{"files": ["src/legacy.js",],}\n'),
        ("run.sh", "echo starting && node ./src/legacy.js\n"),
        (
            ".github/workflows/ci.yml",
            "jobs:\n  scan:\n    steps:\n      - run: node src/legacy.js\n",
        ),
        ("page.html", '<script src="src/legacy.js"></script>'),
    ],
)
def test_declared_file_loads_preserve_liveness(tmp_path, reference, source):
    assert "src/legacy.js" not in _unused(
        tmp_path,
        {
            "src/index.ts": "console.log('entry');",
            "src/legacy.js": "console.log('used');",
            reference: source,
        },
    )


def test_unused_jest_mapper_target_is_not_an_entry_root(tmp_path):
    files = {
        "package.json": json.dumps(
            {
                "name": "app",
                "jest": {
                    "setupFiles": ["<rootDir>/src/setup.ts"],
                    "moduleNameMapper": {
                        "^never-imported$": "<rootDir>/src/unused-mock.ts"
                    },
                },
            }
        ),
        "src/index.ts": "console.log('entry');",
        "src/setup.ts": "console.log('setup');",
        "src/unused-mock.ts": "export const unused = 1;",
    }
    unused = _unused(tmp_path, files)
    assert "src/unused-mock.ts" in unused
    assert "src/setup.ts" not in unused
    (config,) = load_jest_configs(str(tmp_path.resolve()))
    assert resolve_jest_mapping(
        config.mappings, "never-imported", str(tmp_path / "src/index.ts")
    ) == str(tmp_path.resolve() / "src/unused-mock.ts")


@pytest.mark.parametrize(
    "pattern",
    [
        r"^(a|aa)+$",
        r"^(a?)+$",
        r"^a*a*$",
        r"^(a+)\1$",
        r"^(?=a)a+$",
        r"^a{1,100}a{1,100}$",
        "^" + "(a|aa)" * 10 + "$",
    ],
)
def test_mapper_rejects_backtracking_amplifiers_without_executing_them(pattern):
    assert _compile_jest_pattern(pattern) is None


@pytest.mark.parametrize(
    "pattern", [r"^@/(.*)$", r"\.(css|scss)$", r"^image!([\w.-]+)$"]
)
def test_common_literal_and_single_capture_mappers_are_preserved(pattern):
    assert _compile_jest_pattern(pattern) is not None


def test_template_comment_marker_does_not_hide_following_code_lines(tmp_path):
    statements = "  doThing();\n" * 60
    source = (
        "function long() {\nconst message = `\n/* instructions:\n`;\n"
        + statements
        + "}\n"
    )
    path = _write(tmp_path, "src/long.ts", source)
    lengths = [
        row
        for row in scan_typescript_file(str(path))[6]
        if row["rule_id"] == "SKY-C304"
    ]
    assert [row["value"] for row in lengths] == [65]


def test_real_block_comments_and_blank_lines_do_not_inflate_length(tmp_path):
    source = "function short() {\n/*\n" + " note\n" * 60 + "*/\n\nreturn 1;\n}\n"
    path = _write(tmp_path, "src/short.ts", source)
    assert not any(
        row["rule_id"] == "SKY-C304" for row in scan_typescript_file(str(path))[6]
    )


def test_inline_block_comment_keeps_code_on_both_sides(tmp_path):
    source = "function long() {\n" + "act(); /* note */ again();\n" * 55 + "}\n"
    path = _write(tmp_path, "src/long.ts", source)
    lengths = [
        row
        for row in scan_typescript_file(str(path))[6]
        if row["rule_id"] == "SKY-C304"
    ]
    assert [row["value"] for row in lengths] == [57]


def test_flat_logical_chain_does_not_consume_python_call_stack(tmp_path):
    source = (
        "function long() {\nreturn "
        + " &&\n".join(f"x{i}" for i in range(1500))
        + ";\n}\n"
    )
    path = _write(tmp_path, "src/flat.ts", source)
    rows = scan_typescript_file(str(path))[6]
    assert any(row["rule_id"] == "SKY-C304" for row in rows)
    assert not any(row["rule_id"] == "SKY-Q306" for row in rows)


def test_production_next_route_under_tests_keeps_all_function_metrics(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies":{"next":"15.0.0"}}')
    source = (
        "export function GET() {\n"
        + "if (ready) {\n" * 6
        + "return 1;\n"
        + "}\n" * 6
        + "return 0;\n}\n"
    )
    path = _write(tmp_path, "src/app/api/tests/route.ts", source)
    metrics = {
        row["rule_id"]: row["value"]
        for row in scan_typescript_file(str(path))[6]
        if "value" in row
    }
    assert metrics["SKY-Q302"] == 6
    assert metrics["SKY-Q306"] == 21


def test_production_route_does_not_get_test_callback_length_exception(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies":{"next":"15.0.0"}}')
    path = _write(
        tmp_path,
        "src/app/api/tests/route.ts",
        "test('work', () => {\n" + "act();\n" * 55 + "});\n",
    )
    assert any(
        row["rule_id"] == "SKY-C304" for row in scan_typescript_file(str(path))[6]
    )
