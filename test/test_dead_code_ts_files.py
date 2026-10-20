"""JS/TS unused files and exports: loads the import graph cannot see.

Synthetic projects only; fixtures are written to ``tmp_path`` and never run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript.build_configs import (
    JestModuleMapping,
    _compile_jest_pattern,
    _js_unescape,
    load_angular_workspace,
    load_jest_configs,
    resolve_jest_mapping,
)
from skylos.visitors.languages.typescript.conventions import (
    convention_reason,
    is_rc_tool_config,
)
from skylos.visitors.languages.typescript.file_references import (
    collect_ts_path_references,
)


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str]) -> dict:
    _write_tree(root, files)
    return json.loads(analyze(str(root), conf=0, grep_verify=False))


def _relative(root: Path, file_name: str) -> str:
    return Path(file_name).resolve().relative_to(root.resolve()).as_posix()


def _unused_files(root: Path, result: dict) -> set[str]:
    return {
        _relative(root, item["file"])
        for item in result.get("unused_files", [])
        if item.get("rule_id") == "SKY-E003"
    }


def _unused_exports(root: Path, result: dict) -> set[tuple[str, str]]:
    return {
        (_relative(root, item["file"]), item["name"])
        for item in result.get("unused_exports", [])
    }


_ENTRY = {"src/index.ts": "export const ready = true;\n"}


# ------------------------------------------------------- path references


def test_tsconfig_files_entry_is_a_root(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "tsconfig.app.json": '{"files": ["src/polyfills.ts"]}\n',
            "src/polyfills.ts": "globalThis.ready = true;\n",
            "src/orphan.ts": "globalThis.orphan = true;\n",
        },
    )
    unused = _unused_files(tmp_path, result)
    assert "src/polyfills.ts" not in unused
    assert "src/orphan.ts" in unused


def test_python_subprocess_path_is_a_root_but_comments_and_docstrings_are_not(
    tmp_path,
):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "tools/build.py": (
                '"""Replaces legacy-index.js."""\n'
                "import os, subprocess\n"
                "# old-index.js is gone\n"
                "INDEX = os.path.join(os.path.dirname(__file__), 'build-index.js')\n"
                "subprocess.run(['node', INDEX], check=True)\n"
            ),
            "tools/build-index.js": "console.log('index');\n",
            "tools/legacy-index.js": "console.log('legacy');\n",
            "tools/old-index.js": "console.log('old');\n",
        },
    )
    unused = _unused_files(tmp_path, result)
    assert "tools/build-index.js" not in unused
    assert "tools/legacy-index.js" in unused
    assert "tools/old-index.js" in unused


def test_yaml_path_under_another_base_directory_matches_by_unique_suffix(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "mkdocs.yml": (
                "docs_dir: docs/content\n"
                "extra_javascript:\n"
                "  - assets/js/toc.js\n"
                "  # - assets/js/old.js\n"
            ),
            "docs/content/assets/js/toc.js": "document.title = 'x';\n",
            "docs/content/assets/js/old.js": "document.title = 'y';\n",
        },
    )
    unused = _unused_files(tmp_path, result)
    assert "docs/content/assets/js/toc.js" not in unused
    assert "docs/content/assets/js/old.js" in unused


def test_template_expression_script_path_is_a_root(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "theme/base.html": (
                "<script src=\"{{ 'js/theme.js'|url }}\"></script>\n"
                "<!-- <script src=\"{{ 'js/retired.js'|url }}\"></script> -->\n"
            ),
            "theme/js/theme.js": "window.theme = 1;\n",
            "theme/js/retired.js": "window.retired = 1;\n",
        },
    )
    unused = _unused_files(tmp_path, result)
    assert "theme/js/theme.js" not in unused
    assert "theme/js/retired.js" in unused


def test_js_string_reference_lives_only_while_the_referencing_file_lives(tmp_path):
    result = _scan(
        tmp_path,
        {
            "src/index.js": (
                "const worker = new Worker(joinUrl(base, 'search/worker.js'));\n"
            ),
            "src/templates/search/worker.js": "importScripts('segmenter.js');\n",
            "src/vendor-lang/segmenter.js": "self.segment = 1;\n",
            "src/dead.js": "new Worker('jobs/job.js');\n",
            "src/jobs/job.js": "self.job = 1;\n",
        },
    )
    unused = _unused_files(tmp_path, result)
    assert "src/templates/search/worker.js" not in unused
    # A bare file name from another script counts when it is unique.
    assert "src/vendor-lang/segmenter.js" not in unused
    assert "src/dead.js" in unused
    assert "src/jobs/job.js" in unused


@pytest.mark.parametrize(
    ("reference_file", "text"),
    [
        (
            ".github/workflows/ci.yml",
            "jobs:\n  t:\n    steps:\n      - run: node runner.js\n",
        ),
        ("README.md", "Run `node lib/runner.js` to start.\n"),
        (
            "page.html",
            '<script src="https://cdn.example.com/lib/runner.js"></script>\n',
        ),
    ],
)
def test_mentions_that_do_not_resolve_to_the_file_keep_it_unused(
    tmp_path, reference_file, text
):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            reference_file: text,
            "lib/runner.js": "console.log('run');\n",
        },
    )
    assert "lib/runner.js" in _unused_files(tmp_path, result)


def test_shell_command_path_is_a_root(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "run.sh": '#!/bin/sh\nnode ./lib/runner.js "$@"\n',
            "lib/runner.js": "console.log('run');\n",
        },
    )
    assert "lib/runner.js" not in _unused_files(tmp_path, result)


def test_import_specifiers_are_not_counted_as_path_references(tmp_path):
    root = tmp_path.resolve()
    _write_tree(
        root,
        {
            "src/a.js": "import { b } from './b.js';\nconsole.log(b);\n",
            "src/b.js": "export const b = 1;\n",
        },
    )
    js_files = {str(root / "src/a.js"), str(root / "src/b.js")}
    roots, edges = collect_ts_path_references(root, js_files, {str(root / "src/b.js")})
    assert roots == set()
    assert dict(edges) == {}


def test_unreferenced_classic_script_is_still_reported(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "src/legacy-widget.js": "function initWidget() { return 1; }\n",
        },
    )
    assert "src/legacy-widget.js" in _unused_files(tmp_path, result)


# ------------------------------------------------------------------ Jest

_JEST_PROJECT = {
    "package.json": '{"name": "app", "devDependencies": {"jest": "29.0.0"}}\n',
    "jest.config.js": (
        "module.exports = {\n"
        "  setupFilesAfterEnv: ['<rootDir>/setup-jest.ts'],\n"
        "  moduleNameMapper: {\n"
        "    '^pdf-lib/build/pdf\\\\.mjs$': '<rootDir>/src/mocks/pdf-mock.ts',\n"
        "  },\n"
        "}\n"
    ),
    "setup-jest.ts": "globalThis.setup = true;\n",
    "src/index.ts": (
        "import { Doc } from 'pdf-lib/build/pdf.mjs'\nexport const doc = new Doc()\n"
    ),
    "src/mocks/pdf-mock.ts": (
        "export class Doc {}\n"
        "export class Spare {}\n"
        "export function makeSpare() { return [new Doc(), new Spare()] }\n"
    ),
}


def test_jest_setup_file_and_module_name_mapper_target_are_live(tmp_path):
    result = _scan(tmp_path, _JEST_PROJECT)
    unused = _unused_files(tmp_path, result)
    assert "setup-jest.ts" not in unused
    assert "src/mocks/pdf-mock.ts" not in unused


def test_module_name_mapper_consumes_only_the_imported_exports(tmp_path):
    result = _scan(tmp_path, _JEST_PROJECT)
    exports = _unused_exports(tmp_path, result)
    assert ("src/mocks/pdf-mock.ts", "Doc") not in exports
    assert ("src/mocks/pdf-mock.ts", "Spare") in exports


def test_jest_options_in_package_json(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "package.json": '{"name": "app", "jest": {"setupFiles": ["./jest.setup.js"]}}\n',
            "jest.setup.js": "globalThis.setup = true;\n",
        },
    )
    assert "jest.setup.js" not in _unused_files(tmp_path, result)


def test_jest_manual_mock_exports_are_read_by_jest(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            "package.json": '{"name": "app"}\n',
            "__mocks__/some-pkg.ts": (
                "export const fetchThing = () => 1\n"
                "globalThis.someMock = { fetchThing }\n"
            ),
            "src/util.ts": (
                "export const helper = () => 1\nexport const run = () => helper()\n"
            ),
            "src/main.ts": "import { run } from './util'\nrun()\n",
        },
    )
    exports = _unused_exports(tmp_path, result)
    assert ("__mocks__/some-pkg.ts", "fetchThing") not in exports
    # The rule still fires for an ordinary module.
    assert ("src/util.ts", "helper") in exports


def test_js_unescape_matches_javascript_string_values():
    assert _js_unescape(r"^pdf\\.mjs$") == r"^pdf\.mjs$"
    assert _js_unescape(r"\u0041\x42\u{43}\'") == "ABC'"


def test_jest_mapping_uses_first_matching_pattern_and_root_dir(tmp_path):
    root = tmp_path.resolve()
    _write_tree(root, {"app/src/a.ts": "", "app/src/b.ts": ""})
    mappings = [
        JestModuleMapping(
            str(root / "app"), re.compile(r"^lib/(.*)$"), (str(root / "app/src/$1.ts"),)
        ),
        JestModuleMapping(
            str(root / "app"), re.compile(r"^lib/a$"), (str(root / "app/src/b.ts"),)
        ),
    ]
    importer = str(root / "app/src/main.ts")
    assert resolve_jest_mapping(mappings, "lib/a", importer) == str(
        root / "app/src/a.ts"
    )
    assert resolve_jest_mapping(mappings, "lib/a", str(root / "other/main.ts")) is None


@pytest.mark.parametrize("pattern", [r"^(a+)+$", r"(x*)*", "a" * 300, "["])
def test_jest_mapper_skips_unbounded_or_invalid_patterns(pattern):
    assert _compile_jest_pattern(pattern) is None


def test_jest_config_with_root_dir_and_projects(tmp_path):
    root = tmp_path.resolve()
    _write_tree(
        root,
        {
            "jest.config.json": json.dumps(
                {
                    "rootDir": "web",
                    "projects": [{"globalSetup": "<rootDir>/global.ts"}],
                    "testEnvironment": "./env.js",
                }
            ),
            "web/global.ts": "",
            "web/env.js": "",
        },
    )
    (config,) = load_jest_configs(str(root))
    assert config.entry_files == {str(root / "web/global.ts"), str(root / "web/env.js")}


# --------------------------------------------------------------- Angular

_ANGULAR_PROJECT = {
    "package.json": '{"name": "app"}\n',
    "angular.json": json.dumps(
        {
            "projects": {
                "app": {
                    "architect": {
                        "build": {
                            "options": {
                                "browser": "src/bootstrap.ts",
                                "polyfills": ["src/polyfills.ts", "zone.js"],
                            },
                            "configurations": {
                                "production": {
                                    "fileReplacements": [
                                        {
                                            "replace": "src/environments/environment.ts",
                                            "with": "src/environments/environment.prod.ts",
                                        }
                                    ]
                                }
                            },
                        },
                        "test": {"options": {"karmaConfig": "karma.conf.js"}},
                    }
                }
            }
        }
    ),
    "karma.conf.js": "module.exports = function (config) {}\n",
    "src/bootstrap.ts": (
        "import { TITLE } from './environments/environment'\ndocument.title = TITLE\n"
    ),
    "src/polyfills.ts": "globalThis.polyfilled = true\n",
    "src/environments/environment.ts": (
        "export const TITLE = 'App'\nexport const environment = { title: TITLE }\n"
    ),
    "src/environments/environment.prod.ts": (
        "export const TITLE = 'App'\nexport const environment = { title: TITLE }\n"
    ),
}


def test_angular_workspace_entries_and_file_replacements(tmp_path):
    root = tmp_path.resolve()
    _write_tree(root, _ANGULAR_PROJECT)
    workspace = load_angular_workspace(str(root))
    assert workspace is not None
    assert workspace.entry_files == {
        (str(root / "src/bootstrap.ts"), "prod"),
        (str(root / "src/polyfills.ts"), "prod"),
        (str(root / "karma.conf.js"), "dev"),
    }
    assert workspace.file_replacements == (
        (
            str(root / "src/environments/environment.ts"),
            str(root / "src/environments/environment.prod.ts"),
        ),
    )


def test_angular_build_files_are_live_and_replacement_shares_consumers(tmp_path):
    result = _scan(tmp_path, _ANGULAR_PROJECT)
    unused = _unused_files(tmp_path, result)
    assert "src/bootstrap.ts" not in unused
    assert "src/polyfills.ts" not in unused
    assert "src/environments/environment.prod.ts" not in unused
    assert "karma.conf.js" not in unused
    exports = _unused_exports(tmp_path, result)
    assert ("src/environments/environment.prod.ts", "TITLE") not in exports
    assert ("src/environments/environment.ts", "TITLE") not in exports


# ------------------------------------------------------------- rc configs


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/repo/.prettierrc.js", True),
        ("/repo/web/.eslintrc.cjs", True),
        ("/repo/.config/prettierrc.mjs", True),
        ("/repo/prettierrc.js", False),
        ("/repo/.prettierrc.json", False),
        ("/repo/src/.hidden.js", False),
        ("/repo/.config/helpers.js", False),
    ],
)
def test_rc_config_convention(path, expected):
    assert is_rc_tool_config(path) is expected
    assert (convention_reason(path) == "rc-config") is expected


def test_rc_config_without_package_json_is_a_root(tmp_path):
    result = _scan(
        tmp_path,
        {
            **_ENTRY,
            ".prettierrc.js": "const config = { semi: false }\nmodule.exports = config\n",
            "prettierrc.js": "module.exports = { semi: false }\n",
        },
    )
    unused = _unused_files(tmp_path, result)
    assert ".prettierrc.js" not in unused
    assert "prettierrc.js" in unused


# ------------------------------------------------------- dead exports kept


def test_unnecessary_export_in_a_path_referenced_script_is_still_reported(tmp_path):
    result = _scan(
        tmp_path,
        {
            "run.sh": "k6 run load/scenario.js\n",
            "load/scenario.js": (
                "import { drive } from './lib/checks.js'\n"
                "export default function () { drive() }\n"
            ),
            "load/lib/checks.js": (
                "export const params = { timeout: '5s' }\n"
                "export function drive() { return params }\n"
            ),
        },
    )
    assert "load/scenario.js" not in _unused_files(tmp_path, result)
    assert ("load/lib/checks.js", "params") in _unused_exports(tmp_path, result)
