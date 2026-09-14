from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.base import Definition
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.analysis import (
    _discover_esbuild_config_entries,
    _discover_script_entry_candidates,
    _discover_vite_config_entries,
    _discover_vitest_config_entries,
    _esbuild_glob_matches,
    build_ts_import_graph,
)


def _raw_imports(path: Path) -> list[dict]:
    return scan_typescript_file(str(path))[12]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")


def _write_sources(tmp_path: Path, *names: str) -> dict[str, Path]:
    sources = {name: tmp_path / "src" / name for name in names}
    for path in sources.values():
        _write(path, "export {};\n")
    return sources


def _esbuild_entries(tmp_path: Path, code: str, *names: str) -> set[str]:
    sources = _write_sources(tmp_path, *names)
    build_file = tmp_path / "build.mjs"
    _write(build_file, code)
    matches = _discover_esbuild_config_entries(
        str(build_file),
        {str(path.resolve()) for path in sources.values()},
        str(tmp_path),
    )
    return {Path(path).name for path in matches}


def test_jsdoc_import_type_records_a_named_type_edge(tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(source, "/** @typedef {import('./types.js').Greeting} Greeting */\n")

    assert _raw_imports(source) == [
        {
            "source": "./types.js",
            "names": ["Greeting"],
            "line": 1,
            "type_only": True,
        }
    ]


@pytest.mark.parametrize(
    ("comment", "expected"),
    [
        (
            "/**\n * @import {\n *   Greeting as G,\n *   Recipient\n"
            " * } from './types.js'\n */\n",
            {"names": ["Greeting", "Recipient"], "line": 2},
        ),
        (
            "/** @import Greeting from './types.js' */\n",
            {"names": ["default"], "line": 1},
        ),
        (
            "/** @import * as types from './types.js' */\n",
            {"names": [], "line": 1, "consume_all_exports": True},
        ),
        (
            "/** @import DefaultType, {Greeting, Recipient as R} "
            "from './types.js' */\n",
            {"names": ["default", "Greeting", "Recipient"], "line": 1},
        ),
        (
            "/** @import DefaultType, * as types from './types.js' */\n",
            {
                "names": ["default"],
                "line": 1,
                "consume_all_exports": True,
            },
        ),
        (
            "/** @import {Greeting,} from './types.js' */\n",
            {"names": ["Greeting"], "line": 1},
        ),
        (
            "/** @import DefaultType,\n{Greeting} "
            "from './types.js' */\n",
            {"names": ["default", "Greeting"], "line": 1},
        ),
        (
            "/** @type {import('./types.js')['Greeting']} */\n",
            {"names": ["Greeting"], "line": 1},
        ),
        (
            "/** @type {typeof import('./types.js')} */\n",
            {"names": [], "line": 1, "consume_all_exports": True},
        ),
        (
            "/** @type {import(\n * './types.js'\n * ).Greeting} */\n",
            {"names": ["Greeting"], "line": 1},
        ),
        (
            "/** @type {\nimport('./types.js').Greeting\n} */\n",
            {"names": ["Greeting"], "line": 2},
        ),
        (
            "/** @type {`prefix-${import('./types.js').Greeting}`} */\n",
            {"names": ["Greeting"], "line": 1},
        ),
        (
            "/** @type {!import('./types.js').Greeting} */\n",
            {"names": ["Greeting"], "line": 1},
        ),
        (
            "/** @type {()=>import('./types.js').Greeting} */\n",
            {"names": ["Greeting"], "line": 1},
        ),
    ],
)
def test_jsdoc_official_import_forms(comment, expected, tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(source, comment)

    finding = {
        "source": "./types.js",
        "type_only": True,
        **expected,
    }
    assert _raw_imports(source) == [finding]


def test_jsdoc_namespace_forms_consume_all_exports(tmp_path):
    main = tmp_path / "src" / "main.js"
    types = tmp_path / "src" / "types.js"
    main.parent.mkdir(parents=True)
    _write(main, "/** @import * as types from './types.js' */\n")
    _write(types, "export {};\n")
    definitions = {}
    for name in ("Greeting", "Recipient"):
        definition = Definition(name, "type", str(types), 1)
        definition.is_exported = True
        definitions[f"{types}:{name}"] = definition

    consumed, _, _ = build_ts_import_graph({str(main): _raw_imports(main)}, definitions)

    assert consumed[str(types)] == {"Greeting", "Recipient"}


@pytest.mark.parametrize(
    "comment",
    [
        "/** @example import('./dead.js').Value */\n",
        "/** @type {\"import('./dead.js').Value\"} */\n",
        "/** @type {`import('./dead.js').Value`} */\n",
        "/** @type {foo.import('./dead.js').Value} */\n",
        "/** @type {.import('./dead.js').Value} */\n",
        "/** @type {#import('./dead.js').Value} */\n",
        "/** @type {/import('./dead.js').Value} */\n",
        "/** @type {%import('./dead.js').Value} */\n",
        "/** @type {*import('./dead.js').Value} */\n",
        "/** @type {+import('./dead.js').Value} */\n",
        "/** @type {-import('./dead.js').Value} */\n",
        "/** @type {;import('./dead.js').Value} */\n",
        "/** @type {=import('./dead.js').Value} */\n",
        "/** @type {@import('./dead.js').Value} */\n",
        "/** @type {\\import('./dead.js').Value} */\n",
        "/** @type {^import('./dead.js').Value} */\n",
        "/** @type {~import('./dead.js').Value} */\n",
        "/** @type description {import('./dead.js').Value} */\n",
        "/** @returns description {import('./dead.js').Value} */\n",
        "/** value.@type {import('./dead.js').Value} */\n",
        "/** @TYPE {import('./dead.js').Value} */\n",
        "/** @IMPORT {Value} from './dead.js' */\n",
        "/** @import {Value} FROM './dead.js' */\n",
        "/** @import {,Value} from './dead.js' */\n",
        "/** @import {Value AS Alias} from './dead.js' */\n",
        "/** @import {TYPE Value} from './dead.js' */\n",
        "/** @import Value\n * from './dead.js' */\n",
        "/** @import Foo,\n * {Value} from './dead.js' */\n",
        "/** @import Foo\n * , {Value} from './dead.js' */\n",
        "/** @import Foo,\n * * as values from './dead.js' */\n",
        "/** @type {\n * import('./dead.js').Value\n * } */\n",
        "/** @import {Value} from\n * './dead.js' */\n",
        "/** {@link @type {import('./dead.js').Value}} */\n",
    ],
)
def test_jsdoc_invalid_or_non_type_text_does_not_create_edges(comment, tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(source, comment)

    assert _raw_imports(source) == []


@pytest.mark.parametrize(
    "comment",
    [
        "/** Description @type {import('./types.js').Value} */\n",
        "/** @param value {import('./types.js').Value} */\n",
        "/** @param [value] {import('./types.js').Value} */\n",
        "/** @param options.value {import('./types.js').Value} */\n",
        "/** {@LINK label @type {import('./types.js').Value}} */\n",
    ],
)
def test_jsdoc_valid_inline_and_name_first_types_create_edges(comment, tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(source, comment)

    assert _raw_imports(source) == [
        {
            "source": "./types.js",
            "names": ["Value"],
            "line": 1,
            "type_only": True,
        }
    ]


def test_jsdoc_quoted_tag_text_does_not_hide_a_real_union_import(tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(
        source,
        "/** @type {\"hello @type\" | import('./live.js').Value} */\n"
        "/** @type {\"hello @type {import('./dead.js').Value}\"} */\n",
    )

    assert _raw_imports(source) == [
        {
            "source": "./live.js",
            "names": ["Value"],
            "line": 1,
            "type_only": True,
        }
    ]


def test_jsdoc_recovers_after_an_unclosed_type(tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(
        source,
        "/**\n"
        " * @type {string\n"
        " * @type {import('./live.js').Value}\n"
        " */\n",
    )

    assert _raw_imports(source) == [
        {
            "source": "./live.js",
            "names": ["Value"],
            "line": 3,
            "type_only": True,
        }
    ]


def test_jsdoc_does_not_recover_tags_hidden_by_an_unclosed_template(tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(
        source,
        "/** @type {`plain\n"
        " * @type {import('./dead.js').Value}\n"
        " */\n",
    )

    assert _raw_imports(source) == []


def test_jsdoc_recovers_a_tag_after_an_unclosed_template_interpolation(tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(
        source,
        "/** @type {`${string\n"
        " * @type {import('./live.js').Value}\n"
        " */\n",
    )

    assert _raw_imports(source) == [
        {
            "source": "./live.js",
            "names": ["Value"],
            "line": 2,
            "type_only": True,
        }
    ]


def test_jsdoc_empty_named_import_is_valid_but_imports_no_names(tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    _write(source, "/** @import {} from './types.js' */\n")

    assert _raw_imports(source) == [
        {
            "source": "./types.js",
            "names": [],
            "line": 1,
            "type_only": True,
        }
    ]


def test_jsdoc_many_closed_links_and_properties_stay_bounded(tmp_path):
    source = tmp_path / "src" / "main.js"
    source.parent.mkdir(parents=True)
    links = "\n".join(" * {@link Value}" for _ in range(5000))
    properties = "\n".join(
        f" * @property {{string}} value{index}" for index in range(5000)
    )
    _write(
        source,
        f"/**\n{links}\n * @typedef {{Object}} Options\n{properties}\n"
        " * @type {import('./types.js').Value}\n */\n",
    )

    assert _raw_imports(source)[-1]["source"] == "./types.js"


@pytest.mark.parametrize(
    ("import_line", "call", "expected"),
    [
        (
            "import { build } from 'esbuild';",
            "await build({ entryPoints: { worker: 'src/worker.js' } });",
            {"worker.js"},
        ),
        (
            "import { build as bundle } from 'esbuild';",
            "bundle({ entryPoints: ['src/worker.js'] });",
            {"worker.js"},
        ),
        (
            "import * as esbuild from 'esbuild';",
            "esbuild.buildSync({ entryPoints: ['src/worker.js'] });",
            {"worker.js"},
        ),
        (
            "import type { build } from 'esbuild';",
            "build({ entryPoints: ['src/dead.js'] });",
            set(),
        ),
        (
            "import { type build } from 'esbuild';",
            "build({ entryPoints: ['src/dead.js'] });",
            set(),
        ),
        (
            "import esbuild from 'esbuild';",
            "esbuild.build({ entryPoints: ['src/dead.js'] });",
            set(),
        ),
        (
            "const esbuild = require('esbuild');",
            "esbuild.build({ entryPoints: ['src/dead.js'] });",
            set(),
        ),
    ],
)
def test_esbuild_only_uses_immutable_runtime_imports(
    tmp_path, import_line, call, expected
):
    assert (
        _esbuild_entries(
            tmp_path,
            f"{import_line}\n{call}\n",
            "worker.js",
            "dead.js",
        )
        == expected
    )


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            (
                "import { dirname, join } from 'node:path';\n"
                "import { fileURLToPath } from 'node:url';\n"
                "import { build } from 'esbuild';\n"
                "const here = dirname(fileURLToPath(import.meta.url));\n"
                "const shared = { bundle: true };\n"
                "build({ ...shared, "
                "entryPoints: [join(here, 'src', 'worker.js')] });\n"
            ),
            {"worker.js"},
        ),
        (
            (
                "import path from 'node:path';\n"
                "import { fileURLToPath } from 'node:url';\n"
                "import { context } from 'esbuild';\n"
                "const filename = fileURLToPath(import.meta.url);\n"
                "const dirname = path.dirname(filename);\n"
                "context({ entryPoints: "
                "[path.resolve(dirname, 'src', 'worker.js')] });\n"
            ),
            {"worker.js"},
        ),
        (
            (
                "import path from 'node:path';\n"
                "import { build } from 'esbuild';\n"
                "const shared = { bundle: true };\n"
                "build({ ...shared, "
                "entryPoints: [path.join('src', 'worker.js')] });\n"
            ),
            {"worker.js"},
        ),
        (
            (
                "import { build } from 'esbuild';\n"
                "const sourceDir = 'src';\n"
                "build({ entryPoints: [`${sourceDir}/worker.js`] });\n"
            ),
            {"worker.js"},
        ),
        (
            (
                "import * as esbuild from 'esbuild';\n"
                "const bundles = ['worker', 'admin'];\n"
                "esbuild.context({ entryPoints: "
                "bundles.map((name) => `src/${name}.js`) });\n"
            ),
            {"worker.js", "admin.js"},
        ),
        (
            (
                "import { dirname, resolve } from 'node:path';\n"
                "import { fileURLToPath } from 'node:url';\n"
                "import { build } from 'esbuild';\n"
                "const root = dirname(fileURLToPath(import.meta.url));\n"
                "build({ entryPoints: { "
                "worker: resolve(root, 'src/worker.js'), "
                "admin: resolve(root, 'src/admin.js') } });\n"
            ),
            {"worker.js", "admin.js"},
        ),
    ],
)
def test_esbuild_folds_static_computed_entries(tmp_path, code, expected):
    assert _esbuild_entries(tmp_path, code, "worker.js", "admin.js") == expected


@pytest.mark.parametrize(
    "setup",
    [
        "let sourceDir = 'src';\n",
        "const sourceDir = runtimeDir();\n",
        "const sourceDir = `${sourceDir}`;\n",
    ],
)
def test_esbuild_rejects_dynamic_template_bindings(tmp_path, setup):
    code = (
        "import { build } from 'esbuild';\n"
        f"{setup}"
        "build({ entryPoints: [`${sourceDir}/dead.js`] });\n"
    )

    assert _esbuild_entries(tmp_path, code, "dead.js") == set()


def test_esbuild_rejects_unproven_path_helpers(tmp_path):
    code = (
        "import { build } from 'esbuild';\n"
        "const root = 'src';\n"
        "const join = (...parts) => parts.join('/');\n"
        "build({ entryPoints: [join(root, 'dead.js')] });\n"
    )

    assert _esbuild_entries(tmp_path, code, "dead.js") == set()


@pytest.mark.parametrize(
    "path_import",
    [
        "import type { join } from 'node:path';",
        "import { type join } from 'node:path';",
    ],
)
def test_esbuild_rejects_type_only_path_helpers(tmp_path, path_import):
    code = (
        f"{path_import}\n"
        "import { build } from 'esbuild';\n"
        "build({ entryPoints: [join('src', 'dead.js')] });\n"
    )

    assert _esbuild_entries(tmp_path, code, "dead.js") == set()


@pytest.mark.parametrize("method", ["catch", "finally", "then"])
def test_esbuild_top_level_promise_chains_still_execute_the_build(tmp_path, method):
    code = (
        "import { build } from 'esbuild';\n"
        f"build({{ entryPoints: ['src/worker.js'] }}).{method}(() => {{}});\n"
    )

    assert _esbuild_entries(tmp_path, code, "worker.js") == {"worker.js"}


@pytest.mark.parametrize(
    "call",
    [
        "const result = await build({ entryPoints: ['src/worker.js'] });",
        "let result = await build({ entryPoints: ['src/worker.js'] });",
        "var result = build({ entryPoints: ['src/worker.js'] });",
        "export const result = build({ entryPoints: ['src/worker.js'] });",
        "export let result = build({ entryPoints: ['src/worker.js'] });",
        "const result = build({ entryPoints: ['src/worker.js'] }).catch(() => {});",
        "void build({ entryPoints: ['src/worker.js'] });",
        "let ctx = await context({ entryPoints: ['src/worker.js'] });",
    ],
)
def test_esbuild_top_level_initializers_execute_the_build(tmp_path, call):
    code = f"import {{ build, context }} from 'esbuild';\n{call}\n"

    assert _esbuild_entries(tmp_path, code, "worker.js") == {"worker.js"}


@pytest.mark.parametrize(
    "call",
    [
        "function run() { build({ entryPoints: ['src/dead.js'] }); } run();",
        "if (false) build({ entryPoints: ['src/dead.js'] });",
        "build(options);",
        "build({ ...options });",
        "build({ entryPoints });",
        "build({ entryPoints: [...entries] });",
        "build({ get entryPoints() { return ['src/dead.js']; } });",
        "esbuild['build']({ entryPoints: ['src/dead.js'] });",
    ],
)
def test_esbuild_abstains_when_execution_or_options_are_not_static(tmp_path, call):
    code = (
        "import { build } from 'esbuild';\n"
        "import * as esbuild from 'esbuild';\n"
        "const entries = ['src/dead.js'];\n"
        "const entryPoints = entries;\n"
        "const options = { entryPoints };\n"
        f"{call}\n"
    )

    assert _esbuild_entries(tmp_path, code, "dead.js") == set()


def test_esbuild_static_advanced_entries_and_working_directory(tmp_path):
    worker = tmp_path / "web" / "src" / "worker.js"
    _write(worker, "export {};\n")
    build_file = tmp_path / "build.mjs"
    _write(
        build_file,
        "import { context } from 'esbuild';\n"
        "context({ absWorkingDir: 'web', "
        "entryPoints: [{ in: 'src/worker.js', out: 'worker' }] });\n",
    )

    assert _discover_esbuild_config_entries(
        str(build_file), {str(worker.resolve())}, str(tmp_path)
    ) == {str(worker.resolve())}


@pytest.mark.parametrize(
    "entry_points",
    [
        "'src/dead.js'",
        "[{ in: 'src/dead.js' }]",
        "[{ in: 'src/dead.js', out: 'dead', bogus: true }]",
        "[, 'src/dead.js']",
    ],
)
def test_esbuild_rejects_invalid_entry_point_shapes(tmp_path, entry_points):
    code = (
        "import { build } from 'esbuild';\n"
        f"build({{ entryPoints: {entry_points} }});\n"
    )

    assert _esbuild_entries(tmp_path, code, "dead.js") == set()


def test_esbuild_abstains_when_the_build_module_has_syntax_errors(tmp_path):
    code = (
        "import { build } from 'esbuild';\n"
        "build({ entryPoints: ['src/dead.js'] });\n"
        "const = ;\n"
    )

    assert _esbuild_entries(tmp_path, code, "dead.js") == set()


def test_esbuild_js_config_requires_an_esm_package(tmp_path):
    dead = _write_sources(tmp_path, "dead.js")["dead.js"]
    build_file = tmp_path / "build.js"
    _write(
        build_file,
        "import { build } from 'esbuild';\n"
        "build({ entryPoints: ['src/dead.js'] });\n",
    )
    files = {str(dead.resolve())}

    assert _discover_esbuild_config_entries(
        str(build_file), files, str(tmp_path)
    ) == set()

    _write(tmp_path / "package.json", json.dumps({"type": "module"}))
    assert _discover_esbuild_config_entries(
        str(build_file), files, str(tmp_path)
    ) == {str(dead.resolve())}


def test_esbuild_static_globs_use_esbuild_wildcards(tmp_path):
    sources = _write_sources(tmp_path, "one.js", "nested/two.js")
    build_file = tmp_path / "build.mjs"
    _write(
        build_file,
        "import { build } from 'esbuild';\n"
        "build({ entryPoints: ['src/**/*.js'] });\n",
    )

    assert _discover_esbuild_config_entries(
        str(build_file),
        {str(path.resolve()) for path in sources.values()},
        str(tmp_path),
    ) == {str(path.resolve()) for path in sources.values()}
    assert _esbuild_glob_matches("*" + "a" * 200_000 + "b", "a" * 200_000 + "c") is False


def test_esbuild_many_globs_reuse_the_file_inventory(tmp_path):
    count = 500
    files = {
        str((tmp_path / "src" / f"entry-{index}.js").resolve())
        for index in range(count)
    }
    patterns = ", ".join(f"'src/*-{index}.js'" for index in range(count))
    build_file = tmp_path / "build.mjs"
    _write(
        build_file,
        "import { build } from 'esbuild';\n"
        f"build({{ entryPoints: [{patterns}] }});\n",
    )

    started = time.perf_counter()
    result = _discover_esbuild_config_entries(
        str(build_file), files, str(tmp_path)
    )

    assert result == files
    assert time.perf_counter() - started < 5


def test_esbuild_glob_budget_conservatively_keeps_files_in_working_dir(tmp_path):
    inside = {
        str((tmp_path / "web" / "entry.js").resolve()),
        str((tmp_path / "web" / "nested" / "worker.js").resolve()),
    }
    outside = str((tmp_path / "server" / "unused.js").resolve())
    patterns = ", ".join(f"'entry-{index}*.js'" for index in range(513))
    build_file = tmp_path / "build.mjs"
    _write(
        build_file,
        "import { build } from 'esbuild';\n"
        "build({ absWorkingDir: 'web', "
        f"entryPoints: [{patterns}] }});\n",
    )

    result = _discover_esbuild_config_entries(
        str(build_file), inside | {outside}, str(tmp_path)
    )

    assert result == inside


def test_existing_vite_and_vitest_glob_syntax_is_preserved(tmp_path):
    sources = _write_sources(
        tmp_path,
        "page1.js",
        "a.test.ts",
        "b.test.ts",
    )
    files = {str(path.resolve()) for path in sources.values()}
    vite_config = tmp_path / "vite.config.ts"
    _write(
        vite_config,
        "export default { optimizeDeps: { entries: ['src/page?.js'] } };\n",
    )
    vitest_config = tmp_path / "vitest.config.ts"
    _write(
        vitest_config,
        "export default { test: { include: ['src/[ab].test.ts'] } };\n",
    )

    assert _discover_vite_config_entries(
        str(vite_config), files, str(tmp_path)
    ) == {str(sources["page1.js"].resolve())}
    assert _discover_vitest_config_entries(
        str(vitest_config), files, str(tmp_path)
    ) == {
        str(sources["a.test.ts"].resolve()),
        str(sources["b.test.ts"].resolve()),
    }


@pytest.mark.parametrize(
    ("command", "is_executable"),
    [
        ("node build.mjs", True),
        ("cross-env NODE_ENV=production node build.mjs", True),
        ("bun run build.mjs", True),
        ("bun --watch run build.mjs", True),
        ("pnpm tsx build.mjs", True),
        ("yarn tsx build.mjs", True),
        ("bunx tsx build.mjs", True),
        ("pnpx tsx build.mjs", True),
        ("bun -e build.mjs", False),
        ("bun --eval build.mjs", False),
        ("bun -p build.mjs", False),
        ("bun --print build.mjs", False),
        ("node --check build.mjs", False),
        ("node --help build.mjs", False),
        ("node --version build.mjs", False),
        ("node --v8-options build.mjs", False),
        ("node --definitely-invalid build.mjs", False),
        ("bun --help build.mjs", False),
        ("deno --help run build.mjs", False),
        ("deno run --definitely-invalid build.mjs", False),
        ("tsx --help build.mjs", False),
        ("ts-node --showConfig build.mjs", False),
        ("cross-env --definitely-invalid node build.mjs", False),
        ("cd web && node build.mjs", False),
        ("false && node build.mjs", False),
        ("true || node build.mjs", False),
        ("./node build.mjs", False),
        ("tools/node build.mjs", False),
        ("./npx node build.mjs", False),
        ("./cross-env node build.mjs", False),
        ("echo build.mjs", False),
    ],
)
def test_package_scripts_distinguish_executed_build_files(
    tmp_path, command, is_executable
):
    build_file = tmp_path / "build.mjs"
    _write(build_file, "export {};\n")
    _write(
        tmp_path / "package.json", json.dumps({"scripts": {"build": command}})
    )

    direct, executable, _ = _discover_script_entry_candidates(str(tmp_path))

    assert str(build_file.resolve()) in direct
    assert (str(build_file.resolve()) in executable) is is_executable


@pytest.mark.parametrize("suffix", ["?not-a-real-path", "#not-a-real-path"])
def test_package_script_paths_do_not_strip_query_or_fragment(suffix, tmp_path):
    build_file = tmp_path / "build.mjs"
    _write(build_file, "export {};\n")
    _write(
        tmp_path / "package.json",
        json.dumps({"scripts": {"build": f"node build.mjs{suffix}"}}),
    )

    direct, executable, _ = _discover_script_entry_candidates(str(tmp_path))

    assert direct == set()
    assert executable == set()


@pytest.mark.parametrize("command", ["pnpm vite", "yarn vite"])
def test_package_managers_preserve_custom_runner_configs(command, tmp_path):
    config = tmp_path / "custom.config.ts"
    _write(config, "export default {};\n")
    _write(
        tmp_path / "package.json",
        json.dumps(
            {"scripts": {"test": f"{command} --config custom.config.ts"}}
        ),
    )

    _, _, configs = _discover_script_entry_candidates(str(tmp_path))

    assert configs == {str(config.resolve()): ("vite", str(tmp_path))}
