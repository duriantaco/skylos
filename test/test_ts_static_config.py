"""Tool configs read as data without running project code."""

from __future__ import annotations

from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript.static_config import (
    ABSENT,
    UNKNOWN,
    JsRegex,
    OpenDict,
    lookup,
    read_static_config,
    string_values,
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def test_define_config_wrapper_bindings_spreads_and_paths(tmp_path):
    config = _write(
        tmp_path / "vitest.config.ts",
        "import { defineConfig } from 'vitest/config'\n"
        "import path from 'node:path'\n"
        "import { fileURLToPath } from 'node:url'\n"
        "const shared = { include: ['src/**/*.test.ts'] }\n"
        "const extra = ['x.ts']\n"
        "export default defineConfig({\n"
        "  test: { ...shared, setupFiles: [path.join(__dirname, 'setup.ts'), ...extra], env: process.env.X },\n"
        "  root: fileURLToPath(new URL('./app', import.meta.url)),\n"
        "  label: 'a' + 'b',\n"
        "})\n",
    )
    value = read_static_config(config)
    assert lookup(value, "test.include") == ["src/**/*.test.ts"]
    assert lookup(value, "test.setupFiles") == ["./setup.ts", "x.ts"]
    assert lookup(value, "test.env") is UNKNOWN
    assert lookup(value, "test.missing") is ABSENT
    assert lookup(value, "root") == "./app"
    assert lookup(value, "label") == "ab"


def test_unknown_spread_makes_missing_keys_unknown(tmp_path):
    config = _write(tmp_path / ".mocharc.cjs", "module.exports = { ...require('./base'), spec: 'test/**/*.js' }\n")
    value = read_static_config(config)
    assert isinstance(value, OpenDict)
    assert lookup(value, "spec") == "test/**/*.js"
    assert lookup(value, "require") is UNKNOWN


def test_arrow_config_and_computed_values(tmp_path):
    config = _write(
        tmp_path / "rollup.config.mjs",
        "export default ({ mode }) => ({ input: mode === 'x' ? 'a.ts' : 'b.ts', output: __dirname + '/dist' })\n",
    )
    value = read_static_config(config)
    assert lookup(value, "input") is UNKNOWN
    assert lookup(value, "output") == "./dist"
    assert string_values(lookup(value, "input")) == ([], False)


@pytest.mark.parametrize(
    "source",
    [
        "export default makeConfig({ entry: 'a.ts' })\n",  # not a define* wrapper
        "const c = compute(); export default c\n",
        "export default config\n",  # unbound identifier
        "if (x) { module.exports = { a: 1 } } else { module.exports = { a: 2 } }\n",
        "export default { entry: \n",  # syntax error
    ],
)
def test_configs_that_need_execution_are_unknown(tmp_path, source):
    config = _write(tmp_path / "tool.config.js", source)
    value = read_static_config(config)
    assert value is UNKNOWN or lookup(value, "entry") is UNKNOWN or lookup(value, "a") is UNKNOWN


def test_data_formats(tmp_path):
    jsonc = _write(tmp_path / "knip.jsonc", '{\n // c\n "entry": ["a.ts",], /* x */ "url": "http://x"\n}\n')
    assert read_static_config(jsonc) == {"entry": ["a.ts"], "url": "http://x"}
    yaml_file = _write(tmp_path / ".mocharc.yml", "spec:\n  - test/**/*.js\n")
    assert read_static_config(yaml_file) == {"spec": ["test/**/*.js"]}
    toml_file = _write(tmp_path / "netlify.toml", '[functions]\ndirectory = "fns"\n')
    assert lookup(read_static_config(toml_file), "functions.directory") == "fns"
    rc = _write(tmp_path / ".babelrc", '{"presets": ["@babel/preset-env"]}')
    assert read_static_config(rc) == {"presets": ["@babel/preset-env"]}
    broken = _write(tmp_path / "broken.json", "{ nope")
    assert read_static_config(broken) is UNKNOWN
    manifest = _write(tmp_path / "package.json", '{"name": "p", "knip": {"ignore": ["x"]}}')
    assert read_static_config(manifest, "knip") == {"ignore": ["x"]}
    assert read_static_config(manifest, "ava") is ABSENT


def test_regex_literals_are_data(tmp_path):
    config = _write(tmp_path / "knip.ts", "export default { ignoreDependencies: [/^@types\\//, 'lodash'] }\n")
    value = lookup(read_static_config(config), "ignoreDependencies")
    assert value[0] == JsRegex("^@types\\/", "")
    assert value[0].compile().search("@types/node")
    assert value[1] == "lodash"


def test_no_code_is_executed(tmp_path):
    marker = tmp_path / "executed"
    config = _write(
        tmp_path / "tool.config.mjs",
        f"import fs from 'node:fs'; fs.writeFileSync({str(marker)!r}, 'x');\nexport default {{ a: 1 }}\n",
    )
    assert read_static_config(config) == {"a": 1}
    assert not marker.exists()


@pytest.mark.parametrize(
    "source",
    [
        "const config = { entry: 'a.ts' }\nconfig.input = 'b.ts'\nexport default config\n",
        "const config = { entry: 'a.ts' }\nObject.assign(config, extra)\nexport default config\n",
        "module.exports = { entry: 'a.ts' }\nmodule.exports.input = 'b.ts'\n",
    ],
)
def test_a_binding_changed_later_is_open(tmp_path, source):
    config = _write(tmp_path / "tool.config.js", source)
    value = read_static_config(config)
    assert isinstance(value, OpenDict)
    assert lookup(value, "entry") == "a.ts"
    assert lookup(value, "input") is UNKNOWN
