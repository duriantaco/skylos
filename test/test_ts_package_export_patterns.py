"""Package export patterns require exact published-source mapping."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript.analysis import _discover_package_entry_files
from test.fixture_paths import make_fixture_directory, write_fixture


def _project(tmp_path, exports, *, build=True, exclude=None):
    root = make_fixture_directory(tmp_path, "project")
    write_fixture(
        root,
        "package.json",
        json.dumps(
            {"name": "public-library", "main": "./src/main.ts", "exports": exports}
        ),
    )
    write_fixture(root, "src/main.ts", "import './internal';\n")
    write_fixture(
        root,
        "src/utils/url.ts",
        'export const decodeURIComponent_ = (value: string) => value;\ndecodeURIComponent_("ok");\n',
    )
    write_fixture(
        root,
        "src/internal.ts",
        'export const internalOnly = (value: string) => value;\ninternalOnly("ok");\n',
    )
    if build:
        write_fixture(
            root,
            "tsconfig.base.json",
            json.dumps({"compilerOptions": {"declaration": True}}),
        )
        write_fixture(
            root,
            "tsconfig.build.json",
            json.dumps(
                {
                    "extends": "./tsconfig.base.json",
                    "compilerOptions": {"rootDir": "./src", "outDir": "./dist/types"},
                    "include": ["src/**/*.ts"],
                    "exclude": exclude or ["src/**/*.test.ts"],
                }
            ),
        )
    return root


def _names(root, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    result = json.loads(
        analyze(
            str(root),
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return {
        row["name"]
        for row in result.get("unused_exports", [])
        if row.get("rule_id") == "SKY-E004"
    }


@pytest.mark.parametrize(
    "exports",
    [
        {
            "./utils/*": {
                "types": "./dist/types/utils/*.d.ts",
                "import": "./dist/utils/*.js",
                "require": "./dist/cjs/utils/*.js",
            }
        },
        {"./utils/*": {"types": "./dist/types/utils/*.d.ts"}},
        {"./utils/*": "./src/utils/*.ts"},
    ],
)
def test_published_pattern_keeps_only_its_source_interface(
    tmp_path, monkeypatch, exports
):
    root = _project(tmp_path, exports)
    assert _names(root, monkeypatch) == {"internalOnly"}


@pytest.mark.parametrize(
    "exports,build,exclude",
    [
        ({"./utils/*": "./dist/other/*.js"}, True, None),
        ({"./utils/*": "./dist/utils/*.js"}, False, None),
        ({"./utils/*": {"types": "./dist/types/utils/*.d.ts"}}, True, ["src/utils/**"]),
        ({"./utils/*": None}, True, None),
        (
            {"./utils/*": {"default": None, "types": "./dist/types/utils/*.d.ts"}},
            True,
            None,
        ),
        (
            {"./utils/*": {"types": "./dist/types/utils/*.d.ts"}, "./utils/url": None},
            True,
            None,
        ),
        ({"./utils/*": "./src/utils/*.ts", "./utils/u*": None}, True, None),
        (
            {"./utils/*": "./src/utils/*.ts", "./utils/url": "./src/internal.ts"},
            True,
            None,
        ),
        ({"./other/*": "./src/other/*.ts"}, True, None),
        ({"./utils/*": "../other/src/utils/*.ts"}, True, None),
    ],
)
def test_unpublished_or_blocked_patterns_keep_the_export_warning(
    tmp_path, monkeypatch, exports, build, exclude
):
    root = _project(tmp_path, exports, build=build, exclude=exclude)
    assert "decodeURIComponent_" in _names(root, monkeypatch)


def test_conditional_interface_does_not_publish_later_default_branch(
    tmp_path, monkeypatch
):
    root = _project(
        tmp_path, {"./utils/*": {"node": "./src/other/*.ts", "default": None}}
    )
    assert "decodeURIComponent_" in _names(root, monkeypatch)


def test_nested_package_does_not_borrow_parent_wildcard(tmp_path):
    root = _project(tmp_path, {"./*": "./src/*.ts"})
    write_fixture(root, "src/nested/package.json", '{"name":"nested-private"}')
    nested = write_fixture(
        root, "src/nested/url.ts", "export const privateNested = 1;\n"
    )
    entries = _discover_package_entry_files(str(root))
    assert str(nested.resolve()) not in entries


def test_mapped_declaration_does_not_publish_source_excluded_by_build(tmp_path):
    root = _project(tmp_path, {"./utils/*": {"types": "./dist/types/utils/*.d.ts"}})
    ignored = write_fixture(
        root, "src/utils/url.test.ts", "export const testOnly = 1;\n"
    )
    entries = _discover_package_entry_files(str(root))
    assert str(ignored.resolve()) not in entries


def test_external_symlink_target_does_not_supply_package_interface(tmp_path):
    root = _project(tmp_path, {"./utils/*": "./src/utils/*.ts"})
    external = write_fixture(tmp_path, "outside.ts", "export const outside = 1;\n")
    link = root / "src/utils/outside.ts"
    try:
        link.symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert str(external.resolve()) not in _discover_package_entry_files(str(root))


def test_direct_javascript_pattern_only_publishes_existing_js_module(
    tmp_path, monkeypatch
):
    root = _project(tmp_path, {"./utils/*": "./src/utils/*.js"}, build=False)
    write_fixture(
        root,
        "src/utils/runtime.js",
        "export const runtimeOnly = (v) => v;\nruntimeOnly('x');\n",
    )
    names = _names(root, monkeypatch)
    assert "runtimeOnly" not in names
    assert "decodeURIComponent_" in names
    assert "internalOnly" in names


@pytest.mark.parametrize(
    "options",
    [{"noEmit": True}, {"outFile": "./dist/bundle.js"}, {"declaration": False}],
)
def test_non_emitting_or_bundled_configs_do_not_prove_per_file_interface(
    tmp_path, monkeypatch, options
):
    root = _project(tmp_path, {"./utils/*": {"types": "./dist/types/utils/*.d.ts"}})
    path = root / "tsconfig.build.json"
    config = json.loads(path.read_text())
    config["compilerOptions"].update(options)
    write_fixture(root, "tsconfig.build.json", json.dumps(config), overwrite=True)
    assert "decodeURIComponent_" in _names(root, monkeypatch)


def test_invalid_dot_segment_target_does_not_publish_module(tmp_path, monkeypatch):
    root = _project(tmp_path, {"./utils/*": "./src/./utils/*.ts"})
    assert "decodeURIComponent_" in _names(root, monkeypatch)


def test_url_encoded_capture_does_not_publish_literal_percent_filename(tmp_path):
    root = _project(tmp_path, {"./utils/*": "./src/utils/*.ts"})
    encoded = write_fixture(root, "src/utils/%2e.ts", "export const encoded = 1;\n")
    assert str(encoded.resolve()) not in _discover_package_entry_files(str(root))


def test_oversized_export_map_supplies_no_new_pattern_proof(tmp_path, monkeypatch):
    exports = {
        "./utils/*": "./src/utils/*.ts",
        **{f"./blocked-{index}": None for index in range(128)},
    }
    root = _project(tmp_path, exports)
    assert "decodeURIComponent_" in _names(root, monkeypatch)
