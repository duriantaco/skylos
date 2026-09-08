"""Resolve declared build outputs to source without assuming a src root."""

import json
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript.analysis import (
    _discover_package_entry_files,
)
from skylos.visitors.languages.typescript.resolve import (
    MonorepoResolver,
    _candidate_package_targets,
    _resolve_from_pkg_dir,
    _resolve_path_target,
)


def _write(path, source="console.log(1);\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source, encoding="utf-8")
    return path


def _package(root, **fields):
    return _write(root / "package.json", json.dumps({"name": "example", **fields}))


@pytest.mark.parametrize("output_dir", ["dist", "out"])
@pytest.mark.parametrize("prefix", ["", "./"])
@pytest.mark.parametrize(
    ("compiled", "source"),
    [
        ("bin/palee.js", "bin/palee.ts"),
        ("bin/palee.js", "src/bin/palee.ts"),
        ("src/index.js", "src/index.ts"),
    ],
    ids=["root-bin", "src-bin", "preserved-src"],
)
def test_declared_bin_resolves_supported_source_layouts(
    tmp_path, output_dir, prefix, compiled, source
):
    target = f"{prefix}{output_dir}/{compiled}"
    expected = _write(tmp_path / source)
    _package(tmp_path, bin={"palee": target})

    assert _resolve_path_target(str(tmp_path), target) == str(expected)
    assert _discover_package_entry_files(str(tmp_path)) == {str(expected.resolve())}


@pytest.mark.parametrize(
    ("compiled_suffix", "source_suffix"),
    [
        (".js", ".ts"),
        (".js", ".tsx"),
        (".js", ".js"),
        (".jsx", ".tsx"),
        (".mjs", ".mts"),
        (".cjs", ".cts"),
        (".d.ts", ".ts"),
        (".d.ts", ".tsx"),
    ],
)
@pytest.mark.parametrize("output_dir", ["dist", "out"])
def test_root_source_fallback_keeps_extension_variants(
    tmp_path, output_dir, compiled_suffix, source_suffix
):
    target = f"./{output_dir}/bin/launch{compiled_suffix}"
    expected = _write(tmp_path / "bin" / f"launch{source_suffix}")

    assert _resolve_path_target(str(tmp_path), target) == str(expected)


@pytest.mark.parametrize(
    "entry_fields",
    [
        {"bin": "./dist/bin/launch.js"},
        {"bin": {"launch": "./dist/bin/launch.js"}},
        {"main": "./dist/bin/launch.js"},
        {"module": "./dist/bin/launch.js"},
        {"source": "./dist/bin/launch.js"},
        {"types": "./dist/bin/launch.d.ts"},
        {"typings": "./dist/bin/launch.d.ts"},
        {"browser": {"./server.js": "./dist/bin/launch.js", "fs": False}},
        {"exports": {".": {"import": "./dist/bin/launch.js"}}},
        {"exports": ["./dist/bin/launch.js", "./out/bin/launch.js"]},
    ],
    ids=[
        "bin-string",
        "bin-map",
        "main",
        "module",
        "source",
        "types",
        "typings",
        "browser",
        "exports",
        "exports-array",
    ],
)
def test_all_package_entry_fields_use_root_source_fallback(tmp_path, entry_fields):
    expected = _write(tmp_path / "bin" / "launch.ts")
    _package(tmp_path, **entry_fields)

    assert _discover_package_entry_files(str(tmp_path)) == {str(expected.resolve())}


@pytest.mark.parametrize("output_dir", ["dist", "out"])
def test_existing_src_mapping_wins_over_root_and_compiled_fallbacks(
    tmp_path, output_dir
):
    expected = _write(tmp_path / "src" / "bin" / "launch.ts")
    _write(tmp_path / "bin" / "launch.ts")
    _write(tmp_path / output_dir / "bin" / "launch.js")
    target = f"./{output_dir}/bin/launch.js"
    _package(tmp_path, bin=target)

    assert _resolve_path_target(str(tmp_path), target) == str(expected)
    assert _discover_package_entry_files(str(tmp_path)) == {str(expected.resolve())}


@pytest.mark.parametrize("output_dir", ["dist", "out"])
def test_root_source_wins_over_compiled_fallback(tmp_path, output_dir):
    expected = _write(tmp_path / "bin" / "launch.ts")
    _write(tmp_path / output_dir / "bin" / "launch.js")

    assert _resolve_path_target(str(tmp_path), f"{output_dir}/bin/launch.js") == str(
        expected
    )


@pytest.mark.parametrize("output_dir", ["dist", "out"])
def test_declared_compiled_file_remains_resolvable_without_sources(
    tmp_path, output_dir
):
    expected = _write(tmp_path / output_dir / "bin" / "launch.js")

    assert _resolve_path_target(str(tmp_path), f"./{output_dir}/bin/launch.js") == str(
        expected
    )


@pytest.mark.parametrize(
    ("literal_dir", "wrong_dir"),
    [
        ("checkout", "checksrc"),
        ("redist", "resrc"),
        ("src/out", "src/src"),
        ("src/dist", "src/src"),
        ("tools/dist", "tools/src"),
    ],
)
def test_output_words_inside_source_paths_are_not_rewritten(
    tmp_path, literal_dir, wrong_dir
):
    expected = _write(tmp_path / literal_dir / "launch.ts")
    _write(tmp_path / wrong_dir / "launch.ts")
    target = f"./{literal_dir}/launch.js"

    assert _resolve_path_target(str(tmp_path), target) == str(expected)
    assert all(
        wrong_dir not in candidate for candidate in _candidate_package_targets(target)
    )


def test_nested_source_output_word_is_preserved_after_leading_prefix(tmp_path):
    expected = _write(tmp_path / "src" / "out" / "launch.ts")
    _write(tmp_path / "src" / "src" / "launch.ts")

    assert _resolve_path_target(str(tmp_path), "./dist/out/launch.js") == str(expected)


def test_existing_prod_source_mapping_is_preserved(tmp_path):
    expected = _write(tmp_path / "src" / "launch.ts")

    assert _resolve_path_target(str(tmp_path), "./dist/prod/launch.js") == str(expected)


def test_missing_entry_does_not_root_unrelated_files(tmp_path):
    _write(tmp_path / "bin" / "unused.ts")
    _package(tmp_path, bin="./dist/bin/missing.js")

    assert _discover_package_entry_files(str(tmp_path)) == set()


def test_candidates_preserve_family_precedence_and_are_unique():
    candidates = _candidate_package_targets("./dist/bin/launch.js")

    assert candidates.index("./src/bin/launch.ts") < candidates.index("./bin/launch.ts")
    assert candidates.index("./bin/launch.ts") < candidates.index(
        "./dist/bin/launch.js"
    )
    assert len(candidates) == len(set(candidates))


@pytest.mark.parametrize("field", ["source", "module", "main", "types"])
def test_package_fallback_consumer_handles_non_index_root_source(tmp_path, field):
    expected = _write(tmp_path / "lib" / "public-api.ts")
    _package(tmp_path, **{field: "./dist/lib/public-api.js"})

    assert _resolve_from_pkg_dir(str(tmp_path)) == str(expected)


@pytest.mark.parametrize("wildcard", [False, True])
def test_package_import_maps_share_source_fallback(tmp_path, wildcard):
    expected = _write(tmp_path / "lib" / "helpers.ts")
    importer = _write(tmp_path / "app.ts")
    imports = (
        {"#lib/*": "./dist/lib/*.js"}
        if wildcard
        else {"#lib/helpers": "./dist/lib/helpers.js"}
    )
    _package(tmp_path, imports=imports)

    assert MonorepoResolver(str(tmp_path)).resolve(
        "#lib/helpers", str(importer)
    ) == str(expected)


@pytest.mark.parametrize("subpath", [None, "helpers"])
def test_workspace_exports_share_source_fallback(tmp_path, subpath):
    package = tmp_path / "packages" / "library"
    expected = _write(package / "lib" / "helpers.ts")
    importer = _write(tmp_path / "app.ts")
    _package(tmp_path, workspaces=["packages/*"])
    _package(
        package,
        name="@example/library",
        exports={".": "./dist/lib/helpers.js", "./*": "./dist/lib/*.js"},
    )
    source = "@example/library" + (f"/{subpath}" if subpath else "")

    assert MonorepoResolver(str(tmp_path)).resolve(source, str(importer)) == str(
        expected
    )


@pytest.mark.parametrize("source_dir", ["bin", "src/bin"])
@pytest.mark.parametrize("workspace", [False, True])
def test_analyzer_preserves_only_entry_and_its_dependencies(
    tmp_path, monkeypatch, source_dir, workspace
):
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    package = tmp_path / "packages" / "cli" if workspace else tmp_path
    if workspace:
        _package(tmp_path, workspaces=["packages/*"])
    _package(package, bin={"palee": "./dist/bin/palee.js"})
    entry = _write(
        package / source_dir / "palee.ts",
        "import { helper } from './helpers';\nhelper();\n",
    )
    helper = _write(
        package / source_dir / "helpers.ts", "export function helper() { return 1; }\n"
    )
    unused = _write(
        package / source_dir / "unused.ts", "export function unused() { return 2; }\n"
    )
    decoys = set()
    if source_dir == "src/bin":
        decoy = _write(package / "bin" / "palee.ts")
        decoys.add(decoy.resolve())

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    unused_files = {
        Path(finding["file"]).resolve() for finding in result.get("unused_files", [])
    }
    assert entry.resolve() not in unused_files
    assert helper.resolve() not in unused_files
    assert unused.resolve() in unused_files
    assert decoys <= unused_files
    assert result.get("analysis_errors", []) == []


@pytest.mark.parametrize(
    ("target", "source"),
    [
        ("././dist/bin/launch.js", "src/bin/launch.ts"),
        ("dist//bin/launch.js", "bin/launch.ts"),
        ("out//bin/launch.js", "bin/launch.ts"),
        ("./dist/./bin/launch.js", "bin/launch.ts"),
        ("dist/../bin/launch.js", "bin/launch.ts"),
    ],
)
def test_redundant_path_segments_preserve_relative_source_resolution(
    tmp_path, target, source
):
    expected = _write(tmp_path / source)

    assert _resolve_path_target(str(tmp_path), target) == str(expected)
    assert all(
        not candidate.startswith("/")
        for candidate in _candidate_package_targets(target)
    )


@pytest.mark.parametrize("target", ["dist/", "out/", "dist/.", "././out/."])
def test_output_directory_targets_keep_existing_src_index_resolution(tmp_path, target):
    expected = _write(tmp_path / "src" / "index.ts")

    assert _resolve_path_target(str(tmp_path), target) == str(expected)
