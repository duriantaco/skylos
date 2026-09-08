import ast
import inspect
import json
import os
import pathlib

import pytest

from skylos.analysis import ast_cache
from skylos.analysis.ast_cache import (
    MODE_IGNORE,
    MODE_REPLACE,
    MODE_SAFE_IGNORE_1MB,
    MODE_SAFE_REPLACE_2MB,
    MODE_STRICT,
    clear_python_ast_cache,
    load_python_module,
    load_python_source,
    mode_max_bytes,
    python_ast_cache_session,
    register_dependent_clear,
)
from skylos.analyzer import Skylos
from skylos.deadcode.python_ast import parse_python_files
from skylos.reporting.architecture_result import _architecture_module_trees
from skylos.rules.ai_defect import phantom_refs
from skylos.rules.ai_defect.api_signature_hallucination import (
    MAX_PYTHON_API_SIGNATURE_SOURCE_BYTES,
)
from skylos.rules.ai_defect.python_api_hallucination import (
    scan_python_local_api_hallucinations,
)

ALL_MODES = (
    MODE_REPLACE,
    MODE_STRICT,
    MODE_IGNORE,
    MODE_SAFE_REPLACE_2MB,
    MODE_SAFE_IGNORE_1MB,
)


@pytest.fixture(autouse=True)
def _isolated_cache():
    clear_python_ast_cache()
    yield
    clear_python_ast_cache()


def _write(path, source):
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        source,
        encoding="utf-8",
    )
    return path


def test_every_read_mode_shares_one_source_object_and_one_tree(tmp_path):
    path = _write(tmp_path / "module.py", "x = 1\n")

    results = [load_python_module(path, mode) for mode in ALL_MODES]

    assert len({id(source) for source, _ in results}) == 1
    assert len({id(tree) for _, tree in results}) == 1
    assert len(ast_cache._trees[str(path)]) == 1


def test_safe_modes_refuse_symlinks_that_plain_modes_follow(tmp_path):
    target = _write(tmp_path / "real.py", "x = 1\n")
    link = tmp_path / "link.py"
    link.symlink_to(target)

    assert load_python_source(link, MODE_REPLACE) == "x = 1\n"
    assert load_python_source(link, MODE_SAFE_REPLACE_2MB) is None


def test_edited_file_is_reread_even_when_the_size_is_unchanged(tmp_path):
    path = _write(tmp_path / "module.py", "x = 1\n")
    first_source, first_tree = load_python_module(path, MODE_REPLACE)
    assert first_source == "x = 1\n"

    _write(path, "x = 9\n")
    os.utime(path, ns=(0, 0))

    second_source, second_tree = load_python_module(path, MODE_REPLACE)
    assert second_source == "x = 9\n"
    assert second_tree is not first_tree


def test_editing_a_file_runs_registered_dependent_clears(tmp_path):
    calls = []

    def _record():
        calls.append(1)

    register_dependent_clear(_record)
    try:
        path = _write(tmp_path / "module.py", "x = 1\n")
        load_python_module(path, MODE_REPLACE)
        calls.clear()

        _write(path, "x = 1\ny = 2\n")
        load_python_module(path, MODE_REPLACE)

        assert calls
    finally:
        ast_cache._dependent_clears.remove(_record)


def test_unreadable_and_unparsable_files_return_none(tmp_path):
    unparsable = _write(tmp_path / "broken.py", "def (:\n")
    source, tree = load_python_module(unparsable, MODE_IGNORE)
    assert source == "def (:\n"
    assert tree is None

    assert load_python_module(tmp_path / "absent.py", MODE_REPLACE) == (None, None)


def test_clear_drops_every_cache(tmp_path):
    path = _write(tmp_path / "module.py", "x = 1\n")
    load_python_module(path, MODE_REPLACE)
    assert ast_cache._sources

    clear_python_ast_cache()

    assert not ast_cache._sources
    assert not ast_cache._trees
    assert not ast_cache._source_pool
    assert not ast_cache._path_tokens


def test_mode_max_bytes_is_the_documented_cap():
    assert mode_max_bytes(MODE_SAFE_IGNORE_1MB) == 1_000_000
    assert mode_max_bytes(MODE_SAFE_IGNORE_1MB) == MAX_PYTHON_API_SIGNATURE_SOURCE_BYTES
    assert mode_max_bytes(MODE_SAFE_REPLACE_2MB) == 2 * 1024 * 1024
    assert mode_max_bytes(MODE_REPLACE) is None


def test_repeated_rule_scans_see_edits_made_between_them(tmp_path):
    lib = _write(tmp_path / "lib.py", "def real():\n    return 1\n")
    app = _write(tmp_path / "app.py", "import lib\n\nlib.missing()\n")
    files = [lib, app]

    findings, _ = scan_python_local_api_hallucinations(
        tmp_path, files, target_files=files
    )
    assert [finding["simple_name"] for finding in findings] == ["missing"]

    _write(lib, "def real():\n    return 1\n\n\ndef missing():\n    return 2\n")

    findings, _ = scan_python_local_api_hallucinations(
        tmp_path, files, target_files=files
    )
    assert findings == []


def test_analyze_releases_the_run_scoped_cache(tmp_path):
    _write(tmp_path / "module.py", "import os\n\n\ndef f():\n    return os.path\n")

    Skylos().analyze(str(tmp_path), enable_ai_defects=True)

    assert not ast_cache._sources
    assert not ast_cache._trees


def test_one_unparsable_file_does_not_suppress_phantom_calls_elsewhere(tmp_path):
    _write(tmp_path / "a_broken.py", "def (:\n")
    _write(
        tmp_path / "b_phantom.py",
        "def process(data):\n    clean = sanitize_input(data)\n    return clean\n",
    )

    result = json.loads(Skylos().analyze(str(tmp_path), enable_ai_defects=True))

    rule_ids = {finding.get("rule_id") for finding in result.get("ai_defects", [])}
    assert "SKY-L012" in rule_ids


def test_public_scanner_releases_everything_it_cached(tmp_path):
    lib = _write(tmp_path / "lib.py", "def real():\n    return 1\n")
    app = _write(tmp_path / "app.py", "import lib\n\nlib.missing()\n")

    scan_python_local_api_hallucinations(tmp_path, [lib, app], target_files=[lib, app])

    assert not ast_cache._sources
    assert not ast_cache._trees
    assert not ast_cache._source_pool
    assert not ast_cache._path_tokens
    assert not phantom_refs._AST_INDEX_CACHE
    assert not phantom_refs._SCOPE_INFOS_CACHE
    assert not phantom_refs._MODULE_FACTS_CACHE
    assert not phantom_refs._POSTPONED_ANNOTATION_CACHE


def test_nested_sessions_share_until_the_outermost_one_exits(tmp_path):
    path = _write(tmp_path / "module.py", "x = 1\n")

    with python_ast_cache_session():
        with python_ast_cache_session():
            _, inner_tree = load_python_module(path, MODE_REPLACE)
        assert ast_cache._trees
        _, outer_tree = load_python_module(path, MODE_REPLACE)
        assert outer_tree is inner_tree

    assert not ast_cache._trees


def test_a_scanner_nested_in_a_session_does_not_drop_it(tmp_path):
    lib = _write(tmp_path / "lib.py", "def real():\n    return 1\n")
    app = _write(tmp_path / "app.py", "import lib\n\nlib.real()\n")

    with python_ast_cache_session():
        _, tree = load_python_module(lib, MODE_REPLACE)
        scan_python_local_api_hallucinations(
            tmp_path, [lib, app], target_files=[lib, app]
        )
        assert ast_cache._trees
        assert load_python_module(lib, MODE_REPLACE)[1] is tree

    assert not ast_cache._trees


def test_rewrite_that_preserves_size_and_mtime_is_still_seen(tmp_path):
    path = _write(tmp_path / "module.py", "x = 111\n")
    before = path.stat()
    load_python_module(path, MODE_REPLACE)

    _write(path, "x = 222\n")
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_size == before.st_size
    assert path.stat().st_mtime_ns == before.st_mtime_ns

    source, _ = load_python_module(path, MODE_REPLACE)
    assert source == "x = 222\n"


def test_only_the_reference_context_module_facts_are_memoized():
    tree = ast.parse("x = 1\n")

    phantom_refs._collect_module_facts(
        tree, "m", set(), include_reference_context=False
    )
    assert not phantom_refs._MODULE_FACTS_CACHE

    phantom_refs._collect_module_facts(tree, "m", set(), include_reference_context=True)
    assert len(phantom_refs._MODULE_FACTS_CACHE) == 1


def test_analyze_keeps_its_explicit_public_signature():
    parameters = inspect.signature(Skylos.analyze).parameters

    assert "path" in parameters
    assert parameters["thr"].default == 60
    assert not any(
        parameter.kind is parameter.VAR_KEYWORD for parameter in parameters.values()
    )
    assert Skylos.analyze.__name__ == "analyze"


def test_parse_python_files_releases_the_cache_but_keeps_its_result(tmp_path):
    first = _write(tmp_path / "a.py", "x = 1\n")
    second = _write(tmp_path / "b.py", "y = 2\n")

    parsed = parse_python_files([first, second])

    assert [entry.path for entry in parsed] == [first, second]
    assert all(isinstance(entry.tree, ast.Module) for entry in parsed)
    assert not ast_cache._sources
    assert not ast_cache._trees
    assert not ast_cache._source_pool


def test_parse_python_files_shares_trees_inside_an_open_session(tmp_path):
    path = _write(tmp_path / "a.py", "x = 1\n")

    with python_ast_cache_session():
        _, tree = load_python_module(path, MODE_STRICT)
        parsed = parse_python_files([path])
        assert parsed[0].tree is tree
        assert ast_cache._trees

    assert not ast_cache._trees


def test_an_analyze_nested_in_a_session_does_not_wipe_it(tmp_path):
    path = _write(tmp_path / "module.py", "x = 1\n")

    with python_ast_cache_session():
        _, tree = load_python_module(path, MODE_REPLACE)
        Skylos().analyze(str(tmp_path))
        assert load_python_module(path, MODE_REPLACE)[1] is tree

    assert not ast_cache._trees


def test_the_outermost_session_starts_from_a_clean_cache(tmp_path):
    path = _write(tmp_path / "module.py", "x = 1\n")
    load_python_module(path, MODE_REPLACE)
    assert ast_cache._trees

    with python_ast_cache_session():
        assert not ast_cache._trees


def test_the_import_findings_fallback_does_not_memoize_a_foreign_tree():
    tree = ast.parse("import os\n")

    phantom_refs._direct_local_import_findings(
        pathlib.Path("x.py"),
        "m",
        tree,
        set(),
        {},
        {},
        set(),
        set(),
        set(),
        set(),
        lambda name: False,
    )

    assert not phantom_refs._AST_INDEX_CACHE


def test_architecture_module_trees_reuse_the_session_cache(tmp_path):
    root = tmp_path.resolve()
    path = _write(root / "module.py", "x = 1\n")

    with python_ast_cache_session():
        _, tree = load_python_module(path, MODE_IGNORE)
        assert _architecture_module_trees([path], {path: "m"}, {})["m"] is tree

    assert _architecture_module_trees([path], {path: "m"}, {"m": 0.5}) == {}
