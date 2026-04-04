import json
import pytest
from unittest.mock import patch, MagicMock

from skylos.llm.verify_orchestrator import (
    _gather_config_files,
    _build_repo_facts,
    _build_graph_context,
    _build_haiku_context,
    _batch_verify_findings,
    _deterministic_suppress,
    _get_cached_search_results,
    _find_survivors,
    _build_source_cache,
    _haiku_prefilter_exports,
    _is_public_library_symbol,
    _finding_complexity_tier,
    _entry_point_cache_path,
    _config_files_hash,
    discover_entry_points,
    verify_with_graph_context,
    challenge_survivor,
    run_verification,
    EntryPoint,
    RepoFacts,
    SuppressionDecision,
    SurvivorVerdict,
    VerifyStats,
)
from skylos.llm.dead_code_verifier import (
    DeadCodeVerifierAgent,
    Verdict,
    VerificationResult,
)


@pytest.fixture
def sample_finding():
    return {
        "name": "old_helper",
        "full_name": "mymodule.old_helper",
        "simple_name": "old_helper",
        "type": "function",
        "file": "/tmp/test_project/mymodule.py",
        "line": 10,
        "confidence": 75,
        "references": 0,
        "calls": ["mymodule.utils.format_data"],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
        "why_unused": ["unreferenced"],
        "why_confidence_reduced": [],
    }


@pytest.fixture
def sample_finding_with_callers():
    return {
        "name": "process_item",
        "full_name": "mymodule.process_item",
        "simple_name": "process_item",
        "type": "function",
        "file": "/tmp/test_project/mymodule.py",
        "line": 20,
        "confidence": 65,
        "references": 0,
        "calls": [],
        "called_by": ["mymodule.batch_processor"],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
        "why_unused": ["all_callers_dead"],
        "why_confidence_reduced": [],
    }


@pytest.fixture
def sample_defs_map():
    return {
        "mymodule.old_helper": {
            "name": "mymodule.old_helper",
            "file": "/tmp/test_project/mymodule.py",
            "line": 10,
            "type": "function",
        },
        "mymodule.batch_processor": {
            "name": "mymodule.batch_processor",
            "file": "/tmp/test_project/mymodule.py",
            "line": 30,
            "type": "function",
        },
        "mymodule.utils.format_data": {
            "name": "mymodule.utils.format_data",
            "file": "/tmp/test_project/utils.py",
            "line": 5,
            "type": "function",
        },
    }


@pytest.fixture
def sample_source_cache():
    return {
        "/tmp/test_project/mymodule.py": (
            "import os\n"
            "import json\n"
            "\n"
            "def main():\n"
            "    print('hello')\n"
            "\n"
            "def used_func():\n"
            "    return 42\n"
            "\n"
            "def old_helper(x):\n"
            "    return x * 2\n"
            "\n"
            "def process_item(item):\n"
            "    return item.strip()\n"
            "\n"
            "def batch_processor(items):\n"
            "    for item in items:\n"
            "        process_item(item)\n"
        ),
    }


@pytest.fixture
def survivor_with_heuristic():
    return {
        "name": "process",
        "full_name": "mymodule.Handler.process",
        "simple_name": "process",
        "file": "/tmp/test_project/mymodule.py",
        "line": 25,
        "type": "method",
        "confidence": 45,
        "references": 1,
        "heuristic_refs": {"same_file_attr": 1.0, "global_attr": 0.3},
    }


@pytest.fixture
def mock_agent():
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    return agent


def test_gather_config_files(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.poetry]\nname = 'test'")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCMD python app.py")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "code.py").write_text("x = 1")

    configs = _gather_config_files(tmp_path)
    assert "pyproject.toml" in configs
    assert "Dockerfile" in configs
    assert "src/code.py" not in configs


def test_gather_config_files_empty(tmp_path):
    configs = _gather_config_files(tmp_path)
    assert configs == {}


def test_gather_config_files_truncates_large(tmp_path):
    (tmp_path / "pyproject.toml").write_text("x" * 20_000)
    configs = _gather_config_files(tmp_path)
    assert "truncated" in configs["pyproject.toml"]


def test_build_repo_facts_parses_pytest_and_mkdocs(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'python_classes = ["Test", "Acceptance"]\n'
        'python_functions = ["test"]\n'
    )
    (tmp_path / "mkdocs.yml").write_text("hooks:\n  - scripts/mkdocs_hooks.py\n")

    facts = _build_repo_facts(tmp_path)

    assert facts.pytest_class_patterns == ["Test", "Acceptance"]
    assert facts.pytest_function_patterns == ["test"]
    assert "scripts/mkdocs_hooks.py" in facts.mkdocs_hook_files


def test_build_graph_context_basic(
    sample_finding, sample_defs_map, sample_source_cache
):
    ctx = _build_graph_context(sample_finding, sample_defs_map, sample_source_cache)
    assert "mymodule.old_helper" in ctx
    assert "NOBODY calls this function" in ctx
    assert "Flagged Symbol" in ctx


def test_build_graph_context_with_callers(
    sample_finding_with_callers, sample_defs_map, sample_source_cache
):
    ctx = _build_graph_context(
        sample_finding_with_callers, sample_defs_map, sample_source_cache
    )
    assert "mymodule.batch_processor" in ctx
    assert "Caller:" in ctx


def test_build_graph_context_with_heuristic_refs(sample_defs_map, sample_source_cache):
    finding = {
        "name": "process",
        "full_name": "mod.process",
        "file": "/tmp/test_project/mymodule.py",
        "line": 5,
        "confidence": 50,
        "references": 0,
        "calls": [],
        "called_by": [],
        "heuristic_refs": {"same_file_attr": 2.0},
        "dynamic_signals": ["getattr"],
    }
    ctx = _build_graph_context(finding, sample_defs_map, sample_source_cache)
    assert "Heuristic refs" in ctx
    assert "Dynamic signals" in ctx
    assert "getattr" in ctx


def test_build_graph_context_compacts_low_ambiguity_dead_candidate(
    sample_defs_map,
    sample_source_cache,
):
    finding = {
        "name": "old_helper",
        "full_name": "mymodule.old_helper",
        "simple_name": "old_helper",
        "type": "function",
        "file": "/tmp/test_project/mymodule.py",
        "line": 10,
        "confidence": 75,
        "references": 0,
        "calls": [],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
        "why_unused": ["unreferenced"],
        "why_confidence_reduced": [],
    }

    with patch(
        "skylos.llm.verify_orchestrator._get_cached_search_results",
        return_value={"references_definition_only": ["mymodule.py:10:def old_helper"]},
    ):
        ctx = _build_graph_context(
            finding,
            sample_defs_map,
            sample_source_cache,
            project_root="/tmp/test_project",
        )

    assert "Search Results Across Project" not in ctx
    assert "Only the definition itself was found" in ctx
    assert "low-ambiguity dead-code candidate" in ctx
    assert len(ctx) < 2500


def test_build_graph_context_skips_search_for_low_ambiguity_dead_candidate(
    sample_defs_map,
    sample_source_cache,
):
    finding = {
        "name": "old_helper",
        "full_name": "mymodule.old_helper",
        "simple_name": "old_helper",
        "type": "function",
        "file": "/tmp/test_project/mymodule.py",
        "line": 10,
        "confidence": 75,
        "references": 0,
        "calls": [],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
        "why_unused": ["unreferenced"],
        "why_confidence_reduced": [],
    }

    with patch(
        "skylos.llm.verify_orchestrator._get_cached_search_results",
        return_value={},
    ):
        ctx = _build_graph_context(
            finding,
            sample_defs_map,
            sample_source_cache,
            project_root="/tmp/test_project",
        )

    assert "low-ambiguity dead-code candidate" in ctx


def test_deterministic_suppress_skips_search_for_private_low_ambiguity_function():
    finding = {
        "name": "_helper",
        "full_name": "mod._helper",
        "simple_name": "_helper",
        "type": "function",
        "file": "/tmp/test_project/mod.py",
        "line": 5,
        "confidence": 80,
        "references": 0,
        "calls": [],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
    }

    with patch(
        "skylos.llm.verify_orchestrator._get_cached_search_results",
        side_effect=AssertionError("search should be skipped"),
    ):
        decision = _deterministic_suppress(
            finding,
            {"/tmp/test_project/mod.py": "def _helper():\n    return 1\n"},
            project_root="/tmp/test_project",
            repo_facts=RepoFacts(),
        )

    assert decision is None


def test_deterministic_suppress_skips_search_for_private_function_with_callees():
    finding = {
        "name": "_helper",
        "full_name": "mod._helper",
        "simple_name": "_helper",
        "type": "function",
        "file": "/tmp/test_project/mod.py",
        "line": 5,
        "confidence": 80,
        "references": 0,
        "calls": ["mod.other"],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
    }

    with patch(
        "skylos.llm.verify_orchestrator._get_cached_search_results",
        side_effect=AssertionError("search should be skipped"),
    ):
        decision = _deterministic_suppress(
            finding,
            {"/tmp/test_project/mod.py": "def _helper():\n    return other()\n"},
            project_root="/tmp/test_project",
            repo_facts=RepoFacts(),
        )

    assert decision is None


def test_build_graph_context_includes_repo_facts_and_path_references(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "mkdocs.yml").write_text("hooks:\n  - scripts/mkdocs_hooks.py\n")
    scripts = proj / "scripts"
    scripts.mkdir()
    hook_file = scripts / "mkdocs_hooks.py"
    hook_file.write_text(
        "def on_nav(nav, *, config, files, **kwargs):\n    return nav\n"
    )

    finding = {
        "name": "on_nav",
        "full_name": "scripts.mkdocs_hooks.on_nav",
        "simple_name": "on_nav",
        "type": "function",
        "file": str(hook_file),
        "line": 1,
        "confidence": 75,
        "references": 0,
        "calls": [],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
        "why_unused": [],
        "why_confidence_reduced": [],
    }

    source_cache = {str(hook_file): hook_file.read_text()}
    ctx = _build_graph_context(
        finding,
        {},
        source_cache,
        project_root=str(proj),
        repo_facts=_build_repo_facts(proj),
    )

    assert "MkDocs hook registration: yes" in ctx
    assert "Config refs" in ctx or "File path refs" in ctx


def test_build_graph_context_includes_file_path_references_for_cli_target(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    assets = proj / "tests" / "assets" / "cli"
    assets.mkdir(parents=True)
    target_file = assets / "func_other_name.py"
    target_file.write_text("def some_function(name='World'):\n    return name\n")
    test_file = proj / "tests" / "test_cli.py"
    test_file.write_text(
        "import subprocess\n\n"
        "def test_script():\n"
        "    subprocess.run([\n"
        "        'python', '-m', 'typer',\n"
        "        'tests/assets/cli/func_other_name.py',\n"
        "        'run',\n"
        "    ])\n"
    )

    finding = {
        "name": "some_function",
        "full_name": "tests.assets.cli.func_other_name.some_function",
        "simple_name": "some_function",
        "type": "function",
        "file": str(target_file),
        "line": 1,
        "confidence": 75,
        "references": 0,
        "calls": [],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
        "why_unused": [],
        "why_confidence_reduced": [],
    }

    source_cache = {str(target_file): target_file.read_text()}
    ctx = _build_graph_context(
        finding,
        {},
        source_cache,
        project_root=str(proj),
        repo_facts=_build_repo_facts(proj),
    )

    assert "File path refs" in ctx
    assert "tests/assets/cli/func_other_name.py" in ctx


def test_build_graph_context_includes_compatibility_notes(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "CHANGELOG.md").write_text(
        "* Reintroduced supposedly-private `URLTypes` shortcut for backwards compatibility.\n"
    )
    source_file = proj / "_types.py"
    source_file.write_text('URLTypes = Union["URL", str]\n')

    finding = {
        "name": "URLTypes",
        "full_name": "_types.URLTypes",
        "simple_name": "URLTypes",
        "type": "variable",
        "file": str(source_file),
        "line": 1,
        "confidence": 90,
        "references": 0,
        "calls": [],
        "called_by": [],
        "decorators": [],
        "heuristic_refs": {},
        "dynamic_signals": [],
        "framework_signals": [],
        "why_unused": [],
        "why_confidence_reduced": [],
    }

    ctx = _build_graph_context(
        finding,
        {},
        {str(source_file): source_file.read_text()},
        project_root=str(proj),
        repo_facts=RepoFacts(),
    )

    assert "Compatibility retention notes: yes" in ctx
    assert "Compatibility notes" in ctx


def test_find_survivors_basic():
    defs_map = {
        "mod.alive_func": {
            "type": "function",
            "references": 5,
            "heuristic_refs": {},
            "file": "x.py",
            "line": 1,
        },
        "mod.suspect": {
            "type": "function",
            "references": 1,
            "heuristic_refs": {"same_file_attr": 1.0},
            "file": "x.py",
            "line": 10,
            "confidence": 50,
        },
        "mod.variable": {
            "type": "variable",
            "references": 0,
            "heuristic_refs": {"global_attr": 0.1},
            "file": "x.py",
            "line": 20,
        },
    }

    survivors = _find_survivors(defs_map, [])
    names = [s["full_name"] for s in survivors]
    assert "mod.suspect" in names
    assert "mod.variable" not in names
    assert "mod.alive_func" not in names


def test_find_survivors_excludes_already_flagged():
    defs_map = {
        "mod.suspect": {
            "type": "function",
            "references": 1,
            "heuristic_refs": {"same_file_attr": 1.0},
            "file": "x.py",
            "line": 10,
            "confidence": 50,
        },
    }
    already_flagged = [{"full_name": "mod.suspect", "name": "suspect"}]

    survivors = _find_survivors(defs_map, already_flagged)
    assert len(survivors) == 0


def test_find_survivors_sorted_by_heuristic_score():
    defs_map = {
        "mod.low": {
            "type": "function",
            "references": 1,
            "heuristic_refs": {"global_attr": 0.1},
            "file": "x.py",
            "line": 1,
            "confidence": 50,
        },
        "mod.high": {
            "type": "function",
            "references": 1,
            "heuristic_refs": {"same_file_attr": 3.0, "global_attr": 1.0},
            "file": "x.py",
            "line": 10,
            "confidence": 50,
        },
    }

    survivors = _find_survivors(defs_map, [])
    assert survivors[0]["full_name"] == "mod.high"


def test_build_source_cache(tmp_path):
    f1 = tmp_path / "a.py"
    f1.write_text("def foo(): pass")

    findings = [{"file": str(f1), "called_by": []}]
    cache = _build_source_cache(findings, {})
    assert str(f1) in cache
    assert "def foo" in cache[str(f1)]


def test_build_source_cache_includes_caller_files(tmp_path):
    f1 = tmp_path / "a.py"
    f1.write_text("def foo(): pass")
    f2 = tmp_path / "b.py"
    f2.write_text("def bar(): foo()")

    defs_map = {"mod.bar": {"file": str(f2), "line": 1, "type": "function"}}
    findings = [{"file": str(f1), "called_by": ["mod.bar"]}]

    cache = _build_source_cache(findings, defs_map)
    assert str(f1) in cache
    assert str(f2) in cache


def test_discover_entry_points_parses_response(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project.scripts]\nmycli = "mypackage.cli:main"'
    )

    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {
            "entry_points": [
                {
                    "name": "mypackage.cli.main",
                    "source": "pyproject.toml",
                    "reason": "console_scripts entry point",
                }
            ]
        }
    )

    eps = discover_entry_points(agent, tmp_path, [])
    assert len(eps) == 1
    assert eps[0].name == "mypackage.cli.main"
    assert eps[0].source == "pyproject.toml"


def test_discover_entry_points_skips_known(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")

    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {
            "entry_points": [
                {"name": "already.known", "source": "pyproject.toml", "reason": ""},
            ]
        }
    )

    eps = discover_entry_points(agent, tmp_path, ["already.known"])
    assert len(eps) == 0


def test_discover_entry_points_handles_bad_json(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]")

    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = "not json at all"

    eps = discover_entry_points(agent, tmp_path, [])
    assert len(eps) == 0


def test_discover_entry_points_no_configs(tmp_path):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    eps = discover_entry_points(agent, tmp_path, [])
    assert len(eps) == 0
    agent._call_llm.assert_not_called()


def test_verify_graph_context_true_positive(sample_finding, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "No dynamic dispatch found"}
    )

    result = verify_with_graph_context(
        agent,
        sample_finding,
        sample_defs_map,
        {sample_finding["file"]: "def old_helper(x):\n    return x * 2\n"},
    )
    assert result.verdict == Verdict.TRUE_POSITIVE
    assert result.adjusted_confidence > result.original_confidence


def test_verify_graph_context_false_positive(sample_finding, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {
            "verdict": "FALSE_POSITIVE",
            "rationale": "Line 15: getattr(module, 'old_helper')",
        }
    )

    result = verify_with_graph_context(agent, sample_finding, sample_defs_map, {})
    assert result.verdict == Verdict.FALSE_POSITIVE
    assert result.adjusted_confidence < result.original_confidence


def test_verify_graph_context_skips_with_refs(sample_defs_map):
    finding = {
        "name": "used_func",
        "full_name": "mod.used_func",
        "file": "x.py",
        "line": 1,
        "confidence": 70,
        "references": 3,
    }

    agent = MagicMock(spec=DeadCodeVerifierAgent)

    result = verify_with_graph_context(agent, finding, sample_defs_map, {})
    assert result.verdict == Verdict.UNCERTAIN
    assert "3 references" in result.rationale
    agent._call_llm.assert_not_called()


def test_verify_graph_context_handles_llm_error(sample_finding, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.side_effect = Exception("API timeout")

    result = verify_with_graph_context(agent, sample_finding, sample_defs_map, {})
    assert result.verdict == Verdict.UNCERTAIN
    assert "failed" in result.rationale.lower()


def test_verify_graph_context_handles_bad_json(sample_finding, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = "not json {{"

    result = verify_with_graph_context(agent, sample_finding, sample_defs_map, {})
    assert result.verdict == Verdict.UNCERTAIN


def test_verify_graph_context_strips_markdown_fences(sample_finding, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = (
        '```json\n{"verdict": "TRUE_POSITIVE", "rationale": "dead"}\n```'
    )

    result = verify_with_graph_context(agent, sample_finding, sample_defs_map, {})
    assert result.verdict == Verdict.TRUE_POSITIVE


def test_deterministic_suppress_pytest_collected_class(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'python_classes = ["Test"]\n'
        'python_functions = ["test"]\n'
    )
    test_file = proj / "test_sample.py"
    test_file.write_text(
        "class TestSample:\n    def test_case(self):\n        assert True\n"
    )
    finding = {
        "name": "TestSample",
        "full_name": "test_sample.TestSample",
        "simple_name": "TestSample",
        "type": "class",
        "file": str(test_file),
        "line": 1,
    }

    decision = _deterministic_suppress(
        finding,
        {str(test_file): test_file.read_text()},
        project_root=str(proj),
        repo_facts=_build_repo_facts(proj),
    )

    assert decision is not None
    assert decision.code == "pytest_collected_test_class"


def test_deterministic_suppress_definition_side_effect(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    test_file = proj / "test_side_effect.py"
    test_file.write_text(
        "import pytest\n\n"
        "def test_final():\n"
        "    with pytest.raises(TypeError):\n"
        "        class SubClass(FinalClass):\n"
        "            pass\n"
    )
    finding = {
        "name": "SubClass",
        "full_name": "test_side_effect.SubClass",
        "simple_name": "SubClass",
        "type": "class",
        "file": str(test_file),
        "line": 5,
    }

    decision = _deterministic_suppress(
        finding,
        {str(test_file): test_file.read_text()},
        project_root=str(proj),
        repo_facts=RepoFacts(),
    )

    assert decision is not None
    assert decision.code == "definition_side_effect"


def test_deterministic_suppress_mkdocs_hook(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "mkdocs.yml").write_text("hooks:\n  - scripts/mkdocs_hooks.py\n")
    scripts = proj / "scripts"
    scripts.mkdir()
    hook_file = scripts / "mkdocs_hooks.py"
    hook_file.write_text(
        "def on_nav(nav, *, config, files, **kwargs):\n    return nav\n"
    )
    finding = {
        "name": "on_nav",
        "full_name": "scripts.mkdocs_hooks.on_nav",
        "simple_name": "on_nav",
        "type": "function",
        "file": str(hook_file),
        "line": 1,
    }

    decision = _deterministic_suppress(
        finding,
        {str(hook_file): hook_file.read_text()},
        project_root=str(proj),
        repo_facts=_build_repo_facts(proj),
    )

    assert decision is not None
    assert decision.code == "mkdocs_hook"


def test_deterministic_suppress_callback_signature_parameter(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "app.py"
    source_file.write_text(
        "def validate_json(ctx, param, value):\n"
        "    return value\n\n"
        "option = click.option('--json', callback=validate_json)\n"
    )
    finding = {
        "name": "param",
        "full_name": "app.validate_json.param",
        "simple_name": "param",
        "type": "parameter",
        "file": str(source_file),
        "line": 1,
    }

    decision = _deterministic_suppress(
        finding,
        {str(source_file): source_file.read_text()},
        project_root=str(proj),
        repo_facts=RepoFacts(),
    )

    assert decision is not None
    assert decision.code == "parameter_signature_contract"


def test_deterministic_suppress_dynamic_globals_family(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "handlers.py"
    source = (
        "def handle_create(payload):\n"
        "    return payload\n\n"
        "def handle_update(payload):\n"
        "    return payload\n\n"
        "HANDLER_MAP = {\n"
        "    action: globals()[f\"handle_{action}\"]\n"
        "    for action in (\"create\", \"update\")\n"
        "}\n\n"
        "def dispatch(action, payload):\n"
        "    return HANDLER_MAP[action](payload)\n"
    )
    source_file.write_text(source)
    finding = {
        "name": "handle_create",
        "full_name": "handlers.handle_create",
        "simple_name": "handle_create",
        "type": "function",
        "file": str(source_file),
        "line": 1,
    }

    decision = _deterministic_suppress(
        finding,
        {str(source_file): source},
        project_root=str(proj),
        repo_facts=RepoFacts(),
    )

    assert decision is not None
    assert decision.code == "dynamic_dispatch"
    assert decision.hard is True
    assert "HANDLER_MAP" in decision.evidence[0]


def test_deterministic_suppress_dynamic_getattr_family(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "export_service.py"
    source = (
        "def export_csv(data):\n"
        "    return data\n\n"
        "def export_json(data):\n"
        "    return data\n\n"
        "def run_export(data, fmt):\n"
        "    import sys\n"
        "    handler = getattr(sys.modules[__name__], f\"export_{fmt}\", None)\n"
        "    return handler(data)\n"
    )
    source_file.write_text(source)
    finding = {
        "name": "export_json",
        "full_name": "export_service.export_json",
        "simple_name": "export_json",
        "type": "function",
        "file": str(source_file),
        "line": 4,
    }
    defs_map = {
        "export_service.run_export": {
            "name": "export_service.run_export",
            "file": str(source_file),
            "line": 7,
            "type": "function",
            "dead": False,
        }
    }

    decision = _deterministic_suppress(
        finding,
        {str(source_file): source},
        project_root=str(proj),
        repo_facts=RepoFacts(),
        defs_map=defs_map,
    )

    assert decision is not None
    assert decision.code == "dynamic_dispatch"
    assert decision.hard is True
    assert "run_export" in decision.evidence[0]


def test_public_library_symbol_detects_src_layout(tmp_path):
    pkg_dir = tmp_path / "src" / "mypkg"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text("")
    api_file = pkg_dir / "api.py"
    api_file.write_text("def public_func():\n    return 1\n")

    finding = {
        "name": "public_func",
        "simple_name": "public_func",
        "full_name": "mypkg.api.public_func",
        "type": "function",
        "file": str(api_file),
        "line": 1,
    }

    assert _is_public_library_symbol(finding, str(tmp_path)) is True


def test_cached_search_results_include_public_api_docs(tmp_path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    api_file = pkg_dir / "api.py"
    api_file.write_text("def public_func():\n    return 1\n")

    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "usage.md").write_text("Use public_func from downstream code.\n")

    finding = {
        "name": "public_func",
        "simple_name": "public_func",
        "full_name": "pkg.api.public_func",
        "type": "function",
        "file": str(api_file),
        "line": 1,
    }

    results = _get_cached_search_results(finding, str(tmp_path))

    assert "public_api_docs" in results
    assert results["public_api_docs"] == [
        f"{docs_dir / 'usage.md'}:1:Use public_func from downstream code."
    ]


def test_deterministic_suppress_documented_public_api(tmp_path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    api_file = pkg_dir / "api.py"
    source = "def public_func():\n    return 1\n"
    api_file.write_text(source)

    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "usage.md").write_text("Use public_func from downstream code.\n")

    finding = {
        "name": "public_func",
        "simple_name": "public_func",
        "full_name": "pkg.api.public_func",
        "type": "function",
        "file": str(api_file),
        "line": 1,
        "decorators": [],
        "framework_signals": [],
    }

    decision = _deterministic_suppress(
        finding,
        {str(api_file): source},
        project_root=str(tmp_path),
        repo_facts=RepoFacts(),
    )

    assert decision is not None
    assert decision.code == "documented_public_api"
    assert decision.evidence == [
        f"{docs_dir / 'usage.md'}:1:Use public_func from downstream code."
    ]


def test_challenge_survivor_dead(survivor_with_heuristic, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {
            "is_dead": True,
            "rationale": "The .process() calls are on Logger, not Handler",
            "heuristic_assessment": "spurious",
        }
    )

    sv = challenge_survivor(
        agent,
        survivor_with_heuristic,
        sample_defs_map,
        {
            "/tmp/test_project/mymodule.py": "class Handler:\n    def process(self): pass\n"
        },
    )
    assert sv.verdict == Verdict.TRUE_POSITIVE
    assert sv.suggested_confidence > sv.original_confidence


def test_challenge_survivor_alive(survivor_with_heuristic, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {
            "is_dead": False,
            "rationale": "self.handler is typed as Handler, so self.handler.process() calls this",
            "heuristic_assessment": "real",
        }
    )

    sv = challenge_survivor(agent, survivor_with_heuristic, sample_defs_map, {})
    assert sv.verdict == Verdict.FALSE_POSITIVE
    assert sv.suggested_confidence < sv.original_confidence


def test_challenge_survivor_uncertain(survivor_with_heuristic, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {
            "is_dead": False,
            "rationale": "can't determine",
            "heuristic_assessment": "uncertain",
        }
    )

    sv = challenge_survivor(agent, survivor_with_heuristic, sample_defs_map, {})
    assert sv.verdict == Verdict.UNCERTAIN
    assert sv.suggested_confidence == sv.original_confidence


def test_challenge_survivor_handles_error(survivor_with_heuristic, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.side_effect = Exception("timeout")

    sv = challenge_survivor(agent, survivor_with_heuristic, sample_defs_map, {})
    assert sv.verdict == Verdict.UNCERTAIN


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_full_pipeline(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value
    call_count = [0]

    def mock_llm(system, user):
        call_count[0] += 1
        if "entry point" in system.lower() or "entry point" in user.lower():
            return json.dumps({"entry_points": []})
        if "survivor" in system.lower() or "heuristic" in system.lower():
            return json.dumps(
                {
                    "is_dead": True,
                    "rationale": "spurious match",
                    "heuristic_assessment": "spurious",
                }
            )
        return json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "no callers"})

    mock_instance._call_llm.side_effect = mock_llm

    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "pyproject.toml").write_text("[project]\nname='test'")
    (proj / "main.py").write_text("def old_func():\n    pass\n")

    findings = [
        {
            "name": "old_func",
            "full_name": "main.old_func",
            "file": str(proj / "main.py"),
            "line": 1,
            "confidence": 75,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        }
    ]

    defs_map = {
        "main.old_func": {
            "name": "main.old_func",
            "file": str(proj / "main.py"),
            "line": 1,
            "type": "function",
        }
    }

    result = run_verification(
        findings=findings,
        defs_map=defs_map,
        project_root=str(proj),
        model="test-model",
        api_key="test-key",
        max_verify=10,
        max_challenge=5,
        quiet=True,
    )

    assert "verified_findings" in result
    assert "new_dead_code" in result
    assert "entry_points" in result
    assert "stats" in result
    assert result["stats"]["total_findings"] == 1


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_removes_false_positives(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value
    mock_instance._call_llm.return_value = json.dumps(
        {"verdict": "FALSE_POSITIVE", "rationale": "registered via decorator"}
    )

    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "app.py").write_text("@app.route('/test')\ndef my_view():\n    pass\n")

    findings = [
        {
            "name": "my_view",
            "full_name": "app.my_view",
            "file": str(proj / "app.py"),
            "line": 2,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    stats = result["stats"]
    assert stats["verified_false_positive"] >= 1

    verified = result["verified_findings"]
    assert verified[0]["_llm_verdict"] == "FALSE_POSITIVE"


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_reopens_weak_llm_false_positive(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value
    mock_instance._call_llm.side_effect = [
        json.dumps({"verdict": "FALSE_POSITIVE", "rationale": "weak dynamic mention"}),
        json.dumps(
            {"verdict": "TRUE_POSITIVE", "rationale": "alive evidence is speculative"}
        ),
    ]

    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "app.py"
    source_file.write_text("def maybe_dead():\n    return 1\n")

    findings = [
        {
            "name": "maybe_dead",
            "full_name": "app.maybe_dead",
            "file": str(source_file),
            "line": 1,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        batch_mode=False,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    verified = result["verified_findings"][0]
    stats = result["stats"]
    assert verified["_llm_verdict"] == "TRUE_POSITIVE"
    assert verified["_suppression_audited"] is True
    assert verified["_suppression_audit_verdict"] == "TRUE_POSITIVE"
    assert verified["_llm_rationale"].startswith("[suppression-audit]")
    assert stats["verified_true_positive"] == 1
    assert stats["verified_false_positive"] == 0
    assert stats["suppression_challenged"] == 1
    assert stats["suppression_reclassified_dead"] == 1
    assert stats["llm_calls"] == 2


@patch("skylos.llm.verify_orchestrator._deterministic_suppress")
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_reopens_soft_deterministic_suppression(
    MockAgent,
    mock_deterministic_suppress,
    tmp_path,
):
    mock_instance = MockAgent.return_value
    mock_instance._call_llm.return_value = json.dumps(
        {
            "verdict": "TRUE_POSITIVE",
            "rationale": "test mention is not executable usage",
        }
    )
    mock_deterministic_suppress.return_value = SuppressionDecision(
        code="test_reference",
        rationale="Project tests mention this symbol",
        evidence=["tests/test_app.py:12"],
    )

    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "app.py"
    source_file.write_text("def maybe_dead():\n    return 1\n")

    findings = [
        {
            "name": "maybe_dead",
            "full_name": "app.maybe_dead",
            "file": str(source_file),
            "line": 1,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        batch_mode=False,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    verified = result["verified_findings"][0]
    stats = result["stats"]
    assert verified["_llm_verdict"] == "TRUE_POSITIVE"
    assert verified["_suppression_reopened"] is True
    assert verified["_suppression_overruled_reason"] == "test_reference"
    assert "_suppression_reason" not in verified
    assert stats["deterministic_suppressed"] == 0
    assert stats["verified_true_positive"] == 1
    assert stats["suppression_challenged"] == 1
    assert stats["suppression_reclassified_dead"] == 1
    assert stats["llm_calls"] == 1


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_judge_all_hard_dynamic_suppression_skips_llm(
    MockAgent, tmp_path
):
    mock_instance = MockAgent.return_value

    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "handlers.py"
    source_file.write_text(
        "def handle_create(payload):\n"
        "    return payload\n\n"
        "def handle_update(payload):\n"
        "    return payload\n\n"
        "HANDLER_MAP = {\n"
        "    action: globals()[f\"handle_{action}\"]\n"
        "    for action in (\"create\", \"update\")\n"
        "}\n\n"
        "def dispatch(action, payload):\n"
        "    return HANDLER_MAP[action](payload)\n"
    )

    findings = [
        {
            "name": "handle_create",
            "full_name": "handlers.handle_create",
            "simple_name": "handle_create",
            "file": str(source_file),
            "line": 1,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        batch_mode=False,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
        verification_mode="judge_all",
    )

    verified = result["verified_findings"][0]
    stats = result["stats"]
    assert verified["_llm_verdict"] == "FALSE_POSITIVE"
    assert verified["_suppression_reason"] == "dynamic_dispatch"
    assert stats["deterministic_suppressed"] == 1
    assert stats["llm_calls"] == 0
    mock_instance._call_llm.assert_not_called()


@patch("skylos.llm.verify_orchestrator._deterministic_suppress")
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_judge_all_uses_prefilter_fact_as_evidence(
    MockAgent,
    mock_deterministic_suppress,
    tmp_path,
):
    mock_instance = MockAgent.return_value
    mock_instance._call_llm.return_value = json.dumps(
        {"verdict": "FALSE_POSITIVE", "rationale": "signature contract keeps it alive"}
    )
    mock_deterministic_suppress.return_value = SuppressionDecision(
        code="parameter_signature_contract",
        rationale="Parameter is required by a runtime callback signature",
        evidence=["callback=handler"],
    )

    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "callbacks.py"
    source_file.write_text("def handler(request, unused):\n    return request\n")

    findings = [
        {
            "name": "unused",
            "full_name": "callbacks.handler.unused",
            "simple_name": "unused",
            "file": str(source_file),
            "line": 1,
            "confidence": 95,
            "references": 0,
            "type": "parameter",
            "calls": [],
            "called_by": [],
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        batch_mode=False,
        enable_entry_discovery=False,
        enable_suppression_challenge=False,
        enable_survivor_challenge=False,
        verification_mode="judge_all",
    )

    verified = result["verified_findings"][0]
    stats = result["stats"]
    assert verified["_llm_verdict"] == "FALSE_POSITIVE"
    assert verified.get("_deterministically_suppressed") is not True
    assert verified["_judge_prefilter_reason"] == "parameter_signature_contract"
    assert verified["_judge_prefilter_rationale"] == (
        "Parameter is required by a runtime callback signature"
    )
    assert verified["_judge_prefilter_evidence"] == ["callback=handler"]
    assert stats["deterministic_suppressed"] == 0
    assert stats["verification_mode"] == "judge_all"
    mock_instance._call_llm.assert_called_once()


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_skips_high_confidence(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value

    proj = tmp_path / "project"
    proj.mkdir()

    findings = [
        {
            "name": "obvious_dead",
            "full_name": "mod.obvious_dead",
            "file": str(proj / "mod.py"),
            "line": 1,
            "confidence": 101,
            "references": 0,
            "type": "function",
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    verified = result["verified_findings"]
    assert verified[0].get("_llm_verdict") == "SKIPPED_HIGH_CONF"


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_reports_token_usage(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value
    mock_instance._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "dead"}
    )

    adapter = MagicMock()
    adapter.total_usage = {
        "prompt_tokens": 123,
        "completion_tokens": 45,
        "total_tokens": 168,
    }
    mock_instance.get_adapter.return_value = adapter

    proj = tmp_path / "project"
    proj.mkdir()
    source_file = proj / "mod.py"
    source_file.write_text("def dead_func():\n    return 1\n")

    findings = [
        {
            "name": "dead_func",
            "full_name": "mod.dead_func",
            "file": str(source_file),
            "line": 1,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        batch_mode=False,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    stats = result["stats"]
    assert stats["prompt_tokens"] == 123
    assert stats["completion_tokens"] == 45
    assert stats["total_tokens"] == 168


def test_run_verification_reclassifies_local_on_emit_listener_without_emit(tmp_path):
    proj = tmp_path / "project"
    app = proj / "app"
    app.mkdir(parents=True)

    events_file = app / "events.py"
    events_file.write_text(
        "class EventBus:\n"
        "    @classmethod\n"
        "    def on(cls, event_name):\n"
        "        def decorator(fn):\n"
        "            return fn\n"
        "        return decorator\n\n"
        "    @classmethod\n"
        "    def emit(cls, event_name, **kwargs):\n"
        "        return None\n\n"
        "@EventBus.on('note_created')\n"
        "def on_note_created(**kwargs):\n"
        "    return kwargs\n\n"
        "@EventBus.on('note_deleted')\n"
        "def on_note_deleted(**kwargs):\n"
        "    return kwargs\n"
    )

    service_file = app / "service.py"
    service_file.write_text(
        "from app.events import EventBus\n\n"
        "def create_note():\n"
        "    EventBus.emit('note_created', title='x')\n"
    )

    defs_map = {
        "app.events.on_note_created": {
            "name": "app.events.on_note_created",
            "file": str(events_file),
            "line": 13,
            "type": "function",
            "called_by": [],
            "references": 0,
            "confidence": 50,
        },
        "app.events.on_note_deleted": {
            "name": "app.events.on_note_deleted",
            "file": str(events_file),
            "line": 17,
            "type": "function",
            "called_by": [],
            "references": 0,
            "confidence": 50,
        },
    }

    result = run_verification(
        findings=[],
        defs_map=defs_map,
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        enable_entry_discovery=False,
    )

    new_dead = result["new_dead_code"]
    assert len(new_dead) == 1
    assert new_dead[0]["full_name"] == "app.events.on_note_deleted"
    assert new_dead[0]["_source"] == "registry_survivor_challenge"
    assert "EventBus.emit('note_deleted')" in new_dead[0]["_llm_rationale"]
    assert result["stats"]["survivors_reclassified_dead"] == 1


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_uses_repo_facts_for_pytest_class(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value

    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'python_classes = ["Test"]\n'
        'python_functions = ["test"]\n'
    )
    test_file = proj / "test_mark.py"
    test_file.write_text(
        "class TestMark:\n    def test_it(self):\n        assert True\n"
    )

    findings = [
        {
            "name": "TestMark",
            "full_name": "test_mark.TestMark",
            "simple_name": "TestMark",
            "file": str(test_file),
            "line": 1,
            "confidence": 70,
            "references": 0,
            "type": "class",
            "calls": [],
            "called_by": [],
        }
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        quiet=True,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    verified = result["verified_findings"][0]
    stats = result["stats"]
    assert verified["_llm_verdict"] == "FALSE_POSITIVE"
    assert verified["_suppression_reason"] == "pytest_collected_test_class"
    assert stats["suppression_challenged"] == 0
    mock_instance._call_llm.assert_not_called()


def test_verify_stats_defaults():
    stats = VerifyStats()
    assert stats.total_findings == 0
    assert stats.verified_true_positive == 0
    assert stats.elapsed_seconds == 0.0


def test_entry_point_dataclass():
    ep = EntryPoint(name="mod.main", source="pyproject.toml", reason="console_scripts")
    assert ep.name == "mod.main"


def test_survivor_verdict_dataclass():
    sv = SurvivorVerdict(
        name="process",
        full_name="mod.process",
        file="x.py",
        line=10,
        heuristic_refs={"same_file_attr": 1.0},
        verdict=Verdict.TRUE_POSITIVE,
        rationale="spurious match",
        original_confidence=45,
        suggested_confidence=75,
    )
    assert sv.verdict == Verdict.TRUE_POSITIVE
    assert sv.suggested_confidence > sv.original_confidence


def test_is_exported_in_graph_context():
    finding = {
        "name": "EventHook",
        "full_name": "locust.event.EventHook",
        "type": "class",
        "file": "/tmp/test/event.py",
        "line": 5,
        "confidence": 90,
        "references": 0,
        "is_exported": True,
    }
    ctx = _build_graph_context(finding, {}, {})
    assert "Export status" in ctx
    assert "public API" in ctx


def test_is_exported_false_not_in_graph_context():
    finding = {
        "name": "_helper",
        "full_name": "mod._helper",
        "type": "function",
        "file": "/tmp/test/mod.py",
        "line": 5,
        "confidence": 90,
        "references": 0,
    }
    ctx = _build_graph_context(finding, {}, {})
    assert "Export status" not in ctx


def test_build_haiku_context_with_export():
    finding = {
        "name": "remove_listener",
        "full_name": "locust.event.EventHook.remove_listener",
        "type": "method",
        "file": "/tmp/test/event.py",
        "line": 2,
        "confidence": 90,
        "references": 0,
        "is_exported": True,
        "decorators": ["staticmethod"],
    }
    source_cache = {
        "/tmp/test/event.py": "class EventHook:\n    def remove_listener(self, handler):\n        self._handlers.remove(handler)\n"
    }
    ctx = _build_haiku_context(finding, source_cache)
    assert "Exported: yes" in ctx
    assert "remove_listener" in ctx
    assert "staticmethod" in ctx


def test_build_haiku_context_without_source():
    finding = {
        "name": "foo",
        "full_name": "mod.foo",
        "type": "function",
        "file": "/tmp/missing.py",
        "line": 1,
        "confidence": 90,
        "references": 0,
        "is_exported": True,
    }
    ctx = _build_haiku_context(finding, {})
    assert "Exported: yes" in ctx
    assert "Definition:" not in ctx


def test_haiku_prefilter_dismisses_public_api():
    findings = [
        {
            "name": "remove_listener",
            "full_name": "event.EventHook.remove_listener",
            "type": "method",
            "file": "/tmp/test/event.py",
            "line": 10,
            "confidence": 90,
            "references": 0,
            "is_exported": True,
        },
    ]
    mock_agent = MagicMock(spec=DeadCodeVerifierAgent)
    with patch(
        "skylos.llm.verify_orchestrator._parse_batch_response",
        return_value=[
            {"public_api": "YES", "reason": "public method on exported class"}
        ],
    ):
        kept, dismissed = _haiku_prefilter_exports(mock_agent, findings, {})

    assert len(dismissed) == 1
    assert len(kept) == 0
    assert dismissed[0]["_llm_verdict"] == "FALSE_POSITIVE"
    assert dismissed[0]["_haiku_prefiltered"] is True
    assert "haiku-prefilter" in dismissed[0]["_llm_rationale"]


def test_haiku_prefilter_keeps_internal_symbols():
    findings = [
        {
            "name": "_cleanup",
            "full_name": "mod._cleanup",
            "type": "function",
            "file": "/tmp/test/mod.py",
            "line": 5,
            "confidence": 90,
            "references": 0,
            "is_exported": True,
        },
    ]
    mock_agent = MagicMock(spec=DeadCodeVerifierAgent)
    with patch(
        "skylos.llm.verify_orchestrator._parse_batch_response",
        return_value=[{"public_api": "NO", "reason": "private implementation detail"}],
    ):
        kept, dismissed = _haiku_prefilter_exports(mock_agent, findings, {})

    assert len(kept) == 1
    assert len(dismissed) == 0
    assert "_llm_verdict" not in kept[0]


def test_haiku_prefilter_empty_input():
    mock_agent = MagicMock(spec=DeadCodeVerifierAgent)
    kept, dismissed = _haiku_prefilter_exports(mock_agent, [], {})
    assert kept == []
    assert dismissed == []


def test_haiku_prefilter_handles_failure():
    findings = [
        {
            "name": "foo",
            "full_name": "mod.foo",
            "type": "function",
            "file": "/tmp/test/mod.py",
            "line": 5,
            "confidence": 90,
            "references": 0,
            "is_exported": True,
        },
    ]
    mock_agent = MagicMock(spec=DeadCodeVerifierAgent)
    with patch(
        "skylos.llm.verify_orchestrator._parse_batch_response",
        side_effect=RuntimeError("API error"),
    ):
        kept, dismissed = _haiku_prefilter_exports(mock_agent, findings, {})

    assert len(kept) == 1
    assert len(dismissed) == 0


def test_haiku_prefilter_mixed_batch():
    findings = [
        {
            "name": "connect",
            "full_name": "db.connect",
            "type": "function",
            "file": "/tmp/db.py",
            "line": 1,
            "confidence": 90,
            "references": 0,
            "is_exported": True,
        },
        {
            "name": "_init_pool",
            "full_name": "db._init_pool",
            "type": "function",
            "file": "/tmp/db.py",
            "line": 20,
            "confidence": 90,
            "references": 0,
            "is_exported": True,
        },
    ]
    mock_agent = MagicMock(spec=DeadCodeVerifierAgent)
    with patch(
        "skylos.llm.verify_orchestrator._parse_batch_response",
        return_value=[
            {"public_api": "YES", "reason": "main connection API"},
            {"public_api": "NO", "reason": "internal pool setup"},
        ],
    ):
        kept, dismissed = _haiku_prefilter_exports(mock_agent, findings, {})

    assert len(dismissed) == 1
    assert dismissed[0]["full_name"] == "db.connect"
    assert len(kept) == 1
    assert kept[0]["full_name"] == "db._init_pool"


def test_batch_verify_falls_back_to_individual_on_batch_failure(
    sample_finding,
    sample_defs_map,
):
    finding_two = {
        **sample_finding,
        "name": "other_helper",
        "full_name": "mymodule.other_helper",
        "simple_name": "other_helper",
        "line": 40,
    }

    agent = MagicMock(spec=DeadCodeVerifierAgent)

    with patch(
        "skylos.llm.verify_orchestrator._build_graph_context",
        return_value="context",
    ), patch(
        "skylos.llm.verify_orchestrator._parse_batch_response",
        return_value=[
            {"verdict": Verdict.UNCERTAIN, "rationale": "LLM call failed"},
            {"verdict": Verdict.UNCERTAIN, "rationale": "LLM call failed"},
        ],
    ) as parse_batch, patch(
        "skylos.llm.verify_orchestrator.verify_with_graph_context",
        side_effect=[
            VerificationResult(
                finding=sample_finding,
                verdict=Verdict.TRUE_POSITIVE,
                rationale="dead",
                original_confidence=75,
                adjusted_confidence=95,
            ),
            VerificationResult(
                finding=finding_two,
                verdict=Verdict.FALSE_POSITIVE,
                rationale="alive",
                original_confidence=75,
                adjusted_confidence=20,
            ),
        ],
    ) as verify_single:
        results = _batch_verify_findings(
            agent,
            [sample_finding, finding_two],
            sample_defs_map,
            {sample_finding["file"]: "def old_helper(): pass"},
        )

    assert parse_batch.call_count == 1
    assert verify_single.call_count == 2
    assert [result.verdict for result in results] == [
        Verdict.TRUE_POSITIVE,
        Verdict.FALSE_POSITIVE,
    ]


def test_verify_stats_haiku_prefiltered():
    """VerifyStats should have haiku_prefiltered field."""
    stats = VerifyStats()
    assert stats.haiku_prefiltered == 0
    stats.haiku_prefiltered = 5
    assert stats.haiku_prefiltered == 5


class TestFindingComplexityTier:
    def test_tier1_trivially_dead(self):
        """Plain function, zero evidence → tier 1."""
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, {}) == 1

    def test_tier1_no_search_results(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, None) == 1

    def test_tier2_has_callers(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": ["a.b"],
        }
        assert _finding_complexity_tier(finding, {}) == 2

    def test_tier2_few_search_hits(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, {"refs": ["a.py:1:x"]}) == 2

    def test_tier3_has_decorators(self):
        finding = {
            "type": "function",
            "decorators": ["route"],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, {}) == 3

    def test_tier3_method_type(self):
        finding = {
            "type": "method",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, {}) == 3

    def test_tier3_exported(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
            "is_exported": True,
        }
        assert _finding_complexity_tier(finding, {}) == 3

    def test_tier3_heuristic_refs(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {"attr": 1.0},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, {}) == 3

    def test_tier3_many_search_hits(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
        }
        hits = {"refs": ["a:1:x", "b:2:y", "c:3:z", "d:4:w"]}
        assert _finding_complexity_tier(finding, hits) == 3

    def test_tier3_framework_signals(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": ["flask"],
            "dynamic_signals": [],
            "heuristic_refs": {},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, {}) == 3

    def test_tier3_dynamic_signals(self):
        finding = {
            "type": "function",
            "decorators": [],
            "framework_signals": [],
            "dynamic_signals": ["getattr"],
            "heuristic_refs": {},
            "called_by": [],
        }
        assert _finding_complexity_tier(finding, {}) == 3


class TestEntryPointCache:
    def test_cache_path(self, tmp_path):
        path = _entry_point_cache_path(tmp_path)
        assert path == tmp_path / ".skylos" / "cache" / "entry_points.json"

    def test_config_hash_stable(self):
        configs = {"pyproject.toml": "[tool.poetry]\nname = 'x'"}
        h1 = _config_files_hash(configs)
        h2 = _config_files_hash(configs)
        assert h1 == h2
        assert len(h1) == 16

    def test_config_hash_changes(self):
        h1 = _config_files_hash({"a.toml": "v1"})
        h2 = _config_files_hash({"a.toml": "v2"})
        assert h1 != h2

    def test_discover_uses_cache(self, tmp_path):
        configs = {"pyproject.toml": "[project]\nname = 'test'"}
        cache_path = _entry_point_cache_path(tmp_path)
        cache_path.parent.mkdir(parents=True)
        current_hash = _config_files_hash(configs)
        cache_path.write_text(
            json.dumps(
                {
                    "hash": current_hash,
                    "entry_points": [
                        {"name": "main", "source": "config", "reason": "entry"}
                    ],
                }
            )
        )

        mock_agent = MagicMock(spec=DeadCodeVerifierAgent)
        with patch(
            "skylos.llm.verify_orchestrator._gather_config_files", return_value=configs
        ):
            results = discover_entry_points(mock_agent, tmp_path, [])

        mock_agent.assert_not_called()
        assert len(results) == 1
        assert results[0].name == "main"

    def test_discover_skips_stale_cache(self, tmp_path):
        configs = {"pyproject.toml": "[project]\nname = 'changed'"}
        cache_path = _entry_point_cache_path(tmp_path)
        cache_path.parent.mkdir(parents=True)
        cache_path.write_text(
            json.dumps(
                {
                    "hash": "stale_hash",
                    "entry_points": [
                        {"name": "old", "source": "config", "reason": "stale"}
                    ],
                }
            )
        )

        mock_agent = MagicMock(spec=DeadCodeVerifierAgent)
        with (
            patch(
                "skylos.llm.verify_orchestrator._gather_config_files",
                return_value=configs,
            ),
            patch(
                "skylos.llm.verify_orchestrator._call_llm_with_retry",
                return_value='{"entry_points": [{"name": "new_ep", "source": "config", "reason": "fresh"}]}',
            ),
        ):
            results = discover_entry_points(mock_agent, tmp_path, [])

        assert len(results) == 1
        assert results[0].name == "new_ep"
