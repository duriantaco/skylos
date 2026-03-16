"""Tests for the dead-code verification orchestrator."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from skylos.llm.verify_orchestrator import (
    _gather_config_files,
    _build_repo_facts,
    _build_graph_context,
    _deterministic_suppress,
    _get_cached_search_results,
    _find_survivors,
    _build_source_cache,
    _is_public_library_symbol,
    discover_entry_points,
    verify_with_graph_context,
    challenge_survivor,
    run_verification,
    EntryPoint,
    EdgeResolution,
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Test _gather_config_files
# ---------------------------------------------------------------------------


def test_gather_config_files(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.poetry]\nname = 'test'")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCMD python app.py")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "code.py").write_text("x = 1")

    configs = _gather_config_files(tmp_path)
    assert "pyproject.toml" in configs
    assert "Dockerfile" in configs
    assert "src/code.py" not in configs  # Not a config file


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


# ---------------------------------------------------------------------------
# Test _build_graph_context
# ---------------------------------------------------------------------------


def test_build_graph_context_basic(sample_finding, sample_defs_map, sample_source_cache):
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


def test_build_graph_context_includes_repo_facts_and_path_references(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "mkdocs.yml").write_text("hooks:\n  - scripts/mkdocs_hooks.py\n")
    scripts = proj / "scripts"
    scripts.mkdir()
    hook_file = scripts / "mkdocs_hooks.py"
    hook_file.write_text(
        "def on_nav(nav, *, config, files, **kwargs):\n"
        "    return nav\n"
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
    assert "Config-file references" in ctx


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

    assert "Repo-relative file path references" in ctx
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
    assert "Compatibility-retention notes" in ctx


# ---------------------------------------------------------------------------
# Test _find_survivors
# ---------------------------------------------------------------------------


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
    # Should find mod.suspect (function with heuristic refs, low real refs)
    # Should NOT find mod.variable (not a function/method)
    # Should NOT find mod.alive_func (refs > 3)
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


# ---------------------------------------------------------------------------
# Test _build_source_cache
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Test discover_entry_points (mocked LLM)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Test verify_with_graph_context (mocked LLM)
# ---------------------------------------------------------------------------


def test_verify_graph_context_true_positive(sample_finding, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "No dynamic dispatch found"}
    )

    result = verify_with_graph_context(
        agent, sample_finding, sample_defs_map, {sample_finding["file"]: "def old_helper(x):\n    return x * 2\n"}
    )
    assert result.verdict == Verdict.TRUE_POSITIVE
    assert result.adjusted_confidence > result.original_confidence


def test_verify_graph_context_false_positive(sample_finding, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        {"verdict": "FALSE_POSITIVE", "rationale": "Line 15: getattr(module, 'old_helper')"}
    )

    result = verify_with_graph_context(
        agent, sample_finding, sample_defs_map, {}
    )
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
    agent._call_llm.return_value = '```json\n{"verdict": "TRUE_POSITIVE", "rationale": "dead"}\n```'

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
        "class TestSample:\n"
        "    def test_case(self):\n"
        "        assert True\n"
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
    hook_file.write_text("def on_nav(nav, *, config, files, **kwargs):\n    return nav\n")
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


# ---------------------------------------------------------------------------
# Test challenge_survivor (mocked LLM)
# ---------------------------------------------------------------------------


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
        {"/tmp/test_project/mymodule.py": "class Handler:\n    def process(self): pass\n"},
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

    sv = challenge_survivor(
        agent, survivor_with_heuristic, sample_defs_map, {}
    )
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

    sv = challenge_survivor(
        agent, survivor_with_heuristic, sample_defs_map, {}
    )
    assert sv.verdict == Verdict.UNCERTAIN
    assert sv.suggested_confidence == sv.original_confidence


def test_challenge_survivor_handles_error(survivor_with_heuristic, sample_defs_map):
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.side_effect = Exception("timeout")

    sv = challenge_survivor(
        agent, survivor_with_heuristic, sample_defs_map, {}
    )
    assert sv.verdict == Verdict.UNCERTAIN


# ---------------------------------------------------------------------------
# Test run_verification (full pipeline, mocked LLM)
# ---------------------------------------------------------------------------


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_full_pipeline(MockAgent, tmp_path):
    # Setup mock
    mock_instance = MockAgent.return_value
    call_count = [0]

    def mock_llm(system, user):
        call_count[0] += 1
        if "entry point" in system.lower() or "entry point" in user.lower():
            return json.dumps({"entry_points": []})
        if "survivor" in system.lower() or "heuristic" in system.lower():
            return json.dumps(
                {"is_dead": True, "rationale": "spurious match", "heuristic_assessment": "spurious"}
            )
        return json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "no callers"})

    mock_instance._call_llm.side_effect = mock_llm

    # Create test project
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
        json.dumps({"verdict": "TRUE_POSITIVE", "rationale": "alive evidence is speculative"}),
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
        {"verdict": "TRUE_POSITIVE", "rationale": "test mention is not executable usage"}
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
            "confidence": 101,  # Above default range (40, 100)
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

    # Should skip verification (high confidence), no LLM calls for this finding
    verified = result["verified_findings"]
    assert verified[0].get("_llm_verdict") == "SKIPPED_HIGH_CONF"


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
        "class TestMark:\n"
        "    def test_it(self):\n"
        "        assert True\n"
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


# ---------------------------------------------------------------------------
# Test data classes
# ---------------------------------------------------------------------------


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
