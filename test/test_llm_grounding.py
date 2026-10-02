from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.llm.repo_activation import build_repo_activation_index


FIXTURE_ROOT = (
    Path(__file__).resolve().parent.parent / "benchmarks" / "agent_review" / "fixtures"
)


def _context_for(case_name: str) -> dict[str, str]:
    case_root = FIXTURE_ROOT / case_name
    files = sorted(case_root.rglob("*.py"))
    index = build_repo_activation_index(files, project_root=case_root)
    return index.context_map_for(files)


def test_grounding_traces_cross_file_sql_paths_without_collapsing_safe_flow():
    context = _context_for("cross_file_sql_injection")
    repository = context[
        str((FIXTURE_ROOT / "cross_file_sql_injection" / "repository.py").resolve())
    ]

    assert "graph callers:" in repository
    assert "app.handle_search -> repository.search_users" in repository
    assert "app.handle_homepage -> repository.list_recent_users" in repository
    assert "repository.search_users -> db.query_all" in repository
    assert "repository.list_recent_users -> db.query_all" in repository
    assert "app.handle_search -> repository.search_users -> db.query_all" in repository
    assert (
        "app.handle_homepage -> repository.list_recent_users -> db.query_all"
        in repository
    )


def test_grounding_distinguishes_shell_hook_entrypoint_paths():
    context = _context_for("shell_hook_runner")
    hooks = context[str((FIXTURE_ROOT / "shell_hook_runner" / "hooks.py").resolve())]

    assert "cli.execute_custom_hook -> hooks.run_named_hook" in hooks
    assert "cli.sync_repository -> hooks.run_builtin" in hooks
    assert "hooks.run_builtin -> hooks.run_named_hook" not in hooks


def test_grounding_adds_neutral_context_for_clean_service():
    context = _context_for("repo_clean_service")
    service = context[
        str((FIXTURE_ROOT / "repo_clean_service" / "service.py").resolve())
    ]
    app = context[str((FIXTURE_ROOT / "repo_clean_service" / "app.py").resolve())]

    assert "app.handle_status -> service.fetch_status" in service
    assert "app.handle_status -> formatter.normalize_headers" in app
    assert "security surfaces:" not in service
    assert "vulnerability" not in service.lower()
    assert "dangerous" not in service.lower()


def test_grounding_context_is_bounded():
    context = _context_for("cross_file_sql_injection")

    for block in context.values():
        graph_lines = [
            line for line in block.splitlines() if line.startswith("- graph ")
        ]
        assert len(graph_lines) <= 8
        assert len(block) < 1600


def _write_source(root: Path, relative: str) -> Path:
    root = root.resolve(strict=True)
    path = root / relative
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, "def fetch_status():\n    return {'ok': True}\n")
    return path


@pytest.mark.parametrize(
    "parent", ["auth", "session", "security", "auth-session-checkout"]
)
def test_grounding_ignores_security_named_checkout_parent(tmp_path, parent):
    root = tmp_path / parent / "clean-project"
    root.mkdir(parents=True)
    service = _write_source(root, "service.py")
    index = build_repo_activation_index([service], project_root=root)
    metadata = index.by_path[str(service.resolve())]
    context = index.context_map_for([service])[str(service.resolve())]

    assert metadata.security_hints == []
    assert "security surfaces:" not in context


@pytest.mark.parametrize(
    "relative", ["auth/service.py", "sessions/service.py", "session.py"]
)
def test_grounding_keeps_project_relative_security_path_signal(tmp_path, relative):
    service = _write_source(tmp_path, relative)
    index = build_repo_activation_index([service], project_root=tmp_path)
    metadata = index.by_path[str(service.resolve())]
    context = index.context_map_for([service])[str(service.resolve())]

    assert metadata.security_hints == ["path suggests a security-sensitive surface"]
    assert "security surfaces: path suggests a security-sensitive surface" in context
