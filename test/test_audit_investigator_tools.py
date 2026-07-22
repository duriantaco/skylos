from __future__ import annotations

from pathlib import Path

import pytest

from skylos.audit.investigator_tools import (
    DEFAULT_EXCLUDED_FOLDERS,
    AuditReadOnlyTools,
    AuditToolBudgetExceeded,
    AuditToolError,
    AuditToolFileChanged,
    InvestigationToolLimits,
)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "def handler(user):\n    return authorize(user)\n",
        encoding="utf-8",
    )
    return root


@pytest.mark.parametrize(
    "path",
    [
        "../app.py",
        "/etc/passwd",
        "C:/Windows/system.ini",
        "\\\\server\\share\\file.py",
        "nested\\app.py",
        "app.py\x00ignored",
        "./app.py",
    ],
)
def test_read_rejects_noncanonical_or_escaping_paths(
    tmp_path: Path,
    path: str,
) -> None:
    tools = AuditReadOnlyTools(_repo(tmp_path))

    with pytest.raises(AuditToolError):
        tools.execute("read_file", {"path": path})


def test_catalog_rejects_symlinks_and_excluded_or_secret_files(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("TOP_SECRET = 'outside'\n", encoding="utf-8")
    try:
        (root / "linked.py").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    (root / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    excluded = root / "node_modules"
    excluded.mkdir()
    (excluded / "package.js").write_text("export const value = 1\n", encoding="utf-8")

    tools = AuditReadOnlyTools(root)

    assert tools.visited_files == ()
    for path in ("linked.py", ".env", "node_modules/package.js"):
        with pytest.raises(AuditToolError):
            tools.execute("read_file", {"path": path})


def test_catalog_exposes_only_redacted_views_of_scan_classified_files(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    token = "ghp_" + "1234567890abcdef" * 2 + "123456"
    (root / "credentials.py").write_text(
        f'INTERNAL_CREDENTIAL = "{token}"\n',
        encoding="utf-8",
    )
    tools = AuditReadOnlyTools(root, denied_paths={"credentials.py"})

    listing = tools.execute("list_files", {})
    source = tools.execute("read_file", {"path": "credentials.py"})

    assert "credentials.py" in listing.content
    assert token not in source.content
    assert "[REDACTED_SECRET]" in source.content
    assert tools.metadata()["excluded_sensitive_files"] == 1
    assert tools.metadata()["redacted_source_files"] == 1
    tools.assert_completion_safe()


def test_read_and_search_return_only_redacted_repository_secrets(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    token = "ghp_" + "1234567890abcdef" * 2 + "123456"
    (root / "policy.py").write_text(
        f'TOKEN = "{token}"\ndef authorize(user):\n    return user.active\n',
        encoding="utf-8",
    )
    direct_tools = AuditReadOnlyTools(root)

    direct = direct_tools.execute("read_file", {"path": "policy.py"})
    assert token not in direct.content
    assert "[REDACTED_SECRET]" in direct.content
    direct_tools.assert_completion_safe()

    search_tools = AuditReadOnlyTools(root)
    search = search_tools.execute(
        "search_code",
        {"query": "[REDACTED_SECRET]"},
    )
    assert token not in search.content
    assert "[REDACTED_SECRET]" in search.content
    assert search.summary["matches"] == 1
    assert search.summary["sensitive_files_withheld"] == 0
    search_tools.assert_completion_safe()


@pytest.mark.parametrize("suffix", [".rb", ".swift", ".sql", ".graphql", ".mjs"])
def test_secret_checks_cover_every_investigator_language(
    tmp_path: Path,
    suffix: str,
) -> None:
    root = _repo(tmp_path)
    token = "aB3d-E5fG7hI9jK2mN4pQ6rS8tU0vW1xY"
    secret_file = root / f"private{suffix}"
    secret_file.write_text(f"credential = '{token}'\n", encoding="utf-8")
    tools = AuditReadOnlyTools(root)

    with pytest.raises(AuditToolError, match="withheld as sensitive"):
        tools.execute("read_file", {"path": secret_file.name})


def test_search_is_literal_and_find_symbol_is_host_escaped(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    tools = AuditReadOnlyTools(root)

    regex_like = tools.execute("search_code", {"query": ".*"})
    symbol = tools.execute("find_symbol", {"query": "authorize"})

    assert regex_like.summary["matches"] == 0
    assert symbol.summary["matches"] == 1
    assert "app.py:2" in symbol.content
    with pytest.raises(AuditToolError):
        tools.execute("find_symbol", {"query": "(a+)+$"})


def test_repository_snapshot_fails_if_a_file_changes(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    tools = AuditReadOnlyTools(root)
    tools.register_initial_file("app.py")
    (root / "app.py").write_text(
        "def handler(user):\n    return authorize(user) and user.admin\n",
        encoding="utf-8",
    )

    with pytest.raises(AuditToolFileChanged):
        tools.execute("read_file", {"path": "app.py"})
    with pytest.raises(AuditToolFileChanged):
        tools.assert_visited_files_current()


def test_tool_call_and_distinct_file_budgets_are_hard_limits(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "policy.py").write_text(
        "def authorize(user):\n    return user.active\n",
        encoding="utf-8",
    )
    call_limited = AuditReadOnlyTools(
        root,
        limits=InvestigationToolLimits(max_tool_calls=1),
    )
    call_limited.execute("list_files", {})
    with pytest.raises(AuditToolBudgetExceeded):
        call_limited.execute("list_files", {})

    file_limited = AuditReadOnlyTools(
        root,
        limits=InvestigationToolLimits(max_distinct_files=1),
    )
    file_limited.register_initial_file("app.py")
    with pytest.raises(AuditToolBudgetExceeded):
        file_limited.execute("read_file", {"path": "policy.py"})


def test_tool_metadata_contains_hashes_but_not_source_content(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    tools = AuditReadOnlyTools(root)
    observation = tools.execute("read_file", {"path": "app.py"})

    metadata = tools.metadata()

    assert "authorize(user)" in observation.content
    assert "authorize(user)" not in str(metadata)
    assert metadata["related_files"][0]["path"] == "app.py"
    assert len(metadata["related_files"][0]["sha256"]) == 64


def test_search_hit_does_not_authorize_citations_to_unseen_lines(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    helper = root / "helper.py"
    helper.write_text(
        "def authorize(user):\n    return user.is_authenticated\n",
        encoding="utf-8",
    )
    tools = AuditReadOnlyTools(root)

    tools.execute("find_symbol", {"query": "authorize"})

    assert tools.validate_evidence("helper.py", 1) == ("helper.py", 1, 1)
    with pytest.raises(AuditToolError, match="not exposed"):
        tools.validate_evidence("helper.py", 2)


def test_truncated_global_search_cannot_support_completion(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "policy.py").write_text(
        "def authorize(user):\n    return user.active\n",
        encoding="utf-8",
    )
    tools = AuditReadOnlyTools(
        root,
        limits=InvestigationToolLimits(max_search_files=1),
    )

    result = tools.execute("find_symbol", {"query": "authorize"})

    assert result.summary["truncated"] is True
    with pytest.raises(AuditToolBudgetExceeded, match="discovery result"):
        tools.assert_completion_safe()


def test_search_does_not_authorize_citation_to_unreturned_long_line(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    long_line = "authorize = '" + ("x" * 30_000) + "'\n"
    (root / "generated.py").write_text(long_line, encoding="utf-8")
    tools = AuditReadOnlyTools(root)

    result = tools.execute("find_symbol", {"query": "authorize"})

    assert result.summary["truncated"] is True
    assert result.summary["matches"] == 1
    assert "generated.py" not in result.content
    with pytest.raises(AuditToolError, match="not inspected"):
        tools.validate_evidence("generated.py", 1)


def test_initial_registration_only_exposes_declared_excerpt_lines(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    tools = AuditReadOnlyTools(root)
    tools.register_initial_file("app.py", visible_end_line=1)

    assert tools.validate_evidence("app.py", 1) == ("app.py", 1, 1)
    with pytest.raises(AuditToolError, match="not exposed"):
        tools.validate_evidence("app.py", 2)


def test_configured_excludes_are_not_in_the_tool_catalog(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    private_dir = root / "private"
    private_dir.mkdir()
    (private_dir / "policy.py").write_text("ALLOW = True\n", encoding="utf-8")
    (root / "sensitive.py").write_text("ALLOW = True\n", encoding="utf-8")

    tools = AuditReadOnlyTools(
        root,
        exclude_folders=(*DEFAULT_EXCLUDED_FOLDERS, "private"),
        excluded_paths={"sensitive.py"},
    )

    listing = tools.execute("list_files", {})
    assert "private/policy.py" not in listing.content
    assert "sensitive.py" not in listing.content
    for path in ("private/policy.py", "sensitive.py"):
        with pytest.raises(AuditToolError):
            tools.execute("read_file", {"path": path})
