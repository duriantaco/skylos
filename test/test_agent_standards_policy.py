import json
import os
from pathlib import Path

import pytest

from skylos.commands.agent_standards_policy import (
    AgentStandardsPolicyError,
    load_agent_standards_policy,
)
from skylos.core.safe_cache_io import write_text_no_symlink


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"),
    reason="requires no-follow directory-relative opens",
)
def test_standards_parent_symlink_rejected_even_if_precheck_misses_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    policy_dir = project / ".skylos"
    policy_dir.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    assert write_text_no_symlink(outside / "rules.md", "# Outside project\n")
    (project / "docs").symlink_to(outside, target_is_directory=True)
    assert write_text_no_symlink(
        policy_dir / "agent-standards.json",
        json.dumps(
            {
                "schema_version": 1,
                "standards_file": "docs/rules.md",
                "enforce_rule_ids": [],
            }
        ),
    )

    original_is_symlink = Path.is_symlink

    def missed_precheck(path: Path) -> bool:
        if path == project / "docs":
            return False
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", missed_precheck)
    with pytest.raises(AgentStandardsPolicyError, match="standards_file"):
        load_agent_standards_policy(project)
