import sys
from unittest.mock import MagicMock, patch

import pytest

from skylos import cli


@pytest.mark.parametrize(
    "summary,options,expected",
    [
        ({"fixed": 1, "failed": 1, "total_findings": 2}, [], 1),
        ({"fixed": 1, "failed": 0, "total_findings": 1}, [], 0),
        ({"fixed": 0, "failed": 1, "total_findings": 1}, [], 1),
        ({"fixed": 0, "failed": 0, "total_findings": 0}, [], 0),
        ({"fixed": 1, "checks_failed": 1, "total_findings": 1}, [], 1),
        ({"fixed": 1, "total_findings": 1}, ["--auto-pr"], 1),
        (
            {"fixed": 1, "total_findings": 1, "pr_url": "https://example.invalid/pr/1"},
            ["--auto-pr"],
            0,
        ),
        ({"fixed": 1, "total_findings": 1}, ["--auto-pr", "--dry-run"], 0),
    ],
)
def test_remediation_cli_exit_reports_failed_checks_even_with_applied_fixes(
    tmp_path, summary, options, expected
):
    with (
        patch.object(
            sys,
            "argv",
            ["skylos", "agent", "remediate", str(tmp_path), "--quiet", *options],
        ),
        patch("skylos.cli.Console", return_value=MagicMock()),
        patch("skylos.cli._ensure_llm_support", return_value=True),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "", "http://127.0.0.1:9/v1", True),
        ),
        patch("skylos.llm.orchestrator.RemediationAgent") as agent,
    ):
        agent.return_value.run.return_value = summary
        with pytest.raises(SystemExit) as result:
            cli.main()
    assert result.value.code == expected
