"""Run the bundled precision controls through the public pack command."""

import json
import shutil
from textwrap import dedent

import pytest

from skylos.commands.rules_cmd import run_rules_command


pytestmark = pytest.mark.skipif(
    not shutil.which("semgrep"), reason="requires Semgrep CLI"
)


def _findings_for_rule(tmp_path, capfd, rule_id, source):
    source_path = tmp_path / "app.py"
    source_path.write_text(dedent(source).lstrip(), encoding="utf-8")
    assert run_rules_command(["vulnhunter", "--format", "json", str(tmp_path)]) == 1
    report = json.loads(capfd.readouterr().out)
    assert not report["errors"]
    lines = source_path.read_text(encoding="utf-8").splitlines()
    return {
        lines[result["start"]["line"] - 1].strip()
        for result in report["results"]
        if result["check_id"] == rule_id
    }


def test_secret_defaults_require_a_standard_environment_read(tmp_path, capfd):
    findings = _findings_for_rule(
        tmp_path,
        capfd,
        "VHOG157",
        """
        import os
        import os as operating_system
        from os import environ as process_environment
        from os import getenv as read_environment

        labels = {}
        label = labels.get("EXAMPLE_TOKEN", "display text")
        empty = os.getenv("EXAMPLE_TOKEN", "")
        direct = os.getenv("EXAMPLE_TOKEN", "demo-placeholder")
        module_alias = operating_system.getenv("DEMO_PASSWORD", "module-placeholder")
        import_alias = read_environment("DEMO_SIGNING_KEY", default="import-placeholder")
        mapping = os.environ.get("DEMO_API_KEY", "mapping-placeholder")
        mapping_alias = process_environment.get("OTHER_TOKEN", "alias-placeholder")
        """,
    )
    assert findings == {
        'direct = os.getenv("EXAMPLE_TOKEN", "demo-placeholder")',
        'module_alias = operating_system.getenv("DEMO_PASSWORD", "module-placeholder")',
        'import_alias = read_environment("DEMO_SIGNING_KEY", default="import-placeholder")',
        'mapping = os.environ.get("DEMO_API_KEY", "mapping-placeholder")',
        'mapping_alias = process_environment.get("OTHER_TOKEN", "alias-placeholder")',
    }


def test_validation_failure_that_returns_none_is_not_swallowed(tmp_path, capfd):
    findings = _findings_for_rule(
        tmp_path,
        capfd,
        "VHOG102",
        """
        def validate_count(text):
            try:
                return int(text)
            except ValueError:
                return None

        def printable_count(text):
            validated = validate_count(text)
            if validated is None:
                return "not a count"
            return str(validated)

        def validate_limit(text):
            try:
                int(text)
            except ValueError:
                pass  # validation failure ignored
            return True

        def validate_optional_count(text):
            try:
                if text is None:
                    pass  # optional input is absent
                else:
                    int(text)
            except ValueError:
                pass  # invalid input ignored
        """,
    )
    assert findings == {
        "pass  # validation failure ignored",
        "pass  # invalid input ignored",
    }
