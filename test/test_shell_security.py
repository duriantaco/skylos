from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.visitors.languages.shell import scan_shell_file


def _scan_shell_findings(
    tmp_path: Path, code: str, filename: str = "deploy.sh"
) -> list[dict]:
    file_path = tmp_path / filename
    file_path.write_text(code, encoding="utf-8")
    return scan_shell_file(str(file_path), {})[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_eval_with_positional_arg_flags_command_injection(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
cmd="$1"
eval "$cmd"
""",
    )

    assert "SKY-D212" in _rule_ids(findings)


def test_source_with_positional_arg_flags_command_injection(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
plugin="$1"
source "$plugin"
""",
    )

    assert "SKY-D212" in _rule_ids(findings)


def test_shell_c_with_positional_arg_flags_command_injection(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
task="$1"
sh -c "$task"
""",
    )

    assert "SKY-D212" in _rule_ids(findings)


def test_sudo_shell_c_with_positional_arg_flags_command_injection(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
task="$1"
sudo -u app bash -c "$task"
""",
    )

    assert "SKY-D212" in _rule_ids(findings)


def test_basename_does_not_sanitize_shell_commands(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
cmd="$(basename -- "$1")"
eval "$cmd"
""",
    )

    assert "SKY-D212" in _rule_ids(findings)


def test_curl_with_read_url_flags_ssrf(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
read -r url
curl -fsSL "$url"
""",
    )

    assert "SKY-D216" in _rule_ids(findings)


def test_curl_fixed_host_with_tainted_path_is_not_ssrf(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
artifact="$1"
curl -fsSL "https://downloads.example.com/releases/$artifact"
""",
    )

    assert "SKY-D216" not in _rule_ids(findings)


def test_file_sink_with_positional_arg_flags_path_traversal(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
backup_name="$1"
cat "/srv/backups/$backup_name"
""",
    )

    assert "SKY-D215" in _rule_ids(findings)


def test_basename_sanitized_file_path_is_safe(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
backup_name="$(basename -- "$1")"
cat "/srv/backups/$backup_name"
""",
    )

    assert "SKY-D215" not in _rule_ids(findings)


def test_analyzer_discovers_shell_scripts(tmp_path):
    script = tmp_path / "deploy.sh"
    script.write_text(
        """
#!/usr/bin/env bash
cmd="$1"
eval "$cmd"
""",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), enable_danger=True, conf=0, grep_verify=False)
    )

    assert result["analysis_summary"]["languages"] == {"Shell": 1}
    assert "SKY-D212" in _rule_ids(result["danger"])
