from __future__ import annotations

import textwrap

import pytest

from skylos.visitors.languages.shell.danger import scan_danger


BASH = "#!/usr/bin/env bash\n"
DIE = BASH + 'die() {\n  echo "error: $*" >&2\n  exit 1\n}\n'
GATE = '[[ "$EUID" -eq 0 ]] || die "run this helper with sudo"\n'


def _findings(code: str) -> list[tuple[str, int, str]]:
    source = textwrap.dedent(code)
    return [
        (finding["rule_id"], finding["line"], finding["severity"])
        for finding in scan_danger("maintain.sh", source)
        if finding["rule_id"] in {"SKY-D212", "SKY-D215", "SKY-D216"}
    ]


def _severity(code: str, rule: str = "SKY-D212") -> str | None:
    found = [
        severity for rule_id, _line, severity in _findings(code) if rule_id == rule
    ]
    if not found:
        return None
    return found[0]


@pytest.mark.parametrize(
    "command",
    [
        'runuser -u "$owner" -- env setup_path="$setup_path" /bin/bash -c \'source "$setup_path"\'',
        'env cmd="$setup_path" bash -c \'eval "$cmd"\'',
        'cmd="$setup_path" sh -c \'eval "$cmd"\'',
        'sudo -u "$owner" bash -c "$setup_path"',
        'sudo bash -c "$setup_path"',
        'runuser -u root -- bash -c "$setup_path"',
        'setpriv --reuid=0 --regid=0 --init-groups bash -c "$setup_path"',
        'setpriv --reuid=1000 bash -c "$setup_path"',
        'setpriv --reuid=1000 --regid=1000 --init-groups --inh-caps=+all --ambient-caps=+all bash -c "$setup_path"',
        'setpriv --reuid=1000 --regid=1000 --keep-groups bash -c "$setup_path"',
        "sudo -u '#0' bash -c \"$setup_path\"",
        "sudo -u '#-1' bash -c \"$setup_path\"",
        "sudo -u '#4294967295' bash -c \"$setup_path\"",
        'runuser -u nobody -- sudo bash -c "$setup_path"',
        'su -c "$setup_path"',
        'doas sh -c "$setup_path"',
        'bash -c "$setup_path" | tee /tmp/log',
        'echo ready | bash -lc "$setup_path"',
        'bash -c \'source "$1"\' _ "$setup_path"',
    ],
)
def test_inner_shell_receives_tainted_value_at_full_severity(command):
    code = f'{BASH}owner="$(stat -c %U "$1")"\nsetup_path="$1"\n{command}\n'
    assert _severity(code) == "CRITICAL"


@pytest.mark.parametrize(
    ("command", "user"),
    [
        ('runuser -u nobody -- env cmd="$1" /bin/bash -c \'eval "$cmd"\'', "nobody"),
        ('sudo -u www-data bash -c "$1"', "www-data"),
        ('sudo -iu app bash -c "$1"', "app"),
        ("sudo -u '#1000' bash -c \"$1\"", "#1000"),
        (
            'setpriv --reuid=1000 --regid=1000 --init-groups bash -c "$1"',
            "1000",
        ),
        ('doas -u builder sh -c "$1"', "builder"),
        ('runuser -l app -c "$1"', "app"),
        ('su deploy -c "$1"', "deploy"),
    ],
)
def test_drop_to_a_named_unprivileged_user_lowers_one_level(command, user):
    findings = scan_danger("maintain.sh", f"{BASH}{command}\n")
    commands = [item for item in findings if item["rule_id"] == "SKY-D212"]
    assert [item["severity"] for item in commands] == ["HIGH"]
    assert f"'{user}'" in commands[0]["message"]
    assert commands[0]["severity_reason"] == "privilege_drop"


@pytest.mark.parametrize(
    "command",
    [
        'env cmd="fixed" bash -c \'eval "$cmd"\'',
        "bash -c 'echo ok' | awk '{print $1}'",
        "runuser -u nobody -- /usr/bin/id",
        'FOO="$1" bash -c \'printf "%s\\n" "$FOO"\'',
        'NAME="$1" sh -c \'echo "hello $NAME"\'',
        "bash -c 'source \"$1\"' _ /etc/fixed.sh",
    ],
)
def test_inner_shell_without_tainted_code_is_not_command_injection(command):
    assert _severity(f"{BASH}{command}\n") is None


@pytest.mark.parametrize(
    ("command", "severity"),
    [
        ('env FILE="$1" sh -c \'wc -l < "$FILE"\'', "HIGH"),
        ('env FILE="$1" sh -c \'cat -- "$FILE"\'', "HIGH"),
        ('sudo -u www-data env FILE="$1" sh -c \'cat -- "$FILE"\'', "MEDIUM"),
    ],
)
def test_env_carried_file_names_are_path_findings(command, severity):
    assert _findings(f"{BASH}{command}\n") == [("SKY-D215", 2, severity)]


ROOT_GATED = (
    DIE
    + GATE
    + """setup_path="$(readlink -f "$1")"
install_prefix="$(dirname "$setup_path")"
resolve() {
  (
    source "$setup_path" >/dev/null
  )
}
resolve
chmod -R a-w "$install_prefix"
curl -fsS "$2"
sudo -iu app bash -c "$1"
"""
)


def test_root_only_script_arguments_lower_one_level():
    findings = scan_danger("maintain.sh", ROOT_GATED)
    assert sorted(
        (item["rule_id"], item["line"], item["severity"], item["severity_reason"])
        for item in findings
        if item["rule_id"] in {"SKY-D212", "SKY-D215", "SKY-D216"}
    ) == [
        ("SKY-D212", 11, "HIGH", "root_only_script_arguments"),
        ("SKY-D212", 17, "MEDIUM", "root_only_script_arguments_and_privilege_drop"),
        ("SKY-D215", 15, "MEDIUM", "root_only_script_arguments"),
        ("SKY-D216", 16, "HIGH", "root_only_script_arguments"),
    ]
    assert "sudo" in next(item["message"] for item in findings if item["line"] == 11)


@pytest.mark.parametrize(
    "gate",
    [
        '[ "$(id -u)" -eq 0 ] || exit 1',
        "(( EUID == 0 )) || exit 1",
        '[[ $EUID -ne 0 ]] && { echo "root only" >&2; exit 1; }',
        'if [[ "${EUID}" -ne 0 ]]; then\n  echo "root only" >&2\n  exit 1\nfi',
        'if ! [[ "$UID" -eq 0 ]]; then die "root only"; fi',
        'test "$EUID" = 0 || die "root only"',
    ],
)
def test_root_gate_forms(gate):
    code = DIE + gate + '\nplugin="$1"\nsource "$plugin"\n'
    assert _severity(code) == "HIGH"


@pytest.mark.parametrize(
    ("interpreter", "severity"),
    [
        ("#!/bin/sh\n", "CRITICAL"),
        ("#!/bin/ksh\n", "CRITICAL"),
        ("#!/usr/bin/env dash\n", "CRITICAL"),
        ("", "CRITICAL"),
        ("#!/bin/zsh\n", "HIGH"),
    ],
)
def test_euid_gates_count_only_where_the_shell_sets_euid(interpreter, severity):
    gate = '[ "$EUID" -eq 0 ] || exit 1\nsource "$1"\n'
    assert _severity(interpreter + gate) == severity
    command_gate = '[ "$(id -u)" -eq 0 ] || exit 1\nsource "$1"\n'
    assert _severity(interpreter + command_gate) == "HIGH"


@pytest.mark.parametrize(
    "code",
    [
        DIE + '[[ "$EUID" -eq 0 ]] || echo "warning: not root"\nsource "$1"\n',
        BASH
        + 'die() {\n  echo "$*" >&2\n  return 1\n}\n[[ "$EUID" -eq 0 ]] || die x\nsource "$1"\n',
        BASH
        + 'die() {\n  echo "$*"\n  return 1\n  exit 1\n}\n[[ "$EUID" -eq 0 ]] || die x\nsource "$1"\n',
        DIE + '[[ "$EUID" -ne 0 ]] || die "do not run as root"\nsource "$1"\n',
        DIE + '[[ "$EUID" -eq 0 ]] && die "do not run as root"\nsource "$1"\n',
        DIE + 'sh -c "$1"\n' + GATE,
        DIE + 'if [[ "${2:-}" == "--strict" ]]; then\n  ' + GATE + 'fi\nsource "$1"\n',
        DIE + "check_root() {\n  " + GATE + '}\nsource "$1"\n',
        DIE + 'plugin="$1"\nload() {\n  sh -c "$plugin"\n}\nload\n' + GATE,
        DIE + GATE + 'read -r extra\nsource "$1$extra"\n',
        DIE + GATE + 'plugin="$1"\nread -r plugin\nsource "$plugin"\n',
        DIE + GATE + 'plugin="$(cat "$1")"\nsource "$plugin"\n',
        DIE + GATE + 'set -- $(cat /tmp/arguments)\nsource "$1"\n',
        DIE + GATE + 'eval set -- "$(curl -fsS https://e.example/a)"\nsource "$1"\n',
        DIE
        + GATE
        + 'if [[ -z "${1:-}" ]]; then set -- $(curl -fsS https://e.example/a); fi\nsource "$1"\n',
        DIE + GATE + 'builtin set -- $(curl -fsS https://e.example/a)\nsource "$1"\n',
        DIE + GATE + '{ set -- $(curl -fsS https://e.example/a); }\nsource "$1"\n',
        DIE + 'exit() {\n  :\n}\n[[ "$EUID" -eq 0 ]] || exit 1\nsource "$1"\n',
        DIE + "eval 'exit() { :; }'\n" + '[[ "$EUID" -eq 0 ]] || exit 1\nsource "$1"\n',
        DIE + "source /opt/app/lib.sh\n" + GATE + 'source "$1"\n',
        DIE + '[[ "$EUID" -eq 0 ]] || exit 1 &\nsource "$1"\n',
        DIE + 'cat <<EOF\n[[ "$EUID" -eq 0 ]] || exit 1\nEOF\nsource "$1"\n',
        DIE
        + 'x=$(cat <<EOF\n)\n[[ $EUID -eq 0 ]] || exit 1\n( true\nEOF\n)\nsource "$1"\n',
        DIE + 'usage=\'\n[[ "$EUID" -eq 0 ]] || exit 1\n\'\nsource "$1"\n',
        DIE + '( [[ "$EUID" -eq 0 ]] || exit 1 )\nsource "$1"\n',
        DIE + 'id() {\n  echo 0\n}\n[ "$(id -u)" -eq 0 ] || exit 1\nsource "$1"\n',
        DIE + GATE + 'run() {\n  source "$1"\n}\nread -r chosen\nrun "$chosen"\n',
    ],
)
def test_root_gate_lookalikes_keep_critical(code):
    assert _severity(code) == "CRITICAL"


def test_option_only_set_keeps_the_root_gate():
    code = DIE + "set -euo pipefail\nset +u\n" + GATE + 'source "$1"\n'
    assert _severity(code) == "HIGH"
