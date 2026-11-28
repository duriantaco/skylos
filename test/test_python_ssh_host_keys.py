from textwrap import dedent

import pytest

from skylos.benchmarks.security import _scan_case
from skylos.rules.danger.danger import scan_ctx


def _source(tmp_path, code):
    path = tmp_path / "ssh_setup.py"
    path.write_text(dedent(code).lstrip(), encoding="utf-8")
    return path


def _findings(tmp_path, code):
    path = _source(tmp_path, code)
    return [
        finding
        for finding in scan_ctx(tmp_path, [path])
        if finding["rule_id"] == "SKY-D380"
    ]


@pytest.mark.parametrize(
    "policy", ["paramiko.AutoAddPolicy()", "paramiko.WarningPolicy"]
)
def test_native_policy_is_reported_at_the_setter(tmp_path, policy):
    path = _source(
        tmp_path,
        f"""
        import paramiko

        def setup(known_hosts):
            client = paramiko.SSHClient()
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy({policy})
        """,
    )
    result = _scan_case(tmp_path)
    findings = [
        item for item in result.get("danger", []) if item["rule_id"] == "SKY-D380"
    ]
    assert len(findings) == 1
    assert findings[0]["file"].endswith(path.name)
    assert findings[0]["line"] == 6
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["symbol"] == "setup"
    assert policy.split(".")[1].removesuffix("()") in findings[0]["message"]


def test_aliases_and_keyword_policy(tmp_path):
    findings = _findings(
        tmp_path,
        """
        from paramiko.client import SSHClient as Client, WarningPolicy as Warn

        def setup():
            client = Client()
            receiver = client
            policy = Warn()
            receiver.set_missing_host_key_policy(policy=policy)
        """,
    )
    assert [(item["line"], item["symbol"]) for item in findings] == [(7, "setup")]


def test_source_order_and_branch_proof(tmp_path):
    findings = _findings(
        tmp_path,
        """
        from paramiko import AutoAddPolicy, RejectPolicy, SSHClient, WarningPolicy

        def setup(fallback, choose):
            client = SSHClient()
            policy = AutoAddPolicy
            if choose:
                policy = WarningPolicy()
            client.set_missing_host_key_policy(policy)
            policy = RejectPolicy()
            client.set_missing_host_key_policy(policy)
            if fallback:
                client = fallback
            client.set_missing_host_key_policy(AutoAddPolicy())
        """,
    )
    assert [item["line"] for item in findings] == [8]


def test_native_context_manager_retains_the_client(tmp_path):
    findings = _findings(
        tmp_path,
        """
        import paramiko

        def setup(unknown):
            with paramiko.SSHClient() as client:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            with unknown as client:
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
        """,
    )
    assert [item["line"] for item in findings] == [5]


def test_local_and_rebound_lookalikes_are_ignored(tmp_path):
    assert not _findings(
        tmp_path,
        """
        import paramiko

        def setup(client, WarningPolicy):
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
            paramiko.SSHClient().set_missing_host_key_policy(WarningPolicy())
            client = [paramiko.SSHClient() for _ in range(2)]
            client.set_missing_host_key_policy(paramiko.WarningPolicy)

        def bind(another):
            client = paramiko.SSHClient()
            client = another
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        """,
    )


def test_repo_local_paramiko_import_is_ignored(tmp_path):
    (tmp_path / "paramiko.py").write_text(
        "# locally supplied module\n", encoding="utf-8"
    )
    assert not _findings(
        tmp_path,
        """
        import paramiko

        paramiko.SSHClient().set_missing_host_key_policy(paramiko.AutoAddPolicy())
        """,
    )


def test_nested_class_has_no_enclosing_class_binding(tmp_path):
    assert not _findings(
        tmp_path,
        """
        from module import client
        import paramiko

        class Outer:
            client = paramiko.SSHClient()

            class Inner:
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
        """,
    )


@pytest.mark.parametrize(
    ("imports", "constructor", "policy"),
    [
        ("import paramiko", "paramiko.SSHClient", "paramiko.WarningPolicy"),
        (
            "from paramiko.client import SSHClient, AutoAddPolicy",
            "SSHClient",
            "AutoAddPolicy",
        ),
    ],
)
def test_application_client_field_does_not_obscure_direct_import(
    tmp_path, imports, constructor, policy
):
    findings = _findings(
        tmp_path,
        f"""
        {imports}

        class ConnectionState:
            def __init__(self):
                self.client = None

        def configure():
            connection = {constructor}()
            connection.set_missing_host_key_policy({policy}())
        """,
    )
    assert [item["line"] for item in findings] == [9]


@pytest.mark.parametrize(
    "setup",
    [
        "paramiko.client = provider",
        "package_alias.client = provider",
        'setattr(paramiko, "client", provider)',
    ],
)
def test_package_member_writes_keep_submodule_lookup_unproven(tmp_path, setup):
    assert not _findings(
        tmp_path,
        f"""
        import paramiko

        def configure(provider):
            package_alias = paramiko
            {setup}
            connection = paramiko.client.SSHClient()
            connection.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        """,
    )


def test_calling_another_native_api_preserves_the_import_binding(tmp_path):
    findings = _findings(
        tmp_path,
        """
        import paramiko as ssh

        def setup(config_path):
            client = ssh.client.SSHClient()
            config = ssh.config.SSHConfig.from_path(config_path)
            client.set_missing_host_key_policy(ssh.client.WarningPolicy())
            return client, config
        """,
    )
    assert [item["line"] for item in findings] == [6]


@pytest.mark.parametrize("fallback", ["available = False", "ssh = alternate"])
def test_optional_import_does_not_equate_a_missing_name_to_a_standin(
    tmp_path, fallback
):
    findings = _findings(
        tmp_path,
        f"""
        try:
            import paramiko as ssh
        except ImportError:
            {fallback}

        def setup():
            client = ssh.SSHClient()
            client.set_missing_host_key_policy(ssh.WarningPolicy)
        """,
    )
    assert [item["line"] for item in findings] == (
        [8] if fallback == "available = False" else []
    )


@pytest.mark.parametrize(
    ("other_module", "guard", "expected"),
    [
        (None, "import paramiko.transport", [6]),
        (None, "import paramiko", []),
        (None, "__path__ = []\nimport paramiko.transport", []),
        ("paramiko.py", "import paramiko.transport", []),
        ("library/paramiko.py", "import paramiko.transport", []),
        ("library/adapter/paramiko.pyi", "import paramiko.transport", []),
    ],
)
def test_a_plain_backend_module_cannot_supply_a_required_package_submodule(
    tmp_path, other_module, guard, expected
):
    target = tmp_path / "library/adapter/paramiko.py"
    target.parent.mkdir(parents=True)
    if other_module is not None:
        (tmp_path / other_module).write_text("# local provider\n", encoding="utf-8")
    target.write_text(
        "import paramiko\n"
        f"{guard}\n\n"
        "def setup():\n"
        "    connection = paramiko.SSHClient()\n"
        "    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == expected


_POLICY_MODULE = """\
from paramiko import SSHClient, WarningPolicy

def setup(transport: SSHClient, configured_key):
    if not (configured_key and configured_key.strip()):
        connection = transport
        connection.set_missing_host_key_policy(WarningPolicy())
"""
_CALLER_MODULE = """\
import paramiko
from library.policy import setup

def run(configuration):
    transport = paramiko.SSHClient()
    setup(transport, configuration.get("host_key"))
"""


@pytest.mark.parametrize(
    ("caller", "policy", "expected"),
    [
        (_CALLER_MODULE, _POLICY_MODULE, [6]),
        (
            _CALLER_MODULE + "\ndef other(transport):\n    setup(transport, None)\n",
            _POLICY_MODULE,
            [6],
        ),
        (_CALLER_MODULE.replace("paramiko.SSHClient()", "fake()"), _POLICY_MODULE, []),
        (_CALLER_MODULE.replace("library.policy", "library.other"), _POLICY_MODULE, []),
        (
            _CALLER_MODULE.replace(
                "    setup(transport,", "    setup = deferred\n    setup(transport,"
            ),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE.replace(
                "    setup(transport,", "    transport = fallback\n    setup(transport,"
            ),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE.replace('configuration.get("host_key")', '"configured"'),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE.replace('configuration.get("host_key")', "None, None"),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE.replace(', configuration.get("host_key")', ""),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE.replace(
                "    setup(transport,", "    if False: setup(transport,"
            ),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE.replace(
                "    setup(transport,",
                "    hand_off([transport])\n    setup(transport,",
            ),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE.replace(
                'configuration.get("host_key")', "hand_off(transport)"
            ),
            _POLICY_MODULE,
            [],
        ),
        (
            _CALLER_MODULE,
            _POLICY_MODULE.replace("connection = transport", "connection = substitute"),
            [],
        ),
        (
            _CALLER_MODULE,
            _POLICY_MODULE.replace(
                "connection = transport",
                "hand_off(transport)\n        connection = transport",
            ),
            [],
        ),
    ],
)
def test_helper_parameters_require_a_native_client_at_an_exact_call_edge(
    tmp_path, caller, policy, expected
):
    package = tmp_path / "library"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    target = package / "policy.py"
    target.write_text(policy, encoding="utf-8")
    (tmp_path / "launcher.py").write_text(caller, encoding="utf-8")
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == expected


@pytest.mark.parametrize(
    ("parameters", "argument", "expected"),
    [
        ("channel, permit_unknown=False", "", []),
        ("channel, *, permit_unknown=False", "", []),
        ("channel, permit_unknown=False, /", "", []),
        ("channel, permit_unknown=False", ", True", [5]),
        ("channel, permit_unknown=False", ", permit_unknown=True", [5]),
        ("channel, *, permit_unknown=False", ", permit_unknown=True", [5]),
        ("channel, permit_unknown=False, /", ", True", [5]),
        ("channel, *, permit_unknown=True", ", permit_unknown=False", []),
        ("channel, *, permit_unknown=True", "", [5]),
        ("channel, permit_unknown=read_config()", "", [5]),
        ("channel, *, permit_unknown=read_config()", "", [5]),
    ],
)
def test_helper_branch_accounts_for_literal_but_not_computed_defaults(
    tmp_path, parameters, argument, expected
):
    target = tmp_path / "profile.py"
    target.write_text(
        "from paramiko import WarningPolicy\n\n"
        f"def configure_peer({parameters}):\n"
        "    if permit_unknown:\n"
        "        channel.set_missing_host_key_policy(WarningPolicy())\n",
        encoding="utf-8",
    )
    (tmp_path / "launcher.py").write_text(
        "from paramiko import SSHClient\nfrom profile import configure_peer\n\n"
        "def prepare():\n"
        "    connection = SSHClient()\n"
        f"    configure_peer(connection{argument})\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == expected


@pytest.mark.parametrize(
    ("body", "condition", "expected"),
    [
        ("    option = False\n    setting = option\n", "option", []),
        ("    option = True\n    setting = option\n", "option", [5]),
        (
            "    setting = False\n    if requested:\n        setting = True\n",
            "option",
            [5],
        ),
        (
            (
                "    if requested:\n        setting = False\n"
                "    else:\n        setting = None\n"
            ),
            "option",
            [],
        ),
        ("    setting = False\n    setting = get_value()\n", "option", [5]),
        (
            (
                "    setting = False\n    def select():\n"
                "        nonlocal setting\n        setting = True\n    select()\n"
            ),
            "option",
            [5],
        ),
        ("    setting = '   '\n", "option.strip()", []),
        ("    setting = 'opt-in'\n", "option.strip()", [5]),
    ],
)
def test_cross_file_argument_facts_follow_local_assignments(
    tmp_path, body, condition, expected
):
    target = tmp_path / "profile.py"
    target.write_text(
        "from paramiko import WarningPolicy\n\n"
        "def configure(peer, option):\n"
        f"    if {condition}:\n"
        "        peer.set_missing_host_key_policy(WarningPolicy)\n",
        encoding="utf-8",
    )
    (tmp_path / "launch.py").write_text(
        "from paramiko import SSHClient\nfrom profile import configure\n\n"
        "def open_connection(requested):\n"
        "    connection = SSHClient()\n"
        f"{body}"
        "    configure(connection, setting)\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == expected


@pytest.mark.parametrize(("option", "expected"), [("True", [8]), ("False", [])])
def test_local_guard_selects_native_host_key_policy(tmp_path, option, expected):
    target = tmp_path / "profile.py"
    target.write_text(
        "from paramiko import SSHClient, WarningPolicy, RejectPolicy\n\n"
        "def configure():\n"
        "    peer = SSHClient()\n"
        f"    enabled = {option}\n"
        "    policy = RejectPolicy\n"
        "    if enabled: policy = WarningPolicy\n"
        "    peer.set_missing_host_key_policy(policy)\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == expected


def test_guard_assignment_does_not_hide_reachable_policy(tmp_path):
    target = tmp_path / "profile.py"
    target.write_text(
        "from paramiko import SSHClient, WarningPolicy\n\n"
        "def configure():\n"
        "    peer = SSHClient()\n"
        "    enabled = False\n"
        "    if (enabled := True) and enabled:\n"
        "        peer.set_missing_host_key_policy(WarningPolicy)\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == [7]


def test_deferred_global_read_cannot_prune_local_guard(tmp_path):
    target = tmp_path / "profile.py"
    target.write_text(
        "from paramiko import SSHClient, WarningPolicy\n"
        "enabled = False\n"
        "exec('enabled = True')\n"
        "def configure():\n"
        "    peer = SSHClient()\n"
        "    option = enabled\n"
        "    if option:\n"
        "        peer.set_missing_host_key_policy(WarningPolicy)\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == [8]


@pytest.mark.parametrize(
    "assignments",
    [
        (
            "    enabled = False\n    class Configure:\n"
            "        nonlocal enabled\n        enabled = True\n"
        ),
        "    enabled = True\n    assert True, (enabled := False)\n",
        "    enabled = True\n    assert (enabled := False) is not None\n",
        "    allowed, enabled = True, False\n    allowed, enabled = enabled, allowed\n",
    ],
)
def test_uncertain_binding_cannot_prune_native_policy(tmp_path, assignments):
    target = tmp_path / "profile.py"
    target.write_text(
        "from paramiko import SSHClient, WarningPolicy\n"
        "def configure():\n"
        "    peer = SSHClient()\n"
        f"{assignments}"
        "    if enabled:\n"
        "        peer.set_missing_host_key_policy(WarningPolicy)\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == [5 + assignments.count("\n")]


@pytest.mark.parametrize(
    ("parameter", "update"),
    [
        ("permit_unknown=False", "configure_peer.__defaults__ = (True,)"),
        (
            "*, permit_unknown=False",
            'configure_peer.__kwdefaults__["permit_unknown"] = True',
        ),
    ],
)
def test_visible_default_changes_keep_omitted_options_uncertain(
    tmp_path, parameter, update
):
    target = tmp_path / "profiles.py"
    target.write_text(
        "from paramiko import WarningPolicy\n\n"
        f"def configure_peer(channel, {parameter}):\n"
        "    if permit_unknown:\n"
        "        channel.set_missing_host_key_policy(WarningPolicy())\n",
        encoding="utf-8",
    )
    (tmp_path / "launcher.py").write_text(
        "from paramiko import SSHClient\nfrom profiles import configure_peer\n\n"
        "def prepare():\n"
        "    connection = SSHClient()\n"
        f"    {update}\n"
        "    configure_peer(connection)\n",
        encoding="utf-8",
    )
    findings = [
        item for item in scan_ctx(tmp_path, [target]) if item["rule_id"] == "SKY-D380"
    ]
    assert [item["line"] for item in findings] == [5]
