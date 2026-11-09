"""D251 requires a sensitive source and a supported output path."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger import scan_file_with_tree


def findings(source):
    source = textwrap.dedent(source)
    result = []
    scan_file_with_tree(ast.parse(source), "sample.py", result, source=source)
    return [f for f in result if f["rule_id"] == "SKY-D251"]


@pytest.mark.parametrize(
    "output",
    [
        "print(value)",
        "print(f'credential: {value}')",
        "print('credential: %s' % value)",
        "print('credential: {}'.format(value))",
        "print(' '.join(['tool', '--token', value]))",
        "logging.warning('credential: %s', value)",
        "logger.error('credential: %s', value)",
    ],
)
def test_sensitive_environment_value_reaches_output(output):
    result = findings(
        "import os\nimport logging\nlogger = logging.getLogger(__name__)\n"
        "value = os.getenv('SERVICE_API_TOKEN')\n" + output
    )
    assert [(f["line"], f["severity"]) for f in result] == [(5, "HIGH")]
    assert "SERVICE_API_TOKEN" in result[0]["message"]
    evidence = result[0]["metadata"]["security_evidence"]
    assert evidence["evidence_kind"] == "source_to_sink"
    assert evidence["source"] == "environment variable SERVICE_API_TOKEN"
    assert evidence["path"][-1].startswith("reaches ")


def test_locust_command_list_and_input_fallback():
    result = findings("""
        import os
        github_api_token = os.getenv("CHANGELOG_GITHUB_TOKEN") or input("Enter Github API token: ")
        cmd = ["generator", "-t", github_api_token, "--version", "1.0"]
        print(f"Running command: {' '.join(cmd)}")
    """)
    assert [f["line"] for f in result] == [5]


@pytest.mark.parametrize(
    "read",
    [
        "os.environ['SERVICE_PASSWORD']",
        "os.environ.get('SERVICE_PASSWORD')",
        "read_secret('SERVICE_PASSWORD')",
        "env['SERVICE_PASSWORD']",
        "input('Enter password: ')",
        "getpass('Credential: ')",
    ],
)
def test_supported_sources_and_import_aliases(read):
    result = findings(
        "import os\nfrom os import getenv as read_secret, environ as env\n"
        "from getpass import getpass\n"
        f"value = {read}\nprint(value)"
    )
    assert [f["line"] for f in result] == [5]


@pytest.mark.parametrize(
    "body",
    [
        "password = 'public label'\nprint(password)",
        "value = os.getenv('HOME')\nprint(value)",
        "value = input('Enter project name: ')\nprint(value)",
        "value = os.getenv('API_TOKEN')\nvalue = '[REDACTED]'\nprint(value)",
        "value = os.getenv('API_TOKEN')\nprint(len(value))",
        "value = os.getenv('API_TOKEN')\nprint(bool(value))",
        "value = os.getenv('API_TOKEN')\nprint('credential configured')",
        "record = {'token': os.getenv('API_TOKEN'), 'status': 'ready'}\nprint(record['status'])",
        "cmd = ['tool', os.getenv('API_TOKEN')]\nprint(cmd[0])",
        "def handler(password):\n    print(password)",
    ],
)
def test_names_public_data_and_explicit_redaction_are_quiet(body):
    assert findings("import os\n" + body) == []


@pytest.mark.parametrize(
    "source",
    [
        "def f(os):\n    print(os.getenv('API_TOKEN'))",
        "import os\nos = object()\nprint(os.getenv('API_TOKEN'))",
        "import os\nos.getenv = replacement\nprint(os.getenv('API_TOKEN'))",
        "def f(input):\n    print(input('Password: '))",
        "import os\ndef f(print):\n    print(os.getenv('API_TOKEN'))",
        "import os\nprint = custom\nprint(os.getenv('API_TOKEN'))",
        "import os\nlogging = custom\nlogging.info(os.getenv('API_TOKEN'))",
        "import os\nimport logging\nlogger = logging.getLogger(__name__)\nlogger = custom\nlogger.info(os.getenv('API_TOKEN'))",
    ],
)
def test_shadowed_providers_and_output_functions_are_not_proven(source):
    assert findings(source) == []


def test_branch_join_retains_possible_secret_but_all_branch_redaction_is_safe():
    result = findings("""
        import os
        value = os.getenv('API_TOKEN')
        if should_redact:
            value = '[REDACTED]'
        print(value)
        if choice:
            value = '[REDACTED]'
        else:
            value = 'hidden'
        print(value)
    """)
    assert [f["line"] for f in result] == [6]


def test_container_append_alias_and_index_sources():
    result = findings("""
        import os
        cmd = ['tool']
        alias = cmd
        alias.append(os.getenv('API_TOKEN'))
        print(' '.join(cmd))
        print(cmd[1])
    """)
    assert [f["line"] for f in result] == [6, 7]


def test_function_local_sources_do_not_leak_into_other_scopes():
    result = findings("""
        import os
        def disclose():
            value = os.getenv('API_TOKEN')
            print(value)
        def unrelated():
            value = 'public'
            print(value)
    """)
    assert [(f["line"], f["symbol"]) for f in result] == [(5, "disclose")]


def test_console_and_logger_aliases_are_followed():
    result = findings("""
        from builtins import print as console
        from logging import warning as warn
        from os import getenv as read
        emit = console
        value = read('API_TOKEN')
        emit(value)
        warn('%s', value)
    """)
    assert [f["line"] for f in result] == [7, 8]


def test_container_rebinding_does_not_mutate_the_original_alias():
    result = findings("""
        import os
        original = ['tool', os.getenv('API_TOKEN')]
        alias = original
        alias = ['safe']
        print(alias)
        print(original)
    """)
    assert [f["line"] for f in result] == [7]


def test_mutating_container_to_redacted_value_clears_its_alias():
    result = findings("""
        import os
        original = ['tool', os.getenv('API_TOKEN')]
        alias = original
        alias[1] = '[REDACTED]'
        print(original)
    """)
    assert result == []


def test_unknown_container_mutation_does_not_taint_unrelated_values():
    assert (
        findings("""
        import os
        def update(container, public_value):
            container[0] = os.getenv('API_TOKEN')
            print(public_value)
    """)
        == []
    )


def test_terminated_branch_does_not_reach_following_output():
    result = findings("""
        import os
        def report(choice):
            value = 'public'
            if choice:
                value = os.getenv('API_TOKEN')
                return value
            print(value)
    """)
    assert result == []


def test_unused_format_arguments_and_duplicate_dictionary_keys_are_quiet():
    assert (
        findings("""
        import os
        value = os.getenv('API_TOKEN')
        print('public'.format(value))
        print('{0}'.format('public', value))
        print({'value': value, 'value': 'redacted'})
    """)
        == []
    )


def test_analysis_without_optional_source_text_also_emits():
    result = []
    tree = ast.parse("import os\nprint(os.getenv('API_TOKEN'))")
    scan_file_with_tree(tree, "sample.py", result)
    assert [
        (f["rule_id"], f["line"]) for f in result if f["rule_id"] == "SKY-D251"
    ] == [("SKY-D251", 2)]


@pytest.mark.parametrize(
    "transform", ["redact(value)", "hash(value)", "value.replace('prefix', 'hidden')"]
)
def test_unproven_transformation_does_not_sanitize(transform):
    result = findings(
        "import os\nvalue = os.getenv('API_TOKEN')\nprint(" + transform + ")"
    )
    assert [f["line"] for f in result] == [3]


@pytest.mark.parametrize(
    "mutation",
    [
        "os.getenv = replacement",
        "os = replacement",
        "setattr(os, 'getenv', replacement)",
    ],
)
def test_module_provider_mutation_after_function_definition_invalidates_proof(mutation):
    assert (
        findings(
            "import os\ndef report():\n    print(os.getenv('API_TOKEN'))\n" + mutation
        )
        == []
    )


def test_module_builtin_shadow_after_function_definition_invalidates_proof():
    assert (
        findings(
            "import os\ndef report():\n    print(os.getenv('API_TOKEN'))\nprint = custom"
        )
        == []
    )
