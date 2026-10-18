"""Security-shaped quality findings require evidence of the claimed context."""

import ast
import textwrap

import pytest

from skylos.rules.quality.logic_security import SecurityTodoRule, UndefinedConfigRule
from skylos.rules.quality.practices import FrameworkPracticeRule


def _findings(rule, source):
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    context = {"filename": "application.py", "source": source}
    return [
        finding
        for node in ast.walk(tree)
        for finding in rule.visit_node(node, context) or []
    ]


@pytest.mark.parametrize(
    ("binding", "decorator"),
    [
        ("from unittest.mock import patch", 'patch("release.get_git_tags")'),
        ("from unittest.mock import patch as replace", 'replace("release.datetime")'),
        ("from unittest import mock", 'mock.patch("release.datetime")'),
        ("import unittest.mock as mock", 'mock.patch("release.datetime")'),
        ("import unittest.mock", 'unittest.mock.patch("release.datetime")'),
    ],
)
def test_stdlib_mock_patch_does_not_register_an_http_route(binding, decorator):
    findings = _findings(
        FrameworkPracticeRule(),
        f"import unittest\n{binding}\nclass ReleaseTests(unittest.TestCase):\n"
        f"    @{decorator}\n    def test_release(self, mocked):\n"
        "        return mocked()\n",
    )
    assert not findings


@pytest.mark.parametrize(
    "source",
    [
        """
        from framework import patch
        @patch('/users')
        def change_user():
            return database.update()
        """,
        """
        from unittest.mock import patch
        @patch('release.clock')
        def change_user(mocked):
            return mocked
        """,
        """
        import unittest
        from unittest.mock import patch
        class ReleaseTests(unittest.TestCase):
            @patch('/users')
            def test_route(self):
                return database.update()
        """,
        """
        import unittest
        from unittest.mock import patch
        unittest.TestCase = framework.Controller
        class ReleaseTests(unittest.TestCase):
            @patch('release.clock')
            def test_route(self):
                return database.update()
        """,
        """
        from unittest import TestCase
        from unittest.mock import patch
        TestCase = framework.Controller
        class ReleaseTests(TestCase):
            @patch('release.clock')
            def test_route(self):
                return database.update()
        """,
        """
        import unittest
        from unittest.mock import patch
        patch = router.patch
        class ReleaseTests(unittest.TestCase):
            @patch('release.clock')
            def test_route(self):
                return database.update()
        """,
        """
        import unittest
        from unittest import mock
        class ReleaseTests(unittest.TestCase):
            @mock.patch('release.clock')
            def install(self, mock):
                return database.update()
        """,
        """
        from unittest.mock import patch
        patch = router.patch
        @patch('/users')
        def change_user():
            return database.update()
        """,
        """
        from unittest import mock
        mock.patch = router.patch
        @mock.patch('/users')
        def change_user():
            return database.update()
        """,
        """
        from unittest.mock import patch
        def register(patch):
            @patch('/users')
            def change_user():
                return database.update()
        """,
        """
        from unittest.mock import patch
        from framework import *
        @patch('/users')
        def change_user():
            return database.update()
        """,
        """
        from unittest import mock
        from unittest import mock as another_mock
        another_mock.patch = router.patch
        @mock.patch('/users')
        def change_user():
            return database.update()
        """,
        """
        from unittest.mock import patch
        try:
            setup()
        except Exception as patch:
            @patch('/users')
            def change_user():
                return database.update()
        """,
        """
        from unittest.mock import patch
        match router.patch:
            case patch:
                @patch('/users')
                def change_user():
                    return database.update()
        """,
        """
        from unittest.mock import patch
        @patch('service.client')
        @app.patch('/users')
        def change_user(mocked):
            return database.update()
        """,
    ],
)
def test_patch_lookalikes_and_independent_routes_keep_authorization_findings(source):
    findings = _findings(FrameworkPracticeRule(), source)
    assert any(item["rule_id"] == "SKY-F102" for item in findings)


@pytest.mark.parametrize(
    "comment",
    [
        "# HACK: The following if statement is a hack for f-string prefixes",
        "# TODO: replace this temporary workaround",
        "# XXX TODO FIXME: format the output",
        "# TODO: determine whether connection retries are disabled",
        "# FIXME: stop hardcoding column widths",
    ],
)
def test_generic_maintenance_words_do_not_assert_unfinished_security(comment):
    assert not _findings(SecurityTodoRule(), f"{comment}\nvalue = 1\n")


@pytest.mark.parametrize(
    "comment",
    [
        "# HACK: temporary workaround disables ssl verification",
        "# TODO: stop hardcoding password",
        "# FIXME: disabled authentication during testing",
        "# TEMP: bypass auth security check",
        "# TODO: add input validation",
        "# XXX handle auth-int",
        "# TODO: workaround for refresh_token rotation",
        "# TODO: disable MFA for admins",
        "# TODO: stop bypassing signature checks",
        "# TODO: replace hardcoded signing key",
        "# TODO: disable HTTPS checks",
        "# TODO: remove hardcoded_password",
        "# FIXME: disabled_authentication",
        "# TODO: stop bypass_auth_check",
        "# TODO: replace hardcoded_api_key",
    ],
)
def test_security_subjects_keep_todo_findings(comment):
    findings = _findings(SecurityTodoRule(), f"{comment}\nvalue = 1\n")
    assert [item["rule_id"] for item in findings] == ["SKY-L010"]


@pytest.mark.parametrize(
    "declaration",
    [
        "USE_FAST_LOCALS = os.environ.get('USE_FAST_LOCALS')",
        "USE_FAST_LOCALS: str | None = os.getenv('USE_FAST_LOCALS')",
        "ENABLE_ADMIN_BYPASS = os.getenv('ENABLE_ADMIN_BYPASS')",
    ],
)
def test_module_external_setting_declaration_is_a_definition(declaration):
    assert not _findings(UndefinedConfigRule(), f"import os\n{declaration}\n")


@pytest.mark.parametrize(
    "statement",
    [
        "if os.getenv('ENABLE_RATE_LIMIT'): apply_rate_limit()",
        "use_cache = os.getenv('USE_REDIS_CACHE')",
        "USE_CACHE = os.getenv('USE_REDIS_CACHE')",
        "def run():\n    USE_FAST_LOCALS = os.getenv('USE_FAST_LOCALS')",
        "ENABLE_A = os.getenv('ENABLE_A')\nif os.getenv('ENABLE_B'): enable_b()",
        "ENABLE_A = os.getenv('ENABLE_A')\nif os.getenv('ENABLE_A'): enable_a()",
    ],
)
def test_undeclared_lookalikes_and_later_flag_checks_remain_visible(statement):
    findings = _findings(UndefinedConfigRule(), f"import os\n{statement}\n")
    assert any(item["rule_id"] == "SKY-L016" for item in findings)
