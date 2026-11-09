import ast

import pytest

from skylos.rules.secrets import scan_ctx


def _scan(source):
    return list(
        scan_ctx(
            {
                "relpath": "app.py",
                "tree": ast.parse(source),
                "lines": source.splitlines(True),
            }
        )
    )


@pytest.mark.parametrize(
    "value",
    [
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "tGzv3JOkF0XG5Qx2TlKWIA",
        "2YotnFZFEjr1zCsicMWpAA",
    ],
)
def test_published_oauth_identifiers_and_examples_are_not_secrets(value):
    assert not _scan(f'token = "{value}"\n')


@pytest.mark.parametrize(
    "value",
    [
        "urn:ietf:params:oauth:grant-type:jwt-bearer-aB3dE5fG7hI9jK2lM4nO6pQ8",
        "tGzv3JOkF0XG5Qx2TlKWIB",
        "2YotnFZFEjr1zCsicMWpAB",
        "aB3dE5fG7hI9jK2lM4nO6pQ8rS0tU1vW2xY3zZ",
    ],
)
def test_changed_examples_and_credentials_in_docstrings_remain_reported(value):
    assert _scan(f'"""Example:\n    token = "{value}"\n"""\n')
