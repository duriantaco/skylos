import ast

import pytest

from skylos.rules.danger.danger_net.ssrf_flow import scan


@pytest.mark.parametrize(
    "body,audit",
    [
        ("return f'https://downloads.example.test/{version}'", False),
        ("return version", True),
        ("return other(version)", True),
        (
            "if version:\n        return version\n    return 'https://example.test'",
            True,
        ),
    ],
)
def test_url_scheme_helper_requires_fixed_scheme_on_every_return(body, audit):
    tree = ast.parse(f"""from urllib.request import urlopen
def get_url(version):
    {body}
def fetch(version):
    return urlopen(get_url(version))
""")
    rows = []
    scan(tree, "app.py", rows)
    assert any(r["rule_id"] == "SKY-D218" for r in rows) == audit


@pytest.mark.parametrize(
    "change",
    [
        "get_url = external",
        "get_url = lambda value: value",
    ],
)
def test_replaced_fixed_scheme_helper_remains_unknown(change):
    tree = ast.parse(f"""from urllib.request import urlopen
def get_url(version):
    return f'https://example.test/{{version}}'
{change}
def fetch(version):
    return urlopen(get_url(version))
""")
    rows = []
    scan(tree, "app.py", rows)
    assert any(r["rule_id"] == "SKY-D218" for r in rows)
