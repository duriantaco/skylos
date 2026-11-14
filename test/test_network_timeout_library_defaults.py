import ast
import textwrap

import pytest

from skylos.rules.quality.logic_security import MissingNetworkTimeoutRule


def _findings(code):
    rule = MissingNetworkTimeoutRule()
    rows = []
    for node in ast.walk(ast.parse(textwrap.dedent(code))):
        found = rule.visit_node(node, {"filename": "app.py"})
        if found:
            rows.extend(found)
    return sorted((row["name"], row["value"]) for row in rows)


@pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete", "head", "options"])
def test_httpx_default_timeout_is_not_a_missing_timeout(method):
    code = f"""
        import httpx
        def call(url):
            return httpx.{method}(url)
    """
    assert _findings(code) == []


def test_httpx_timeout_none_disables_the_default_and_reports():
    code = """
        import httpx
        def call(url):
            return httpx.get(url, timeout=None)
    """
    assert _findings(code) == [("httpx.get", "timeout_none")]


def test_requests_without_timeout_still_reports():
    code = """
        import requests
        def call(url):
            return requests.get(url)
    """
    assert _findings(code) == [("requests.get", "no_timeout")]


def test_urlopen_without_timeout_still_reports():
    code = """
        from urllib.request import urlopen
        def call(url):
            return urlopen(url)
    """
    assert _findings(code) == [("urlopen", "no_timeout")]
