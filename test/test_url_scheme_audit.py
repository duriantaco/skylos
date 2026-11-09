import textwrap

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.catalog import get_rule_catalog


def scan(tmp_path, source):
    path = tmp_path / "download.py"
    path.write_text(textwrap.dedent(source))
    return [f for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == "SKY-D218"]


def test_scheme_audit_catalog_contract():
    entry = next(rule for rule in get_rule_catalog() if rule["id"] == "SKY-D218")
    assert entry["severity"] == "MEDIUM"
    assert entry["finding_type"] == "review"


@pytest.mark.parametrize("url", ["url", "u.Request(url)", "u.Request(url=url)"])
def test_dynamic_urllib_url_is_a_conditional_audit(tmp_path, url):
    findings = scan(
        tmp_path,
        f"import urllib.request as u\ndef fetch(url):\n    return u.urlopen({url})\n",
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert (
        findings[0]["metadata"]["security_evidence"]["evidence_kind"]
        == "url_scheme_audit"
    )
    assert "Audit" in findings[0]["message"]


def test_request_variable_keeps_scheme_audit(tmp_path):
    assert scan(
        tmp_path,
        """
        from urllib import request
        def fetch(url):
            req = request.Request(url, headers={"User-Agent": "demo"})
            with request.urlopen(req) as response:
                return response.read()
    """,
    )


@pytest.mark.parametrize(
    "expr",
    [
        "'https://example.invalid/x'",
        "'file:///explicit/local/path'",
        "f'https://example.invalid/{path}'",
        "'https://' + 'example.invalid/'",
    ],
)
def test_explicit_scheme_does_not_need_dynamic_scheme_audit(tmp_path, expr):
    assert not scan(
        tmp_path,
        f"from urllib.request import urlopen\ndef fetch(path):\n    return urlopen({expr})\n",
    )


@pytest.mark.parametrize(
    "guard",
    [
        "if urlsplit(url).scheme not in ('http', 'https'):\n        raise ValueError()",
        "if urlsplit(url).scheme != 'https':\n        return None",
        "if not url.startswith(('http://', 'https://')):\n        raise ValueError()",
    ],
)
def test_dominating_scheme_allowlist_is_quiet(tmp_path, guard):
    assert not scan(
        tmp_path,
        "from urllib.request import urlopen\nfrom urllib.parse import urlsplit\ndef fetch(url):\n    "
        + guard
        + "\n    return urlopen(url)\n",
    )


@pytest.mark.parametrize(
    "body",
    [
        "if urlsplit(url).scheme not in ('http', 'https'):\n        pass\n    return urlopen(url)",
        "if urlsplit(url).scheme not in ('http', 'https'):\n        raise ValueError()\n    url = other\n    return urlopen(url)",
        "if urlsplit(other).scheme not in ('http', 'https'):\n        raise ValueError()\n    return urlopen(url)",
        "if urlsplit(url).scheme not in ('http', 'file'):\n        raise ValueError()\n    return urlopen(url)",
        "if url.startswith('http'):\n        return urlopen(url)",
        "if other:\n        url = 'https://example.invalid/'\n    return urlopen(url)",
    ],
)
def test_unsafe_lookalike_guards_keep_audit(tmp_path, body):
    assert scan(
        tmp_path,
        "from urllib.request import urlopen\nfrom urllib.parse import urlsplit\ndef fetch(url, other):\n    "
        + body
        + "\n",
    )


def test_shadowed_urlopen_is_not_a_urllib_audit(tmp_path):
    assert not scan(
        tmp_path,
        """
        from urllib.request import urlopen
        def fetch(url, urlopen):
            return urlopen(url)
    """,
    )


def test_rebound_parser_does_not_prove_safe_scheme(tmp_path):
    assert scan(
        tmp_path,
        """
        from urllib.request import urlopen
        from urllib.parse import urlsplit
        def fetch(url, urlsplit):
            if urlsplit(url).scheme != 'https':
                raise ValueError()
            return urlopen(url)
    """,
    )


def test_literal_local_url_and_request_are_quiet(tmp_path):
    assert not scan(
        tmp_path,
        """
        from urllib.request import Request, urlopen
        def fetch():
            url = 'https://example.invalid/'
            req = Request(url)
            return urlopen(req)
    """,
    )


def test_mutated_request_keeps_audit(tmp_path):
    assert scan(
        tmp_path,
        """
        from urllib.request import Request, urlopen
        def fetch(url):
            req = Request('https://example.invalid/')
            req.full_url = url
            return urlopen(req)
    """,
    )


def test_later_parser_import_does_not_hide_prior_monkeypatch(tmp_path):
    assert scan(
        tmp_path,
        """
        import urllib.parse as p
        from types import SimpleNamespace
        p.urlsplit = lambda value: SimpleNamespace(scheme='https')
        from urllib.parse import urlsplit
        from urllib.request import urlopen
        def fetch(url):
            if urlsplit(url).scheme != 'https':
                raise ValueError()
            return urlopen(url)
    """,
    )


def test_custom_right_add_cannot_prove_http_scheme(tmp_path):
    assert scan(
        tmp_path,
        """
        from urllib.request import urlopen
        class Replacement:
            def __radd__(self, other):
                return 'file:///tmp/private'
        def fetch(url):
            return urlopen('https://' + url)
    """,
    )


def test_later_request_import_does_not_hide_prior_monkeypatch(tmp_path):
    assert scan(
        tmp_path,
        """
        import urllib.request as u
        original = u.Request
        u.Request = lambda url: original('file:///tmp/private')
        from urllib.request import Request, urlopen
        def fetch():
            return urlopen(Request('https://example.invalid/'))
    """,
    )


def test_patched_parser_does_not_prove_scheme_guard(tmp_path):
    assert scan(
        tmp_path,
        """
        from unittest.mock import patch
        from urllib.parse import urlsplit
        from urllib.request import urlopen
        @patch('urllib.parse.urlsplit')
        def fetch(mock, url):
            if urlsplit(url).scheme != 'https':
                raise ValueError()
            return urlopen(url)
    """,
    )


@pytest.mark.parametrize(
    "body",
    [
        "return urlopen(API_URL)",
        "return urlopen(Request(API_URL, data=payload))",
        "req = Request(API_URL, data=payload)\n    return urlopen(req)",
        "url = API_URL\n    req = Request(url)\n    return urlopen(req)",
    ],
)
def test_module_literal_url_keeps_its_explicit_scheme(tmp_path, body):
    assert not scan(
        tmp_path,
        "from urllib.request import Request, urlopen\n"
        "API_URL = 'https://api.example.invalid/v1'\n"
        "def fetch(payload):\n    " + body + "\n",
    )


def test_ordered_module_literal_aliases_keep_explicit_scheme(tmp_path):
    assert not scan(
        tmp_path,
        """
        from urllib.request import Request, urlopen
        endpoint = 'https://api.example.invalid/v1'
        API_URL = endpoint
        URL_ALIAS: str = API_URL
        def fetch():
            return urlopen(Request(URL_ALIAS))
        """,
    )


@pytest.mark.parametrize(
    "setup,signature,body",
    [
        ("", "API_URL", "return urlopen(Request(API_URL))"),
        ("", "url", "API_URL = url\n    return urlopen(Request(API_URL))"),
        ("API_URL = input()\n", "", "return urlopen(Request(API_URL))"),
        (
            "", "url",
            "global API_URL\n    API_URL = url\n    return urlopen(API_URL)",
        ),
        ("", "url", "globals()['API_URL'] = url\n    return urlopen(API_URL)"),
        (
            "import sys\n",
            "url",
            "setattr(sys.modules[__name__], 'API_URL', url)\n    return urlopen(API_URL)",
        ),
        (
            "",
            "url",
            "req = Request(API_URL)\n    req.full_url = url\n    return urlopen(req)",
        ),
        (
            "",
            "mutate",
            "req = Request(API_URL)\n    mutate(req)\n    return urlopen(req)",
        ),
        (
            "from unittest.mock import patch\n@patch('download.API_URL')\n",
            "mock",
            "return urlopen(API_URL)",
        ),
        ("", "url", "return urlopen(API_URL + url)"),
    ],
    ids=[
        "parameter-shadow", "local-shadow", "module-rebinding", "global-write",
        "namespace-write", "module-setattr", "request-mutation", "request-escape",
        "mock-patch", "custom-right-add",
    ],
)
def test_module_literal_lookalikes_keep_audit(tmp_path, setup, signature, body):
    assert scan(
        tmp_path,
        "from urllib.request import Request, urlopen\n"
        "API_URL = 'https://api.example.invalid/v1'\n"
        + setup
        + f"def fetch({signature}):\n    " + body + "\n",
    )


@pytest.mark.parametrize(
    "setup",
    [
        "if enabled:\n    API_URL = 'https://api.example.invalid/v1'",
        "import os\nAPI_URL = os.environ['URL']",
        "from config import API_URL",
        "API_URL = later\nlater = 'https://api.example.invalid/v1'",
        "API_URL = 'https://' + suffix",
    ],
    ids=["conditional", "environment", "imported", "forward-alias", "unknown-add"],
)
def test_unproven_module_url_bindings_keep_audit(tmp_path, setup):
    assert scan(
        tmp_path,
        "from urllib.request import Request, urlopen\n"
        + setup
        + "\ndef fetch():\n    return urlopen(Request(API_URL))\n",
    )


def test_fixed_observed_callers_do_not_suppress_unknown_parameter_audit(tmp_path):
    assert scan(
        tmp_path,
        """
        from urllib.request import Request, urlopen
        API_URL = 'https://api.example.invalid/v1'
        class Client:
            def _request_json(self, url):
                return urlopen(Request(url))
            def send(self):
                return self._request_json(API_URL)
        """,
    )
