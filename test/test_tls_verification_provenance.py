"""TLS findings follow provider identity and actual verification state."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


def _both(tmp_path, source):
    root = tmp_path.resolve()
    path = root / "client.py"
    path.write_text(source)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(source))
    return [
        [row for row in findings if row["rule_id"] == "SKY-D210"]
        for findings in (scan_ctx(root, [path]), linter.findings)
    ]


@pytest.mark.parametrize(
    "setup",
    [
        "ctx.verify_mode = ssl.CERT_NONE",
        "ctx.check_hostname = False",
        "if condition:\n        ctx.verify_mode = ssl.CERT_REQUIRED",
        "ctx.verify_mode = ssl.CERT_REQUIRED\n    ctx.verify_mode = ssl.CERT_NONE",
        "ctx.check_hostname = True\n    ctx.check_hostname = False",
        "ctx.load_cert_chain('client.pem')",
        "ctx.verify_mode = ssl.CERT_REQUIRED",
        "other = ctx\n    other.verify_mode = ssl.CERT_NONE",
    ],
)
def test_nonverifying_or_conditional_client_setup_keeps_finding(tmp_path, setup):
    source = (
        "import ssl\nfrom urllib.request import HTTPSHandler\n"
        "def client(condition=False):\n"
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n"
        f"    {setup}\n"
        "    return HTTPSHandler(context=ctx)\n"
    )
    for findings in _both(tmp_path, source):
        assert [(row["line"], row["severity"]) for row in findings] == [(4, "HIGH")]


@pytest.mark.parametrize(
    "body",
    [
        "ctx.check_hostname = False",
        "ctx.check_hostname = False\n    ctx.verify_mode = ssl.CERT_NONE",
        "if condition:\n        ctx.check_hostname = False",
    ],
)
def test_client_default_does_not_hide_later_disabling_writes(tmp_path, body):
    source = (
        "import ssl\nfrom urllib.request import HTTPSHandler\n"
        "def client(condition=False):\n"
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        f"    {body}\n"
        "    return HTTPSHandler(context=ctx)\n"
    )
    for findings in _both(tmp_path, source):
        assert [row["line"] for row in findings] == [4]


@pytest.mark.parametrize(
    "source",
    [
        "import ssl\ndef client():\n    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n    ctx.verify_mode = ssl.CERT_REQUIRED\n    ctx.check_hostname = True\n    return ctx\n",
        "from ssl import SSLContext as Context, PROTOCOL_TLS as Protocol, CERT_REQUIRED as Required\ndef client():\n    ctx = Context(Protocol)\n    ctx.verify_mode = Required\n    ctx.check_hostname = True\n    return ctx\n",
        "import ssl as secure\ndef client():\n    return secure.SSLContext(secure.PROTOCOL_TLS_CLIENT)\n",
    ],
)
def test_native_verifying_contexts_and_import_aliases_are_quiet(tmp_path, source):
    assert _both(tmp_path, source) == [[], []]


@pytest.mark.parametrize(
    "source",
    [
        "def render(ignore_https_errors=False):\n    return {'ignored': ignore_https_errors}\nrender(ignore_https_errors=True)\n",
        "class SSLContext:\n    def __init__(self, protocol=None):\n        pass\nSSLContext()\n",
        "class BrowserConfig:\n    def __init__(self, ignore_https_errors=False):\n        self.ignored = ignore_https_errors\nBrowserConfig(ignore_https_errors=True)\n",
    ],
)
def test_proven_local_or_shadowed_provider_lookalikes_are_quiet(tmp_path, source):
    assert _both(tmp_path, source) == [[], []]


@pytest.mark.parametrize(
    "source",
    [
        "import ssl as s\ns._create_unverified_context()\n",
        "import ssl\ndef render(ssl):\n    return ssl._create_unverified_context()\nrender(ssl)\n",
        "import requests\ndef render(requests):\n    return requests.get('https://example.test', verify=False)\nrender(requests)\n",
        "from ssl import SSLContext as C, PROTOCOL_TLS as P\nC(P)\n",
        "import requests as r\nr.get('https://example.test', verify=False)\n",
        "import requests\nrequests.get('https://example.test', verify=0)\n",
        "from requests import Session as S\ns = S()\ns.get('https://example.test', verify=False)\n",
        "import httpx as h\nclient = h.Client(verify=False)\n",
        "from crawl4ai import BrowserConfig as Config\nConfig(ignore_https_errors=True)\n",
        "from playwright.sync_api import sync_playwright\nwith sync_playwright() as p:\n    p.chromium.launch().new_context(ignore_https_errors=True)\n",
    ],
)
def test_native_provider_aliases_keep_findings(tmp_path, source):
    for findings in _both(tmp_path, source):
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "body",
    [
        "old = ctx\n    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    ctx.verify_mode = ssl.CERT_REQUIRED\n    ctx.check_hostname = True\n    return HTTPSHandler(context=old)",
        "ctx.verify_mode = ssl.CERT_REQUIRED\n    ctx.check_hostname = True\n    configure(ctx)\n    return ctx",
        "ctx.verify_mode = ssl.CERT_REQUIRED\n    ctx.check_hostname = True\n    box.context = ctx\n    return ctx",
        "return HTTPSHandler(context=ctx)\n    ctx.verify_mode = ssl.CERT_REQUIRED\n    ctx.check_hostname = True",
    ],
)
def test_rebinding_or_opaque_mutation_cannot_lend_context_safety(tmp_path, body):
    source = (
        "import ssl\nfrom urllib.request import HTTPSHandler\n"
        "def client():\n"
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n"
        f"    {body}\n"
    )
    for findings in _both(tmp_path, source):
        assert any(row["line"] == 4 for row in findings)


def test_replaced_ssl_constant_does_not_prove_verification(tmp_path):
    source = (
        "import ssl\nssl.CERT_REQUIRED = ssl.CERT_NONE\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n"
        "ctx.verify_mode = ssl.CERT_REQUIRED\nctx.check_hostname = True\n"
    )
    for findings in _both(tmp_path, source):
        assert [row["line"] for row in findings] == [3]


@pytest.mark.parametrize(
    "source,line",
    [
        (
            "import ssl\ndef context(condition):\n    if condition:\n        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n        ctx.check_hostname = False\n        return ctx\n",
            4,
        ),
        (
            "import ssl\nfirst = second = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nsecond.check_hostname = False\n",
            2,
        ),
        (
            "import ssl\ndef context(condition):\n    if condition:\n        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n        configure(ctx)\n        return ctx\n",
            4,
        ),
        (
            "import ssl\ndef context(condition):\n    if condition:\n        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n        setattr(ctx, 'check_hostname', False)\n        return ctx\n",
            4,
        ),
    ],
)
def test_conditional_or_chained_context_creation_retains_disabling_writes(
    tmp_path, source, line
):
    for findings in _both(tmp_path, source):
        assert [row["line"] for row in findings] == [line]


def test_native_report_lists_unsafe_context_and_fails_zero_security_gate(tmp_path):
    path = tmp_path.resolve() / "client.py"
    path.write_text(
        "import ssl\nfrom urllib.request import HTTPSHandler\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "handler = HTTPSHandler(context=ctx)\n"
    )
    result = json.loads(
        analyze(
            str(path.parent),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    [finding] = [r for r in result.get("danger", []) if r["rule_id"] == "SKY-D210"]
    assert finding["listing"]["listed"] is True
    passed, reasons = check_gate(result, {"gate": {"max_security": 0, "max_high": 0}})
    assert passed is False
    assert any("security issue" in reason for reason in reasons)
