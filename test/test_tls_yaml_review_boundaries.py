"""Frozen independent-review TLS/YAML controls; scan source without executing it."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


def test_replaced_native_context_method_is_not_a_safe_configuration_call(tmp_path):
    source = (
        "import ssl\nfrom urllib.request import HTTPSHandler\n"
        "def override(protocols):\n    ctx.check_hostname=False\n    ctx.verify_mode=ssl.CERT_NONE\n"
        "ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "ctx.set_alpn_protocols=override\nctx.set_alpn_protocols(['h2'])\n"
        "handler=HTTPSHandler(context=ctx)\n"
    )
    path = tmp_path.resolve() / "app.py"
    path.write_text(source)
    assert any(row["rule_id"] == "SKY-D210" for row in scan_ctx(path.parent, [path]))


def test_saved_native_alpn_method_keeps_verifying_client_quiet(tmp_path):
    path = tmp_path.resolve() / "app.py"
    path.write_text(
        "import ssl\nfrom urllib.request import HTTPSHandler\n"
        "ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "configure=ctx.set_alpn_protocols\nconfigure(['h2'])\n"
        "handler=HTTPSHandler(context=ctx)\n"
    )
    assert not any(
        row["rule_id"] == "SKY-D210" for row in scan_ctx(path.parent, [path])
    )


def test_native_server_socket_wrapper_does_not_require_client_verification(tmp_path):
    path = tmp_path.resolve() / "app.py"
    path.write_text(
        "import ssl\ndef server(sock):\n"
        "    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS)\n"
        "    ctx.load_cert_chain('server.pem')\n"
        "    return ctx.wrap_socket(sock, server_side=True)\n"
    )
    assert not any(
        row["rule_id"] == "SKY-D210" for row in scan_ctx(path.parent, [path])
    )


def test_context_capability_walk_handles_deep_and_bounded_expressions():
    from skylos.rules.danger.tls_provenance import _uses

    expression = ast.Name(id="ctx", ctx=ast.Load())
    for _ in range(2000):
        expression = ast.UnaryOp(op=ast.UAdd(), operand=expression)
    assert _uses(expression, {"ctx"}) is True
    # At the work boundary an unknown expression cannot prove absence of the
    # context capability; it must retain the original security candidate.
    assert (
        _uses(ast.List(elts=[ast.Constant(value=0) for _ in range(10001)]), {"ctx"})
        is True
    )


@pytest.mark.parametrize(
    "source",
    [
        "def render(ignore_https_errors=False):\n    return {'ignored':ignore_https_errors}\nrender.__code__=browser.new_context.__code__\nrender(ignore_https_errors=True)\n",
        "def render(ignore_https_errors=False):\n    return {'ignored':ignore_https_errors}\nalias=render\nsetattr(alias, '__code__', browser.new_context.__code__)\nrender(ignore_https_errors=True)\n",
        "def render(ignore_https_errors=False):\n    return {'ignored':ignore_https_errors}\nvalue=render(ignore_https_errors=True)\nforward(value)\n",
    ],
)
def test_local_body_cannot_refute_replacement_or_result_escape(tmp_path, source):
    path = tmp_path.resolve() / "app.py"
    path.write_text(source)
    assert any(row["rule_id"] == "SKY-D210" for row in scan_ctx(path.parent, [path]))


CASES = [
    (
        "tls-saved-setter",
        'import ssl\nimport urllib.request\ndef connect():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    setter=ctx.__setattr__\n    setter("check_hostname", False)\n    setter("verify_mode", ssl.CERT_NONE)\n    return urllib.request.urlopen("https://service.example", context=ctx)\n',
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-saved-setter-late-disable",
        'import ssl\nimport urllib.request\ndef connect():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    ctx.check_hostname=True\n    ctx.verify_mode=ssl.CERT_REQUIRED\n    setter=ctx.__setattr__\n    setter("check_hostname", False)\n    setter("verify_mode", ssl.CERT_NONE)\n    return urllib.request.urlopen("https://service.example", context=ctx)\n',
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-provider-local-ssl",
        'import ssl\nimport urllib.request\ndef connect():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    pass\n    return urllib.request.urlopen("https://service.example", context=ctx)\n',
        {
            "ssl.py": "from _ssl import _SSLContext as SSLContext, PROTOCOL_TLS, CERT_NONE\nPROTOCOL_TLS_CLIENT=PROTOCOL_TLS\n"
        },
        "SKY-D210",
        True,
    ),
    (
        "tls-local-requests-noop",
        'import requests\nrequests.get("label", verify=False)\n',
        {"requests.py": "def get(value, verify=True):\n    return value\n"},
        "SKY-D210",
        False,
    ),
    (
        "tls-local-ssl-noop",
        "import ssl\nctx=ssl.SSLContext(ssl.PROTOCOL_TLS)\n",
        {
            "ssl.py": "PROTOCOL_TLS=1\nclass SSLContext:\n    def __init__(self, protocol):\n        self.protocol=protocol\n"
        },
        "SKY-D210",
        False,
    ),
    (
        "yaml-saved-setter",
        'import yaml\nsetter=yaml.__setattr__\nsetter("SafeLoader", yaml.Loader)\ndef load(value):\n    return yaml.load(value, Loader=yaml.SafeLoader)\n',
        {},
        "SKY-D206",
        True,
    ),
    (
        "tls-container-alias-disable",
        'import ssl\nimport urllib.request\ndef connect():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    contexts=[ctx]\n    contexts[0].check_hostname=False\n    contexts[0].verify_mode=ssl.CERT_NONE\n    return urllib.request.urlopen("https://service.example", context=ctx)\n',
        {},
        "SKY-D210",
        True,
    ),
    (
        "yaml-import-alias-constructor-mutation",
        'import yaml\nfrom yaml import SafeLoader as Loader\ndef unsafe(loader,node):\n    return eval(loader.construct_scalar(node))\nLoader.add_constructor("!run", unsafe)\ndef load(value):\n    return yaml.load(value,Loader=Loader)\n',
        {},
        "SKY-D206",
        True,
    ),
    (
        "tls-client-control",
        "import ssl\nfrom urllib.request import HTTPSHandler\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    return HTTPSHandler(context=ctx)\n",
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-client-log-mode",
        "import ssl\nfrom urllib.request import HTTPSHandler\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    print(ctx.verify_mode)\n    return HTTPSHandler(context=ctx)\n",
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-client-alpn",
        'import ssl\nfrom urllib.request import HTTPSHandler\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    ctx.set_alpn_protocols(["h2", "http/1.1"])\n    return HTTPSHandler(context=ctx)\n',
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-client-configure-negative",
        "import ssl\nfrom urllib.request import HTTPSHandler\ndef disable(ctx):\n    ctx.check_hostname=False\n    ctx.verify_mode=ssl.CERT_NONE\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    disable(ctx)\n    return HTTPSHandler(context=ctx)\n",
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-client-log-hostname",
        "import ssl\nfrom urllib.request import HTTPSHandler\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    print(ctx.check_hostname)\n    return HTTPSHandler(context=ctx)\n",
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-playwright-sync-context",
        "from playwright.sync_api import sync_playwright\ndef run():\n    with sync_playwright() as p:\n        browser=p.chromium.launch()\n        context=browser.new_context(ignore_https_errors=True)\n",
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-playwright-async-context",
        "from playwright.async_api import async_playwright\nasync def run():\n    async with async_playwright() as p:\n        browser=await p.chromium.launch()\n        context=await browser.new_context(ignore_https_errors=True)\n",
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-playwright-branch-context",
        "from playwright.sync_api import sync_playwright\ndef run(flag):\n    with sync_playwright() as p:\n        if flag:\n            browser=p.chromium.launch()\n        else:\n            browser=p.firefox.launch()\n        context=browser.new_context(ignore_https_errors=True)\n",
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-playwright-container-context",
        'from playwright.sync_api import sync_playwright\ndef run():\n    with sync_playwright() as p:\n        browsers={"chrome":p.chromium}\n        browser=browsers["chrome"].launch()\n        context=browser.new_context(ignore_https_errors=True)\n',
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-browserconfig-wrapper",
        "from playwright.sync_api import sync_playwright\ndef BrowserConfig(browser,ignore_https_errors=False):\n    return browser.new_context(ignore_https_errors=ignore_https_errors)\ndef run():\n    with sync_playwright() as p:\n        browser=p.chromium.launch()\n        return BrowserConfig(browser,ignore_https_errors=True)\n",
        {},
        "SKY-D210",
        True,
    ),
    (
        "tls-local-render-inert",
        'def render(ignore_https_errors=False):\n    return {"ignored":ignore_https_errors}\nrender(ignore_https_errors=True)\n',
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-client-callback-mode",
        "import ssl\nfrom urllib.request import HTTPSHandler\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    callback(ctx.verify_mode)\n    return HTTPSHandler(context=ctx)\n",
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-client-native-constant-alias",
        "import ssl\nfrom urllib.request import HTTPSHandler\nPROTOCOL=ssl.PROTOCOL_TLS_CLIENT\ndef client():\n    ctx=ssl.SSLContext(PROTOCOL)\n    return HTTPSHandler(context=ctx)\n",
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-client-literal-config-alias",
        "import ssl\nfrom urllib.request import HTTPSHandler\nCHECK=True\nVERIFY=2\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS)\n    ctx.verify_mode=VERIFY\n    ctx.check_hostname=CHECK\n    return HTTPSHandler(context=ctx)\n",
        {},
        "SKY-D210",
        False,
    ),
    (
        "tls-dict-alias-disable",
        'import ssl\nfrom urllib.request import HTTPSHandler\ndef client():\n    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    contexts={"main":ctx}\n    contexts["main"].check_hostname=False\n    return HTTPSHandler(context=ctx)\n',
        {},
        "SKY-D210",
        True,
    ),
    (
        "yaml-local-provider",
        "import yaml\ndef load(value):\n    return yaml.load(value, Loader=yaml.SafeLoader)\n",
        {
            "yaml.py": "from pickle import loads\nclass SafeLoader: pass\ndef load(value, Loader=None):\n    return loads(value)\n"
        },
        "SKY-D206",
        True,
    ),
    (
        "yaml-searchpath-replacement",
        'import sys\nsys.path.insert(0, "plugins")\nimport yaml\ndef load(value):\n    return yaml.load(value, Loader=yaml.SafeLoader)\n',
        {},
        "SKY-D206",
        True,
    ),
    (
        "tls-protocol-searchpath",
        'import sys\nsys.path.insert(0, "plugins")\nimport ssl\nctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n',
        {},
        "SKY-D210",
        True,
    ),
]


@pytest.mark.parametrize(
    "name,source,providers,rule,want", CASES, ids=[row[0] for row in CASES]
)
def test_reviewed_tls_yaml_boundary(tmp_path, name, source, providers, rule, want):
    root = tmp_path.resolve()
    path = root / "app.py"
    path.write_text(source)
    for relative, text in providers.items():
        provider = root / relative
        provider.parent.mkdir(parents=True, exist_ok=True)
        provider.write_text(text)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = root
    linter.visit(ast.parse(source))
    for findings in (scan_ctx(root, [path]), linter.findings):
        assert any(row["rule_id"] == rule for row in findings) is want


@pytest.mark.parametrize(
    "name,source,providers,rule,want",
    [
        row
        for row in CASES
        if "playwright" in row[0]
        or row[0]
        in {
            "tls-client-log-mode",
            "tls-client-alpn",
            "yaml-saved-setter",
            "tls-browserconfig-wrapper",
            "tls-local-render-inert",
        }
    ],
    ids=lambda value: value if isinstance(value, str) and "\n" not in value else None,
)
def test_reviewed_boundary_reaches_native_gate(
    tmp_path, name, source, providers, rule, want
):
    root = tmp_path.resolve()
    (root / "app.py").write_text(source)
    for relative, text in providers.items():
        provider = root / relative
        provider.parent.mkdir(parents=True, exist_ok=True)
        provider.write_text(text)
    report = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not report.get("analysis_errors")
    rows = [row for row in report.get("danger", []) if row["rule_id"] == rule]
    assert bool(rows) is want
    if rows:
        assert all(row["listing"]["listed"] for row in rows)
    passed, reasons = check_gate(
        {**report, "danger": rows}, {"gate": {"max_security": 0, "max_high": 0}}
    )
    assert passed is (not want), reasons
