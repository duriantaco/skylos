import ast

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.calls import DangerousCallsRule


def _scan(tmp_path, code):
    path = tmp_path / "browser.py"
    path.write_text(code)
    rows = [r for r in scan_ctx(tmp_path, [path]) if r["rule_id"] == "SKY-D210"]
    rule = DangerousCallsRule()
    native = []
    for node in ast.walk(ast.parse(code)):
        native.extend(rule.visit_node(node, {"filename": str(path)}) or [])
    assert [(r["rule_id"], r["line"]) for r in rows] == [
        (r["rule_id"], r["line"]) for r in native if r["rule_id"] == "SKY-D210"
    ]
    return rows


@pytest.mark.parametrize("option", ["True", "False", "configured"])
def test_browser_tls_option_requires_disabled_native_context(tmp_path, option):
    rows = _scan(
        tmp_path,
        f"""
from playwright.async_api import async_playwright
async def fetch():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        return await browser.new_context(ignore_https_errors={option})
""",
    )
    assert bool(rows) == (option == "True")


def test_both_native_launch_branches_preserve_browser_identity(tmp_path):
    rows = _scan(
        tmp_path,
        """
from playwright.async_api import async_playwright
async def fetch(firefox):
    async with async_playwright() as p:
        browser = None
        if firefox:
            browser = await p.firefox.launch()
        else:
            browser = await p.chromium.launch()
        return await browser.new_context(ignore_https_errors=True)
""",
    )
    assert len(rows) == 1


@pytest.mark.parametrize(
    "change",
    [
        "browser = replacement",
        "p = replacement",
        "p.chromium.launch = replacement",
    ],
)
def test_replaced_or_uncertain_browser_still_reviews_disabled_verification(
    tmp_path, change
):
    assert _scan(
        tmp_path,
        f"""
from playwright.async_api import async_playwright
async def fetch():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        {change}
        return await browser.new_context(ignore_https_errors=True)
""",
    )


def test_unrelated_new_context_keyword_does_not_claim_browser_tls(tmp_path):
    assert not _scan(
        tmp_path,
        """
class Local:
    def new_context(self, **kwargs): return kwargs
Local().new_context(ignore_https_errors=True)
""",
    )


@pytest.mark.parametrize(
    "change",
    [
        "Local.new_context = replacement",
        "alias = Local\nalias.new_context = replacement",
        "forward(Local)",
    ],
)
def test_replaced_or_escaped_local_method_does_not_prove_inert(tmp_path, change):
    assert _scan(
        tmp_path,
        f"""
class Local:
    def new_context(self, **kwargs): return kwargs
{change}
Local().new_context(ignore_https_errors=True)
""",
    )


@pytest.mark.parametrize(
    "method",
    [
        "def new_context(self, **kwargs): return callback(**kwargs)",
        "def __init__(self): callback()\n    def new_context(self, **kwargs): return kwargs",
        "def __getattribute__(self, name): return callback\n    def new_context(self, **kwargs): return kwargs",
    ],
)
def test_effectful_or_protocol_local_object_does_not_prove_inert(tmp_path, method):
    assert _scan(
        tmp_path,
        f"""
class Local:
    {method}
Local().new_context(ignore_https_errors=True)
""",
    )


def test_used_local_method_return_does_not_prove_inert(tmp_path):
    assert _scan(
        tmp_path,
        """
class Local:
    def new_context(self, **kwargs): return kwargs
def build():
    return Local().new_context(ignore_https_errors=True)
""",
    )


@pytest.mark.parametrize(
    "patch",
    [
        "browser.Local.new_context = replacement",
        "browser.Local.__new__ = replacement",
        "vars(browser.Local)['new_context'] = replacement",
    ],
)
def test_imported_project_mutation_refutes_local_method_proof(tmp_path, patch):
    (tmp_path / "mutator.py").write_text(f"import browser\n{patch}\n")
    assert _scan(
        tmp_path,
        """
class Local:
    def new_context(self, **kwargs): return kwargs
import mutator
Local().new_context(ignore_https_errors=True)
""",
    )
