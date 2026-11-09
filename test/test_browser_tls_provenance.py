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
def test_replaced_browser_providers_are_not_asserted_native(tmp_path, change):
    assert not _scan(
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
