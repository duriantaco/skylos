"""An inert local body needs complete import effects and provider ownership."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


def test_reused_caller_tree_rechecks_imported_callable_effects(tmp_path):
    root = tmp_path.resolve()
    path = root / "app.py"
    source = (
        "def render(ignore_https_errors=False):\n    return {'ignored':ignore_https_errors}\n"
        "import mutator\nrender(ignore_https_errors=True)\n"
    )
    path.write_text(source)
    mutator = root / "mutator.py"
    mutator.write_text("pass\n")
    tree = ast.parse(source)

    def hits():
        linter = LinterVisitor([DangerousCallsRule()], str(path))
        linter.context["project_root"] = root
        linter.visit(tree)
        return any(row["rule_id"] == "SKY-D210" for row in linter.findings)

    assert hits() is False
    mutator.write_text(
        "import app\nfrom crawl4ai import BrowserConfig as Native\napp.render=Native\n"
    )
    assert hits() is True


@pytest.mark.parametrize("mutate", [True, False], ids=["patched", "pure"])
@pytest.mark.parametrize(
    "package_init", [True, False], ids=["regular-package", "namespace-package"]
)
def test_package_qualified_import_can_replace_an_inline_callable(
    tmp_path, mutate, package_init
):
    package = tmp_path.resolve() / "pkg"
    package.mkdir()
    if package_init:
        (package / "__init__.py").write_text("")
    path = package / "app.py"
    source = (
        "def render(ignore_https_errors=False):\n    return {'ignored':ignore_https_errors}\n"
        "from . import mutator\nrender(ignore_https_errors=True)\n"
    )
    path.write_text(source)
    (package / "mutator.py").write_text(
        "import pkg.app\nfrom crawl4ai import BrowserConfig as Native\npkg.app.render=Native\n"
        if mutate
        else "pass\n"
    )
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(source))
    assert any(row["rule_id"] == "SKY-D210" for row in linter.findings) is mutate


@pytest.mark.parametrize(
    "explicit_root", [True, False], ids=["project-root", "filename-parent"]
)
@pytest.mark.parametrize(
    "source,providers,want",
    [
        (
            "import mutator\nimport requests\nrequests.get('https://example.com',verify=False)\n",
            {
                "requests.py": "def get(url,verify=True):\n    return {'url':url}\n",
                "mutator.py": "import requests,httpx\nrequests.get=httpx.get\n",
            },
            True,
        ),
        (
            "import requests\nrequests.get('https://example.com',verify=False)\n",
            {"requests.py": "def get(url,verify=True):\n    return {'url':url}\n"},
            False,
        ),
        (
            "def BrowserConfig(ignore_https_errors=False):\n    return {'ignored':ignore_https_errors}\nimport mutator\nBrowserConfig(ignore_https_errors=True)\n",
            {
                "mutator.py": "import app\nfrom crawl4ai import BrowserConfig as Native\napp.BrowserConfig=Native\n"
            },
            True,
        ),
        (
            "def render(ignore_https_errors=False):\n    return {'ignored':ignore_https_errors}\nimport mutator\nrender(ignore_https_errors=True)\n",
            {
                "mutator.py": "import app\nfrom crawl4ai import BrowserConfig as Native\napp.render=Native\n"
            },
            True,
        ),
    ],
    ids=[
        "imported-provider-patch",
        "pure-provider",
        "imported-inline-classname-patch",
        "imported-inline-render-patch",
    ],
)
def test_inert_proof_includes_imported_project_effects(
    tmp_path, explicit_root, source, providers, want
):
    root = tmp_path.resolve()
    path = root / "app.py"
    path.write_text(source)
    for relative, text in providers.items():
        (root / relative).write_text(text)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    if explicit_root:
        linter.context["project_root"] = root
    linter.visit(ast.parse(source))
    for rows in (scan_ctx(root if explicit_root else None, [path]), linter.findings):
        assert any(row["rule_id"] == "SKY-D210" for row in rows) is want


@pytest.mark.parametrize(
    "metadata",
    [
        "requests.so",
        "requests.pyd",
        "package-and-module",
        "compiled-package",
        "symlink-provider",
    ],
)
def test_opaque_or_ambiguous_provider_metadata_cannot_prove_inert(tmp_path, metadata):
    root = tmp_path.resolve()
    path = root / "app.py"
    path.write_text(
        "import requests\nrequests.get('https://example.com',verify=False)\n"
    )
    text = "def get(url,verify=True):\n    return {'url':url}\n"
    provider = root / "requests.py"
    if metadata == "symlink-provider":
        implementation = root / "implementation.py"
        implementation.write_text(text)
        provider.symlink_to(implementation)
    else:
        provider.write_text(text)
        if metadata in {"package-and-module", "compiled-package"}:
            (root / "requests").mkdir()
            if metadata == "package-and-module":
                (root / "requests/__init__.py").write_text(text)
            else:
                (root / "requests/__init__.so").write_bytes(
                    b"opaque package import provider metadata"
                )
        else:
            # Metadata uncertainty control only: this artifact is never loaded
            # or executed, and no vulnerability in it is asserted.
            (root / metadata).write_bytes(b"opaque import provider metadata")
    assert any(row["rule_id"] == "SKY-D210" for row in scan_ctx(root, [path]))
