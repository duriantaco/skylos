"""SKY-L012 for phantom submodules of installed packages, and SKY-D224
unknown keywords to installed APIs (agent-code benchmark mb-01 / fa-05)."""

from __future__ import annotations

import importlib.util
import inspect
import textwrap

import pytest

from skylos.rules.ai_defect.api_signature_hallucination import (
    DEFAULT_API_SIGNATURE_ALLOWLIST,
    RULE_ID_API_SIGNATURE,
    RULE_ID_PHANTOM_REFERENCE,
    installed_submodule_exists,
    scan_python_api_signature_hallucinations,
)


def _scan_fake(tmp_path, source, *, surfaces, existing, allowed=("pkg",)):
    path = tmp_path / "app.py"
    path.write_text(  # skylos: ignore[SKY-D324] fixed app.py fixture under pytest tmp_path
        textwrap.dedent(source), encoding="utf-8"
    )

    def loader(_root, module_name):
        return surfaces.get(module_name)

    def resolver(module_name):
        return existing.get(module_name)

    return scan_python_api_signature_hallucinations(
        tmp_path,
        [path],
        allowed_modules=allowed,
        surface_loader=loader,
        submodule_resolver=resolver,
    )


PKG_SURFACE = {
    "pkg": {"members": {"Session": {"kind": "class", "parameters": []}}},
    "pkg.adapters": {"members": {"HTTPAdapter": {"kind": "class"}}},
}


@pytest.mark.parametrize(
    "source",
    [
        "from pkg.retry import RetryPolicy\n",
        "import pkg.retry\n",
        "import pkg.retry as r\n",
        "from pkg.retry.policy import X\n",
    ],
)
def test_phantom_submodule_of_installed_package_is_reported(tmp_path, source):
    findings = _scan_fake(
        tmp_path,
        source,
        surfaces=PKG_SURFACE,
        existing={"pkg.retry": False, "pkg.adapters": True},
    )
    assert [f["rule_id"] for f in findings] == [RULE_ID_PHANTOM_REFERENCE]
    assert findings[0]["line"] == 1
    assert "pkg.retry" in findings[0]["message"]
    assert findings[0]["category"] == "ai_defect"


@pytest.mark.parametrize(
    "source,existing",
    [
        # real submodule
        ("from pkg.adapters import HTTPAdapter\n", {"pkg.adapters": True}),
        # attribute re-export from the root
        ("from pkg import Session\n", {}),
        # existence unknown (import error / lazy __getattr__)
        ("from pkg.retry import X\n", {"pkg.retry": None}),
        # guarded optional import
        (
            """
            try:
                from pkg.retry import X
            except ImportError:
                X = None
            """,
            {"pkg.retry": False},
        ),
        (
            """
            try:
                import pkg.retry
            except (ModuleNotFoundError, OSError):
                pass
            """,
            {"pkg.retry": False},
        ),
        # the parent exports the name as an attribute (e.g. a module alias)
        ("from pkg.Session import x\n", {"pkg.Session": False}),
        # relative import is local, never third-party
        ("from .pkg.retry import X\n", {"pkg.retry": False}),
    ],
)
def test_submodule_negatives(tmp_path, source, existing):
    findings = _scan_fake(tmp_path, source, surfaces=PKG_SURFACE, existing=existing)
    assert [f for f in findings if f["rule_id"] == RULE_ID_PHANTOM_REFERENCE] == []


def test_uninstalled_package_is_left_to_other_rules(tmp_path):
    findings = _scan_fake(
        tmp_path,
        "from pkg.retry import X\n",
        surfaces={},
        existing={"pkg.retry": False},
    )
    assert findings == []


def test_project_local_package_shadowing_is_not_third_party(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    findings = _scan_fake(
        tmp_path,
        "from pkg.retry import X\n",
        surfaces=PKG_SURFACE,
        existing={"pkg.retry": False},
    )
    assert findings == []


def test_installed_submodule_exists_real_modules():
    assert installed_submodule_exists("json.decoder") is True
    assert installed_submodule_exists("os.path") is True
    assert installed_submodule_exists("json.no_such_module_xyz") is False
    assert installed_submodule_exists("no_such_pkg_xyz.sub") is None


requests_installed = importlib.util.find_spec("requests") is not None


@pytest.mark.skipif(not requests_installed, reason="requests not installed")
def test_requests_retry_is_reported_end_to_end(tmp_path):
    path = tmp_path / "translate.py"
    path.write_text(
        "import requests\n"
        "from requests.retry import RetryPolicy\n"
        "from requests.adapters import HTTPAdapter\n"
        "from requests.exceptions import HTTPError\n"
        "from requests import Session\n",
        encoding="utf-8",
    )
    findings = scan_python_api_signature_hallucinations(tmp_path, [path])
    phantom = [f for f in findings if f["rule_id"] == RULE_ID_PHANTOM_REFERENCE]
    assert [f["line"] for f in phantom] == [2]
    assert [f for f in findings if f["rule_id"] == RULE_ID_API_SIGNATURE] == []


def test_jwt_is_in_default_allowlist():
    assert "jwt" in DEFAULT_API_SIGNATURE_ALLOWLIST


def _jwt_encode_is_strict() -> bool:
    try:
        import jwt  # noqa: PLC0415
    except Exception:
        return False
    encode = getattr(jwt, "encode", None)
    if encode is None:
        return False
    try:
        params = inspect.signature(encode).parameters.values()
    except (TypeError, ValueError):
        return False
    return not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params)


@pytest.mark.skipif(not _jwt_encode_is_strict(), reason="PyJWT encode unavailable")
def test_jwt_encode_unknown_keyword_is_reported(tmp_path):
    path = tmp_path / "security.py"
    path.write_text(
        "import jwt\n"
        "\n"
        "def make(payload, key, delta):\n"
        "    ok = jwt.encode(payload, key, algorithm='HS256', headers={'kid': '1'})\n"
        "    return jwt.encode(\n"
        "        payload,\n"
        "        key,\n"
        "        algorithm='HS256',\n"
        "        expires_in=int(delta.total_seconds()),\n"
        "    )\n",
        encoding="utf-8",
    )
    findings = scan_python_api_signature_hallucinations(tmp_path, [path])
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        (RULE_ID_API_SIGNATURE, 5)
    ]
    assert "expires_in" in findings[0]["message"]


def test_unknown_keyword_with_known_multi_parameter_signature(tmp_path):
    surfaces = {
        "pkg": {
            "members": {
                "encode": {
                    "kind": "function",
                    "signature": "(payload, key, algorithm=None)",
                    "parameters": [
                        {"name": "payload", "kind": "POSITIONAL_OR_KEYWORD"},
                        {"name": "key", "kind": "POSITIONAL_OR_KEYWORD"},
                        {"name": "algorithm", "kind": "POSITIONAL_OR_KEYWORD"},
                    ],
                },
                "decode": {
                    "kind": "function",
                    "signature": "(token, **kwargs)",
                    "parameters": [
                        {"name": "token", "kind": "POSITIONAL_OR_KEYWORD"},
                        {"name": "kwargs", "kind": "VAR_KEYWORD"},
                    ],
                },
            }
        }
    }
    findings = _scan_fake(
        tmp_path,
        """
        import pkg
        pkg.encode({}, "k", algorithm="HS256")
        pkg.encode({}, "k", expires_in=5)
        pkg.decode("t", anything=1)
        pkg.encode({}, "k", **{"expires_in": 5})
        """,
        surfaces=surfaces,
        existing={},
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        (RULE_ID_API_SIGNATURE, 4)
    ]
