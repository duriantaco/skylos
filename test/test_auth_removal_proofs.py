"""Positive and adversarial evidence for authentication-control changes."""

import difflib

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.quality.regression import detect_security_regressions

IMPORTS = "from django.contrib.auth.decorators import login_required\nfrom django.http import HttpResponseForbidden\n"
PROTECTED = (
    IMPORTS + "\n@login_required\ndef export_customer(request):\n    return 42\n"
)
OPEN = PROTECTED.replace("@login_required\n", "")


def _regressions(before, after):
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(True),
            after.splitlines(True),
            fromfile="a/views.py",
            tofile="b/views.py",
        )
    )
    return detect_security_regressions(
        diff, "views.py", old_source=before, new_source=after
    )


@pytest.mark.parametrize(
    "after",
    [
        OPEN,
        OPEN.replace("    return 42", "    require_auth(request)\n    return 42"),
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n        pass\n    return 42",
        ),
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n        return 200\n    return 42",
        ),
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n        return HttpResponseForbidden('', None, 200)\n    return 42",
        ),
        OPEN.replace(
            "    return 42",
            "    sensitive_side_effect()\n    if not request.user.is_authenticated:\n        return HttpResponseForbidden()\n    return 42",
        ),
        OPEN + "\n@login_required\ndef another(request):\n    return 0\n",
        PROTECTED.replace("@login_required", "@lookalike.login_required"),
        PROTECTED.replace("@login_required", "@unknown_wrapper\n@login_required"),
        PROTECTED.replace("@login_required", "@login_required()")
        + "\nlogin_required = lambda f: f\n",
        PROTECTED.replace("@login_required", "@login_required()")
        + "\naliased = login_required\naliased.__code__ = unprotected.__code__\n",
        PROTECTED.replace("@login_required", "@login_required()")
        + "\ntamper(login_required)\n",
        PROTECTED.replace("@login_required", "@login_required()")
        + "\ntamper([login_required])\n",
        PROTECTED.replace("@login_required", "@login_required()")
        + "\naliased = [login_required]\naliased[0].__globals__['user_passes_test'] = unprotected\n",
        PROTECTED.replace("@login_required", "@login_required()")
        + "\nlogin_required.__globals__['user_passes_test'] = unprotected\n",
    ],
)
def test_unproven_auth_replacements_are_not_safety_evidence(after):
    # A wrapper addition with the original decorator unchanged is outside this
    # removal rule; force the old line to be part of the replacement comparison.
    before = PROTECTED.replace("@login_required", "@login_required(login_url='/login')")
    assert any(item["control_type"] == "auth" for item in _regressions(before, after))


@pytest.mark.parametrize(
    "after",
    [
        PROTECTED.replace("return 42", "return 43"),
        PROTECTED.replace(
            "@login_required", "@login_required(login_url='/accounts/login')"
        ),
        PROTECTED.replace("@login_required", "@login_required\n@unknown_wrapper"),
        PROTECTED.replace(
            "import login_required", "import login_required as authenticated_view"
        ).replace("@login_required", "@authenticated_view"),
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n        return HttpResponseForbidden()\n    return 42",
        ),
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n        raise PermissionDenied\n    return 42",
        ).replace(
            IMPORTS, IMPORTS + "from django.core.exceptions import PermissionDenied\n"
        ),
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n        return HttpResponse(status=403)\n    return 42",
        ).replace(IMPORTS, IMPORTS + "from django.http import HttpResponse\n"),
        IMPORTS,  # removing the complete function removes its original body too
    ],
)
def test_proven_direct_authentication_boundary_is_preserved(after):
    assert not _regressions(PROTECTED, after)


def test_unrelated_decorator_removal_is_not_an_auth_loss():
    before = PROTECTED + "\n@staticmethod\ndef utility():\n    return 0\n"
    assert not _regressions(before, before.replace("@staticmethod\n", ""))


def test_inline_guard_loss_and_same_function_replacement():
    guard = OPEN.replace(
        "    return 42",
        "    if not request.user.is_authenticated:\n        return HttpResponseForbidden()\n    return 42",
    )
    assert _regressions(guard, OPEN)
    assert not _regressions(guard, PROTECTED)
    assert _regressions(
        guard,
        OPEN
        + "\ndef other(request):\n    if not request.user.is_authenticated:\n        return HttpResponseForbidden()\n",
    )


def test_nested_auth_removal_keeps_conservative_detection():
    before = (
        "class Views:\n    @login_required\n    def export(self):\n        return 42\n"
    )
    assert _regressions(before, before.replace("    @login_required\n", ""))


@pytest.mark.parametrize(
    "before",
    [
        PROTECTED,
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n        return HttpResponseForbidden()\n    return 42",
        ),
    ],
)
def test_renamed_unprotected_handler_is_not_complete_deletion(before):
    after = OPEN.replace("export_customer", "export_orders")
    assert _regressions(before, after)


@pytest.mark.parametrize(
    "shadow", ["django.py", "django/__init__.py", "src/django/__init__.py"]
)
def test_project_local_framework_shadow_is_not_import_proof(tmp_path, shadow):
    marker = tmp_path / shadow
    marker.parent.mkdir(parents=True, exist_ok=True)
    _write(marker, "def login_required(view):\n    return view\n")
    before = OPEN.replace(
        "    return 42",
        "    if not request.user.is_authenticated:\n        return HttpResponseForbidden()\n    return 42",
    )
    diff = "".join(
        difflib.unified_diff(before.splitlines(True), PROTECTED.splitlines(True))
    )
    findings = detect_security_regressions(
        diff,
        str(tmp_path / "views.py"),
        old_source=before,
        new_source=PROTECTED,
        project_root=tmp_path,
    )
    assert any(item["control_type"] == "auth" for item in findings)


def _write(path, content):
    assert write_text_no_symlink(path, content)


def test_unchanged_decorator_with_invalidated_binding_has_factual_message():
    findings = _regressions(
        PROTECTED, PROTECTED + "\nlogin_required = lambda view: view\n"
    )
    assert findings
    assert "no longer resolves to a proven control" in findings[0]["message"]
    assert "was removed" not in findings[0]["message"]
