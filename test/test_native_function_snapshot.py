import ast

import pytest

from skylos.rules.danger.import_proof import provider_binding_is_stable
from skylos.rules.danger.native_function_snapshot import (
    native_function_snapshot_is_stable,
)


SOURCE = """from hashlib import md5 as _md5
from .error import *
class Holder:
    def remember(self):
        self.hashmod = _md5
"""
ERRORS = """class Failure(Exception):
    pass
class DetailedFailure(Failure):
    def __init__(self, message):
        self.message = message
"""


def fixture(tmp_path, source=SOURCE, errors=ERRORS):
    package = tmp_path / "client"
    package.mkdir()
    path = package / "__init__.py"
    path.write_text(source)
    (package / "error.py").write_text(errors)
    return path, ast.parse(source)


def test_optional_native_copy_proof_does_not_change_strict_cache(tmp_path):
    path, tree = fixture(tmp_path)
    for optional_first in (False, True):
        if optional_first:
            assert native_function_snapshot_is_stable(
                "hashlib.md5", tree, path, tmp_path
            )
        assert not provider_binding_is_stable("hashlib.md5", tree, path, tmp_path)
        assert native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)
        assert not provider_binding_is_stable("hashlib.md5", tree, path, tmp_path)


def test_optional_policy_cache_is_separate_without_star_view(tmp_path):
    path, tree = fixture(tmp_path, SOURCE.replace("from .error import *\n", ""))
    assert not provider_binding_is_stable("hashlib.md5", tree, path, tmp_path)
    assert native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)
    assert not provider_binding_is_stable("hashlib.md5", tree, path, tmp_path)


@pytest.mark.parametrize(
    "extra",
    [
        "import hashlib\nhashlib.md5 = lambda value: value\n",
        "import hashlib\nsetattr(hashlib, 'md5', lambda value: value)\n",
        "_md5.__self__.__dict__.clear()\n",
        "exec('unmodelled()')\n",
    ],
)
def test_provider_writes_and_reflection_remain_unknown(tmp_path, extra):
    path, tree = fixture(tmp_path, SOURCE + extra)
    assert not native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)


@pytest.mark.parametrize(
    "extra",
    [
        "__all__ = ['_md5']\n",
        "import hashlib\nhashlib.md5 = lambda value: value\n",
        "def __getattr__(name):\n    return None\n",
        "class Hook(Failure):\n    def __init_subclass__(cls):\n        pass\n",
    ],
)
def test_nonpassive_star_namespace_is_not_normalized(tmp_path, extra):
    path, tree = fixture(tmp_path, errors=ERRORS + extra)
    assert not native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)


def test_star_export_source_changes_invalidate_optional_proof(tmp_path):
    path, tree = fixture(tmp_path)
    assert native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)
    (path.parent / "error.py").write_text(ERRORS + "__all__ = ['_md5']\n")
    assert not native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)


def test_modified_ast_is_not_attested_as_original_source(tmp_path):
    path, tree = fixture(tmp_path)
    tree.body.append(ast.Pass())
    assert not native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)


def test_mutable_python_callable_cannot_opt_in(tmp_path):
    path, tree = fixture(tmp_path)
    assert not native_function_snapshot_is_stable(
        "base64.b64encode", tree, path, tmp_path
    )


def test_project_hashlib_provider_is_not_native(tmp_path):
    path, tree = fixture(tmp_path)
    (tmp_path / "hashlib.py").write_text("def md5(value):\n    return value\n")
    assert not native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)


def test_star_export_cannot_overwrite_a_public_native_import_alias(tmp_path):
    errors = (
        ERRORS
        + "class digest(Failure):\n    def hexdigest(self):\n        import secrets\n        return secrets.token_hex(16)\n"
    )
    path, tree = fixture(tmp_path, SOURCE.replace("_md5", "digest"), errors)
    assert not native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)


def test_optional_proof_does_not_spend_shared_effect_or_context_budgets(tmp_path):
    from skylos.rules.danger.import_proof import _effects
    from skylos.rules.danger.project_imports import project_import_context

    path, tree = fixture(tmp_path, SOURCE.replace("from .error import *\n", ""))
    assert provider_binding_is_stable("ssl.CERT_NONE", tree, path, tmp_path)
    effects = _effects(tree)
    effects.ref_work = 65535
    context = project_import_context(tree, path, tmp_path)
    remaining = context.budget
    assert native_function_snapshot_is_stable("hashlib.md5", tree, path, tmp_path)
    assert effects.ref_work == 65535
    assert effects.complete
    assert context.budget == remaining
    assert provider_binding_is_stable("ssl.CERT_NONE", tree, path, tmp_path)


@pytest.mark.parametrize("optional_first", [False, True])
def test_effect_cache_keys_include_the_immutable_policy(optional_first):
    from skylos.rules.danger.import_proof import _provider_effects

    tree = ast.parse(SOURCE.replace("from .error import *\n", ""))
    names = {"hashlib.md5"}
    if optional_first:
        assert _provider_effects(names, tree, immutable_values=names)
    assert not _provider_effects(names, tree)
    assert _provider_effects(names, tree, immutable_values=names)
    assert not _provider_effects(names, tree)
