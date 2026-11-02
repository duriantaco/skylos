import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.deadcode import public_api


def _scan(tmp_path, source):
    package = tmp_path / "lib"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "impl.py").write_text(source)
    (package / "exports.py").write_text('__all__ = ["visible"]\n')
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert not result.get("analysis_errors")
    return {row["simple_name"] for row in result.get("unused_variables", [])}


@pytest.mark.parametrize(
    "binding",
    [
        '(__all__ := ["visible"])\n',
        "from .exports import __all__\n",
        '__all__ = ["visible"]\n__all__.append("other")\n',
        "for __all__ in [[]]:\n    pass\n",
    ],
)
def test_module_export_bindings_cannot_be_widened_by_attribute_docs(tmp_path, binding):
    unused = _scan(
        tmp_path,
        binding
        + 'HIDDEN_URL = "https://example.invalid/private"\n"""Documented but excluded."""\n',
    )
    assert "HIDDEN_URL" in unused


@pytest.mark.parametrize(
    "prefix",
    [
        "def helper():\n    __all__ = []\n    return __all__\n",
        "class Internal:\n    __all__ = []\n",
        "__all__: list[str]\n",
    ],
)
def test_local_or_annotation_only_all_does_not_hide_public_documentation(
    tmp_path, prefix
):
    unused = _scan(
        tmp_path,
        prefix + 'PUBLIC_URL = "https://example.invalid/public"\n"""Public data."""\n',
    )
    assert "PUBLIC_URL" not in unused


def test_unicode_attribute_comment_uses_ast_byte_offsets(tmp_path):
    unused = _scan(tmp_path, 'PUBLIC_VALUE = "💚"  #: Public metadata.\n')
    assert "PUBLIC_VALUE" not in unused


def test_empty_string_does_not_document_an_attribute(tmp_path):
    unused = _scan(tmp_path, 'EMPTY_URL = "https://example.invalid/unused"\n""\n')
    assert "EMPTY_URL" in unused


@pytest.mark.parametrize(
    "update",
    [
        '__all__ += ["second"]',
        '__all__.append("second")',
        '__all__.extend(["second"])',
    ],
)
def test_literal_export_updates_preserve_both_declared_names(update):
    tree = ast.parse('__all__ = ["first"]\n' + update + "\n")
    assert public_api._all_info(tree) == (True, {"first", "second"})
