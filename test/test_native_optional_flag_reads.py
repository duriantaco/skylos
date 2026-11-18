"""Optional native integer lookup is a read, not os capability escape."""

import ast

import pytest

from skylos.rules.danger.import_proof import provider_binding_is_stable


def _proof(tmp_path, expression, *, prelude="", modules=None, provider="os.open"):
    source = "import os\n" + prelude + "\ndef flags():\n    return " + expression + "\n"
    path = tmp_path / "app.py"
    path.write_text(source)
    for name, text in (modules or {}).items():
        (tmp_path / name).write_text(text)
    return provider_binding_is_stable(provider, ast.parse(source), path, tmp_path)


@pytest.mark.parametrize(
    "flag",
    ["O_RDONLY", "O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_EXCL"],
)
def test_literal_optional_native_integer_flag_does_not_escape_os(tmp_path, flag):
    assert _proof(tmp_path, f"getattr(os, {flag!r}, 0)")


@pytest.mark.parametrize(
    "expression,prelude",
    [
        ("getattr(os, field, 0)", ""),
        ("getattr(os, 'open', 0)", ""),
        ("getattr(os, 'O_NOFOLLOW', callback())", ""),
        ("getattr(os, 'O_NOFOLLOW', False)", ""),
        ("getattr(os, 'O_UNKNOWN', 0)", ""),
        (
            "getattr(os, 'O_NOFOLLOW', 0)",
            "def getattr(*args):\n    return opaque(*args)\n",
        ),
        ("getattr(os, 'O_NOFOLLOW', 0)", "import builtins\nbuiltins.getattr=opaque\n"),
        ("getattr(os, 'O_NOFOLLOW', 0)", "os=opaque\n"),
        ("opaque(os)", ""),
        ("os", ""),
    ],
)
def test_nonliteral_or_non_native_lookup_cannot_hide_module_escape(
    tmp_path, expression, prelude
):
    assert not _proof(tmp_path, expression, prelude=prelude)


def test_imported_getter_replacement_invalidates_native_projection(tmp_path):
    assert not _proof(
        tmp_path,
        "getattr(os, 'O_NOFOLLOW', 0)",
        prelude="import patcher\n",
        modules={"patcher.py": "import builtins\nbuiltins.getattr=opaque\n"},
    )


def test_project_flag_mutation_remains_unsafe_even_with_a_native_getter(tmp_path):
    assert not _proof(
        tmp_path,
        "getattr(os, 'O_NOFOLLOW', 0)",
        prelude="import patcher\n",
        modules={"patcher.py": "import os\nos.O_NOFOLLOW=0\n"},
        provider="os.O_NOFOLLOW",
    )
