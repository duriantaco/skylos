"""Only the reaching native typing contract can exempt a declaration."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.base import Visitor


def _visitor(tmp_path, source, extra=None):
    path = tmp_path / "app.py"
    path.write_text(source)
    for name, body in (extra or {}).items():
        (tmp_path / name).write_text(body)
    visitor = Visitor("app", path)
    visitor.visit(ast.parse(source))
    return visitor


@pytest.mark.parametrize(
    "source",
    [
        "class Parent: pass\nP = Parent\ndef configure():\n    from typing import Protocol as P\nclass Repo(P):\n    stale = 1\n",
        "class Parent: pass\nP = Parent\nclass Namespace:\n    from typing import Protocol as P\nclass Repo(P):\n    stale = 1\n",
        "class Parent: pass\nP = Parent\nif enabled:\n    from typing import Protocol as P\nclass Repo(P):\n    stale = 1\n",
        "from typing import Protocol\ndef make(Protocol):\n    class Repo(Protocol):\n        stale = 1\n    return Repo\n",
        "from typing import Protocol\ndef make():\n    class Repo(Protocol):\n        stale = 1\n    from typing import Protocol\n    return Repo\n",
        "import typing\nclass Parent: pass\ntyping.Protocol = Parent\nclass Repo(typing.Protocol):\n    stale = 1\n",
        "import typing as t\nsetattr(t, 'Protocol', replacement)\nclass Repo(t.Protocol):\n    stale = 1\n",
        "import typing as t\nalias = t\nalias.Protocol = replacement\nfrom typing import Protocol\nclass Repo(Protocol):\n    stale = 1\n",
        "import typing\nconfigure(typing)\nclass Repo(typing.Protocol):\n    stale = 1\n",
        "import typing\ntyping.__dict__['Protocol'] = replacement\nclass Repo(typing.Protocol):\n    stale = 1\n",
        "import typing\nnamespace = typing.__dict__\nnamespace['Protocol'] = replacement\nclass Repo(typing.Protocol):\n    stale = 1\n",
        "import typing\nsetter = setattr\nsetter(typing, 'Protocol', replacement)\nclass Repo(typing.Protocol):\n    stale = 1\n",
        "import typing\nfrom builtins import setattr as setter\nsetter(typing, 'Protocol', replacement)\nclass Repo(typing.Protocol):\n    stale = 1\n",
        "import typing\nvars(typing)['Protocol'] = replacement\nclass Repo(typing.Protocol):\n    stale = 1\n",
    ],
)
def test_uncertain_or_replaced_protocol_base_is_not_a_contract(tmp_path, source):
    assert not _visitor(tmp_path, source).protocol_class_decls


@pytest.mark.parametrize(
    "source",
    [
        "from typing import Protocol\nclass Repo(Protocol):\n    field: str\n",
        "from typing_extensions import Protocol as P\nclass Repo(P):\n    field: str\n",
        "import typing as t\nclass Repo(t.Protocol):\n    field: str\n",
        "import typing_extensions as t\nclass Repo(t.Protocol):\n    field: str\n",
        "from typing import Protocol, TypeVar\nT = TypeVar('T')\nclass Repo(Protocol[T]):\n    field: T\n",
        "from typing import Protocol\ndef configure():\n    from asyncio import Protocol\nclass Repo(Protocol):\n    field: str\n",
        "import typing\ndef configure():\n    import random as typing\nclass Repo(typing.Protocol):\n    field: str\n",
        "Protocol = int; from typing import Protocol\nclass Repo(Protocol):\n    field: str\n",
        "from typing import Protocol\nclass Repo(Protocol):\n    field: str\nProtocol = int\n",
        "import typing\nclass Repo(typing.Protocol):\n    field: str\ntyping.Protocol = replacement\n",
        "def make():\n    from typing import Protocol as P\n    class Repo(P):\n        field: str\n    return Repo\n",
        "import typing\nclass Outer:\n    typing = replacement\n    def make(self):\n        class Repo(typing.Protocol):\n            field: str\n        return Repo\n",
        "from typing import Protocol as P\nclass Repo(P):\n    field: str\nP = replacement\n",
        "import typing\nfrom typing import Protocol as P\ntyping.Protocol = replacement\nclass Repo(P):\n    field: str\n",
        "import typing\nclass Repo(typing.Protocol):\n    field: str\nconfigure(typing)\n",
        "from typing import Protocol\nclass Namespace:\n    from asyncio import Protocol\nclass Repo(Protocol):\n    field: str\n",
    ],
)
def test_native_protocol_identity_respects_scope_and_source_order(tmp_path, source):
    assert len(_visitor(tmp_path, source).protocol_class_decls) == 1


@pytest.mark.parametrize("module", ["typing", "typing_extensions"])
def test_project_provider_with_typing_name_is_not_native(tmp_path, module):
    visitor = _visitor(
        tmp_path,
        f"from {module} import Protocol\nclass Repo(Protocol):\n    stale = 1\n",
        {module + ".py": "class Protocol: pass\n"},
    )
    assert not visitor.protocol_class_decls


@pytest.mark.parametrize(
    "body, ordinary_name",
    [
        ("    global STALE\n    STALE = 1\n", "STALE"),
        ("    factory = lambda: (forgotten := 1)\n", "forgotten"),
    ],
)
def test_non_attribute_bindings_do_not_gain_protocol_exemption(
    tmp_path, body, ordinary_name
):
    source = (
        "from typing import Protocol\nclass Repo(Protocol):\n"
        + body
        + "def use(repo: Repo): return repo\nUSE = use\n"
    )
    _visitor(tmp_path, source)
    result = json.loads(analyze(str(tmp_path), conf=0, grep_cache=False))
    assert not any(
        row["name"] == ordinary_name and row.get("reason") == "Protocol class member"
        for row in result.get("whitelisted", [])
    )
    if ordinary_name == "STALE":
        assert any(row["name"] == ordinary_name for row in result["unused_variables"])


@pytest.mark.parametrize(
    "source, section, name",
    [
        (
            "import typing\nclass Parent: pass\ndef factory():\n    class Repo(typing.Protocol):\n        stale = 1\n    return Repo\ndef configure():\n    typing.Protocol = Parent\nconfigure()\nRepo = factory()\nEXPORTED = Repo\n",
            "unused_variables",
            "stale",
        ),
        (
            "from typing import Protocol as Contract\nclass Repo(Contract):\n    required: str\ndef factory():\n    class Repo:\n        stale = 1\n        def unused(self): return 2\n    return Repo\nFACTORY = factory\n",
            "unused_functions",
            "unused",
        ),
    ],
)
def test_deferred_mutation_and_unrelated_class_keep_dead_members(
    tmp_path, source, section, name
):
    _visitor(tmp_path, source)
    result = json.loads(analyze(str(tmp_path), conf=60, grep_cache=False))
    assert any(
        row.get("simple_name", row["name"]) == name for row in result.get(section, [])
    )


@pytest.mark.parametrize(
    "body",
    [
        "    typing.Protocol = Ordinary\n",
        "    alias = typing\n    alias.Protocol = Ordinary\n",
        "    configure(typing)\n",
        "    setter = setattr\n    setter(typing, 'Protocol', Ordinary)\n",
        "    typing.__dict__['Protocol'] = Ordinary\n",
        "    class Nested:\n        typing.Protocol = Ordinary\n",
    ],
)
def test_eager_class_body_provider_effects_reach_later_bases(tmp_path, body):
    source = (
        "import typing\nclass Ordinary: pass\nclass Configure:\n"
        + body
        + "class Repo(typing.Protocol):\n    stale = 1\n"
    )
    assert not _visitor(tmp_path, source).protocol_class_decls


@pytest.mark.parametrize(
    "source",
    [
        "import typing\nNative = typing.Protocol\nclass Configure:\n    typing.Protocol = replacement\nclass Repo(Native):\n    field: str\n",
        "import typing\nclass Repo(typing.Protocol):\n    field: str\nclass Configure:\n    typing.Protocol = replacement\n",
        "import typing\nclass Namespace:\n    import random as typing\nclass Repo(typing.Protocol):\n    field: str\n",
        "import typing\nclass Namespace:\n    typing = replacement\n    typing.Protocol = replacement\nclass Repo(typing.Protocol):\n    field: str\n",
    ],
)
def test_eager_class_effects_preserve_captured_and_unrelated_bindings(tmp_path, source):
    assert len(_visitor(tmp_path, source).protocol_class_decls) == 1


def test_nested_eager_class_body_skips_outer_class_namespace(tmp_path):
    source = (
        "import typing\nclass Ordinary: pass\nclass Outer:\n"
        "    typing = replacement\n    class Configure:\n"
        "        typing.Protocol = Ordinary\n"
        "class Repo(typing.Protocol):\n    stale = 1\n"
    )
    assert not _visitor(tmp_path, source).protocol_class_decls


@pytest.mark.parametrize("name", ["Protocol", "P"])
def test_native_protocol_header_reads_binding_before_class_name(tmp_path, name):
    alias = "" if name == "Protocol" else " as P"
    source = (
        f"from typing import Protocol{alias}\nclass {name}({name}):\n    field: str\n"
    )
    assert len(_visitor(tmp_path, source).protocol_class_decls) == 1


@pytest.mark.parametrize("call", ["configure()", "alias = configure\nalias()"])
def test_called_local_function_applies_provider_member_writes(tmp_path, call):
    source = (
        "import typing\nclass Ordinary: pass\ndef configure():\n"
        "    typing.Protocol = Ordinary\n"
        + call
        + "\nclass Repo(typing.Protocol):\n    stale = 1\n"
    )
    assert not _visitor(tmp_path, source).protocol_class_decls


def test_called_local_slot_replacement_preserves_captured_native_class(tmp_path):
    source = (
        "import typing\nNative = typing.Protocol\nclass Ordinary: pass\n"
        "def configure():\n    typing.Protocol = Ordinary\nconfigure()\n"
        "class Repo(Native):\n    field: str\n"
    )
    assert len(_visitor(tmp_path, source).protocol_class_decls) == 1
