"""An inner import cannot supply reads of an outer type-only binding."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _scan(tmp_path, body, *, grep_verify):
    write_fixture(tmp_path, "app.py", textwrap.dedent(body).lstrip())
    return json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=grep_verify, grep_cache=False)
    )


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "outer,body",
    [
        ("from library import Group", """
def make():
    from library import Group
    return Group()
make()
"""),
        ("from library import Group as Outer", """
def make():
    from library import Group as Inner
    return Inner()
make()
"""),
        ("from library import Group", """
def make():
    from library import Group
    def nested() -> "Group":
        return Group()
    return nested()
make()
"""),
        ("from library import Group", """
class Screen:
    def __init__(self):
        from library import Group
        self.renderable = Group()
Screen()
"""),
        ("from library import Group", """
def make():
    from other_library import Group
    return Group()
make()
"""),
        ("from library import Group", """
def make():
    return 1
make()
"""),
        ("from library import Group", """
def values():
    items = [(Group := item) for item in (1,)]
    return Group, items
def make():
    from library import Group
    return Group()
values()
make()
"""),
    ],
    ids=[
        "local", "aliases", "closure", "constructor", "other-provider", "unused",
        "comprehension-walrus-is-a-function-local",
    ],
)
def test_unread_outer_type_import_stays_reported(tmp_path, outer, body, grep_verify):
    result = _scan(
        tmp_path,
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    "
        + outer + "\n" + body,
        grep_verify=grep_verify,
    )
    findings = result["unused_imports"]
    assert [(item["full_name"], item["line"]) for item in findings] == [
        ("library.Group", 3)
    ]
    # Raw detection and default-threshold listing must both retain the outer
    # import. The inner live import must not acquire a second finding.
    assert findings[0]["references"] == 0
    assert findings[0]["confidence"] >= 60
    assert findings[0]["listing"]["listed"] is True
    assert not findings[0].get("called_by")


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "use",
    [
        'def typed() -> "Group":\n    return None\ntyped()',
        'def typed() -> "list[\'Group\']":\n    return []\ntyped()',
        'def typed(value: "Group"):\n    return value\ntyped(None)',
        'class Typed:\n    item: "Group"\nTyped()',
        'value: "Group" = None',
        "Group()",
        "def outer_use():\n    return Group()\nouter_use()",
        "def outer_use():\n    global Group\n    return Group()\nouter_use()",
        '__all__ = ["Group"]',
        'def dynamic():\n    return globals()["Group"]\ndynamic()',
        "def outer_use():\n    items = [Group for Group in ()]\n"
        "    return Group(), items\nouter_use()",
        'def typed() -> "Group":\n    from library import Group\n'
        '    return Group()\ntyped()',
        "def typed(value=Group()):\n    from library import Group\n"
        "    return value, Group()\ntyped()",
        "class Typed:\n    Group = 1\n    def method(self):\n"
        "        return Group()\nTyped().method()",
    ],
    ids=[
        "return", "nested-annotation", "argument", "class-annotation",
        "module-annotation", "runtime", "global-read", "global-statement",
        "export", "dynamic", "comprehension-scope", "signature-before-local-import",
        "default-before-local-import", "class-does-not-shadow-method-global",
    ],
)
def test_real_outer_type_import_use_is_preserved(tmp_path, use, grep_verify):
    result = _scan(
        tmp_path,
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
        "    from library import Group\n"
        + use
        + "\ndef make():\n    from library import Group\n    return Group()\nmake()\n",
        grep_verify=grep_verify,
    )
    assert result["unused_imports"] == []


@pytest.mark.parametrize("grep_verify", [False, True])
def test_outer_import_used_by_another_module_is_preserved(tmp_path, grep_verify):
    write_fixture(tmp_path, "consumer.py", "from app import Group\nGroup()\n")
    result = _scan(
        tmp_path,
        """
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from library import Group
        def make():
            from library import Group
            return Group()
        make()
        """,
        grep_verify=grep_verify,
    )
    assert result["unused_imports"] == []


@pytest.mark.parametrize("grep_verify", [False, True])
def test_unused_and_used_aliases_on_the_same_line_do_not_mix(tmp_path, grep_verify):
    result = _scan(
        tmp_path,
        """
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from library import Group, Context
        def make() -> "Context":
            from library import Group
            return Group()
        make()
        """,
        grep_verify=grep_verify,
    )
    assert [(item["full_name"], item["line"]) for item in result["unused_imports"]] == [
        ("library.Group", 3)
    ]


def test_shadowed_read_still_keeps_the_original_provider(tmp_path):
    write_fixture(tmp_path, "library.py", "class Group:\n    pass\n")
    result = _scan(
        tmp_path,
        """
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from library import Group
        def make():
            from library import Group
            return Group()
        make()
        """,
        grep_verify=False,
    )
    assert [(item["full_name"], item["line"]) for item in result["unused_imports"]] == [
        ("library.Group", 3)
    ]
    assert not any(
        item["full_name"] == "library.Group" for item in result["unused_classes"]
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_outer_annotation_alias_is_preserved(tmp_path, grep_verify):
    result = _scan(
        tmp_path,
        """
        from typing import TYPE_CHECKING as TC
        if TC:
            from library import Group as Outer
        def make() -> "Outer":
            from library import Group as Inner
            return Inner()
        make()
        """,
        grep_verify=grep_verify,
    )
    assert result["unused_imports"] == []


@pytest.mark.parametrize("grep_verify", [False, True])
def test_class_mangled_name_keeps_the_matching_module_import(tmp_path, grep_verify):
    result = _scan(
        tmp_path,
        """
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from library import Group as _Screen__Group
        class Screen:
            def make(self):
                return __Group()
            def local(self):
                from library import Group
                return Group()
        Screen().make()
        Screen().local()
        """,
        grep_verify=grep_verify,
    )
    assert result["unused_imports"] == []
