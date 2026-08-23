import ast

import pytest

from skylos.rules.ai_defect.python_api_hallucination import (
    scan_python_local_api_hallucinations,
)
from skylos.verify_change import verify_change_path


def _scan(tmp_path, files, targets=None):
    paths = []
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
            source,
            encoding="utf-8",
        )
        paths.append(path)
    target_paths = [tmp_path / name for name in (targets or files)]
    return scan_python_local_api_hallucinations(
        tmp_path,
        paths,
        target_files=target_paths,
    )


def test_python_local_api_check_passes_existing_member(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "def verify_token(value):\n    return bool(value)\n",
            "app.py": "import security\nsecurity.verify_token('ok')\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 2


def test_python_local_api_check_fails_missing_member(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "def verify_token(value):\n    return bool(value)\n",
            "app.py": "import security\nsecurity.verify_session('ok')\n",
        },
        targets=["app.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["verify_session"]
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 1


def test_python_local_api_check_is_incomplete_for_dynamic_surface(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "plugins.py": "def __getattr__(name):\n    return lambda: name\n",
            "app.py": "import plugins\nplugins.generated_helper()\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "dynamic_module_surface", "count": 1}]


def test_python_local_api_check_is_incomplete_for_target_parse_error(tmp_path):
    findings, check = _scan(
        tmp_path,
        {"app.py": "def broken(:\n    pass\n"},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "parse_error", "count": 1}]


def test_python_local_api_check_ignores_external_package_surface(tmp_path):
    findings, check = _scan(
        tmp_path,
        {"app.py": "import requests\nrequests.get('https://example.test')\n"},
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 0


def test_python_local_api_check_passes_existing_direct_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "from security import VERIFY_TOKEN as token\nprint(token)\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_python_local_api_check_accepts_module_control_flow_members(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "control_flow_package/__init__.py": "",
            "control_flow_package/provider.py": (
                "from typing import TYPE_CHECKING, TypeAlias\n\n"
                "DIRECT_VALUE = 0\n\n"
                "if TYPE_CHECKING:\n"
                "    TypeOnlyValue: TypeAlias = int\n\n"
                "if True:\n"
                "    IF_VALUE = 1\n"
                "else:\n"
                "    IF_VALUE = 3\n\n"
                "try:\n"
                "    TRY_VALUE = 2\n"
                "except RuntimeError:\n"
                "    TRY_VALUE = -1\n"
            ),
            "reproduce.py": (
                "from __future__ import annotations\n"
                "from typing import TYPE_CHECKING\n\n"
                "from control_flow_package.provider import (\n"
                "    DIRECT_VALUE,\n"
                "    IF_VALUE,\n"
                "    TRY_VALUE,\n"
                ")\n\n"
                "if TYPE_CHECKING:\n"
                "    from control_flow_package.provider import TypeOnlyValue\n\n"
                "def identity(value: TypeOnlyValue) -> TypeOnlyValue:\n"
                "    return value\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 4
    assert check["verified_references"] == 4


def test_python_local_api_check_accepts_mixed_control_flow_bindings(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "package/__init__.py": "",
            "package/backend_a.py": "class SelectedBackend:\n    pass\n",
            "package/backend_b.py": "class SelectedBackend:\n    pass\n",
            "package/provider.py": (
                "import sys\n\n"
                "if sys.version_info < (3, 9):\n"
                "    get_all_type_hints = len\n"
                "else:\n"
                "    def get_all_type_hints(value):\n"
                "        return value\n\n"
                "try:\n"
                "    from package.backend_a import SelectedBackend\n"
                "except ImportError:\n"
                "    from package.backend_b import SelectedBackend\n"
            ),
            "app.py": (
                "from package.provider import (\n"
                "    SelectedBackend,\n"
                "    get_all_type_hints,\n"
                ")\n"
            ),
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 2


def test_python_local_api_check_keeps_one_sided_and_runtime_names_flagged(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if runtime_flag:\n"
                "    ONE_SIDED = 1\n\n"
                "try:\n"
                "    TRY_ONLY = 2\n"
                "except RuntimeError:\n"
                "    pass\n\n"
                "if TYPE_CHECKING:\n"
                "    TYPE_ONLY = int\n\n"
                "if False:\n"
                "    NEVER_DEFINED = 3\n"
            ),
            "app.py": (
                "from provider import (\n"
                "    MISSING,\n"
                "    NEVER_DEFINED,\n"
                "    ONE_SIDED,\n"
                "    TRY_ONLY,\n"
                "    TYPE_ONLY,\n"
                ")\n"
            ),
        },
        targets=["app.py"],
    )

    assert {finding["simple_name"] for finding in findings} == {
        "MISSING",
        "NEVER_DEFINED",
        "ONE_SIDED",
        "TRY_ONLY",
        "TYPE_ONLY",
    }
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 5


def test_python_local_api_check_does_not_export_nested_scope_members(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "if True:\n"
                "    def public_factory():\n"
                "        function_local = 1\n"
                "        return function_local\n\n"
                "    class PublicNamespace:\n"
                "        class_local = 2\n"
            ),
            "app.py": (
                "from provider import (\n"
                "    PublicNamespace,\n"
                "    class_local,\n"
                "    function_local,\n"
                "    public_factory,\n"
                ")\n"
            ),
        },
        targets=["app.py"],
    )

    assert {finding["simple_name"] for finding in findings} == {
        "class_local",
        "function_local",
    }
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 2


def test_python_local_api_check_ignores_type_only_dynamic_getattr_at_runtime(
    tmp_path,
):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    def __getattr__(name):\n"
                "        return name\n"
            ),
            "app.py": "import provider\nprint(provider.missing)\n",
        },
        targets=["app.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["missing"]
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 1


def test_python_local_api_check_handles_type_checking_contexts(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    TypeOnly = int\n"
                "else:\n"
                "    RuntimeOnly = int\n"
            ),
            "app.py": (
                "from __future__ import annotations\n"
                "from typing import TYPE_CHECKING\n"
                "import typing as t\n\n"
                "TYPE_CHECKING: bool\n\n"
                "if not TYPE_CHECKING:\n"
                "    from provider import RuntimeOnly\n"
                "else:\n"
                "    from provider import TypeOnly\n\n"
                "def nested():\n"
                "    if t.TYPE_CHECKING:\n"
                "        from provider import TypeOnly\n\n"
                "class Namespace:\n"
                "    if t.TYPE_CHECKING:\n"
                "        from provider import TypeOnly\n\n"
                "if TYPE_CHECKING:\n"
                "    import provider\n\n"
                "def identity(value: provider.TypeOnly) -> provider.TypeOnly:\n"
                "    return value\n"
            ),
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"


def test_python_local_api_check_keeps_dynamic_surfaces_conservative(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "source.py": "EXPORTED = 1\n",
            "wildcard_provider.py": ("from source import *\n\n__getattr__ = None\n"),
            "with_provider.py": (
                "from contextlib import nullcontext\n\n"
                "EXPORTED = 1\n\n"
                "def __getattr__(name):\n"
                "    return name\n\n"
                "with nullcontext(), nullcontext(None) as __getattr__:\n"
                "    del EXPORTED\n"
            ),
            "unpack_provider.py": (
                "class SuppressingContext:\n"
                "    def __enter__(self):\n"
                "        return []\n\n"
                "    def __exit__(self, *args):\n"
                "        return True\n\n"
                "with SuppressingContext() as (UNPACKED,):\n"
                "    pass\n"
            ),
            "try_provider.py": (
                "def __getattr__(name):\n"
                "    return name\n\n"
                "try:\n"
                "    __getattr__ = None\n"
                "    risky_operation()\n"
                "    def __getattr__(name):\n"
                "        return name\n"
                "except RuntimeError:\n"
                "    pass\n"
            ),
            "match_provider.py": (
                "if True:\n"
                "    def __getattr__(name):\n"
                "        return name\n\n"
                "    match 1:\n"
                "        case _ if (__getattr__ := 1):\n"
                "            pass\n"
            ),
            "assert_provider.py": (
                "if True:\n"
                "    def __getattr__(name):\n"
                "        return name\n\n"
                "    assert (__getattr__ := 1)\n"
            ),
            "header_provider.py": (
                "if True:\n"
                "    def __getattr__(name):\n"
                "        return name\n\n"
                "    def helper(value=(__getattr__ := 1)):\n"
                "        return value\n"
            ),
            "handler_type_provider.py": (
                "if True:\n"
                "    def __getattr__(name):\n"
                "        return name\n\n"
                "    try:\n"
                "        raise RuntimeError\n"
                "    except (__getattr__ := (RuntimeError,)):\n"
                "        pass\n"
            ),
            "app.py": (
                "import assert_provider\n"
                "import handler_type_provider\n"
                "import header_provider\n"
                "import match_provider\n"
                "import try_provider\n"
                "import wildcard_provider\n"
                "import with_provider\n\n"
                "from unpack_provider import UNPACKED\n"
                "from with_provider import EXPORTED\n\n"
                "print(assert_provider.unknown)\n"
                "print(handler_type_provider.unknown)\n"
                "print(header_provider.unknown)\n"
                "print(match_provider.unknown)\n"
                "print(try_provider.unknown)\n"
                "print(wildcard_provider.unknown)\n"
                "print(with_provider.unknown)\n"
            ),
        },
        targets=["app.py"],
    )

    assert {finding["name"] for finding in findings} == {
        "EXPORTED",
        "UNPACKED",
        "assert_provider.unknown",
        "handler_type_provider.unknown",
        "header_provider.unknown",
        "match_provider.unknown",
        "try_provider.unknown",
        "with_provider.unknown",
    }
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 8


def test_python_local_api_check_rejects_transient_try_mutations(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "EXPORTED = 1\n\n"
                "def __getattr__(name):\n"
                "    return name\n\n"
                "try:\n"
                "    if runtime_flag:\n"
                "        del EXPORTED\n"
                "        __getattr__ = None\n"
                "        risky_operation()\n"
                "        EXPORTED = 2\n"
                "        def __getattr__(name):\n"
                "            return name\n"
                "except RuntimeError:\n"
                "    pass\n"
            ),
            "app.py": (
                "from provider import EXPORTED\n"
                "import provider\n\n"
                "print(provider.unknown)\n"
            ),
        },
        targets=["app.py"],
    )

    assert {finding["name"] for finding in findings} == {
        "EXPORTED",
        "provider.unknown",
    }
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 2


def test_python_local_api_check_handles_definite_compound_bindings(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "PRESERVED = 1\n\n"
                "while False:\n"
                "    del PRESERVED\n"
                "else:\n"
                "    WHILE_ELSE = 2\n\n"
                "for item in []:\n"
                "    del PRESERVED\n"
                "else:\n"
                "    FOR_ELSE = 3\n\n"
                "match 1:\n"
                "    case 1:\n"
                "        MATCHED = 4\n"
                "    case _:\n"
                "        MATCHED = 5\n\n"
                "if (WALRUS := 1):\n"
                "    pass\n"
            ),
            "app.py": (
                "from provider import (\n"
                "    FOR_ELSE,\n"
                "    MATCHED,\n"
                "    PRESERVED,\n"
                "    WALRUS,\n"
                "    WHILE_ELSE,\n"
                ")\n"
            ),
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 5


def test_python_local_api_check_rejects_mutated_type_checking_sentinel(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "import typing as t\n\n"
                "t.TYPE_CHECKING = runtime_flag\n"
                "if t.TYPE_CHECKING:\n"
                "    TRUE_BRANCH = 1\n"
                "else:\n"
                "    FALSE_BRANCH = 2\n"
            ),
            "app.py": ("from provider import FALSE_BRANCH, TRUE_BRANCH\n"),
        },
        targets=["app.py"],
    )

    assert {finding["simple_name"] for finding in findings} == {
        "FALSE_BRANCH",
        "TRUE_BRANCH",
    }
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 2


def test_python_local_api_check_rejects_function_local_type_checking_annotation(
    tmp_path,
):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    MissingType = int\n"
            ),
            "app.py": (
                "from typing import TYPE_CHECKING\n\n"
                "def load_type():\n"
                "    TYPE_CHECKING: bool\n"
                "    if TYPE_CHECKING:\n"
                "        from provider import MissingType\n"
            ),
        },
        targets=["app.py"],
    )

    assert [finding["name"] for finding in findings] == ["MissingType"]
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 1


def test_python_local_api_check_rejects_shadowed_type_checking_guards(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    ClassAttributeOnly = int\n"
                "    ClassOnly = int\n"
                "    ClassNonlocalOnly = int\n"
                "    ExceptOnly = int\n"
                "    FunctionAfterClassAttributeOnly = int\n"
                "    GlobalOnly = int\n"
                "    HandlerTypeOnly = int\n"
                "    LoopOnly = int\n"
                "    MatchOnly = int\n"
                "    NonlocalOnly = int\n"
                "    SetattrOnly = int\n"
            ),
            "app.py": (
                "from typing import TYPE_CHECKING as CLASS_FLAG\n"
                "import typing as typing_module\n\n"
                "RUNTIME_FLAG = True\n\n"
                "def before_class_attribute_mutation():\n"
                "    if typing_module.TYPE_CHECKING:\n"
                "        from provider import FunctionAfterClassAttributeOnly\n\n"
                "def outer():\n"
                "    from typing import TYPE_CHECKING as GLOBAL_FLAG\n\n"
                "    def inner():\n"
                "        global GLOBAL_FLAG\n"
                "        if GLOBAL_FLAG:\n"
                "            from provider import GlobalOnly\n\n"
                "def loop():\n"
                "    from typing import TYPE_CHECKING as LOOP_FLAG\n"
                "    while keep_going():\n"
                "        if LOOP_FLAG:\n"
                "            from provider import LoopOnly\n"
                "        LOOP_FLAG = RUNTIME_FLAG\n\n"
                "def nonlocal_outer():\n"
                "    from typing import TYPE_CHECKING as NONLOCAL_FLAG\n\n"
                "    def inner():\n"
                "        nonlocal NONLOCAL_FLAG\n"
                "        if NONLOCAL_FLAG:\n"
                "            from provider import NonlocalOnly\n"
                "        NONLOCAL_FLAG = RUNTIME_FLAG\n\n"
                "def class_nonlocal():\n"
                "    from typing import TYPE_CHECKING as CLASS_NONLOCAL_FLAG\n\n"
                "    class Mutator:\n"
                "        nonlocal CLASS_NONLOCAL_FLAG\n"
                "        CLASS_NONLOCAL_FLAG = RUNTIME_FLAG\n\n"
                "    if CLASS_NONLOCAL_FLAG:\n"
                "        from provider import ClassNonlocalOnly\n\n"
                "class Mutator:\n"
                "    global CLASS_FLAG\n"
                "    CLASS_FLAG = RUNTIME_FLAG\n\n"
                "if CLASS_FLAG:\n"
                "    from provider import ClassOnly\n\n"
                "class AttributeMutator:\n"
                "    typing_module.TYPE_CHECKING = RUNTIME_FLAG\n\n"
                "if typing_module.TYPE_CHECKING:\n"
                "    from provider import ClassAttributeOnly\n\n"
                "import typing as setattr_module\n\n"
                "setattr(setattr_module, 'TYPE_CHECKING', RUNTIME_FLAG)\n"
                "if setattr_module.TYPE_CHECKING:\n"
                "    from provider import SetattrOnly\n\n"
                "from typing import TYPE_CHECKING as HANDLER_FLAG\n\n"
                "try:\n"
                "    raise ValueError\n"
                "except (HANDLER_FLAG := TypeError):\n"
                "    pass\n"
                "except ValueError:\n"
                "    if HANDLER_FLAG:\n"
                "        from provider import HandlerTypeOnly\n\n"
                "from typing import TYPE_CHECKING as MATCH_FLAG\n\n"
                "match 1:\n"
                "    case _ if not (MATCH_FLAG := RUNTIME_FLAG):\n"
                "        pass\n"
                "    case _:\n"
                "        if MATCH_FLAG:\n"
                "            from provider import MatchOnly\n\n"
                "try:\n"
                "    raise RuntimeError\n"
                "except (EXCEPT_FLAG := RuntimeError):\n"
                "    if EXCEPT_FLAG:\n"
                "        from provider import ExceptOnly\n"
            ),
        },
        targets=["app.py"],
    )

    assert {finding["name"] for finding in findings} == {
        "ClassAttributeOnly",
        "ClassOnly",
        "ClassNonlocalOnly",
        "ExceptOnly",
        "FunctionAfterClassAttributeOnly",
        "GlobalOnly",
        "HandlerTypeOnly",
        "LoopOnly",
        "MatchOnly",
        "NonlocalOnly",
        "SetattrOnly",
    }
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 11


def test_python_local_api_check_rejects_try_star_handler_rebinding(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    LaterHandlerOnly = int\n"
            ),
            "app.py": (
                "from typing import TYPE_CHECKING as HANDLER_FLAG\n\n"
                "RUNTIME_FLAG = True\n\n"
                "try:\n"
                "    raise ExceptionGroup(\n"
                "        'boom', [ValueError(), TypeError()]\n"
                "    )\n"
                "except* ValueError:\n"
                "    HANDLER_FLAG = RUNTIME_FLAG\n"
                "except* TypeError:\n"
                "    if HANDLER_FLAG:\n"
                "        from provider import LaterHandlerOnly\n"
            ),
        },
        targets=["app.py"],
    )

    if hasattr(ast, "TryStar"):
        assert [finding["name"] for finding in findings] == ["LaterHandlerOnly"]
        assert check["outcome"] == "fail"
        assert check["finding_count"] == 1
    else:
        assert findings == []
        assert check["outcome"] == "incomplete"


def test_python_local_api_check_rejects_type_parameter_shadowing(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "provider.py": (
                "from typing import TYPE_CHECKING\n\n"
                "if TYPE_CHECKING:\n"
                "    ClassTypeOnly = int\n"
                "    FunctionTypeOnly = int\n"
            ),
            "app.py": (
                "from typing import TYPE_CHECKING\n\n"
                "def generic[TYPE_CHECKING]():\n"
                "    if TYPE_CHECKING:\n"
                "        from provider import FunctionTypeOnly\n\n"
                "class Generic[TYPE_CHECKING]:\n"
                "    if TYPE_CHECKING:\n"
                "        from provider import ClassTypeOnly\n"
            ),
        },
        targets=["app.py"],
    )

    if hasattr(ast, "TypeVar"):
        assert {finding["name"] for finding in findings} == {
            "ClassTypeOnly",
            "FunctionTypeOnly",
        }
        assert check["outcome"] == "fail"
        assert check["finding_count"] == 2
    else:
        assert findings == []
        assert check["outcome"] == "incomplete"


def test_python_local_api_check_passes_explicit_dotted_submodule_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_package/__init__.py": "",
            "sample_package/child.py": "VALUE = 42\n",
            "reproduce.py": (
                "import sample_package.child\n\n"
                "child_module = sample_package.child\n"
                "assert child_module.VALUE == 42\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_python_local_api_check_flags_unimported_submodule_attribute(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_package/__init__.py": "",
            "sample_package/child.py": "VALUE = 42\n",
            "reproduce.py": (
                "import sample_package\n\n"
                "child_module = sample_package.child\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["child"]
    assert findings[0]["metadata"]["reference_kind"] == "module_member"
    assert check["outcome"] == "fail"


def test_python_local_api_check_passes_module_dunder_attributes(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_package/__init__.py": "",
            "reproduce.py": (
                "import sample_package\n\n"
                "for attr in (\n"
                "    sample_package.__name__,\n"
                "    sample_package.__spec__,\n"
                "    sample_package.__package__,\n"
                "    sample_package.__loader__,\n"
                "    sample_package.__file__,\n"
                "    sample_package.__cached__,\n"
                "    sample_package.__path__,\n"
                "    sample_package.__doc__,\n"
                "    sample_package.__dict__,\n"
                "    sample_package.__annotations__,\n"
                "    sample_package.__class__,\n"
                "):\n"
                "    pass\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 12
    assert check["verified_references"] == 12


def test_python_local_api_check_passes_module_dunder_attributes_via_alias(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_package/__init__.py": "",
            "reproduce.py": (
                "import sample_package as pkg\n\n"
                "print(pkg.__file__)\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 2
    assert check["verified_references"] == 2


@pytest.mark.parametrize(
    ("usage", "rule_id", "finding_type"),
    [
        ("module_path = sample_module.__path__\n", "SKY-L012", "module_member"),
        ("sample_module.__path__()\n", "SKY-L012", "call"),
        (
            "@sample_module.__path__\ndef protected():\n    pass\n",
            "SKY-L023",
            "decorator",
        ),
    ],
)
def test_python_local_api_check_flags_package_only_path_on_module(
    tmp_path,
    usage,
    rule_id,
    finding_type,
):
    findings, check = _scan(
        tmp_path,
        {
            "sample_module.py": "",
            "reproduce.py": "import sample_module\n\n" + usage,
        },
        targets=["reproduce.py"],
    )

    assert [
        (finding["rule_id"], finding["type"], finding["simple_name"])
        for finding in findings
    ] == [(rule_id, finding_type, "__path__")]
    assert check["outcome"] == "fail"
    assert check["references"] == 2
    assert check["verified_references"] == 1


def test_python_local_api_check_flags_unknown_dunder_attribute(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_module.py": "",
            "reproduce.py": (
                "import sample_module\n\n"
                "missing = sample_module.__not_a_module_attribute__\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert [finding["simple_name"] for finding in findings] == [
        "__not_a_module_attribute__"
    ]
    assert check["outcome"] == "fail"


def test_python_local_api_check_does_not_assume_versioned_module_attribute(
    tmp_path,
):
    findings, check = _scan(
        tmp_path,
        {
            "pyproject.toml": '[project]\nrequires-python = ">=3.10,<3.14"\n',
            "sample_module.py": "",
            "reproduce.py": (
                "import sample_module\n\n"
                "annotate = sample_module.__annotate__\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["__annotate__"]
    assert check["outcome"] == "fail"


def test_python_local_api_check_passes_annotate_on_314_floor(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "pyproject.toml": '[project]\nrequires-python = ">=3.14"\n',
            "sample_module.py": "",
            "reproduce.py": (
                "import sample_module\n\n"
                "annotate = sample_module.__annotate__\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"


def test_python_local_api_check_flags_annotate_without_pyproject(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_module.py": "",
            "reproduce.py": (
                "import sample_module\n\n"
                "annotate = sample_module.__annotate__\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["__annotate__"]
    assert check["outcome"] == "fail"


def test_python_local_api_check_flags_annotate_with_future_annotations(tmp_path):
    # from __future__ import annotations does NOT create __annotate__
    # (maintainer-verified on 3.12). It must stay a phantom below 3.14.
    findings, check = _scan(
        tmp_path,
        {
            "sample_module.py": "",
            "reproduce.py": (
                "from __future__ import annotations\n"
                "import sample_module\n\n"
                "annotate = sample_module.__annotate__\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["__annotate__"]
    assert check["outcome"] == "fail"


def test_python_local_api_check_passes_module_dunder_direct_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_module.py": "",
            "reproduce.py": "from sample_module import __file__\n",
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 1
    assert check["verified_references"] == 1


def test_python_local_api_check_passes_package_path_direct_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_package/__init__.py": "",
            "reproduce.py": "from sample_package import __path__\n",
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 1
    assert check["verified_references"] == 1


def test_python_local_api_check_flags_module_path_direct_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_module.py": "",
            "reproduce.py": "from sample_module import __path__\n",
        },
        targets=["reproduce.py"],
    )

    assert [
        (finding["rule_id"], finding["type"], finding["simple_name"])
        for finding in findings
    ] == [("SKY-L012", "from_import", "__path__")]
    assert check["outcome"] == "fail"


def test_python_local_api_check_passes_imported_submodule_dunder(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "sample_package/__init__.py": "",
            "sample_package/child.py": "",
            "reproduce.py": (
                "import sample_package.child\n\n"
                "module_file = sample_package.child.__file__\n"
            ),
        },
        targets=["reproduce.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 2
    assert check["verified_references"] == 2


def test_python_local_api_check_passes_pep695_type_alias_import(tmp_path):
    if not hasattr(ast, "TypeAlias"):
        return

    findings, check = _scan(
        tmp_path,
        {
            "alias_package/consumer.py": (
                "from .provider import NativePostStepCall\n"
                "assert NativePostStepCall.__value__ is int\n"
            ),
            "alias_package/provider.py": "type NativePostStepCall = int\n",
        },
        targets=["alias_package/consumer.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_python_local_api_check_fails_missing_direct_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "from security import VERIFY_SESSION\n",
        },
        targets=["app.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["VERIFY_SESSION"]
    assert findings[0]["metadata"]["reference_kind"] == "from_import"
    assert check["outcome"] == "fail"


def test_python_local_api_check_fails_missing_attribute_value(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "import security\nvalue = security.VERIFY_SESSION\n",
        },
        targets=["app.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["VERIFY_SESSION"]
    assert findings[0]["metadata"]["reference_kind"] == "module_member"
    assert check["outcome"] == "fail"


def test_python_local_api_check_uses_stub_only_api_surface(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.pyi": "def verify_token(value: str) -> bool: ...\n",
            "app.py": "import security\nsecurity.verify_token('ok')\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 2


def test_python_local_submodule_import_is_incomplete_when_ownership_is_uncertain(
    tmp_path,
):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "import security.missing\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "local_import_ownership_uncertain", "count": 1}
    ]


def test_verify_change_discovers_python_stub_files(tmp_path):
    (tmp_path / "security.pyi").write_text(
        "def verify_token(value: str) -> bool: ...\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import security\nsecurity.verify_token('ok')\n",
        encoding="utf-8",
    )

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "pass"
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "python_local_api_reference"
    )
    assert check["applicable_files"] == 2


def test_verify_change_python_surface_respects_excluded_folders(tmp_path):
    (tmp_path / "security.py").write_text(
        "def verify_token(value):\n    return bool(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import security\nsecurity.verify_session('ok')\n",
        encoding="utf-8",
    )
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "security.py").write_text(
        "def verify_session(value):\n    return bool(value)\n",
        encoding="utf-8",
    )

    payload = verify_change_path(tmp_path, exclude_folders=["generated"])

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["member_name"] == "verify_session"


def test_verify_change_keeps_nested_python_surface_inside_requested_scan(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    case_root = tmp_path / "benchmarks" / "current"
    case_root.mkdir(parents=True)
    (case_root / "security.py").write_text(
        "def verify_token(value):\n    return bool(value)\n",
        encoding="utf-8",
    )
    (case_root / "app.py").write_text(
        "import security\nsecurity.verify_session('ok')\n",
        encoding="utf-8",
    )
    sibling = tmp_path / "benchmarks" / "sibling"
    sibling.mkdir(parents=True)
    (sibling / "security.py").write_text(
        "def verify_session(value):\n    return bool(value)\n",
        encoding="utf-8",
    )

    payload = verify_change_path(case_root)

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["member_name"] == "verify_session"
