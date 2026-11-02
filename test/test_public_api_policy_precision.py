"""Public API evidence must obey the declared, conservative Skylos policy."""

import ast
import builtins
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.deadcode import public_api
from skylos.deadcode.python_ast import ParsedPythonFile
from test.fixture_paths import write_fixture


def _write(root, relative, source):
    return write_fixture(root, relative, textwrap.dedent(source).lstrip())


def _function(name, doc=""):
    documentation = f'    """{doc}"""\n' if doc else ""
    return (
        f"def {name}(path):\n{documentation}"
        '    with open(path, encoding="utf-8") as handle:\n'
        "        rows = handle.read().splitlines()\n"
        "    return [row.strip() for row in rows if row]\n\n"
    )


def _project(root, sources, evidence=None):
    """Build static definitions; none of the authored modules are imported."""
    sources = {"lib/__init__.py": "", **sources}
    definitions = {}
    parsed = []
    module_names = {}
    for relative, source in sources.items():
        path = _write(root, relative, source)
        tree = ast.parse(path.read_text())
        parsed.append(ParsedPythonFile(path, tree))
        parts = list(Path(relative).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        module_names[str(path)] = module

        def collect(body, prefix, *, in_class=False):
            for node in body:
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    name = f"{prefix}.{node.name}"
                    kind = (
                        "class"
                        if isinstance(node, ast.ClassDef)
                        else ("method" if in_class else "function")
                    )
                    definitions[name] = SimpleNamespace(
                        name=name,
                        simple_name=node.name,
                        type=kind,
                        filename=str(path),
                        line=node.lineno,
                    )
                    if isinstance(node, ast.ClassDef):
                        collect(node.body, name, in_class=True)
                elif isinstance(node, (ast.Assign, ast.AnnAssign)) and not in_class:
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for target in targets:
                        if isinstance(target, ast.Name):
                            name = f"{prefix}.{target.id}"
                            definitions[name] = SimpleNamespace(
                                name=name,
                                simple_name=target.id,
                                type="variable",
                                filename=str(path),
                                line=node.lineno,
                            )

        collect(tree.body, module)
    for relative, source in (evidence or {}).items():
        _write(root, relative, source)
    return definitions, parsed, module_names


def _declared(root, project):
    definitions, parsed, module_names = project
    return {
        target.name
        for target, _reason in public_api.find_declared_public_api_targets(
            definitions, parsed, root, module_names
        )
    }


@pytest.mark.parametrize(
    "mechanism", ["directive", "role", "members", "mkdocs", "stub"]
)
@pytest.mark.parametrize("all_value", ["[]", '["listed_export"]'])
def test_explicit_all_cannot_be_widened_by_other_evidence(
    tmp_path, mechanism, all_value
):
    evidence = {"docs/positive.rst": ".. autofunction:: lib.positive.public_control\n"}
    if mechanism == "directive":
        evidence["docs/api.rst"] = ".. autofunction:: lib.exact.excluded_export\n"
    elif mechanism == "role":
        evidence["docs/api.rst"] = "See :func:`lib.exact.excluded_export`.\n"
    elif mechanism == "members":
        evidence["docs/api.rst"] = (
            ".. automodule:: lib.exact\n   :members: excluded_export\n"
        )
    elif mechanism == "mkdocs":
        evidence["docs/api.md"] = (
            "::: lib.exact\n    options:\n      members: [excluded_export]\n"
        )
    else:
        evidence["lib/exact.pyi"] = "def excluded_export(path: str) -> list[str]: ...\n"
    project = _project(
        tmp_path,
        {
            "lib/exact.py": f"__all__ = {all_value}\n"
            + _function("excluded_export")
            + _function("listed_export"),
            "lib/positive.py": _function("public_control"),
        },
        evidence,
    )

    declared = _declared(tmp_path, project)

    assert "lib.exact.excluded_export" not in declared
    assert "lib.positive.public_control" in declared


@pytest.mark.parametrize(
    "binding,expected_public",
    [
        ('__all__ = ["candidate"]\ndel __all__[:]\n', False),
        ('__all__ = ["candidate"]\n__all__[:] = []\n', False),
        ('__all__ = ["candidate"]\nalias = __all__\nalias.clear()\n', False),
        (
            '__all__ = ["candidate"]\nfor alias in (__all__,):\n    alias.clear()\n',
            False,
        ),
        (
            '__all__ = ["candidate"]\nmatch []:\n    case __all__:\n        pass\n',
            False,
        ),
        (
            '__all__ = ["candidate"]\ndef helper(value=__all__.clear()):\n    pass\n',
            False,
        ),
        (
            "def factory(value):\n    value.clear()\n    return object\n"
            '__all__ = ["candidate"]\nclass Marker(factory(__all__)):\n    pass\n',
            False,
        ),
        (
            '__all__ = ["candidate"]\ntry:\n    raise RuntimeError("reset")\n'
            "except RuntimeError as __all__:\n    pass\n",
            False,
        ),
        ('__all__ = ["candidate"]\n', True),
        ('__all__ = []\n__all__.append("candidate")\n', True),
        ('__all__ = []\n__all__.extend(["candidate"])\n', True),
    ],
)
def test_literal_all_mutation_cannot_leave_a_stale_public_target(
    tmp_path, binding, expected_public
):
    project = _project(
        tmp_path,
        {
            "lib/exact.py": binding + _function("candidate"),
            "lib/control.py": _function("public_control"),
        },
        {
            "docs/api.rst": (
                ".. autofunction:: lib.exact.candidate\n\n"
                ".. autofunction:: lib.control.public_control\n"
            ),
        },
    )

    declared = _declared(tmp_path, project)

    expected = {"lib.control.public_control"}
    if expected_public:
        expected.add("lib.exact.candidate")
    assert declared == expected


@pytest.mark.parametrize(
    "declaration",
    [
        "if True:\n    __all__ = []\n",
        "try:\n    __all__ = []\nexcept Exception:\n    pass\n",
    ],
)
def test_module_scope_nested_all_is_exact_but_function_local_all_is_not(
    tmp_path, declaration
):
    project = _project(
        tmp_path,
        {
            "lib/nested.py": declaration + _function("excluded_nested"),
            "lib/local.py": "def configure():\n    __all__ = []\n\n"
            + _function("public_control"),
        },
        {
            "docs/api.rst": (
                ".. autofunction:: lib.nested.excluded_nested\n\n"
                ".. autofunction:: lib.local.public_control\n"
            )
        },
    )

    declared = _declared(tmp_path, project)

    assert "lib.nested.excluded_nested" not in declared
    assert "lib.local.public_control" in declared


@pytest.mark.parametrize("exact_owner", ["exporter", "implementation"])
def test_lazy_exports_obey_all_on_exporter_and_implementation(tmp_path, exact_owner):
    init = """
        import importlib
        _LAZY = {"excluded_export": ".impl"}
        def __getattr__(name):
            if name in _LAZY:
                return getattr(importlib.import_module(_LAZY[name], __name__), name)
            raise AttributeError(name)
    """
    implementation = _function("excluded_export")
    if exact_owner == "exporter":
        init = "__all__ = []\n" + textwrap.dedent(init)
    else:
        implementation = "__all__ = []\n" + implementation
    project = _project(
        tmp_path,
        {
            "lib/__init__.py": init,
            "lib/impl.py": implementation,
            "lib/positive.py": _function("public_control"),
        },
        {"docs/api.rst": ".. autofunction:: lib.positive.public_control\n"},
    )

    declared = _declared(tmp_path, project)

    assert "lib.impl.excluded_export" not in declared
    assert "lib.positive.public_control" in declared


@pytest.mark.parametrize("mechanism", ["docs", "stub", "lazy"])
def test_private_markers_apply_to_every_evidence_provider(tmp_path, mechanism):
    sources = {
        "lib/impl.py": _function("private_target", ":meta private:")
        + _function("public_control"),
    }
    if mechanism == "docs":
        evidence = {
            "docs/api.rst": (
                ".. autofunction:: lib.impl.private_target\n\n"
                ".. autofunction:: lib.impl.public_control\n"
            )
        }
    elif mechanism == "stub":
        evidence = {
            "lib/impl.pyi": (
                "def private_target(path: str) -> list[str]: ...\n"
                "def public_control(path: str) -> list[str]: ...\n"
            )
        }
    else:
        sources["lib/__init__.py"] = """
            import importlib
            _LAZY = {"private_target": ".impl", "public_control": ".impl"}
            def __getattr__(name):
                if name in _LAZY:
                    return getattr(importlib.import_module(_LAZY[name], __name__), name)
                raise AttributeError(name)
        """
        evidence = {}
    project = _project(tmp_path, sources, evidence)

    declared = _declared(tmp_path, project)

    assert "lib.impl.private_target" not in declared
    assert "lib.impl.public_control" in declared


def test_private_marker_in_attribute_comment_block_is_not_lost(tmp_path):
    project = _project(
        tmp_path,
        {
            "lib/constants.py": """
        #: :meta private:
        #: Additional description does not change visibility.
        PRIVATE_VALUE = "internal"

        #: Additional public description.
        PUBLIC_VALUE = "external"
    """
        },
    )

    declared = _declared(tmp_path, project)

    assert "lib.constants.PRIVATE_VALUE" not in declared
    assert "lib.constants.PUBLIC_VALUE" in declared


@pytest.mark.parametrize("mechanism", ["docs", "stub"])
def test_class_and_method_privacy_is_checked_for_the_whole_object_path(
    tmp_path, mechanism
):
    source = '''
        class HiddenByMarker:
            """@private"""
            def operation(self): ...
        class _HiddenByName:
            def operation(self): ...
        class Public:
            def hidden_method(self):
                """:meta private:"""
                ...
            def public_method(self): ...
            def omitted_method(self): ...
    '''
    if mechanism == "docs":
        evidence = {
            "docs/api.rst": "\n\n".join(
                f".. automethod:: lib.objects.{name}"
                for name in (
                    "HiddenByMarker.operation",
                    "_HiddenByName.operation",
                    "Public.hidden_method",
                    "Public.public_method",
                )
            )
        }
    else:
        evidence = {
            "lib/objects.pyi": """
            class HiddenByMarker:
                def operation(self) -> None: ...
            class _HiddenByName:
                def operation(self) -> None: ...
            class Public:
                def hidden_method(self) -> None: ...
                def public_method(self) -> None: ...
        """
        }
    project = _project(tmp_path, {"lib/objects.py": source}, evidence)

    declared = _declared(tmp_path, project)

    assert "lib.objects.Public.public_method" in declared
    assert {
        "lib.objects.HiddenByMarker",
        "lib.objects.HiddenByMarker.operation",
        "lib.objects._HiddenByName",
        "lib.objects._HiddenByName.operation",
        "lib.objects.Public.hidden_method",
        "lib.objects.Public.omitted_method",
    }.isdisjoint(declared)


def test_nested_method_reference_obeys_module_all_top_level_class(tmp_path):
    project = _project(
        tmp_path,
        {
            "lib/objects.py": """
        __all__ = ["Public"]
        class Public:
            def declared_method(self): ...
        class Excluded:
            def hidden_method(self): ...
    """
        },
        {
            "docs/api.rst": (
                ".. automethod:: lib.objects.Public.declared_method\n\n"
                ".. automethod:: lib.objects.Excluded.hidden_method\n"
            )
        },
    )

    declared = _declared(tmp_path, project)

    assert "lib.objects.Public.declared_method" in declared
    assert "lib.objects.Excluded.hidden_method" not in declared


@pytest.mark.parametrize("kind", ["object", "module"])
def test_qualified_targets_do_not_fall_back_to_ambiguous_module_suffixes(
    tmp_path, kind
):
    project = _project(
        tmp_path,
        {
            "lib/a/__init__.py": "",
            "lib/a/mod.py": _function("same_leaf", "Documented."),
            "lib/b/__init__.py": "",
            "lib/b/mod.py": _function("same_leaf", "Documented."),
            "lib/exact.py": _function("public_control", "Documented."),
        },
        {
            "docs/api.rst": (
                ".. autofunction:: mod.same_leaf\n\n.. autofunction:: lib.exact.public_control\n"
                if kind == "object"
                else ".. automodule:: a.mod\n   :members:\n\n"
                ".. automodule:: lib.exact\n   :members:\n"
            )
        },
    )

    declared = _declared(tmp_path, project)

    assert "lib.exact.public_control" in declared
    assert {"lib.a.mod.same_leaf", "lib.b.mod.same_leaf"}.isdisjoint(declared)


def test_valid_leading_dot_lookup_requires_one_exact_object_suffix(tmp_path):
    project = _project(
        tmp_path,
        {
            "lib/a/__init__.py": "",
            "lib/a/mod.py": _function("same_leaf"),
            "lib/b/__init__.py": "",
            "lib/b/mod.py": _function("same_leaf"),
            "lib/unique.py": _function("public_control"),
        },
        {
            "docs/api.rst": (
                "See :func:`.mod.same_leaf` and :func:`.unique.public_control`.\n"
            )
        },
    )

    declared = _declared(tmp_path, project)

    assert "lib.unique.public_control" in declared
    assert {"lib.a.mod.same_leaf", "lib.b.mod.same_leaf"}.isdisjoint(declared)


@pytest.mark.parametrize(
    "import_line",
    [
        "from .impl import exported as exported",
        "from lib.impl import exported as exported",
        'from .impl import exported as public_alias\n__all__ = ["public_alias"]',
    ],
)
def test_stub_reexports_resolve_explicit_export_spellings(tmp_path, import_line):
    project = _project(
        tmp_path,
        {
            "lib/impl.py": _function("exported")
            + _function("incidental")
            + _function("unmentioned"),
        },
        {"lib/__init__.pyi": import_line + "\nfrom .impl import incidental\n"},
    )

    declared = _declared(tmp_path, project)

    assert "lib.impl.exported" in declared
    assert {"lib.impl.incidental", "lib.impl.unmentioned"}.isdisjoint(declared)


def test_stub_all_excludes_unlisted_reexports_and_declarations(tmp_path):
    project = _project(
        tmp_path,
        {
            "lib/impl.py": _function("included") + _function("excluded"),
            "lib/typed.py": _function("declared") + _function("omitted"),
        },
        {
            "lib/__init__.pyi": (
                "from .impl import included as included\nfrom .impl import excluded as excluded\n"
                '__all__ = ["included"]\n'
            ),
            "lib/typed.pyi": (
                "def declared(path: str) -> list[str]: ...\n"
                'def omitted(path: str) -> list[str]: ...\n__all__ = ["declared"]\n'
            ),
        },
    )

    declared = _declared(tmp_path, project)

    assert {"lib.impl.included", "lib.typed.declared"} <= declared
    assert {"lib.impl.excluded", "lib.typed.omitted"}.isdisjoint(declared)


@pytest.mark.parametrize(
    "stub,expected_targets",
    [
        (
            "from .first import shared as shared\n"
            "from .second import shared as shared\n",
            {"lib.second.shared"},
        ),
        (
            "from .first import shared as public_alias\n"
            "from .second import shared as public_alias\n"
            '__all__ = ["public_alias"]\n',
            {"lib.second.shared"},
        ),
        (
            "from .first import shared as shared\nshared: int = 0\n",
            set(),
        ),
        (
            "from .first import shared as shared\nfrom .second import *\n",
            set(),
        ),
    ],
)
def test_stub_reexports_follow_the_current_alias_binding(
    tmp_path, stub, expected_targets
):
    project = _project(
        tmp_path,
        {
            "lib/first.py": _function("shared"),
            "lib/second.py": _function("shared"),
            "lib/control.py": _function("public_control"),
        },
        {
            "lib/__init__.pyi": stub,
            "lib/control.pyi": "def public_control(path: str) -> list[str]: ...\n",
        },
    )

    declared = _declared(tmp_path, project)

    assert declared == expected_targets | {"lib.control.public_control"}


@pytest.mark.parametrize(
    "local_binding,stub,expected_targets",
    [
        (False, "from .impl import candidate\n", {"lib.impl.candidate"}),
        (True, "from .impl import candidate\n", {"lib.candidate"}),
        (True, "def candidate(path: str) -> list[str]: ...\n", set()),
    ],
)
def test_attach_stub_follows_runtime_bindings_and_factory_export_names(
    tmp_path, local_binding, stub, expected_targets
):
    source = "import lazy_loader as lazy\n"
    if local_binding:
        source += _function("candidate")
    source += "__getattr__, __dir__, __all__ = lazy.attach_stub(__name__, __file__)\n"
    project = _project(
        tmp_path,
        {
            "lib/__init__.py": source,
            "lib/impl.py": _function("candidate"),
            "lib/control.py": _function("public_control"),
        },
        {
            "lib/__init__.pyi": stub,
            "lib/control.pyi": "def public_control(path: str) -> list[str]: ...\n",
        },
    )

    declared = _declared(tmp_path, project)

    assert declared == expected_targets | {"lib.control.public_control"}


@pytest.mark.parametrize(
    "unsupported_import",
    [
        "from lib.impl import other\n",
        "from ..impl import other\n",
        "from .impl import *\n",
        "from .impl import other as renamed\n",
    ],
)
def test_attach_stub_unsupported_import_invalidates_the_whole_factory_proof(
    tmp_path, unsupported_import
):
    project = _project(
        tmp_path,
        {
            "lib/__init__.py": (
                "import lazy_loader as lazy\n"
                "__getattr__, __dir__, __all__ = lazy.attach_stub(__name__, __file__)\n"
            ),
            "lib/impl.py": _function("candidate") + _function("other"),
            "lib/control.py": _function("public_control"),
        },
        {
            "lib/__init__.pyi": "from .impl import candidate\n" + unsupported_import,
            "lib/control.pyi": "def public_control(path: str) -> list[str]: ...\n",
        },
    )

    declared = _declared(tmp_path, project)

    assert declared == {"lib.control.public_control"}


def test_attach_stub_runtime_import_does_not_declare_a_shadowed_stub_target(tmp_path):
    project = _project(
        tmp_path,
        {
            "lib/__init__.py": (
                "import lazy_loader as lazy\n"
                "from .real import candidate\n"
                "__getattr__, __dir__, __all__ = lazy.attach_stub(__name__, __file__)\n"
            ),
            "lib/impl.py": _function("candidate"),
            "lib/real.py": _function("candidate"),
            "lib/control.py": _function("public_control"),
        },
        {
            "lib/__init__.pyi": "from .impl import candidate\n",
            "lib/control.pyi": "def public_control(path: str) -> list[str]: ...\n",
        },
    )

    declared = _declared(tmp_path, project)

    # Existing import analysis owns lib.real.candidate. The API evidence pass
    # must not add a different implementation or invent an __init__ definition.
    assert declared == {"lib.control.public_control"}


def _guard_file_open(monkeypatch, blocked):
    """Fail before opening unsafe fixtures, including FIFOs without a writer."""
    blocked = {os.path.abspath(os.fspath(path)) for path in blocked}
    blocked_basenames = {os.path.basename(path) for path in blocked}

    def guard(original):
        def checked(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                spelling = os.fsdecode(path)
                absolute = os.path.abspath(spelling)
                relative_unsafe = not os.path.isabs(spelling) and (
                    os.path.basename(spelling) in blocked_basenames
                )
                assert absolute not in blocked and not relative_unsafe, (
                    f"attempted unsafe read: {spelling}"
                )
            return original(path, *args, **kwargs)

        return checked

    monkeypatch.setattr(Path, "read_text", guard(Path.read_text))
    monkeypatch.setattr(Path, "open", guard(Path.open))
    monkeypatch.setattr(builtins, "open", guard(builtins.open))
    monkeypatch.setattr(io, "open", guard(io.open))
    monkeypatch.setattr(os, "open", guard(os.open))


@pytest.mark.parametrize(
    "kind", ["fifo", "external_symlink", "internal_symlink", "oversize"]
)
@pytest.mark.parametrize("provider", ["docs", "stub"])
def test_evidence_readers_reject_unsafe_files_before_open(
    tmp_path, monkeypatch, kind, provider
):
    root = tmp_path / "project"
    root.mkdir()
    safe_evidence = (
        {"docs/safe.rst": ".. autofunction:: lib.safe.public_control\n"}
        if provider == "docs"
        else {"lib/safe.pyi": "def public_control(path: str) -> list[str]: ...\n"}
    )
    project = _project(
        root,
        {
            "lib/unsafe.py": _function("unsafe_target"),
            "lib/safe.py": _function("public_control"),
        },
        safe_evidence,
    )
    unsafe = root / ("docs/unsafe.rst" if provider == "docs" else "lib/unsafe.pyi")
    blocked_reads = [unsafe]
    content = (
        ".. autofunction:: lib.unsafe.unsafe_target\n"
        if provider == "docs"
        else "def unsafe_target(path: str) -> list[str]: ...\n"
    )
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO fixture requires os.mkfifo")
        os.mkfifo(unsafe)
    elif kind.endswith("symlink"):
        destination = (
            tmp_path / "external-evidence"
            if kind == "external_symlink"
            else root / "evidence-target"
        )
        destination.write_text(content)
        unsafe.symlink_to(destination)
        blocked_reads.append(destination)
    else:
        limit = (
            getattr(public_api, "MAX_STUB_FILE_BYTES", public_api.MAX_DOC_FILE_BYTES)
            if provider == "stub"
            else public_api.MAX_DOC_FILE_BYTES
        )
        unsafe.write_text(content + "#" * (limit + 1))
    _guard_file_open(monkeypatch, blocked_reads)

    declared = _declared(root, project)

    assert "lib.unsafe.unsafe_target" not in declared
    assert "lib.safe.public_control" in declared


def test_symlinked_documentation_directory_cannot_supply_evidence(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    root.mkdir()
    project = _project(root, {"lib/impl.py": _function("unsafe_target")}, {})
    outside = tmp_path / "external-docs"
    outside.mkdir()
    (outside / "api.rst").write_text(".. autofunction:: lib.impl.unsafe_target\n")
    (root / "docs").symlink_to(outside, target_is_directory=True)
    _guard_file_open(monkeypatch, [root / "docs/api.rst", outside / "api.rst"])

    assert not _declared(root, project)


@pytest.mark.parametrize("provider", ["docs", "stub"])
def test_file_limit_applies_to_actual_bytes_despite_small_path_stat(
    tmp_path, monkeypatch, provider
):
    project = _project(tmp_path, {"lib/impl.py": _function("oversize_target")}, {})
    if provider == "docs":
        limit = public_api.MAX_DOC_FILE_BYTES
        relative = "docs/oversize.rst"
        declaration = ".. autofunction:: lib.impl.oversize_target\n"
    else:
        limit = getattr(
            public_api, "MAX_STUB_FILE_BYTES", public_api.MAX_DOC_FILE_BYTES
        )
        relative = "lib/impl.pyi"
        declaration = "def oversize_target(path: str) -> list[str]: ...\n"
    unsafe = write_fixture(tmp_path, relative, " " * (limit + 1) + "\n" + declaration)
    original_stat = Path.stat

    def small_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == unsafe:
            fields = list(result)
            fields[6] = 1
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "stat", small_stat)

    assert "lib.impl.oversize_target" not in _declared(tmp_path, project)


def test_scanner_output_keeps_excluded_api_findings_and_real_public_controls(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    _write(tmp_path, "pyproject.toml", '[project]\nname = "precision"\nversion = "1"\n')
    _write(tmp_path, "lib/__init__.py", "")
    _write(tmp_path, "lib/exact.py", "__all__ = []\n" + _function("excluded_export"))
    _write(
        tmp_path,
        "lib/normal.py",
        _function("public_control") + _function("unmentioned"),
    )
    _write(
        tmp_path,
        "docs/api.rst",
        (
            ".. autofunction:: lib.exact.excluded_export\n\n"
            ".. autofunction:: lib.normal.public_control\n"
        ),
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    unused = {item["simple_name"] for item in result.get("unused_functions", [])}

    assert {"excluded_export", "unmentioned"} <= unused
    assert "public_control" not in unused
