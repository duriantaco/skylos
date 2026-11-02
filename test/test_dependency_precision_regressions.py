from __future__ import annotations

import pytest
from packaging.specifiers import SpecifierSet

from skylos.rules.ai_defect import dependency_hallucination as dep


@pytest.fixture(autouse=True)
def offline_registry(monkeypatch):
    monkeypatch.setattr(
        dep,
        "_get_stdlib_modules",
        lambda: {
            "os",
            "sys",
            "typing",
            "typing_extensions",
            "builtins",
            "importlib",
            "ast",
        },
    )
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})
    monkeypatch.setattr(dep, "_build_installed_requirements", lambda: {})
    monkeypatch.setattr(dep, "installed_module_mapping", lambda builder: {})
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(dep, "_fetch_dist_modules", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        dep,
        "_check_pypi_status",
        lambda name, cache: "exists" if name == "known_package" else "missing",
    )


def _write(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _scan(root, source, mode, module="known_package"):
    _write(root / "requirements.txt", "")
    path = _write(root / "app.py", source)
    if mode == "full":
        findings = dep.scan_python_dependency_hallucinations(root, [path])
        assert findings.unverified_imports == {}
    else:
        line = next(
            (
                number
                for number, text in enumerate(source.splitlines(), 1)
                if f"import {module}" in text
            ),
            1,
        )
        findings, unreachable = dep.scan_diff_added_imports(
            root, [("app.py", line, module)]
        )
        assert unreachable is False
    return {(row["symbol"], row["rule_id"]) for row in findings}


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize(
    "prefix",
    [
        "import typing\ntyping.TYPE_CHECKING = True\n",
        "import typing as t\nt.TYPE_CHECKING = True\ntyping = t\n",
        "import typing\nsetattr(typing, 'TYPE_CHECKING', True)\n",
        "import typing\ntyping.__dict__['TYPE_CHECKING'] = True\n",
        "import typing\nnamespace = vars(typing)\nnamespace['TYPE_CHECKING'] = True\n",
        "import typing\nother = typing\nother.TYPE_CHECKING = True\n",
        "import typing\nmutate(typing)\n",
    ],
)
def test_mutable_typing_module_does_not_prove_an_import_is_type_only(
    tmp_path, mode, prefix
):
    source = prefix + "if typing.TYPE_CHECKING:\n    import known_package\n"
    assert _scan(tmp_path, source, mode) == {("known_package", "SKY-D223")}


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize(
    "writer",
    [
        "globals()['TYPE_CHECKING'] = True\n",
        "locals().update(TYPE_CHECKING=True)\n",
        "exec('TYPE_CHECKING = True')\n",
        "import builtins\nbuiltins.exec('TYPE_CHECKING = True')\n",
        "import builtins\ngetattr(builtins, 'exec')('TYPE_CHECKING = True')\n",
        "__builtins__['exec']('TYPE_CHECKING = True')\n",
        "import importlib\nt = importlib.import_module('typing')\nt.TYPE_CHECKING = True\nfrom typing import TYPE_CHECKING\n",
        "import sys\nsys.modules['typing'].__setattr__('TYPE_CHECKING', True)\nfrom typing import TYPE_CHECKING\n",
        "import sys\nsys.modules['typing'].__getattribute__('__dict__')['TYPE_CHECKING'] = True\nfrom typing import TYPE_CHECKING\n",
        "import sys\nobject.__setattr__(sys.modules['typing'], 'TYPE_CHECKING', True)\nfrom typing import TYPE_CHECKING\n",
        "import importlib\nimportlib.import_module('typing').__setattr__('TYPE_CHECKING', True)\nfrom typing import TYPE_CHECKING\n",
        "import sys\nsys.modules['typing'] = type('Typing', (), {'TYPE_CHECKING': True})()\nfrom typing import TYPE_CHECKING\n",
        "import sys\nsys.modules.update(typing=type('Typing', (), {'TYPE_CHECKING': True})())\nfrom typing import TYPE_CHECKING\n",
        "from config import *\n",
        "import typing\ntyping.TYPE_CHECKING = True\nfrom typing import TYPE_CHECKING\n",
    ],
)
def test_namespace_writers_do_not_prove_an_import_is_type_only(tmp_path, mode, writer):
    _write(tmp_path / "config.py", "TYPE_CHECKING = True\n")
    source = (
        "from typing import TYPE_CHECKING\n"
        + writer
        + "if TYPE_CHECKING:\n    import known_package\n"
    )
    assert _scan(tmp_path, source, mode) == {("known_package", "SKY-D223")}


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize("module", ["typing", "typing_extensions"])
@pytest.mark.parametrize("layout", ["module", "package", "src", "sibling"])
def test_local_typing_provider_cannot_prove_a_false_flag(
    tmp_path, mode, module, layout
):
    importer = tmp_path
    if layout == "package":
        _write(tmp_path / module / "__init__.py", "TYPE_CHECKING = True\n")
    elif layout == "src":
        _write(tmp_path / "src" / module / "__init__.py", "TYPE_CHECKING = True\n")
    elif layout == "sibling":
        importer = tmp_path / "tools"
        _write(importer / f"{module}.py", "TYPE_CHECKING = True\n")
    else:
        _write(tmp_path / f"{module}.py", "TYPE_CHECKING = True\n")
    _write(tmp_path / "requirements.txt", "")
    path = _write(
        importer / "app.py",
        f"from {module} import TYPE_CHECKING\nif TYPE_CHECKING:\n    import known_package\n",
    )
    if mode == "full":
        findings = dep.scan_python_dependency_hallucinations(tmp_path, [path])
    else:
        findings, _ = dep.scan_diff_added_imports(
            tmp_path, [(str(path.relative_to(tmp_path)), 3, "known_package")]
        )
    assert {(row["symbol"], row["rule_id"]) for row in findings} == {
        ("known_package", "SKY-D223")
    }


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize(
    "source",
    [
        "from typing import TYPE_CHECKING as CHECK\nif CHECK:\n    import known_package\n",
        "import typing as t\nVALUE: t.Optional[str] = None\nif t.TYPE_CHECKING:\n    import known_package\n",
        "from typing_extensions import TYPE_CHECKING\nif TYPE_CHECKING:\n    import known_package\n",
    ],
)
def test_native_unmodified_type_guards_remain_quiet(tmp_path, mode, source):
    assert _scan(tmp_path, source, mode) == set()


@pytest.mark.parametrize(
    "package, rule", [("known_package", "SKY-D223"), ("absent_package", "SKY-D222")]
)
@pytest.mark.parametrize(
    "template",
    [
        'exec("""\nimport {package}\n""")\n',
        'exec("import {package}")\n',
        'exec(compile("""\nimport {package}\n""", "embedded", "exec"))\n',
        'exec(compile("""\nimport {package}\n""", "embedded", mode="exec"))\n',
        'exec(compile(source="""\nimport {package}\n""", filename="embedded", mode="exec"))\n',
        'exec(compile("import {package}", "embedded", mode="single"))\n',
        'exec(compile("""\nimport {package}\n""", "embedded", "exec", flags=unknown_flags))\n',
        'CODE = """\nimport {package}\n"""\nexec(CODE)\n',
        'CODE = compile("import {package}", "embedded", "exec")\nexec(CODE)\n',
        'exec("import " + "{package}")\n',
        'exec("""\nimport {package}\n""", globals())\n',
        'def load():\n    CODE = """\nimport {package}\n"""\n    exec(CODE)\nload()\n',
        'def unrelated(exec):\n    pass\nexec("""\nimport {package}\n""")\n',
    ],
)
def test_literal_executed_code_keeps_real_imports(tmp_path, package, rule, template):
    assert _scan(tmp_path, template.format(package=package), "full", package) == {
        (package, rule)
    }


@pytest.mark.parametrize(
    "source",
    [
        '"""Example:\nimport known_package\n"""\n',
        'TEXT = """\nimport known_package\n"""\n',
        'compile("""\nimport known_package\n""", "example", "exec")\n',
        'def exec(code):\n    return code\nexec("""\nimport known_package\n""")\n',
        'def compile(*args):\n    return "pass"\nexec(compile("""\nimport known_package\n""", "example", "exec"))\n',
        'import ast\nexec(compile("""\nimport known_package\n""", "example", "exec", flags=ast.PyCF_ONLY_AST))\n',
        'exec(compile("""\nimport known_package\n""", "example", "exec", flags=1024))\n',
        'from ast import PyCF_ONLY_AST as FLAGS\nexec(compile("""\nimport known_package\n""", "example", "exec", flags=FLAGS))\n',
        'exec(compile("""\nimport known_package\n""", "example", "eval"))\n',
        'CODE = """\nimport known_package\n"""\nCODE = "pass"\nexec(CODE)\n',
    ],
)
def test_unexecuted_or_rebound_code_text_does_not_invent_imports(tmp_path, source):
    assert _scan(tmp_path, source, "full") == set()


@pytest.mark.parametrize(
    "source, expected_line",
    [
        ('exec("""\nimport known_package\n""")\n', 2),
        ('CODE = """\n\nimport known_package\n"""\nexec(CODE)\n', 3),
        ('exec(compile("""\nimport known_package\n""", "embedded", "exec"))\n', 2),
        (
            'def load():\n    CODE = """\nimport known_package\n"""\n    exec(CODE)\nload()\n',
            3,
        ),
        ('exec("import known_package")\n', 1),
    ],
)
def test_executed_import_locations_refer_to_the_original_source(
    tmp_path, source, expected_line
):
    _scan(tmp_path, source, "full")
    findings = dep.scan_python_dependency_hallucinations(
        tmp_path, [tmp_path / "app.py"]
    )
    assert [(row["symbol"], row["line"]) for row in findings] == [
        ("known_package", expected_line)
    ]


def test_nonlocal_code_write_prevents_literal_inference(tmp_path):
    source = (
        'def outer():\n    CODE = """\nimport known_package\n"""\n'
        '    def mutate():\n        nonlocal CODE\n        CODE = "pass"\n'
        "    mutate()\n    exec(CODE)\nouter()\n"
    )
    assert _scan(tmp_path, source, "full") == set()


@pytest.mark.parametrize("local_provider", [False, True])
def test_ast_only_flag_spelling_does_not_prove_the_flag_value(tmp_path, local_provider):
    if local_provider:
        _write(tmp_path / "ast.py", "PyCF_ONLY_AST = 0\n")
        prefix = "import ast\n"
    else:
        prefix = "import ast\nast.PyCF_ONLY_AST = 0\n"
    source = (
        prefix
        + 'exec(compile("""\nimport known_package\n""", "example", "exec", flags=ast.PyCF_ONLY_AST))\n'
    )
    assert _scan(tmp_path, source, "full") == {("known_package", "SKY-D223")}


@pytest.mark.parametrize(
    "prefix, flag",
    [
        ("import ast\nexec('ast.PyCF_ONLY_AST = 0')\n", "ast.PyCF_ONLY_AST"),
        ("from ast import PyCF_ONLY_AST as FLAGS\nexec('FLAGS = 0')\n", "FLAGS"),
        (
            "import ast\nimport sys\nsys.modules['ast'].__setattr__('PyCF_ONLY_AST', 0)\n",
            "ast.PyCF_ONLY_AST",
        ),
        (
            "import ast\nimport sys\ngetattr(sys.modules['ast'], '__dict__')['PyCF_ONLY_AST'] = 0\n",
            "ast.PyCF_ONLY_AST",
        ),
        (
            "import sys\nsys.modules['ast'] = type('Ast', (), {'PyCF_ONLY_AST': 0})()\nimport ast\n",
            "ast.PyCF_ONLY_AST",
        ),
    ],
)
def test_reflective_ast_flag_writes_keep_executable_imports(tmp_path, prefix, flag):
    source = (
        prefix
        + f'exec(compile("""\nimport known_package\n""", "example", "exec", flags={flag}))\n'
    )
    assert _scan(tmp_path, source, "full") == {("known_package", "SKY-D223")}


@pytest.mark.parametrize("expression", ["1024 | Zero()", "Zero() | 1024"])
def test_compile_flag_operator_overloads_do_not_prove_ast_only(tmp_path, expression):
    source = (
        "class Zero:\n    def __or__(self, other):\n        return 0\n"
        "    def __ror__(self, other):\n        return 0\n"
        f'exec(compile("""\nimport known_package\n""", "example", "exec", flags={expression}))\n'
    )
    assert _scan(tmp_path, source, "full") == {("known_package", "SKY-D223")}


def test_repeated_nested_literal_execution_reuses_source_analysis(monkeypatch):
    original = dep._parse_import_source
    counts = []
    for width in (2, 8):
        source = "import known_package\n"
        for level in range(3):
            name = f"CODE_{level}"
            source = f"{name} = {source!r}\n" + f"exec({name})\n" * width
        source += 'exec("import absent_package")\n'
        calls = []

        def counted(value):
            calls.append(value)
            return original(value)

        with monkeypatch.context() as context:
            context.setattr(dep, "_parse_import_source", counted)
            analysis = dep._SourceImportAnalysis(source)
        assert analysis.modules == {"known_package", "absent_package"}
        counts.append(len(calls))
    assert counts[0] == counts[1]


@pytest.mark.parametrize("mode", ["full", "diff"])
@pytest.mark.parametrize("runtime_has_cgi", [False, True])
@pytest.mark.parametrize(
    "constraint, expected",
    [
        (">=3.11,<3.13", False),
        (">=3.13", True),
        ("==3.13.*", True),
        ("==3.13.1", True),
        ("~=3.13", True),
        (">=3.9,>=3.13", True),
        (">=3.13,>=3.9", True),
        (">=3.12,!=3.12.*", True),
        (">3.12.99,<3.13", False),
        ("==3.12.*", False),
        ("~=3.12.3", False),
        (">=3.12,!=3.12.0", False),
    ],
)
def test_removed_stdlib_respects_all_python_constraints(
    tmp_path, monkeypatch, mode, runtime_has_cgi, constraint, expected
):
    runtime = {"os", "sys", "typing"}
    if runtime_has_cgi:
        runtime.add("cgi")
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set(runtime))
    _write(
        tmp_path / "pyproject.toml",
        f'[project]\nname = "app"\nrequires-python = "{constraint}"\ndependencies = []\n',
    )
    actual = _scan(tmp_path, "import cgi\n", mode, "cgi")
    assert actual == ({("cgi", "SKY-D222")} if expected else set())


@pytest.mark.parametrize(
    "constraint, witness",
    [
        ("!=3.11.*,==3.12.0.*,>3.11,!=3.12,!=3.12.99", "3.12.0.dev0"),
        ("!=3.12,==3.12.*,<3.12.1,!=3.11.*", "3.12.0.dev0"),
        ("!=3.12,==3.12.*,<=3.12.0", "3.12.0a1"),
        ("!=3.12,~=3.12,<3.12.1", "3.12.0.post0"),
        ("!=3.12.0,>=3.12.0,<3.12.1,!=3.11.*,<=3.13", "3.12.0.post0"),
        ("!=3.13,!=3.9,~=3.12,==3.12.0.*,!=3.12", "3.12.0.post0"),
        ("==3.12.0.*,>=3.12,!=3.12,!=3.12.1.*", "3.12.0.post0"),
        (">3.12a1.dev1,<3.12a1", "3.12a1.dev2"),
        (">3.12a1.post1,<3.12a2", "3.12a1.post2"),
        (">=3.9,!=3.12.1,==3.12.1.*", "3.12.1.dev0"),
        ("~=3.11,==3.12.0.*,!=3.12,<3.12.1,>=3.12", "3.12.0.post0"),
        ("~=3.12,>3.12,!=3.12.1,==3.12.1.*", "3.12.1.dev0"),
    ],
)
def test_python_constraint_phase_boundaries_keep_supported_old_versions(
    constraint, witness
):
    specifiers = SpecifierSet(constraint)
    assert specifiers.contains(witness, prereleases=True)
    assert dep._supports_python_before(specifiers, (3, 13)) is True
