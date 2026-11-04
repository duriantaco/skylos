"""A YAML loader name bound more than once, as in the C-loader fallback
``try: from yaml import CSafeLoader as SafeLoader`` / ``except ImportError:
from yaml import SafeLoader``, is safe only when every binding that can reach
the call is a native safe loader: SafeLoader, CSafeLoader, BaseLoader or
CBaseLoader from yaml, yaml.loader or yaml.cyaml."""

import ast
import json
import time

import pytest

from skylos.analyzer import analyze
from skylos.core.linter import LinterVisitor
from skylos.reporting.listing import is_listed
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx

READ = "def read(stream):\n    return load(stream, Loader=SafeLoader)\n"
TIME_CEILING = 5

PYDRIVE2 = (
    "from yaml import load\n"
    "try:\n"
    "    from yaml import CSafeLoader as SafeLoader\n"
    "except ImportError:\n"
    "    from yaml import SafeLoader\n"
    "\n"
    "\n" + READ
)


YAML_READ = "def read(stream):\n    return yaml.load(stream, Loader=SafeLoader)\n"

IMPORT_HOOK = (
    "import builtins, types, yaml\n"
    "original = builtins.__import__\n"
    "proxy = types.SimpleNamespace(\n"
    "    CSafeLoader=yaml.UnsafeLoader, SafeLoader=yaml.UnsafeLoader\n"
    ")\n"
    "def fake(name, *args, **kwargs):\n"
    "    return proxy\n"
    "builtins.__import__ = fake\n"
)


def _fallback(name):
    return (
        "from yaml import load\n"
        "try:\n"
        "    from yaml import CSafeLoader as SafeLoader\n"
        "except ImportError:\n"
        f"    from yaml import {name} as SafeLoader\n" + READ
    )


REPORTED = {
    **{
        f"fallback_{name}": _fallback(name)
        for name in ("UnsafeLoader", "Loader", "FullLoader", "CLoader", "CFullLoader")
    },
    "c_import_unsafe_under_safe_name": (
        "from yaml import load\n"
        "try:\n"
        "    from yaml import CLoader as SafeLoader\n"
        "except ImportError:\n"
        "    from yaml import SafeLoader\n" + READ
    ),
    "except_not_import_error_rebinds": (
        "import yaml\n"
        "from yaml import load\n"
        "try:\n"
        "    from yaml import CSafeLoader as SafeLoader\n"
        "except AttributeError:\n"
        "    SafeLoader = yaml.UnsafeLoader\n" + READ
    ),
    "rebound_after_try": PYDRIVE2.replace(
        "\n\n\ndef read", "\nimport yaml\nSafeLoader = yaml.UnsafeLoader\ndef read"
    ),
    "if_else_unsafe_branch": (
        "import os\n"
        "from yaml import load\n"
        "if os.environ.get('FAST'):\n"
        "    from yaml import CSafeLoader as SafeLoader\n"
        "else:\n"
        "    from yaml import UnsafeLoader as SafeLoader\n" + READ
    ),
    "fallback_assigns_unsafe_alias": (
        "from yaml import load, UnsafeLoader as Fallback\n"
        "try:\n"
        "    from yaml import CSafeLoader as SafeLoader\n"
        "except ImportError:\n"
        "    SafeLoader = Fallback\n" + READ
    ),
    "fallback_from_wrapper_call": (
        "from yaml import load\n"
        "def pick():\n"
        "    from yaml import UnsafeLoader\n"
        "    return UnsafeLoader\n"
        "try:\n"
        "    from yaml import CSafeLoader as SafeLoader\n"
        "except ImportError:\n"
        "    SafeLoader = pick()\n" + READ
    ),
    "fallback_constructor_mutation": PYDRIVE2.replace(
        "\n\n\ndef read",
        "\nimport subprocess\n"
        "def unsafe(loader, node):\n"
        "    return subprocess.run(loader.construct_scalar(node), shell=True)\n"
        "SafeLoader.add_constructor('!run', unsafe)\n"
        "def read",
    ),
    "fallback_provider_replaced": PYDRIVE2.replace(
        "\n\n\ndef read",
        "\nimport yaml\nyaml.CSafeLoader = yaml.UnsafeLoader\ndef read",
    ),
    "fallback_then_globals_write": PYDRIVE2.replace(
        "\n\n\ndef read",
        "\nimport yaml\nglobals()['SafeLoader'] = yaml.UnsafeLoader\ndef read",
    ),
    "import_hook_fallback": IMPORT_HOOK + "try:\n"
    "    from yaml import CSafeLoader as SafeLoader\n"
    "except ImportError:\n"
    "    from yaml import SafeLoader\n"
    "builtins.__import__ = original\n" + YAML_READ,
    "import_hook_single_binding": IMPORT_HOOK + "from yaml import SafeLoader\n"
    "builtins.__import__ = original\n" + YAML_READ,
    "import_hook_local_subclass": IMPORT_HOOK + "from yaml import SafeLoader\n"
    "builtins.__import__ = original\n"
    "class Strict(SafeLoader):\n"
    "    pass\n"
    "def read(stream):\n"
    "    return yaml.load(stream, Loader=Strict)\n",
    "importlib_swap": (
        "import importlib\n"
        "import yaml\n"
        "importlib.import_module('yaml').SafeLoader = yaml.UnsafeLoader\n"
        "from yaml import SafeLoader\n" + YAML_READ
    ),
    "sys_modules_swap": (
        "import sys, types, yaml\n"
        "sys.modules['yaml'] = types.SimpleNamespace(SafeLoader=yaml.UnsafeLoader)\n"
        "from yaml import SafeLoader\n" + YAML_READ
    ),
    "sys_modules_imported_by_name": (
        "import types, yaml\n"
        "from sys import modules\n"
        "modules['yaml'] = types.SimpleNamespace(SafeLoader=yaml.UnsafeLoader)\n"
        "from yaml import SafeLoader\n" + YAML_READ
    ),
    "sys_modules_through_alias": (
        "import sys as rt, types, yaml\n"
        "rt.modules['yaml'] = types.SimpleNamespace(SafeLoader=yaml.UnsafeLoader)\n"
        "from yaml import SafeLoader\n" + YAML_READ
    ),
    "sys_modules_through_os": (
        "import os, types, yaml\n"
        "os.sys.modules['yaml'] = types.SimpleNamespace(SafeLoader=yaml.UnsafeLoader)\n"
        "from yaml import SafeLoader\n" + YAML_READ
    ),
    "builtins_dict_import_hook": (
        "import types, yaml\n"
        "proxy = types.SimpleNamespace(SafeLoader=yaml.UnsafeLoader)\n"
        "def fake(name, *args, **kwargs):\n"
        "    return proxy\n"
        "globals()['__builtins__']['__import__'] = fake\n"
        "from yaml import SafeLoader\n" + YAML_READ
    ),
    "sys_modules_through_getattr": (
        "import sys, types, yaml\n"
        "getattr(sys, 'modules')['yaml'] = types.SimpleNamespace(\n"
        "    SafeLoader=yaml.UnsafeLoader\n"
        ")\n"
        "from yaml import SafeLoader\n" + YAML_READ
    ),
}

QUIET = {
    "pydrive2_fallback": PYDRIVE2,
    "module_alias_fallback": (
        "import yaml as y\n"
        "try:\n"
        "    from yaml import CSafeLoader as Loader\n"
        "except ImportError:\n"
        "    from yaml import SafeLoader as Loader\n"
        "def read(stream):\n"
        "    return y.load(stream, Loader=Loader)\n"
    ),
    "cyaml_import": (
        "import yaml\n"
        "from yaml.cyaml import CSafeLoader\n"
        "def read(stream):\n"
        "    return yaml.load(stream, Loader=CSafeLoader)\n"
    ),
    "cyaml_loader_module_fallback": (
        "import yaml\n"
        "try:\n"
        "    from yaml.cyaml import CSafeLoader as SafeLoader\n"
        "except ImportError:\n"
        "    from yaml.loader import SafeLoader\n"
        "def read(stream):\n"
        "    return yaml.load(stream, Loader=SafeLoader)\n"
    ),
    "base_loader_fallback": (
        "import yaml\n"
        "try:\n"
        "    from yaml import CBaseLoader as Loader\n"
        "except ImportError:\n"
        "    from yaml import BaseLoader as Loader\n"
        "def read(stream):\n"
        "    return yaml.load_all(stream, Loader)\n"
    ),
    "base_loader_attribute": (
        "import yaml\n"
        "def read(stream):\n"
        "    return yaml.load(stream, Loader=yaml.BaseLoader)\n"
    ),
    "function_scope_fallback": (
        "import yaml\n"
        "def read(stream):\n"
        "    try:\n"
        "        from yaml import CSafeLoader as SafeLoader\n"
        "    except ImportError:\n"
        "        from yaml import SafeLoader\n"
        "    return yaml.load(stream, Loader=SafeLoader)\n"
    ),
    "pydrive2_with_torch_modules": PYDRIVE2 + "def count(model):\n"
    "    total = 0\n"
    "    for m in model.modules():\n"
    "        total += 1\n"
    "    return total\n",
    "pydrive2_with_setattr": PYDRIVE2 + "class Config:\n"
    "    pass\n"
    "cfg = Config()\n"
    "setattr(cfg, 'x', 1)\n",
    "pydrive2_with_qt_exec": PYDRIVE2 + "def run(app):\n    return app.exec()\n",
    "single_binding_with_vars_and_modules": (
        "import yaml\n"
        "def read(stream, model):\n"
        "    print(vars(model), list(model.modules()))\n"
        "    return yaml.load(stream, Loader=yaml.SafeLoader)\n"
    ),
    "pydrive2_with_sys_argv": "import sys\n"
    + PYDRIVE2
    + "def main():\n    return read(open(sys.argv[1]))\n",
}


def _both(tmp_path, source):
    root = tmp_path.resolve()
    path = root / "loader.py"
    path.write_text(source)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = root
    linter.visit(ast.parse(source))
    return [
        [row for row in findings if row["rule_id"] == "SKY-D206"]
        for findings in (scan_ctx(root, [path]), linter.findings)
    ]


@pytest.fixture(scope="module")
def analyzed_rows(tmp_path_factory):
    root = tmp_path_factory.mktemp("yaml_fallbacks").resolve()
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    for name, source in {**REPORTED, **QUIET}.items():
        (root / f"{name}.py").write_text(source)
    report = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not report.get("analysis_errors")
    rows = {}
    for row in report.get("danger", []):
        if row.get("rule_id") == "SKY-D206":
            stem = row["file"].replace("\\", "/").rsplit("/", 1)[-1][:-3]
            rows.setdefault(stem, []).append(row)
    return rows


@pytest.mark.parametrize("case", sorted(REPORTED))
def test_unsafe_or_unproved_fallback_binding_stays_listed(
    tmp_path, analyzed_rows, case
):
    for findings in _both(tmp_path, REPORTED[case]):
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
    [row] = analyzed_rows[case]
    assert is_listed(row, "danger")


@pytest.mark.parametrize("case", sorted(QUIET))
def test_native_safe_loader_bindings_stay_quiet(tmp_path, analyzed_rows, case):
    assert _both(tmp_path, QUIET[case]) == [[], []]
    assert case not in analyzed_rows


def test_many_unresolved_loader_names_are_checked_in_bounded_time(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    calls = "".join(
        f"yaml.load(data, Loader=missing_{index})\n" for index in range(400)
    )
    (tmp_path / "loads.py").write_text("import yaml\ndata = input()\n" + calls)
    start = time.process_time()
    report = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    elapsed = time.process_time() - start
    rows = [row for row in report.get("danger", []) if row["rule_id"] == "SKY-D206"]
    assert len(rows) == 400
    assert elapsed < TIME_CEILING
