"""A YAML loader name bound more than once, as in the C-loader fallback
``try: from yaml import CSafeLoader as SafeLoader`` / ``except ImportError:
from yaml import SafeLoader``, is safe only when every binding that can reach
the call is a native safe loader: SafeLoader, CSafeLoader, BaseLoader or
CBaseLoader from yaml, yaml.loader or yaml.cyaml."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.linter import LinterVisitor
from skylos.reporting.listing import is_listed
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx

READ = "def read(stream):\n    return load(stream, Loader=SafeLoader)\n"

PYDRIVE2 = (
    "from yaml import load\n"
    "try:\n"
    "    from yaml import CSafeLoader as SafeLoader\n"
    "except ImportError:\n"
    "    from yaml import SafeLoader\n"
    "\n"
    "\n" + READ
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
