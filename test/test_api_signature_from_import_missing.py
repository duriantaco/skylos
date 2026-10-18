"""SKY-D224 reports a name imported with ``from pkg import name`` and then
called when the inspected package exposes no such callable.

``pkg.name()`` was already reported; ``from pkg import name`` then ``name()``
was silently accepted (agent-pr-bench fa-04 shape).
"""

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.ai_defect.api_signature_hallucination import (
    RULE_ID_API_SIGNATURE,
    scan_python_api_signature_hallucinations,
)


def _surface(*, truncated=False):
    return {
        "module": "pandas",
        "members": {
            "read_csv": {
                "kind": "function",
                "parameters": [
                    {"name": "filepath_or_buffer", "kind": "POSITIONAL_OR_KEYWORD"},
                ],
            },
        },
        "members_truncated": truncated,
    }


def _scan(tmp_path, source, loader=lambda *_: _surface(), exists=False):
    # ``exists`` is the import system's answer for ``pandas.<name>``: False
    # (no such submodule or attribute), True (a submodule), None (unknown,
    # such as a lazy module ``__getattr__``).
    path = tmp_path / "app.py"
    assert write_text_no_symlink(path, source, encoding="utf-8")
    return scan_python_api_signature_hallucinations(
        tmp_path, [path], surface_loader=loader, submodule_resolver=lambda _: exists
    )


def _summary(findings):
    return [(f["rule_id"], f["line"], f["symbol"], f["message"]) for f in findings]


def test_called_name_missing_from_package_is_reported(tmp_path):
    findings = _scan(
        tmp_path, "from pandas import read_parquet_fast\n\nread_parquet_fast('x')\n"
    )

    assert _summary(findings) == [
        (
            RULE_ID_API_SIGNATURE,
            3,
            "pandas.read_parquet_fast",
            "Installed package 'pandas' does not expose callable API "
            "'pandas.read_parquet_fast'.",
        )
    ]


def test_aliased_missing_name_is_reported_at_the_call(tmp_path):
    findings = _scan(tmp_path, "from pandas import made_up as mu\nmu()\n")

    assert [(f["line"], f["symbol"]) for f in findings] == [(2, "pandas.made_up")]


def test_existing_callable_is_not_reported(tmp_path):
    assert _scan(tmp_path, "from pandas import read_csv\nread_csv('x')\n") == []


def test_imported_but_never_called_name_is_not_reported(tmp_path):
    # Non-callable members (constants, instances) are not in the surface, so
    # an uncalled name is no evidence of a missing API.
    assert _scan(tmp_path, "from pandas import NA\nvalue = NA\n") == []


def test_truncated_surface_is_not_evidence(tmp_path):
    loader = lambda *_: _surface(truncated=True)  # noqa: E731
    assert _scan(tmp_path, "from pandas import made_up\nmade_up()\n", loader) == []


def test_unavailable_surface_is_not_evidence(tmp_path):
    loader = lambda *_: None  # noqa: E731
    assert _scan(tmp_path, "from pandas import made_up\nmade_up()\n", loader) == []


def test_import_guarded_by_import_error_is_not_reported(tmp_path):
    source = (
        "try:\n"
        "    from pandas import made_up\n"
        "except ImportError:\n"
        "    made_up = None\n"
        "made_up()\n"
    )
    assert _scan(tmp_path, source) == []


def test_rebound_name_is_not_reported(tmp_path):
    source = "from pandas import made_up\nmade_up = build()\nmade_up()\n"
    assert _scan(tmp_path, source) == []


def test_submodule_import_is_not_reported(tmp_path):
    assert _scan(tmp_path, "from pandas import io\nio()\n", exists=True) == []


def test_unknown_existence_is_not_reported(tmp_path):
    # A lazy module ``__getattr__`` can provide names that ``dir()`` omits.
    assert _scan(tmp_path, "from pandas import made_up\nmade_up()\n", exists=None) == []


def test_private_name_is_not_reported(tmp_path):
    # The surface lists public names only.
    assert _scan(tmp_path, "from pandas import _made_up\n_made_up()\n") == []


def test_installed_requests_missing_class_is_reported(tmp_path):
    path = tmp_path / "app.py"
    source = "from requests import RetryPolicy\n\nRetryPolicy(total=3)\n"
    assert write_text_no_symlink(path, source, encoding="utf-8")

    findings = scan_python_api_signature_hallucinations(tmp_path, [path])

    assert [(f["line"], f["symbol"]) for f in findings] == [
        (3, "requests.RetryPolicy")
    ]


def test_relative_import_of_a_local_module_is_not_the_installed_package(tmp_path):
    # ``from .pandas import x`` is a local wrapper module, not pandas.
    assert _scan(tmp_path, "from .pandas import made_up\nmade_up()\n") == []


def test_import_inside_suppress_import_error_is_not_reported(tmp_path):
    source = (
        "import contextlib\n"
        "with contextlib.suppress(ImportError):\n"
        "    from pandas import made_up\n"
        "    made_up()\n"
    )
    assert _scan(tmp_path, source) == []


def test_same_name_bound_in_an_unrelated_function_still_reports(tmp_path):
    # Bindings are counted per scope: a parameter elsewhere does not rebind
    # the module-level import. The call inside ``other`` uses its parameter.
    source = (
        "from pandas import made_up\n"
        "\n"
        "def other(made_up):\n"
        "    return made_up()\n"
        "\n"
        "made_up()\n"
    )
    assert [(f["line"], f["symbol"]) for f in _scan(tmp_path, source)] == [
        (6, "pandas.made_up")
    ]


def test_call_shadowed_by_an_enclosing_local_is_not_reported(tmp_path):
    source = (
        "from pandas import made_up\n"
        "\n"
        "def outer():\n"
        "    made_up = lambda: 1\n"
        "    def inner():\n"
        "        return made_up()\n"
        "    return inner\n"
    )
    assert _scan(tmp_path, source) == []


def test_import_inside_a_function_is_not_tracked(tmp_path):
    source = "def load():\n    from pandas import made_up\n    return made_up()\n"
    assert _scan(tmp_path, source) == []


def test_homemade_suppress_is_not_an_import_guard(tmp_path):
    source = (
        "def suppress(*errors):\n"
        "    return open('log')\n"
        "\n"
        "with suppress(ImportError):\n"
        "    from pandas import made_up\n"
        "\n"
        "made_up()\n"
    )
    assert [(f["line"], f["symbol"]) for f in _scan(tmp_path, source)] == [
        (7, "pandas.made_up")
    ]


def test_aliased_contextlib_suppress_is_an_import_guard(tmp_path):
    source = (
        "from contextlib import suppress as quiet\n"
        "\n"
        "with quiet(ImportError):\n"
        "    from pandas import made_up\n"
        "\n"
        "made_up()\n"
    )
    assert _scan(tmp_path, source) == []


def _declare(tmp_path, *requirements):
    assert write_text_no_symlink(
        tmp_path / "requirements.txt", "\n".join(requirements) + "\n", encoding="utf-8"
    )


def test_installed_package_from_another_distribution_is_not_evidence(
    tmp_path, monkeypatch
):
    # The project declares ``jwt`` (GehirnInc); the scanner has PyJWT, which
    # ships the same import name. PyJWT's API says nothing about the
    # project's package, in either import style.
    from skylos.rules.ai_defect import api_signature_hallucination as api

    monkeypatch.setattr(api, "_installed_providers", lambda: {"pandas": ["pandas-ng"]})
    _declare(tmp_path, "pandas==1.0")
    assert _scan(tmp_path, "from pandas import made_up\nmade_up()\n") == []
    assert _scan(tmp_path, "import pandas\npandas.made_up()\n") == []


def test_declared_distribution_that_is_installed_is_evidence(tmp_path, monkeypatch):
    from skylos.rules.ai_defect import api_signature_hallucination as api

    monkeypatch.setattr(api, "_installed_providers", lambda: {"pandas": ["pandas"]})
    _declare(tmp_path, "pandas==2.2")
    assert [f["line"] for f in _scan(tmp_path, "from pandas import made_up\nmade_up()\n")] == [2]


def test_undeclared_installed_package_keeps_reporting(tmp_path, monkeypatch):
    # Nothing in the manifest claims the import name for another
    # distribution, so the installed package is the only evidence there is.
    from skylos.rules.ai_defect import api_signature_hallucination as api

    monkeypatch.setattr(api, "_installed_providers", lambda: {"pandas": ["pandas"]})
    _declare(tmp_path, "requests==2.32")
    assert [f["line"] for f in _scan(tmp_path, "from pandas import made_up\nmade_up()\n")] == [2]


def test_missing_name_used_as_a_bare_decorator_is_reported(tmp_path):
    # A decorator is called with the function, so it must be callable.
    source = "from pandas import made_up\n\n@made_up\ndef handler():\n    pass\n"
    assert [(f["line"], f["symbol"]) for f in _scan(tmp_path, source)] == [
        (3, "pandas.made_up")
    ]


def test_missing_module_attribute_used_as_a_decorator_is_reported(tmp_path):
    source = "import pandas\n\n@pandas.made_up\ndef handler():\n    pass\n"
    assert [(f["line"], f["symbol"]) for f in _scan(tmp_path, source)] == [
        (3, "pandas.made_up")
    ]


def test_existing_callable_used_as_a_decorator_is_not_reported(tmp_path):
    source = "from pandas import read_csv\n\n@read_csv\ndef handler():\n    pass\n"
    assert _scan(tmp_path, source) == []


def test_decorator_is_resolved_outside_the_function_it_decorates(tmp_path):
    # The parameter ``made_up`` does not exist yet when the decorator runs.
    source = "from pandas import made_up\n\n@made_up\ndef handler(made_up):\n    return made_up\n"
    assert [(f["line"], f["symbol"]) for f in _scan(tmp_path, source)] == [
        (3, "pandas.made_up")
    ]


def test_missing_name_used_as_a_class_decorator_is_reported(tmp_path):
    source = "from pandas import made_up\n\n@made_up\nclass Handler:\n    pass\n"
    assert [(f["line"], f["symbol"]) for f in _scan(tmp_path, source)] == [
        (3, "pandas.made_up")
    ]


def test_aliased_contextlib_module_suppress_is_an_import_guard(tmp_path):
    source = (
        "import contextlib as ctx\n"
        "\n"
        "with ctx.suppress(ImportError):\n"
        "    from pandas import made_up\n"
        "    made_up()\n"
    )
    assert _scan(tmp_path, source) == []


def test_suppress_on_another_module_is_not_an_import_guard(tmp_path):
    source = (
        "import errors as contextlib_like\n"
        "\n"
        "with contextlib_like.suppress(ImportError):\n"
        "    from pandas import made_up\n"
        "\n"
        "made_up()\n"
    )
    assert [f["line"] for f in _scan(tmp_path, source)] == [6]


def test_project_name_is_not_a_competing_distribution(tmp_path, monkeypatch):
    # A project called ``python-pandas`` does not declare where ``pandas``
    # comes from; only its dependencies do.
    from skylos.rules.ai_defect import api_signature_hallucination as api

    monkeypatch.setattr(api, "_installed_providers", lambda: {"pandas": ["pandas"]})
    assert write_text_no_symlink(
        tmp_path / "pyproject.toml",
        '[project]\nname = "python-pandas"\nversion = "0"\n',
        encoding="utf-8",
    )
    assert [f["line"] for f in _scan(tmp_path, "import pandas\npandas.made_up()\n")] == [2]


def _write(tmp_path, relative, text):
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(target, text, encoding="utf-8")


def _installed(monkeypatch, providers, versions=None):
    from skylos.rules.ai_defect import api_signature_hallucination as api

    monkeypatch.setattr(api, "_installed_providers", lambda: providers)
    monkeypatch.setattr(
        api, "_installed_version", lambda dist: (versions or {}).get(dist)
    )


def test_pipfile_declaring_another_distribution_is_respected(tmp_path, monkeypatch):
    _installed(monkeypatch, {"pandas": ["pandas-ng"]})
    _write(tmp_path, "Pipfile", '[packages]\npandas = "==1.0"\n')
    assert _scan(tmp_path, "from pandas import made_up\nmade_up()\n") == []


def test_nested_service_manifest_is_respected(tmp_path, monkeypatch):
    _installed(monkeypatch, {"pandas": ["pandas-ng"]})
    _write(tmp_path, "services/auth/requirements.txt", "pandas==1.0\n")
    assert _scan(tmp_path, "from pandas import made_up\nmade_up()\n") == []


def test_installed_version_outside_the_declared_range_is_not_evidence(
    tmp_path, monkeypatch
):
    _installed(monkeypatch, {"pandas": ["pandas"]}, {"pandas": "2.2.0"})
    _write(tmp_path, "requirements.txt", "pandas==1.5.3\n")
    assert _scan(tmp_path, "from pandas import made_up\nmade_up()\n") == []
    assert _scan(tmp_path, "import pandas\npandas.made_up()\n") == []


def test_installed_version_inside_the_declared_range_is_evidence(tmp_path, monkeypatch):
    _installed(monkeypatch, {"pandas": ["pandas"]}, {"pandas": "2.2.0"})
    _write(tmp_path, "requirements.txt", "pandas>=2,<3\n")
    assert [f["line"] for f in _scan(tmp_path, "from pandas import made_up\nmade_up()\n")] == [2]


def test_conditional_import_is_not_tracked(tmp_path):
    source = (
        "import pandas\n"
        "\n"
        "if hasattr(pandas, 'made_up'):\n"
        "    from pandas import made_up\n"
        "    made_up()\n"
    )
    assert _scan(tmp_path, source) == []


@pytest.mark.parametrize(
    ("spec", "installed", "verifiable"),
    [
        ("==2.31.0", "2.34.2", True),   # same API line: minor drift
        ("==1.7.1", "2.13.0", False),   # PyJWT 1 vs 2: another API line
        (">=2,<3", "2.2.0", True),
        ("<2", "2.2.0", False),
        ("==0.3.1", "0.4.0", False),    # 0.x: the minor is the API line
        ("==0.3.1", "0.3.9", True),
        ("~=1.4", "1.9.0", True),
        ("==2.*", "2.5.0", True),
        ("==not-a-version", "2.0.0", False),
    ],
)
def test_installed_version_is_evidence_on_the_same_api_line(spec, installed, verifiable):
    from skylos.rules.ai_defect.api_signature_hallucination import _same_api_line

    assert _same_api_line(spec, installed) is verifiable
