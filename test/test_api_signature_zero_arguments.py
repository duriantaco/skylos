"""Known empty signatures reject keywords; unavailable signatures stay unknown."""

import json
from types import ModuleType

import pytest

from skylos.core import python_api_surface
from skylos.core.api_symbol_truth import (
    SURFACE_KIND_PYTHON_MODULE,
    cache_api_symbol_surface,
    cached_api_symbol_surface,
    python_module_api_symbol_surface,
)
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.ai_defect.api_signature_hallucination import (
    RULE_ID_API_SIGNATURE,
    _keyword_accepted,
    scan_python_api_signature_hallucinations,
)


@pytest.mark.parametrize("kind", ["function", "class", "method"])
@pytest.mark.parametrize(
    "signature", [{}, {"signature": "()"}, {"signature": "() -> int"}]
)
@pytest.mark.parametrize("keyword", ["timeout", "retries"])
def test_known_empty_signature_rejects_keywords(kind, signature, keyword):
    entry = {"kind": kind, "parameters": [], **signature}
    assert _keyword_accepted(entry, keyword) is False


@pytest.mark.parametrize("parameters", [None, {}, "", "()", (), False])
def test_non_list_parameters_remain_unknown(parameters):
    assert _keyword_accepted({"parameters": parameters}, "timeout") is True


def test_missing_parameters_remain_unknown():
    assert _keyword_accepted({"kind": "function"}, "timeout") is True


@pytest.mark.parametrize("kind", ["function", "class", "method"])
def test_failed_inspection_marker_remains_unknown(kind):
    entry = {"kind": kind, "parameters": [], "signature": ""}
    assert _keyword_accepted(entry, "timeout") is True


@pytest.mark.parametrize(
    ("kind", "accepted"),
    [
        ("POSITIONAL_ONLY", False),
        ("POSITIONAL_OR_KEYWORD", True),
        ("KEYWORD_ONLY", True),
        ("VAR_POSITIONAL", False),
        ("VAR_KEYWORD", True),
    ],
)
def test_existing_parameter_kind_rules_are_preserved(kind, accepted):
    entry = {"parameters": [{"name": "timeout", "kind": kind}]}
    assert _keyword_accepted(entry, "timeout") is accepted
    assert _keyword_accepted(entry, "imaginary") is (kind == "VAR_KEYWORD")


def _write(path, source):
    assert write_text_no_symlink(path, source, encoding="utf-8")
    return path


def _surface():
    # These are trusted test definitions, not code imported from a scan target.
    def zero() -> int:
        return 0

    def flexible(**kwargs):
        return kwargs

    def unknown(**kwargs):
        return kwargs

    # A deterministic inspect.signature failure, independent of Python version.
    unknown.__signature__ = "unavailable"

    class Client:
        def __init__(self):
            pass

        def close(self):
            pass

        @staticmethod
        def static_close():
            pass

        @classmethod
        def from_env(cls):
            return cls()

    module = ModuleType("zeroargapi")
    module.zero = zero
    module.flexible = flexible
    module.unknown = unknown
    module.Client = Client
    surface = python_api_surface.build_python_api_surface(
        "zeroargapi", importer=lambda _: module
    )
    assert surface is not None
    assert surface["members"]["zero"]["parameters"] == []
    assert surface["members"]["zero"]["signature"].startswith("()")
    assert surface["members"]["Client"]["parameters"] == []
    assert surface["members"]["unknown"]["parameters"] == []
    assert surface["members"]["unknown"]["signature"] == ""
    return surface


_IMPORTS = (
    "import zeroargapi as api\n"
    "from zeroargapi import zero as make\n"
    "client = api.Client()\n"
)


@pytest.mark.parametrize(
    ("call", "symbol"),
    [
        ("api.zero(timeout=30)", "zeroargapi.zero"),
        ("make(timeout=30)", "zeroargapi.zero"),
        ("api.Client(timeout=30)", "zeroargapi.Client"),
        ("client.close(timeout=30)", "zeroargapi.Client.close"),
        ("client.static_close(timeout=30)", "zeroargapi.Client.static_close"),
        ("client.from_env(timeout=30)", "zeroargapi.Client.from_env"),
        ("api.zero(timeout=30, **payload)", "zeroargapi.zero"),
    ],
)
def test_scan_reports_bad_keywords_from_captured_signatures(tmp_path, call, symbol):
    source = _write(tmp_path / "app.py", _IMPORTS + call + "\n")
    surface = _surface()
    findings = scan_python_api_signature_hallucinations(
        tmp_path,
        [source],
        allowed_modules=("zeroargapi",),
        surface_loader=lambda *_: surface,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == RULE_ID_API_SIGNATURE
    assert finding["category"] == "ai_defect"
    assert finding["symbol"] == symbol
    assert finding["file"] == str(source)
    assert finding["line"] == 4
    assert "argument 'timeout'" in finding["message"]


@pytest.mark.parametrize(
    "call",
    [
        "api.zero()",
        "make()",
        "api.Client()",
        "client.close()",
        "client.static_close()",
        "client.from_env()",
        "api.flexible(timeout=30)",
        "api.unknown(timeout=30)",
        "api.zero(**payload)",
    ],
)
def test_scan_preserves_valid_calls_and_unknown_arguments(tmp_path, call):
    source = _write(tmp_path / "app.py", _IMPORTS + call + "\n")
    surface = _surface()
    assert (
        scan_python_api_signature_hallucinations(
            tmp_path,
            [source],
            allowed_modules=("zeroargapi",),
            surface_loader=lambda *_: surface,
        )
        == []
    )


@pytest.mark.parametrize("pre_cached", [False, True], ids=["cold", "existing-cache"])
def test_cached_signatures_keep_known_empty_and_unknown_distinct(
    tmp_path, monkeypatch, pre_cached
):
    source = _write(
        tmp_path / "app.py",
        _IMPORTS
        + "api.zero(timeout=30, retries=3)\n"
        + "api.unknown(timeout=30)\n"
        + "api.flexible(timeout=30)\n",
    )
    surface = _surface()
    expected_shared = python_module_api_symbol_surface(
        surface, environment_key=python_api_surface.python_environment_key()
    )
    assert expected_shared is not None
    if pre_cached:
        assert cache_api_symbol_surface(tmp_path, expected_shared)

    captured = []

    def builder(module_name):
        captured.append(module_name)
        assert not pre_cached, "Existing matching cache must not need a rebuild"
        return surface

    monkeypatch.setattr(python_api_surface, "build_python_api_surface", builder)
    results = [
        scan_python_api_signature_hallucinations(
            tmp_path, [source], allowed_modules=("zeroargapi",)
        )
        for _ in range(2)
    ]

    assert results[0] == results[1]
    assert [finding["symbol"] for finding in results[0]] == ["zeroargapi.zero"] * 2
    assert all(finding["rule_id"] == RULE_ID_API_SIGNATURE for finding in results[0])
    assert "argument 'timeout'" in results[0][0]["message"]
    assert "argument 'retries'" in results[0][1]["message"]
    assert captured == ([] if pre_cached else ["zeroargapi"])
    shared = cached_api_symbol_surface(
        tmp_path,
        SURFACE_KIND_PYTHON_MODULE,
        "zeroargapi",
        environment_key=python_api_surface.python_environment_key(),
    )
    assert shared == expected_shared


def test_bad_zero_argument_keyword_survives_analyzer_json(tmp_path, monkeypatch):
    from skylos.analyzer import analyze
    from skylos.rules.ai_defect import dependency_hallucination as dependency
    from skylos.rules.ai_defect import manifest_dependency_hallucination as manifest

    source = _write(
        tmp_path / "app.py", "import requests\nrequests.session(timeout=30)\n"
    )
    surface = _surface()
    requests_surface = {
        "module": "requests",
        "members": {"session": surface["members"]["zero"]},
    }
    monkeypatch.setattr(
        python_api_surface, "build_python_api_surface", lambda _: requests_surface
    )
    # Keep unrelated registry scans offline; the signature rule runs normally.
    monkeypatch.setattr(
        dependency, "scan_python_dependency_hallucinations", lambda *a, **k: []
    )
    monkeypatch.setattr(
        manifest, "scan_manifest_dependency_hallucinations", lambda *a, **k: []
    )
    monkeypatch.setenv("SKYLOS_JOBS", "1")

    result = json.loads(
        analyze(str(tmp_path), enable_ai_defects=True, grep_verify=False)
    )
    findings = [
        finding
        for finding in result.get("ai_defects", [])
        if finding["rule_id"] == RULE_ID_API_SIGNATURE
    ]
    assert len(findings) == 1
    assert findings[0]["symbol"] == "requests.session"
    assert findings[0]["file"] == str(source)
    assert findings[0]["line"] == 2
    assert "argument 'timeout'" in findings[0]["message"]
