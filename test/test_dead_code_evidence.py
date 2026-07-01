import json
import sqlite3

from skylos.analyzer import analyze
from skylos.deadcode.collect import collect_dead_code_findings
from skylos.deadcode.evidence import (
    CandidateClassification,
    EvidenceEvent,
    EvidenceKind,
    EvidenceLedger,
    SymbolKey,
)


def _entries_by_name(result):
    return {
        entry["qualified_name"]: entry
        for entry in result["dead_code_evidence"]["symbols"]
    }


def _event_kinds(entry):
    return {event["kind"] for event in entry["evidence"]}


def _event_roles(entry):
    return {event["role"] for event in entry["evidence"]}


def _unused_full_names(result, bucket):
    return {
        item.get("full_name") or item.get("name")
        for item in result.get(bucket, [])
    }


def test_evidence_ledger_uses_paper_classification_precedence():
    symbol = SymbolKey(
        file="app.py",
        qualified_name="app.unused",
        kind="function",
        line=1,
    )
    ledger = EvidenceLedger()

    assert ledger.classify(symbol) == CandidateClassification.LIKELY_DEAD

    ledger.add(
        symbol,
        EvidenceEvent(
            kind=EvidenceKind.UNCERTAINTY,
            reason="weak helper shape",
            source="test",
        ),
    )
    assert ledger.classify(symbol) == CandidateClassification.UNCERTAIN

    ledger.add(
        symbol,
        EvidenceEvent(
            kind=EvidenceKind.STATIC_REFERENCE,
            reason="referenced by another symbol",
            source="test",
        ),
    )
    assert ledger.classify(symbol) == CandidateClassification.ALIVE

    ledger.add(
        symbol,
        EvidenceEvent(
            kind=EvidenceKind.VALIDATION_FAIL,
            reason="validator found a real use",
            source="test",
        ),
    )
    assert ledger.classify(symbol) == CandidateClassification.ALIVE

    ledger.add(
        symbol,
        EvidenceEvent(
            kind=EvidenceKind.VALIDATION_PASS,
            reason="validator confirmed no use",
            source="test",
        ),
    )
    assert ledger.classify(symbol) == CandidateClassification.VALIDATED_DEAD


def test_analyzer_outputs_dead_code_evidence_without_changing_findings(tmp_path):
    module = tmp_path / "app.py"
    module.write_text(
        "\n".join(
            [
                "def used():",
                "    return 1",
                "",
                "def unused():",
                "    return 2",
                "",
                "value = used()",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )

    unused_names = {item["name"] for item in result["unused_functions"]}
    assert "unused" in unused_names
    assert "used" not in unused_names

    by_name = _entries_by_name(result)

    assert by_name["app.used"]["classification"] == "alive"
    assert _event_kinds(by_name["app.used"]) >= {"top_level_execution"}
    assert "reachable_from_root" not in _event_kinds(by_name["app.used"])
    assert "supports_dead" not in _event_roles(by_name["app.used"])

    assert by_name["app.unused"]["classification"] == "likely_dead"
    assert _event_kinds(by_name["app.unused"]) >= {
        "no_static_references",
        "not_exported",
        "no_entrypoint",
    }
    assert _event_roles(by_name["app.unused"]) >= {"supports_dead"}
    assert by_name["app.unused"]["decision"]["reason_tags"][:3] == [
        "no_refs",
        "not_exported",
        "no_entrypoint",
    ]

    unused_finding = next(
        item for item in result["unused_functions"] if item["name"] == "unused"
    )
    assert unused_finding["dead_code_classification"] == "likely_dead"
    assert unused_finding["dead_code_reason_tags"][:3] == [
        "no_refs",
        "not_exported",
        "no_entrypoint",
    ]
    assert unused_finding["dead_code_reason"].startswith("No static references")
    assert {event["role"] for event in unused_finding["dead_code_evidence"]} >= {
        "supports_dead"
    }

    collected = collect_dead_code_findings(result)
    collected_unused = next(item for item in collected if item["name"] == "unused")
    assert collected_unused["dead_code_classification"] == "likely_dead"
    assert collected_unused["dead_code_reason_tags"][:3] == [
        "no_refs",
        "not_exported",
        "no_entrypoint",
    ]


def test_uncertain_dead_code_decision_leads_with_uncertainty(tmp_path):
    module = tmp_path / "app.py"
    module.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        "\n".join(
            [
                "def format_admin_status():",
                "    return 'ok'",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )

    finding = next(
        item
        for item in result["unused_functions"]
        if item["name"] == "format_admin_status"
    )
    assert finding["dead_code_classification"] == "uncertain"
    assert finding["dead_code_reason_tags"][0] == "uncertainty"
    assert finding["dead_code_reason"].startswith("Uncertainty evidence present")


def test_pyproject_entrypoint_is_reported_as_package_evidence(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "demo"',
                'version = "0.1.0"',
                "",
                "[project.scripts]",
                'demo = "app:main"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "def main():",
                "    return 0",
                "",
                "def unused():",
                "    return 1",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )
    by_name = _entries_by_name(result)

    assert by_name["app.main"]["classification"] == "alive"
    assert _event_kinds(by_name["app.main"]) >= {"package_entrypoint"}


def test_dynamic_pattern_evidence_is_reported_from_analyzer(tmp_path):
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "class Box:",
                "    pass",
                "",
                "def handle_login():",
                "    return 1",
                "",
                "def configure(name):",
                "    attr = f'handle_{name}'",
                "    return getattr(Box(), attr, None)",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )
    by_name = _entries_by_name(result)

    assert by_name["app.handle_login"]["classification"] == "alive"
    assert _event_kinds(by_name["app.handle_login"]) >= {"dynamic_pattern"}
    assert "reachable_from_root" not in _event_kinds(by_name["app.handle_login"])


def test_gunicorn_config_settings_and_hooks_are_not_reported_dead(tmp_path):
    gunicorn_project = tmp_path / "gunicorn_project"
    ordinary_project = tmp_path / "ordinary_project"
    gunicorn_project.mkdir()
    ordinary_project.mkdir()

    (gunicorn_project / "gunicorn_config.py").write_text(
        "\n".join(
            [
                'bind = "0.0.0.0:80"',
                'forwarded_allow_ips = "*"',
                "workers = 4",
                "preload_app = True",
                "control_socket_disable = True",
                "",
                "def worker_exit(server, worker):",
                "    server.log.info('worker %s exiting', worker.pid)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (ordinary_project / "ordinary.py").write_text(
        "\n".join(
            [
                'bind = "127.0.0.1:8000"',
                "",
                "def worker_exit(server, worker):",
                "    return server, worker",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(gunicorn_project), conf=60, grep_verify=False, trace_file=False)
    )

    unused_functions = _unused_full_names(result, "unused_functions")
    unused_variables = _unused_full_names(result, "unused_variables")

    assert "gunicorn_config.worker_exit" not in unused_functions
    assert "gunicorn_config.bind" not in unused_variables
    assert "gunicorn_config.forwarded_allow_ips" not in unused_variables
    assert "gunicorn_config.workers" not in unused_variables
    assert "gunicorn_config.preload_app" not in unused_variables
    assert "gunicorn_config.control_socket_disable" not in unused_variables

    by_name = _entries_by_name(result)
    gunicorn_bind = by_name["gunicorn_config.bind"]
    assert gunicorn_bind["classification"] == "uncertain"
    assert any(
        event["reason"] == "Gunicorn config setting"
        for event in gunicorn_bind["evidence"]
    )

    ordinary_result = json.loads(
        analyze(str(ordinary_project), conf=60, grep_verify=False, trace_file=False)
    )
    assert "ordinary.worker_exit" in _unused_full_names(
        ordinary_result,
        "unused_functions",
    )
    assert "ordinary.bind" in _unused_full_names(ordinary_result, "unused_variables")


def test_django_urlconf_error_handler_aliases_are_not_reported_dead(tmp_path):
    django_project = tmp_path / "django_project"
    plain_project = tmp_path / "plain_project"
    django_project.mkdir()
    plain_project.mkdir()

    (django_project / "urls.py").write_text(
        "\n".join(
            [
                "from django.http import HttpResponseBadRequest, HttpResponseNotFound",
                "",
                "def _bad_request(request, exception):",
                '    return HttpResponseBadRequest("Bad request")',
                "",
                "def _not_found(request, exception):",
                '    return HttpResponseNotFound("Not found")',
                "",
                "handler400 = _bad_request",
                "handler404 = _not_found",
                "urlpatterns = []",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (plain_project / "plain.py").write_text(
        "\n".join(
            [
                "def fallback():",
                "    return 404",
                "",
                "handler404 = fallback",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(django_project), conf=60, grep_verify=False, trace_file=False)
    )

    unused_variables = _unused_full_names(result, "unused_variables")

    assert "urls.handler400" not in unused_variables
    assert "urls.handler404" not in unused_variables

    by_name = _entries_by_name(result)
    handler = by_name["urls.handler404"]
    assert handler["classification"] == "uncertain"
    assert any(
        event["reason"] == "Django URLconf error handler"
        for event in handler["evidence"]
    )

    plain_result = json.loads(
        analyze(str(plain_project), conf=60, grep_verify=False, trace_file=False)
    )
    assert "plain.handler404" in _unused_full_names(
        plain_result,
        "unused_variables",
    )


def test_django_registered_path_converter_protocol_is_not_reported_dead(tmp_path):
    django_project = tmp_path / "django_project"
    ordinary_project = tmp_path / "ordinary_project"
    wrapped_project = tmp_path / "wrapped_project"
    django_project.mkdir()
    ordinary_project.mkdir()
    wrapped_project.mkdir()

    (django_project / "converters.py").write_text(
        "\n".join(
            [
                "class FourDigitYearConverter:",
                '    regex = "[0-9]{4}"',
                "",
                "    def to_python(self, value):",
                "        return int(value)",
                "",
                "    def to_url(self, value):",
                '        return "%04d" % value',
                "",
            ]
        ),
        encoding="utf-8",
    )
    (django_project / "urls.py").write_text(
        "\n".join(
            [
                "import converters",
                "from django.urls import path, register_converter",
                "",
                'register_converter(converters.FourDigitYearConverter, "yyyy")',
                "urlpatterns = []",
                "",
            ]
        ),
        encoding="utf-8",
    )

    (ordinary_project / "converters.py").write_text(
        "\n".join(
            [
                "class FourDigitYearConverter:",
                '    regex = "[0-9]{4}"',
                "",
                "    def to_python(self, value):",
                "        return int(value)",
                "",
                "    def to_url(self, value):",
                '        return "%04d" % value',
                "",
                "converter = FourDigitYearConverter()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (wrapped_project / "converters.py").write_text(
        "\n".join(
            [
                "class FourDigitYearConverter:",
                '    regex = "[0-9]{4}"',
                "",
                "    def to_python(self, value):",
                "        return int(value)",
                "",
                "    def to_url(self, value):",
                '        return "%04d" % value',
                "",
                "converter = FourDigitYearConverter()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (wrapped_project / "urls.py").write_text(
        "\n".join(
            [
                "import converters",
                "from django.urls import register_converter",
                "",
                "def configure_converters():",
                '    register_converter(converters.FourDigitYearConverter, "yyyy")',
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(django_project), conf=60, grep_verify=False, trace_file=False)
    )
    unused_functions = _unused_full_names(result, "unused_functions")
    unused_variables = _unused_full_names(result, "unused_variables")

    assert "converters.FourDigitYearConverter.to_python" not in unused_functions
    assert "converters.FourDigitYearConverter.to_url" not in unused_functions
    assert "converters.FourDigitYearConverter.regex" not in unused_variables

    by_name = _entries_by_name(result)
    regex = by_name["converters.FourDigitYearConverter.regex"]
    assert regex["classification"] == "uncertain"
    assert any(
        event["reason"] == "Django path converter regex"
        for event in regex["evidence"]
    )

    ordinary_result = json.loads(
        analyze(str(ordinary_project), conf=60, grep_verify=False, trace_file=False)
    )
    assert "converters.FourDigitYearConverter.to_python" in _unused_full_names(
        ordinary_result,
        "unused_functions",
    )
    assert "converters.FourDigitYearConverter.to_url" in _unused_full_names(
        ordinary_result,
        "unused_functions",
    )
    assert "converters.FourDigitYearConverter.regex" in _unused_full_names(
        ordinary_result,
        "unused_variables",
    )

    wrapped_result = json.loads(
        analyze(str(wrapped_project), conf=60, grep_verify=False, trace_file=False)
    )
    assert "converters.FourDigitYearConverter.to_python" in _unused_full_names(
        wrapped_result,
        "unused_functions",
    )
    assert "converters.FourDigitYearConverter.to_url" in _unused_full_names(
        wrapped_result,
        "unused_functions",
    )
    assert "converters.FourDigitYearConverter.regex" in _unused_full_names(
        wrapped_result,
        "unused_variables",
    )


def test_trace_and_coverage_evidence_are_reported_from_analyzer(tmp_path):
    module = tmp_path / "app.py"
    module.write_text(
        "def traced():\n    return 1\n\ndef covered():\n    return 2\n",
        encoding="utf-8",
    )
    (tmp_path / ".skylos_trace").write_text(
        json.dumps(
            {
                "version": 1,
                "calls": [
                    {
                        "file": str(module),
                        "function": "traced",
                        "line": 1,
                        "count": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    conn = sqlite3.connect(tmp_path / ".coverage")
    cur = conn.cursor()
    cur.execute("CREATE TABLE file (id INTEGER PRIMARY KEY, path TEXT)")
    cur.execute("CREATE TABLE line_bits (file_id INTEGER, numbits BLOB)")
    cur.execute("INSERT INTO file VALUES (1, ?)", (str(module),))
    cur.execute("INSERT INTO line_bits VALUES (1, ?)", (bytes([16]),))
    conn.commit()
    conn.close()

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    by_name = _entries_by_name(result)

    assert _event_kinds(by_name["app.traced"]) >= {"trace_hit"}
    assert _event_kinds(by_name["app.covered"]) >= {"coverage_hit"}


def test_framework_and_test_roots_are_reported_as_roots(tmp_path):
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "from flask import Flask",
                "app = Flask(__name__)",
                "",
                "@app.route('/')",
                "def home():",
                "    return 'ok'",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "conftest.py").write_text(
        "\n".join(
            [
                "import pytest",
                "",
                "@pytest.fixture",
                "def client():",
                "    return object()",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )
    by_name = _entries_by_name(result)

    assert by_name["app.home"]["classification"] == "alive"
    assert _event_kinds(by_name["app.home"]) >= {"framework_root"}
    assert by_name["conftest.client"]["classification"] == "alive"
    assert _event_kinds(by_name["conftest.client"]) >= {"test_entrypoint"}


def test_reference_safe_policy_marks_weak_dead_candidates_uncertain(tmp_path):
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "def format_name(value):",
                "    return value.strip()",
                "",
                "class Widget:",
                "    def __init__(self):",
                "        self.ready = True",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )
    by_name = _entries_by_name(result)

    assert by_name["app.format_name"]["classification"] == "uncertain"
    assert _event_kinds(by_name["app.format_name"]) >= {"uncertainty"}
    assert by_name["app.Widget.__init__"]["classification"] == "uncertain"
    assert _event_kinds(by_name["app.Widget.__init__"]) >= {"uncertainty"}
