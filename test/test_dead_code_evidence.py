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

    assert by_name["app.unused"]["classification"] == "likely_dead"
    assert by_name["app.unused"]["evidence"] == []

    unused_finding = next(
        item for item in result["unused_functions"] if item["name"] == "unused"
    )
    assert unused_finding["dead_code_classification"] == "likely_dead"
    assert unused_finding["dead_code_evidence"] == []

    collected = collect_dead_code_findings(result)
    collected_unused = next(item for item in collected if item["name"] == "unused")
    assert collected_unused["dead_code_classification"] == "likely_dead"


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
