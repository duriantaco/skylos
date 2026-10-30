import ast

import skylos.core.review_decisions as review_decisions
from skylos.config import DEFAULTS
from skylos.core.review_context import build_analysis_review_context
from skylos.core.review_decisions import annotate_result_identities

IDENTITY_FIELDS = (
    "fingerprint_version",
    "stable_fingerprint",
    "context_hash",
    "rule_revision",
    "rule_id",
    "file_path",
)


def _review_context(path):
    return build_analysis_review_context(
        path.parent,
        path,
        config=DEFAULTS,
        threshold=60,
        exclude_folders=(),
        requested_changed_files=None,
        effective_changed_files=None,
        enable_secrets=False,
        enable_danger=True,
        enable_quality=False,
        enable_ai_defects=False,
        enable_sca=False,
        enable_dependency_hallucinations=True,
        grep_verify=True,
        trace_file=None,
        required_config_rules=None,
        dependency_bump_diff_base=None,
        custom_rules_data=None,
        extra_visitors=None,
        analysis_scope={"kind": "file", "complete_repository": False},
        environ={},
    )


def _result(path, lines):
    return {
        "danger": [
            {
                "rule_id": "SKY-D215",
                "file": str(path),
                "line": line,
                "symbol": f"write_report_{line}",
                "severity": "HIGH",
                "message": f"unsafe call on line {line}",
            }
            for line in lines
        ],
        "analysis_summary": {
            "danger_count": len(lines),
            "review_context": _review_context(path),
        },
    }


def _many_sinks(tmp_path, prelude=""):
    source = tmp_path / "app.py"
    validator = tmp_path / "validator.py"
    body = [prelude + "from validator import safe_path\n"]
    for index in range(6):
        body.append(
            f"def write_report_{index}():\n"
            f"    open(safe_path(input())).write('unsafe {index}')\n"
        )
    source.write_text("".join(body))
    validator.write_text("def safe_path(value):\n    return '/tmp/report'\n")
    lines = [
        number
        for number, text in enumerate(source.read_text().splitlines(), start=1)
        if "open(" in text
    ]
    return source, lines


def _identity(finding):
    return {field: finding.get(field) for field in IDENTITY_FIELDS}


def test_shared_cache_identities_match_one_finding_at_a_time(tmp_path):
    source, lines = _many_sinks(tmp_path)

    together = annotate_result_identities(_result(source, lines), tmp_path)["danger"]
    alone = [
        annotate_result_identities(_result(source, [line]), tmp_path)["danger"][0]
        for line in lines
    ]

    assert len(together) == 6
    assert all(finding.get("stable_fingerprint") for finding in together)
    assert [_identity(finding) for finding in together] == [
        _identity(finding) for finding in alone
    ]


def test_high_risk_repository_snapshot_reads_each_input_once(tmp_path, monkeypatch):
    source, lines = _many_sinks(tmp_path)
    caller = tmp_path / "caller.py"
    caller.write_text("from app import write_report_0\nwrite_report_0()\n")
    reads = []
    real_read = review_decisions.read_project_text_no_symlink

    def counted_read(project_root, path, **kwargs):
        reads.append(str(path))
        return real_read(project_root, path, **kwargs)

    monkeypatch.setattr(review_decisions, "read_project_text_no_symlink", counted_read)
    annotated = annotate_result_identities(_result(source, lines), tmp_path)["danger"]

    assert len(annotated) == 6
    assert all(finding.get("context_hash") for finding in annotated)
    for relative in ("app.py", "caller.py", "validator.py"):
        assert reads.count(relative) == 1


def test_finding_file_parses_do_not_grow_with_its_finding_count(tmp_path, monkeypatch):
    source, lines = _many_sinks(tmp_path)
    app_source = source.read_text()
    parses = []
    real_parse = ast.parse

    def counting_parse(text, *args, **kwargs):
        if text == app_source:
            parses.append(1)
        return real_parse(text, *args, **kwargs)

    monkeypatch.setattr(review_decisions.ast, "parse", counting_parse)

    annotate_result_identities(_result(source, lines[:1]), tmp_path)
    one_finding = len(parses)
    parses.clear()
    annotated = annotate_result_identities(_result(source, lines), tmp_path)["danger"]

    assert all(finding.get("stable_fingerprint") for finding in annotated)
    assert len(parses) == one_finding == 3


def test_runtime_loader_file_still_gets_no_identity_for_every_finding(tmp_path):
    source, lines = _many_sinks(
        tmp_path, prelude="import importlib\nloader = importlib\n"
    )

    annotated = annotate_result_identities(_result(source, lines), tmp_path)["danger"]

    assert len(annotated) == 6
    assert not any(finding.get("stable_fingerprint") for finding in annotated)


def test_changed_source_under_the_same_path_is_checked_again():
    cache = {}
    static = "import os\n"
    runtime_loader = "import importlib\nloader = importlib\n"

    assert (
        review_decisions._python_primary_loader_is_static("app.py", static, cache)
        is True
    )
    assert (
        review_decisions._python_primary_loader_is_static(
            "app.py", runtime_loader, cache
        )
        is False
    )
    assert (
        review_decisions._python_primary_loader_is_static("app.py", static, cache)
        is True
    )
    assert (
        review_decisions._python_primary_loader_is_static("app.py", "def (:\n", cache)
        is False
    )
