import json
from pathlib import Path

import pytest

from skylos.analysis.sql_files import analyze_sql_file
from skylos.analyzer import analyze


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_public_scan_partitions_dialects_and_reports_advisories(tmp_path):
    pytest.importorskip("pglast")
    query = "WITH spare AS (SELECT 1) SELECT 1 WHERE 1 = NULL AND 2 NOT IN (0, NULL);"
    for folder, dialect in [("pg", "postgresql"), ("my", "mysql"), ("ms", "tsql")]:
        write(tmp_path / folder / "skylos.toml", f'[sql]\ndialect = "{dialect}"\n')
        write(tmp_path / folder / "sample.SQL", query)
    write(tmp_path / "other" / "sample.sql", query)
    write(tmp_path / "pg" / "invalid.sql", "SELECT (;")
    write(
        tmp_path / "pg" / "routine.sql",
        """
CREATE FUNCTION count_ones() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';
""",
    )
    report = json.loads(analyze(str(tmp_path), enable_danger=True, enable_quality=True))
    sql = report["analysis_summary"]["sql_analysis"]
    assert sql["checked_files"] == 2
    assert sql["unchecked_files"] == 4
    statuses = {
        Path(r["file"]).relative_to(tmp_path).as_posix(): r["status"]
        for r in sql["files"]
    }
    assert statuses == {
        "pg/sample.SQL": "checked",
        "pg/routine.sql": "checked",
        "pg/invalid.sql": "unparsed",
        "other/sample.sql": "unknown_dialect",
        "ms/sample.SQL": "unsupported_dialect",
        "my/sample.SQL": "unsupported_dialect",
    }
    measured = {
        (r["rule_id"], Path(r["file"]).name)
        for k in ("danger", "quality")
        for r in report.get(k, [])
    }
    assert ("SKY-D417", "routine.sql") in measured
    assert {r for r in measured if r[1] == "sample.SQL"} == {
        ("SKY-Q503", "sample.SQL"),
        ("SKY-Q504", "sample.SQL"),
        ("SKY-Q505", "sample.SQL"),
    }
    from skylos.ui.scope_notes import scope_note_lines

    assert any("1 unknown dialect" in note for note in scope_note_lines(report))


def test_local_prisma_provider_respects_project_boundary_and_conflicts(tmp_path):
    root = tmp_path / "repo"
    lock = write(root / "migrations/migration_lock.toml", 'provider = "mysql"')
    path = write(root / "migrations/v1/migration.sql", "SELECT 1")
    assert analyze_sql_file(path, {}, root)[1]["status"] == "unsupported_dialect"
    assert (
        analyze_sql_file(path, {"sql": {"dialect": "postgresql"}}, root)[1]["status"]
        == "conflicting_dialect"
    )
    assert analyze_sql_file(path, {}, path.parent)[1]["status"] == "unknown_dialect"
    lock.write_text("not valid toml!", encoding="utf-8")
    assert analyze_sql_file(path, {}, root)[1]["status"] == "unknown_dialect"


def test_sql_file_read_does_not_follow_symlinks(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = write(tmp_path / "outside.sql", "SELECT 1")
    path = root / "inside.sql"
    path.symlink_to(outside)
    assert (
        analyze_sql_file(path, {"sql": {"dialect": "postgresql"}}, root)[1]["status"]
        == "unparsed"
    )


def test_sql_gaps_are_visible_without_masking_other_file_failures():
    from skylos.core.gate_incomplete import analysis_coverage

    report = {
        "analysis_summary": {
            "total_files": 2,
            "sql_analysis": {
                "files": [{"file": "legacy.sql", "status": "unknown_dialect"}]
            },
        }
    }
    coverage = analysis_coverage(report)
    assert coverage.status == "partial"
    assert coverage.unchecked_file_count == 1
    assert not coverage.blocking
    assert analysis_coverage(report, strict=True).blocking
    report["analysis_errors"] = [
        {"file": "app.py", "kind": "syntax_error", "message": "Invalid Python"}
    ]
    assert analysis_coverage(report).blocking
