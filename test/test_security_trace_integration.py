"""Actual analyzer integration, without importing any inspected modules."""

import copy
import hashlib
import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from test.fixture_paths import write_fixture


def _project(tmp_path, sources):
    paths = {}
    for name, source in sources.items():
        paths[name] = write_fixture(tmp_path, name, textwrap.dedent(source))
    return paths


def _analyze(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    return json.loads(
        analyze(
            str(tmp_path),
            exclude_folders=[],
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )


def _sql(result):
    return [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D211"]


def _without_trace(rows):
    rows = copy.deepcopy(rows)
    for row in rows:
        metadata = row.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("security_trace", None)
    return rows


def test_analyzer_traces_flask_request_through_two_imported_helpers(
    tmp_path, monkeypatch
):
    from skylos.security import static_trace

    paths = _project(
        tmp_path,
        {
            "api.py": '''\
                raise RuntimeError("the inspected module must never execute")
                from flask import Flask, request
                from service import search
                app = Flask(__name__)
                @app.get("/search")
                def endpoint():
                    return search(request.args["name"])
            ''',
            "service.py": '''\
                raise RuntimeError("the inspected module must never execute")
                from repository import fetch
                def search(term):
                    return fetch(term)
            ''',
            "repository.py": '''\
                raise RuntimeError("the inspected module must never execute")
                import sqlite3
                def fetch(term):
                    connection = sqlite3.connect(":memory:")
                    cursor = connection.cursor()
                    return cursor.execute(f"SELECT name FROM users WHERE name = '{term}'")
            ''',
        },
    )
    original_bytes = {name: path.read_bytes() for name, path in paths.items()}
    with monkeypatch.context() as unchanged:
        unchanged.setattr(static_trace, "attach_security_traces", lambda *a, **kw: None)
        without = _analyze(tmp_path, monkeypatch)
    traced = _analyze(tmp_path, monkeypatch)
    assert not without.get("analysis_errors")
    assert not traced.get("analysis_errors")
    assert len(_sql(without)) == len(_sql(traced)) == 1
    assert _sql(traced)[0]["severity"] == "CRITICAL"
    assert _without_trace(traced["danger"]) == without["danger"]
    config = {"gate": {"max_critical": 0}}
    assert check_gate(traced, config) == check_gate(without, config)

    trace = _sql(traced)[0]["metadata"]["security_trace"]
    assert trace["version"] == 1
    assert trace["status"] in {"source_to_sink", "partial"}
    steps = trace["steps"]
    assert any(step["kind"] == "source" and step["file"] == "api.py" for step in steps)
    assert any(step["kind"] == "call" and step["file"] == "service.py" for step in steps)
    assert any(
        step["kind"] == "sink"
        and step["file"] == "repository.py"
        and step["line"] == 6
        for step in steps
    )
    for step in steps:
        if step.get("file") in original_bytes:
            assert step["source_sha256"] == hashlib.sha256(
                original_bytes[step["file"]]
            ).hexdigest()
    assert {name: path.read_bytes() for name, path in paths.items()} == original_bytes


def test_analyzer_does_not_call_source_proved_formatter_execute_a_sql_sink(
    tmp_path, monkeypatch
):
    _project(
        tmp_path,
        {
            "formatting.py": '''\
                raise RuntimeError("the inspected module must never execute")
                class Formatter:
                    def execute(self, value):
                        return value
                db = Formatter()
                db.execute(input())
            ''',
        },
    )
    result = _analyze(tmp_path, monkeypatch)
    assert not result.get("analysis_errors")
    assert not _sql(result)


@pytest.mark.parametrize(
    "source",
    [
        '''\
            raise RuntimeError("the inspected module must never execute")
            def run(db):
                return db.execute(input())
        ''',
        '''\
            raise RuntimeError("the inspected module must never execute")
            class Formatter:
                def execute(self, value):
                    return value
            db = Formatter()
            db.execute = replacement
            db.execute(input())
        ''',
    ],
)
def test_analyzer_keeps_unknown_or_dynamic_receiver_with_partial_trace(
    tmp_path, monkeypatch, source
):
    _project(tmp_path, {"unknown.py": source})
    result = _analyze(tmp_path, monkeypatch)
    assert not result.get("analysis_errors")
    rows = _sql(result)
    assert len(rows) == 1
    assert rows[0]["severity"] == "CRITICAL"
    metadata = rows[0]["metadata"]
    assert metadata["receiver_resolution"]["status"] in {"unknown", "ambiguous"}
    trace = metadata["security_trace"]
    assert trace["version"] == 1
    assert trace["status"] in {"partial", "unknown"}
    assert trace["limitations"]
    assert any(step["kind"] == "sink" for step in trace["steps"])


def test_optional_trace_index_failure_keeps_original_warning(tmp_path, monkeypatch):
    from skylos.security import static_trace

    _project(
        tmp_path,
        {
            "unknown.py": '''\
                raise RuntimeError("the inspected module must never execute")
                def run(db):
                    return db.execute(input())
            ''',
        },
    )

    def unavailable(*args, **kwargs):
        raise OSError("index unavailable")

    monkeypatch.setattr(static_trace, "build_index", unavailable)
    result = _analyze(tmp_path, monkeypatch)
    rows = _sql(result)
    assert len(rows) == 1
    assert rows[0]["severity"] == "CRITICAL"
    trace = rows[0]["metadata"]["security_trace"]
    assert trace["status"] == "unknown"
    assert trace["limitations"]
