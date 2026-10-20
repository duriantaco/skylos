"""Budget, source-file and optional-explanation failure boundaries."""

import copy
import hashlib
import json

import pytest

from skylos.security import static_trace
from skylos.security.static_trace import TraceLimits, attach_security_traces
from test.fixture_paths import write_fixture


def finding(tmp_path, name="sink.py", *, rule="SKY-D324", line=2):
    return {
        "rule_id": rule,
        "file": str(tmp_path / name),
        "line": line,
        "severity": "HIGH",
        "message": "PRIVATE_EXISTING_EVIDENCE",
        "metadata": {"security_evidence": {"preserve": "PRIVATE_EXISTING_EVIDENCE"}},
    }


def attach(tmp_path, row, paths, **options):
    original = copy.deepcopy(row)
    attach_security_traces([row], project_root=tmp_path, files=paths, **options)
    trace = row["metadata"].pop("security_trace")
    assert row == original
    assert "PRIVATE_EXISTING_EVIDENCE" not in json.dumps(trace)
    assert any(step["kind"] == "sink" for step in trace["steps"])
    return trace


def test_crlf_digest_uses_original_bytes_for_source_viewing(tmp_path):
    source = b"value = input()\r\nopen(value, 'w')\r\n"
    path = write_fixture(tmp_path, "sink.py", source)
    trace = attach(tmp_path, finding(tmp_path), [path])
    assert trace["file_digests"]["sink.py"] == hashlib.sha256(source).hexdigest()


@pytest.mark.parametrize(
    "name,source",
    [
        ("workflow.yml", "name: CI\non: push\n"),
        ("source.ts", "open(input())\n"),
        ("broken.py", "not python at all !\n"),
    ],
)
def test_unsupported_sources_keep_factual_hash_and_location(tmp_path, name, source):
    path = write_fixture(tmp_path, name, source)
    trace = attach(tmp_path, finding(tmp_path, name, rule="SKY-D291", line=1), [path])
    assert trace["status"] == "unknown"
    assert len(trace["steps"]) == 1
    assert trace["steps"][0]["file"] == name
    assert trace["steps"][0]["line"] == 1
    assert trace["file_digests"][name] == hashlib.sha256(source.encode()).hexdigest()


def test_text_rule_does_not_invent_a_neighboring_python_sink(tmp_path):
    path = write_fixture(tmp_path, "sink.py", "value = input()\nopen(value, 'w')\n")
    trace = attach(tmp_path, finding(tmp_path, rule="SKY-D260"), [path])
    assert trace["status"] == "unknown"
    assert len(trace["steps"]) == 1
    assert trace["file_digests"]["sink.py"]


def test_multiple_calls_on_one_line_require_exact_column(tmp_path):
    path = write_fixture(
        tmp_path, "sink.py", "value = input()\nopen('safe'); open(value)\n"
    )
    trace = attach(tmp_path, finding(tmp_path), [path])
    assert trace["status"] == "unknown"
    exact = finding(tmp_path)
    exact["col"] = 14
    trace = attach(tmp_path, exact, [path])
    assert any(step["kind"] == "source" for step in trace["steps"])


def test_finding_source_is_prioritized_ahead_of_unrelated_file_budget(tmp_path):
    early = write_fixture(tmp_path, "aaa.py", "irrelevant = 1\n")
    sink = write_fixture(tmp_path, "zzz.py", "value = input()\nopen(value, 'w')\n")
    trace = attach(
        tmp_path,
        finding(tmp_path, "zzz.py"),
        [early, sink],
        limits=TraceLimits(max_files=1),
    )
    assert trace["file_digests"]["zzz.py"]
    assert any(step["kind"] == "source" for step in trace["steps"])
    assert trace["status"] == "partial"
    assert any("file-count budget" in message for message in trace["limitations"])


@pytest.mark.parametrize(
    "limits,fragment",
    [
        (TraceLimits(max_file_bytes=4), "Source unavailable"),
        (TraceLimits(max_total_bytes=4), "byte budget"),
        (TraceLimits(max_ast_nodes=2), "AST work budget"),
        (TraceLimits(max_steps=1), "step budget"),
        (TraceLimits(max_depth=1), "depth budget"),
    ],
)
def test_deterministic_limits_preserve_original_warning(tmp_path, limits, fragment):
    path = write_fixture(tmp_path, "sink.py", "value = input()\nopen(value, 'w')\n")
    trace = attach(tmp_path, finding(tmp_path), [path], limits=limits)
    assert trace["status"] in {"partial", "unknown"}
    assert any(fragment in message for message in trace["limitations"])


def test_caller_budget_is_explicit(tmp_path):
    path = write_fixture(
        tmp_path,
        "sink.py",
        "def save(path):\n    open(path, 'w')\nsave(input())\nsave('safe')\n",
    )
    trace = attach(
        tmp_path, finding(tmp_path), [path], limits=TraceLimits(max_callers=1)
    )
    assert trace["status"] == "partial"
    assert any("Caller branch budget" in message for message in trace["limitations"])


def test_excluded_source_is_not_read_or_followed(tmp_path):
    path = write_fixture(tmp_path, "sink.py", "def save(path):\n    open(path, 'w')\n")
    write_fixture(tmp_path, "excluded.py", "from sink import save\nsave(input())\n")
    trace = attach(tmp_path, finding(tmp_path), [path])
    assert not any(step["kind"] == "source" for step in trace["steps"])
    assert "excluded.py" not in trace["file_digests"]


@pytest.mark.parametrize("parent", [False, True])
def test_symlinked_source_components_are_not_read(tmp_path, parent):
    outside = tmp_path / "outside"
    write_fixture(tmp_path, "outside/real.py", "value = input()\nopen(value, 'w')\n")
    name = "sink.py"
    if parent:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
        name = "linked/real.py"
    else:
        (tmp_path / name).symlink_to(outside / "real.py")
    trace = attach(tmp_path, finding(tmp_path, name), [tmp_path / name])
    assert trace["status"] == "unknown"
    assert not trace["file_digests"]


def test_optional_index_failure_records_class_only_and_retains_finding(
    tmp_path, monkeypatch
):
    path = write_fixture(tmp_path, "sink.py", "value = input()\nopen(value, 'w')\n")

    def broken(*args, **kwargs):
        raise OSError("PRIVATE_EXCEPTION_DATA")

    monkeypatch.setattr(static_trace, "build_index", broken)
    trace = attach(tmp_path, finding(tmp_path), [path])
    assert trace["status"] == "unknown"
    assert trace["error"] == "OSError"
    assert "PRIVATE_EXCEPTION_DATA" not in json.dumps(trace)


def test_per_finding_failure_does_not_drop_other_explanations(tmp_path, monkeypatch):
    path = write_fixture(tmp_path, "sink.py", "value = input()\nopen(value, 'w')\n")
    original = static_trace.trace_finding

    def one_broken(row, index):
        if row["rule_id"] == "SKY-D324":
            raise RuntimeError("PRIVATE_EXCEPTION_DATA")
        return original(row, index)

    monkeypatch.setattr(static_trace, "trace_finding", one_broken)
    first = finding(tmp_path)
    second = finding(tmp_path, rule="SKY-D215")
    attach_security_traces([first, second], project_root=tmp_path, files=[path])
    assert first["metadata"]["security_trace"]["error"] == "RuntimeError"
    assert first["metadata"]["security_trace"]["status"] == "unknown"
    assert second["metadata"]["security_trace"]["status"] == "source_to_sink"
    assert "error" not in second["metadata"]["security_trace"]


def test_interrupt_is_not_swallowed_by_optional_explanation(tmp_path, monkeypatch):
    path = write_fixture(tmp_path, "sink.py", "value = input()\nopen(value, 'w')\n")

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(static_trace, "build_index", interrupt)
    with pytest.raises(KeyboardInterrupt):
        attach_security_traces([finding(tmp_path)], project_root=tmp_path, files=[path])


def test_algorithm_parser_scope_and_limits_are_auditable(tmp_path):
    path = write_fixture(tmp_path, "sink.py", "value = input()\nopen(value, 'w')\n")
    trace = attach(
        tmp_path, finding(tmp_path), [path], limits=TraceLimits(max_steps=12)
    )
    context = trace["context"]
    assert context["algorithm"] == "security-static-trace-v1"
    assert context["analyzer_version"]
    assert context["python_syntax_version"]
    assert context["receiver_model_version"] == 2
    assert context["limits"]["max_steps"] == 12
    assert context["selected_file_count"] == 1
    assert len(context["selected_scope_sha256"]) == 64


def test_default_discovery_is_bounded_and_still_prioritizes_finding(tmp_path):
    write_fixture(tmp_path, "aaa.py", "unused = 1\n")
    sink = write_fixture(tmp_path, "zzz.py", "value = input()\nopen(value, 'w')\n")
    row = finding(tmp_path, "zzz.py")
    attach_security_traces(
        [row], project_root=tmp_path, limits=TraceLimits(max_discovery_entries=1)
    )
    trace = row["metadata"]["security_trace"]
    assert (
        trace["file_digests"]["zzz.py"] == hashlib.sha256(sink.read_bytes()).hexdigest()
    )
    assert trace["status"] == "partial"
    assert any("discovery work budget" in message for message in trace["limitations"])


def test_relocated_equal_snapshots_have_equal_proofs(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    source = "value = input()\nopen(value, 'w')\n"
    first_path = write_fixture(tmp_path, "first/sink.py", source)
    second_path = write_fixture(tmp_path, "second/sink.py", source)
    left = attach(first, finding(first), [first_path])
    right = attach(second, finding(second), [second_path])
    assert left == right


def test_file_path_alias_and_rule_message_never_leak_original_payload(tmp_path):
    source = "value = input()\nopen(value, 'w')\n"
    path = write_fixture(tmp_path, "sink.py", source)
    row = finding(tmp_path)
    row["file_path"] = row.pop("file")
    trace = attach(tmp_path, row, [path])
    assert trace["file_digests"]["sink.py"]
    assert trace["status"] == "source_to_sink"


def test_no_findings_do_not_build_or_read_a_project_index(tmp_path, monkeypatch):
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(args)
        raise AssertionError("an empty report has no trace work")

    monkeypatch.setattr(static_trace, "build_index", unexpected)
    attach_security_traces([], project_root=tmp_path)
    assert calls == []
