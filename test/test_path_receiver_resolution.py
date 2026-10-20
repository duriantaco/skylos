"""Do not confuse source-proven rendering methods with filesystem methods."""

import ast
import textwrap

import pytest

from test.fixture_paths import write_fixture
from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.security.receiver_resolution import ReceiverResolver


def _findings(tmp_path, source):
    source = textwrap.dedent(source)
    write_fixture(tmp_path, "receiver.py", source)
    findings = []
    scan(ast.parse(source), tmp_path / "receiver.py", findings)
    return findings


def test_source_proven_in_memory_write_text_is_not_a_symlink_sink(tmp_path):
    findings = _findings(
        tmp_path,
        """
        class Formatter:
            def __init__(self): self.buffer = []
            def write_text(self, text): self.buffer.append(text)
        formatter = Formatter()
        def render(text): formatter.write_text(text)
    """,
    )
    assert not findings


@pytest.mark.parametrize(
    "method, rule",
    [
        ("write_text", "SKY-D324"),
        ("write_bytes", "SKY-D324"),
        ("read_text", "SKY-D325"),
        ("read_bytes", "SKY-D325"),
    ],
)
def test_real_path_receiver_and_untrusted_path_are_retained(tmp_path, method, rule):
    args = ", text" if method.startswith("write") else ""
    values = "text" if method.startswith("write") else ""
    findings = _findings(
        tmp_path,
        f"""
        from pathlib import Path as File
        def run(user_path{args}):
            return File(user_path).{method}({values})
    """,
    )
    row = next(row for row in findings if row["rule_id"] == rule)
    assert row["metadata"]["receiver_resolution"]["receiver_is_path"] is True
    assert row["metadata"]["path_source"] == "helper_parameter"


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "class Formatter:\n    def write_text(self, text): return text\n",
    ],
)
def test_unknown_or_annotation_only_receiver_keeps_its_warning(tmp_path, prefix):
    annotation = ": Formatter" if prefix else ""
    findings = _findings(
        tmp_path,
        prefix
        + f"def render(formatter{annotation}, text):\n    formatter.write_text(text)\n",
    )
    row = next(row for row in findings if row["rule_id"] == "SKY-D324")
    assert row["metadata"]["receiver_resolution"]["status"] == "unknown"


def test_proven_wrapper_checks_the_path_argument_not_controller_taint(tmp_path):
    findings = _findings(
        tmp_path,
        """
        class Reader:
            def open(self, file, mode='r'): return open(file, mode)
        controller = Reader()
        def read(user_path): return controller.open(user_path)
    """,
    )
    wrapper = next(
        row
        for row in findings
        if row["rule_id"] == "SKY-D325" and row["symbol"] == "read"
    )
    proof = wrapper["metadata"]["receiver_resolution"]
    assert proof["effects"]["filesystem"] == "wrapped_path_argument"
    assert proof["path_argument_index"] == 0


def test_wrapper_with_static_file_does_not_treat_other_argument_as_path(tmp_path):
    findings = _findings(
        tmp_path,
        """
        class Reader:
            def open(self, file, label): return open(file, 'r')
        controller = Reader()
        def read(user_label): return controller.open('fixed.txt', user_label)
    """,
    )
    assert not any(
        row["rule_id"] == "SKY-D325" and row["symbol"] == "read" for row in findings
    )
    # The generic wrapper body remains an unresolved helper boundary.
    assert any(
        row["rule_id"] == "SKY-D325" and row["symbol"] == "open" for row in findings
    )


def test_nested_real_path_sink_survives_safe_outer_method(tmp_path):
    findings = _findings(
        tmp_path,
        """
        from pathlib import Path
        class Formatter:
            def write_text(self, text): return text
        formatter = Formatter()
        def run(user_path): formatter.write_text(Path(user_path).read_text())
    """,
    )
    assert any(row["rule_id"] == "SKY-D325" for row in findings)


def test_receiver_proof_failure_retains_existing_warning(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError("unavailable")

    monkeypatch.setattr(ReceiverResolver, "resolve_call", unavailable)
    findings = _findings(tmp_path, "def read(path): return path.read_text()\n")
    row = next(row for row in findings if row["rule_id"] == "SKY-D325")
    assert row["metadata"]["receiver_resolution"]["status"] == "unknown"
