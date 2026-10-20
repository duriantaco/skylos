"""Receiver evidence is source-derived; fixture modules are never imported."""

import ast
import json
import textwrap

import pytest

from test.fixture_paths import write_fixture
from skylos.security.receiver_resolution import ReceiverResolver


def _resolve(tmp_path, source, expression="writer.write_text(text)"):
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    path = tmp_path / "app.py"
    write_fixture(tmp_path, "app.py", source)
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node) == expression
    )
    return ReceiverResolver(tree, path, project_root=tmp_path).resolve_call(call)


def test_concrete_memory_writer_has_source_and_effect_proof(tmp_path):
    proof = _resolve(
        tmp_path,
        """
        class Writer:
            def __init__(self):
                self.buffer = []
            def write_text(self, text):
                self.buffer.append(text)
        writer = Writer()
        writer.write_text(text)
    """,
    )
    assert proof["status"] == "resolved"
    assert proof["qualified_name"] == "app.Writer.write_text"
    assert proof["effects"] == {"filesystem": "none", "database": "none"}
    assert proof["receiver_is_non_path"] is True
    assert proof["bound_method"] is True
    assert proof["line"] == 5
    assert proof["steps"][0]["kind"] == "source_binding"


def test_imported_alias_constructor_resolves_without_importing_target(tmp_path):
    write_fixture(
        tmp_path,
        "helper.py",
        """
raise RuntimeError('THIS MODULE MUST NEVER BE IMPORTED')
class Writer:
    def write_text(self, text):
        return text
""",
    )
    proof = _resolve(
        tmp_path,
        """
        from helper import Writer as Output
        writer = Output()
        writer.write_text(text)
    """,
    )
    assert proof["status"] == "resolved"
    assert proof["qualified_name"] == "helper.Writer.write_text"
    assert proof["kind"] == "imported_method"
    assert proof["file"] == str(tmp_path / "helper.py")


def test_path_import_alias_is_a_real_path_receiver(tmp_path):
    proof = _resolve(
        tmp_path,
        """
        from pathlib import Path as File
        writer = File(user_path)
        writer.write_text(text)
    """,
    )
    assert proof["status"] == "resolved"
    assert proof["receiver_is_path"] is True
    assert proof["effects"]["filesystem"] == "path_receiver"


@pytest.mark.parametrize(
    "source",
    [
        """
    class Writer:
        def write_text(self, text): return text
    def run(writer: Writer, text):
        writer.write_text(text)
    """,
        """
    class Writer:
        def write_text(self, text): return text
    writer = Writer()
    writer = unknown_factory()
    writer.write_text(text)
    """,
        """
    class Writer:
        def write_text(self, text): return text
    if enabled:
        writer = Writer()
    writer.write_text(text)
    """,
        """
    class Writer(UnknownBase):
        def write_text(self, text): return text
    writer = Writer()
    writer.write_text(text)
    """,
        """
    @replace
    class Writer:
        def write_text(self, text): return text
    writer = Writer()
    writer.write_text(text)
    """,
        """
    class Writer:
        def write_text(self, text): return text
    Alias = Writer
    Alias.write_text = replacement
    writer = Writer()
    writer.write_text(text)
    """,
        """
    class Writer:
        def write_text(self, text): return text
    writer = Writer()
    alias = writer
    alias.write_text = replacement
    writer.write_text(text)
    """,
        """
    import builtins
    class Writer:
        def write_text(self, text): return text
    builtins.setattr(Writer, 'write_text', replacement)
    writer = Writer()
    writer.write_text(text)
    """,
        """
    class Writer:
        def write_text(self, text): return text
    configure(Writer)
    writer = Writer()
    writer.write_text(text)
    """,
        """
    class Writer:
        def __init__(self): self.__dict__['write_text'] = replacement
        def write_text(self, text): return text
    writer = Writer()
    writer.write_text(text)
    """,
    ],
)
def test_annotations_rebindings_and_mutation_do_not_prove_receiver(tmp_path, source):
    assert _resolve(tmp_path, source)["status"] in {"unknown", "ambiguous"}


@pytest.mark.parametrize(
    "body",
    [
        "return callback(text)",
        "return handler[text]",
        "return service.result",
        "return other + text",
        "if text: return text",
        "def nested(value=callback(text)): pass",
        "return str(text)",
        "return 'prefix {}'.format(text)",
    ],
)
def test_resolved_method_with_unknown_delegates_is_not_harmless(tmp_path, body):
    proof = _resolve(
        tmp_path,
        f"""
        class Writer:
            def write_text(self, text):
                {body}
        writer = Writer()
        writer.write_text(text)
    """,
    )
    assert proof["effects"]["filesystem"] == "unknown"
    assert proof["effects"]["database"] == "unknown"


def test_field_reassignment_invalidates_primitive_effect_proof(tmp_path):
    proof = _resolve(
        tmp_path,
        """
        class Writer:
            def __init__(self): self.buffer = []
            def configure(self): self.buffer = external
            def write_text(self, text): self.buffer.append(text)
        writer = Writer()
        writer.write_text(text)
    """,
    )
    assert proof["effects"]["filesystem"] == "unknown"


def test_wrapper_reports_the_actual_file_argument_role(tmp_path):
    proof = _resolve(
        tmp_path,
        """
        class Reader:
            def open(self, file, mode='r'):
                return open(file, mode)
        reader = Reader()
        reader.open(user_path)
    """,
        "reader.open(user_path)",
    )
    assert proof["status"] == "resolved"
    assert proof["receiver_is_non_path"] is True
    assert proof["effects"]["filesystem"] == "wrapped_path_argument"
    assert proof["path_argument_index"] == 0
    assert proof["path_argument_name"] == "file"


def test_evidence_never_serializes_source_literal_payloads(tmp_path):
    proof = _resolve(
        tmp_path,
        """
        class Writer:
            def write_text(self, text):
                return 'SENSITIVE_LITERAL_PAYLOAD_MUST_NOT_APPEAR'
        writer = Writer()
        writer.write_text(text)
    """,
    )
    assert "SENSITIVE_LITERAL_PAYLOAD_MUST_NOT_APPEAR" not in json.dumps(proof)


def test_cross_file_symlink_outside_project_is_unknown(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    write_fixture(
        outside.parent,
        outside.name,
        "class Writer:\n    def write_text(self, text): return text\n",
    )
    (tmp_path / "helper.py").symlink_to(outside)
    proof = _resolve(
        tmp_path,
        """
        from helper import Writer
        writer = Writer()
        writer.write_text(text)
    """,
    )
    assert proof["status"] == "unknown"


@pytest.mark.parametrize(
    "expression",
    [
        "sqlite3.connect(':memory:').execute(text)",
        "sqlite3.connect(':memory:').cursor().execute(text)",
    ],
)
def test_stdlib_sqlite_constructor_and_cursor_prove_actual_database(
    tmp_path, expression
):
    proof = _resolve(tmp_path, f"import sqlite3\n{expression}\n", expression)
    assert proof["status"] == "resolved"
    assert proof["kind"] == "database_method"
    assert proof["effects"]["database"] == "sql_receiver"
    assert proof["steps"][-1]["kind"] == "standard_library_contract"


def test_local_sqlite_lookalike_uses_actual_source_instead_of_stdlib_model(tmp_path):
    write_fixture(
        tmp_path,
        "sqlite3.py",
        """
class Connection:
    def execute(self, value): return value
def connect(): return Connection()
""",
    )
    proof = _resolve(
        tmp_path,
        "import sqlite3\nsqlite3.connect().execute(text)\n",
        "sqlite3.connect().execute(text)",
    )
    assert proof["qualified_name"] == "sqlite3.Connection.execute"
    assert proof["kind"] == "imported_method"
    assert proof["effects"]["database"] == "none"


def test_unreadable_local_sqlite_shadow_does_not_fall_back_to_standard_model(tmp_path):
    write_fixture(tmp_path, "sqlite3.py", "not valid Python !!!")
    proof = _resolve(
        tmp_path,
        "import sqlite3\nsqlite3.connect().execute(text)\n",
        "sqlite3.connect().execute(text)",
    )
    assert proof["status"] == "unknown"


def test_provider_read_failure_is_unknown(tmp_path, monkeypatch):
    write_fixture(
        tmp_path,
        "helper.py",
        "class Writer:\n    def write_text(self, text): return text\n",
    )
    monkeypatch.setattr(
        "skylos.security.receiver_resolution.read_project_text_no_symlink",
        lambda *args, **kwargs: None,
    )
    proof = _resolve(
        tmp_path,
        "from helper import Writer\nwriter = Writer()\nwriter.write_text(text)\n",
    )
    assert proof["status"] == "unknown"


@pytest.mark.parametrize(
    "binding",
    [
        "match unknown:\n    case writer: pass",
        "try: pass\nexcept Exception as writer: pass",
        "alias = (writer := unknown)",
        "def replace(value=(writer := unknown)): pass",
    ],
)
def test_non_assignment_binding_forms_do_not_reuse_earlier_constructor(
    tmp_path, binding
):
    source = (
        "class Writer:\n    def write_text(self, text): return text\n"
        "writer = Writer()\n" + binding + "\nwriter.write_text(text)\n"
    )
    assert _resolve(tmp_path, source)["status"] == "unknown"


def test_self_parameter_alone_is_not_a_constructor_proof(tmp_path):
    proof = _resolve(
        tmp_path,
        """
        class Writer:
            def write_text(self, text): return text
            def emit(self, text): self.write_text(text)
    """,
        "self.write_text(text)",
    )
    assert proof["status"] == "unknown"


def test_concrete_bound_receiver_can_summarize_owned_method_delegation(tmp_path):
    proof = _resolve(
        tmp_path,
        """
        class Writer:
            def write_text(self, text): return text
            def emit(self, text): self.write_text(text)
        writer = Writer()
        writer.emit(text)
    """,
        "writer.emit(text)",
    )
    assert proof["status"] == "resolved"
    assert proof["effects"] == {"filesystem": "none", "database": "none"}
