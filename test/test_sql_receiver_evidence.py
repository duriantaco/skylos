"""SQL receiver proofs use source, never target imports or execution."""

import ast
import copy
import textwrap

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_sql.sql_flow import scan
from skylos.security.receiver_resolution import ReceiverResolver
from test.fixture_paths import write_fixture


def _check(tmp_path, source, *, pipeline=False):
    source = textwrap.dedent(source)
    path = write_fixture(tmp_path, "receiver_case.py", source, overwrite=True)
    if pipeline:
        findings = scan_ctx(tmp_path, [path])
    else:
        findings = []
        scan(ast.parse(source), path, findings)
    return [row for row in findings if row["rule_id"] == "SKY-D211"]


@pytest.mark.parametrize("method", ["execute", "executemany", "executescript"])
def test_source_proved_non_db_method_is_not_a_sql_sink(tmp_path, method):
    assert not _check(
        tmp_path,
        f"""
        class Formatter:
            def {method}(self, value):
                return value

        db = Formatter()

        def render(value):
            return db.{method}(f"message: {{value}}")
        """,
    )


def test_non_db_receiver_proof_reaches_security_pipeline(tmp_path):
    assert not _check(
        tmp_path,
        """
        class Formatter:
            def execute(self, value):
                return value

        db = Formatter()
        db.execute(input())
        """,
        pipeline=True,
    )


@pytest.mark.parametrize(
    "call",
    [
        'cursor.execute(f"SELECT {input()}")',
        'cursor.execute(f"SELECT {input()}", ())',
        'cursor.execute(f"SELECT {input()}", parameters={})',
        'sqlite3.connect(":memory:").execute(f"SELECT {input()}")',
    ],
)
def test_database_interpolation_remains_unsafe_even_with_parameters(tmp_path, call):
    findings = _check(
        tmp_path,
        f"""
        import sqlite3
        cursor = sqlite3.connect(":memory:").cursor()
        {call}
        """,
    )
    assert findings
    assert all(row["severity"] == "CRITICAL" for row in findings)
    assert any(
        row.get("metadata", {}).get("security_evidence") for row in findings
    )


def test_static_parameterized_database_query_stays_safe(tmp_path):
    assert not _check(
        tmp_path,
        """
        import sqlite3
        cursor = sqlite3.connect(":memory:").cursor()
        cursor.execute("SELECT name FROM users WHERE id = ?", (input(),))
        """,
    )


def test_non_db_outer_receiver_does_not_hide_nested_database_sink(tmp_path):
    findings = _check(
        tmp_path,
        """
        class Formatter:
            def execute(self, value):
                return value
        import sqlite3
        cursor = sqlite3.connect(":memory:").cursor()
        db = Formatter()
        db.execute(cursor.execute(f"SELECT {input()}"))
        """,
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["metadata"]["security_evidence"]


def test_optional_receiver_resolution_failure_preserves_sql_finding(
    tmp_path, monkeypatch
):
    def unavailable(self, node):
        raise ValueError("unavailable")

    monkeypatch.setattr(ReceiverResolver, "resolve_call", unavailable)
    findings = _check(tmp_path, "def run(db):\n    db.execute(input())\n")
    assert len(findings) == 1
    assert findings[0]["metadata"]["security_evidence"]
    proof = findings[0]["metadata"]["receiver_resolution"]
    assert proof["status"] == "unknown"
    assert proof["limitations"] == [
        "Receiver resolution unavailable (ValueError)."
    ]


def test_optional_receiver_index_failure_preserves_sql_finding(tmp_path, monkeypatch):
    def unavailable(self, *args, **kwargs):
        raise ValueError("unavailable")

    monkeypatch.setattr(ReceiverResolver, "__init__", unavailable)
    findings = _check(tmp_path, "def run(db):\n    db.execute(input())\n")
    assert len(findings) == 1
    assert findings[0]["metadata"]["security_evidence"]
    assert findings[0]["metadata"]["receiver_resolution"]["status"] == "unknown"


@pytest.mark.parametrize(
    "source",
    [
        # An ordinary helper parameter is not a proven non-database object.
        "def run(db, query):\n    db.execute(query)\n",
        # An annotation is a claim, not a constructor/implementation binding.
        """
        class Formatter:
            def execute(self, value):
                return value
        def run(db: Formatter, query):
            db.execute(query)
        """,
        # A resolved local method can forward SQL to another receiver.
        """
        class Adapter:
            def execute(self, query):
                return self.connection.execute(query)
        db = Adapter()
        db.execute(input())
        """,
        # An arbitrary callback may itself execute SQL.
        """
        class Adapter:
            def execute(self, query):
                return callback(query)
        db = Adapter()
        db.execute(input())
        """,
        # Instance replacement invalidates the method-body proof.
        """
        class Formatter:
            def execute(self, value):
                return value
        db = Formatter()
        db.execute = replacement
        db.execute(input())
        """,
        # Class replacement also invalidates its original method body.
        """
        class Formatter:
            def execute(self, value):
                return value
        Formatter.execute = replacement
        db = Formatter()
        db.execute(input())
        """,
        # Rebinding to an arbitrary factory must not reuse an earlier proof.
        """
        class Formatter:
            def execute(self, value):
                return value
        db = Formatter()
        db = get_connection()
        db.execute(input())
        """,
        # Unknown inheritance can replace dispatch, even with a local method.
        """
        class Formatter(ExternalBase):
            def execute(self, value):
                return value
        db = Formatter()
        db.execute(input())
        """,
        # A class decorator can replace the entire receiver implementation.
        """
        @replace_class
        class Formatter:
            def execute(self, value):
                return value
        db = Formatter()
        db.execute(input())
        """,
        # Dynamic attribute dispatch can replace the apparent local method.
        """
        class Formatter:
            def __getattribute__(self, name):
                return replacement
            def execute(self, value):
                return value
        db = Formatter()
        db.execute(input())
        """,
        # The constructor may replace a method on the new instance.
        """
        class Formatter:
            def __init__(self):
                self.execute = replacement
            def execute(self, value):
                return value
        db = Formatter()
        db.execute(input())
        """,
        # Constructor changes to dispatch/instance dictionaries are mutations.
        """
        class Formatter:
            def __init__(self):
                self.__class__ = Replacement
            def execute(self, value):
                return value
        db = Formatter()
        db.execute(input())
        """,
        """
        class Formatter:
            def __init__(self):
                self.__dict__["execute"] = replacement
            def execute(self, value):
                return value
        db = Formatter()
        db.execute(input())
        """,
        # Implicit protocol dispatch can execute arbitrary database code.
        """
        class Adapter:
            def execute(self, query):
                return handler[query]
        db = Adapter()
        db.execute(input())
        """,
        """
        class Adapter:
            def execute(self, query):
                return handler + query
        db = Adapter()
        db.execute(input())
        """,
        # Nested function defaults run now, not when the function is called.
        """
        class Adapter:
            def execute(self, query):
                def nested(value=callback(query)):
                    return value
                return nested
        db = Adapter()
        db.execute(input())
        """,
        # Qualified mutators are not less capable than bare setattr.
        """
        import builtins
        class Formatter:
            def execute(self, value):
                return value
        builtins.setattr(Formatter, "execute", replacement)
        db = Formatter()
        db.execute(input())
        """,
        # Passing a class or instance to an unresolved callable escapes it.
        """
        class Formatter:
            def execute(self, value):
                return value
        configure(Formatter)
        db = Formatter()
        db.execute(input())
        """,
        """
        class Formatter:
            def execute(self, value):
                return value
        db = Formatter()
        configure(db)
        db.execute(input())
        """,
    ],
)
def test_unknown_and_replaced_receivers_retain_existing_sql_finding(tmp_path, source):
    findings = _check(tmp_path, source)
    assert findings
    assert all(row["severity"] == "CRITICAL" for row in findings)
    proofs = [row.get("metadata", {}).get("receiver_resolution") for row in findings]
    assert all(isinstance(proof, dict) for proof in proofs)
    assert all(
        proof.get("status") != "resolved"
        or proof.get("effects", {}).get("database") != "none"
        for proof in proofs
    )


def test_receiver_metadata_is_deterministic_and_preserves_taint_evidence(tmp_path):
    source = "def run(db):\n    db.execute(input())\n"
    first = _check(tmp_path, source)
    saved = copy.deepcopy(first)
    second = _check(tmp_path, source)
    assert first == saved == second
    proof = first[0]["metadata"]["receiver_resolution"]
    assert proof["status"] in {"unknown", "ambiguous"}
    assert isinstance(proof["steps"], list)
    assert isinstance(proof["limitations"], list)
    evidence = first[0]["metadata"]["security_evidence"]
    assert evidence["source"]
    assert evidence["sink"]
