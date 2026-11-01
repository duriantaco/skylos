"""SKY-D211: class attributes that hold fixed SQL text are static SQL.

A class constant read through ``self``, ``cls`` or the class name is fixed
text only when every class body in the module binds it once to SQL-safe text,
nothing in the module writes an attribute of that name, and the class cannot
turn the binding into a per-instance field.
"""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _d211_lines(tmp_path, monkeypatch, source, listed_only=False):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, "app.py", textwrap.dedent(source).lstrip("\n"))
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="proof"\n')
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not result.get("analysis_errors")
    return sorted(
        finding["line"]
        for finding in result.get("danger", [])
        if finding["rule_id"] == "SKY-D211"
        and (not listed_only or finding["listing"]["listed"])
    )


STATIC_CLASS_SQL = {
    "self_constant_without_parameters": """
        import sqlite3


        class Cache:
            SQL_DROP = (
                "DELETE FROM blobs WHERE sha256 IN ("
                " SELECT sha256 FROM blobs LEFT JOIN blob_map USING (sha256)"
                " WHERE blob_map.sha256 IS NULL)"
            )

            def maintenance(self, path):
                conn = sqlite3.connect(path)
                conn.execute(self.SQL_DROP)
    """,
    "annotated_constant_in_fstring_with_module_override": """
        import abc
        import sqlite3


        class Appl(abc.ABC):
            JOURNAL_MODE: str = "WAL"

            def connect(self, path):
                conn = sqlite3.connect(path)
                conn.execute(f"PRAGMA journal_mode={self.JOURNAL_MODE}")
                return conn


        class Properties(Appl):
            JOURNAL_MODE: str = "WAL"
            DDL: str = "CREATE TABLE IF NOT EXISTS properties (name TEXT, value TEXT)"

            def create_schema(self, conn):
                conn.execute(self.DDL)
    """,
    "classmethod_and_class_name": """
        import sqlite3


        class Repo:
            SQL = "SELECT name FROM sqlite_master WHERE type='table'"

            @classmethod
            def tables(cls, conn):
                return conn.execute(cls.SQL).fetchall()


        def tables(path):
            conn = sqlite3.connect(path)
            return conn.execute(Repo.SQL).fetchall()
    """,
    "final_class_with_imported_base": """
        import typing as t

        from app_base import sqlitedb


        @t.final
        class FaviconCache(sqlitedb.Appl):
            SQL_ITER = "SELECT sha256, bytes_c FROM blobs ORDER BY m_time"

            def maintenance(self, conn):
                for row in conn.execute(self.SQL_ITER):
                    print(row)
    """,
}


@pytest.mark.parametrize("name", sorted(STATIC_CLASS_SQL))
def test_fixed_class_sql_text_is_not_reported(tmp_path, monkeypatch, name):
    assert _d211_lines(tmp_path, monkeypatch, STATIC_CLASS_SQL[name]) == []


STILL_REPORTED = {
    "instance_write_from_request": (
        """
        from flask import request


        class Repo:
            SQL = "SELECT * FROM users"

            def configure(self):
                self.SQL = request.args["q"]

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        11,
    ),
    "write_through_an_object_alias": (
        """
        from flask import request


        class Repo:
            SQL = "SELECT * FROM users"

            def run(self, cursor):
                cursor.execute(self.SQL)


        repo = Repo()
        repo.SQL = request.args["q"]
        """,
        8,
    ),
    "module_subclass_overrides_from_environment": (
        """
        import os


        class Repo:
            SQL = "SELECT * FROM users"

            def run(self, cursor):
                cursor.execute(self.SQL)


        class Configured(Repo):
            SQL = os.getenv("REPO_SQL")
        """,
        8,
    ),
    "literal_setattr": (
        """
        class Repo:
            SQL = "SELECT * FROM users"

            def configure(self, value):
                setattr(self, "SQL", value)

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        8,
    ),
    "aliased_setattr": (
        """
        put = setattr


        class Repo:
            SQL = "SELECT * FROM users"

            def configure(self, value):
                put(self, "SQL", value)

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        11,
    ),
    "computed_setattr": (
        """
        class Repo:
            SQL = "SELECT * FROM users"

            def __init__(self, **options):
                for key, value in options.items():
                    setattr(self, key, value)

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        9,
    ),
    "constant_built_from_fstring_variable": (
        """
        TABLE = "users"


        class Repo:
            SQL = f"SELECT * FROM {TABLE}"

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        8,
    ),
    "tainted_value_beside_constant_in_fstring": (
        """
        from flask import request


        class Repo:
            SQL = "SELECT * FROM users"

            def run(self, cursor):
                cursor.execute(f"{self.SQL} WHERE id = {request.args['id']}")
        """,
        8,
    ),
    "tainted_value_concatenated_to_constant": (
        """
        from flask import request


        class Repo:
            SQL = "SELECT * FROM users WHERE name = '"

            def run(self, cursor):
                cursor.execute(self.SQL + request.args["name"] + "'")
        """,
        8,
    ),
    "dataclass_field_default": (
        """
        from dataclasses import dataclass


        @dataclass
        class Query:
            table: str = "users"

            def run(self, cursor):
                cursor.execute(f"SELECT * FROM {self.table}")
        """,
        9,
    ),
    "settings_model_field_from_environment": (
        """
        from pydantic_settings import BaseSettings


        class Settings(BaseSettings):
            TABLE: str = "users"

            def run(self, cursor):
                cursor.execute(f"SELECT * FROM {self.TABLE}")
        """,
        8,
    ),
    "pydantic_v1_unannotated_field": (
        """
        from pydantic.v1 import BaseModel


        class Query(BaseModel):
            table = "users"

            def run(self, cursor):
                cursor.execute(f"SELECT * FROM {self.table}")
        """,
        8,
    ),
    "metaclass_keyword": (
        """
        from registry import Meta


        class Repo(metaclass=Meta):
            SQL = "SELECT * FROM users"

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        8,
    ),
    "wrapper_function_parameter": (
        """
        class Repo:
            SQL = "SELECT * FROM users"


        def run(obj, cursor):
            cursor.execute(obj.SQL)
        """,
        6,
    ),
    "staticmethod_alias_parameter": (
        """
        static = staticmethod


        class Repo:
            SQL = "SELECT * FROM users"

            @static
            def run(conf, cursor):
                cursor.execute(conf.SQL)
        """,
        9,
    ),
    "method_called_through_class_with_foreign_object": (
        """
        from types import SimpleNamespace

        from flask import request


        class Repo:
            SQL = "SELECT * FROM users"

            def run(self, cursor):
                cursor.execute(self.SQL)


        def handler(cursor):
            Repo.run(SimpleNamespace(SQL=request.args["q"]), cursor)
        """,
        10,
    ),
    "receiver_rebound_inside_method": (
        """
        class Repo:
            SQL = "SELECT * FROM users"

            def run(self, other, cursor):
                self = other
                cursor.execute(self.SQL)
        """,
        6,
    ),
    "prefix_check_does_not_make_input_static": (
        """
        class Repo:
            SQL = "SELECT * FROM users"

            def configure(self, value):
                if value.startswith("SELECT"):
                    self.SQL = value

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        9,
    ),
    "conditional_class_body_binding": (
        """
        import os


        class Repo:
            if os.getenv("DEBUG"):
                SQL = "SELECT 1"
            else:
                SQL = os.getenv("REPO_SQL")

            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        11,
    ),
    "class_name_rebound_at_runtime": (
        """
        from app.repos import load_repo


        class Repo:
            SQL = "SELECT * FROM users"


        Repo = load_repo()


        def run(cursor):
            cursor.execute(Repo.SQL)
        """,
        12,
    ),
    "class_alias_write_from_request": (
        """
        from flask import request


        class Repo:
            SQL = "SELECT * FROM users"


        def configure():
            alias = Repo
            alias.SQL = request.args["q"]


        def run(cursor):
            cursor.execute(Repo.SQL)
        """,
        14,
    ),
    "classmethod_with_module_subclass_override": (
        """
        import os


        class Repo:
            SQL = "SELECT * FROM users"

            @classmethod
            def run(cls, cursor):
                cursor.execute(cls.SQL)


        class Configured(Repo):
            SQL = os.getenv("REPO_SQL")
        """,
        9,
    ),
    "class_passed_to_a_wrapper": (
        """
        class Repo:
            SQL = "SELECT * FROM users"


        def run(klass, cursor):
            cursor.execute(klass.SQL)


        def handler(cursor):
            run(Repo, cursor)
        """,
        6,
    ),
    "class_name_check_does_not_guard_concatenation": (
        """
        from flask import request


        class Repo:
            SQL = "SELECT * FROM users WHERE "


        def run(cursor):
            if Repo.SQL.startswith("SELECT"):
                cursor.execute(Repo.SQL + request.args["where"])
        """,
        10,
    ),
    "constant_inherited_from_an_imported_base": (
        """
        from lib import Base


        class Other:
            SQL = "SELECT 1"


        class Repo(Base):
            def run(self, cursor):
                cursor.execute(self.SQL)
        """,
        10,
    ),
}


@pytest.mark.parametrize("name", sorted(STILL_REPORTED))
def test_class_attribute_that_can_carry_input_still_reports(
    tmp_path, monkeypatch, name
):
    source, line = STILL_REPORTED[name]
    assert line in _d211_lines(tmp_path, monkeypatch, source, listed_only=True)
