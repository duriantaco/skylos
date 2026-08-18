from __future__ import annotations

import textwrap
from pathlib import Path

from skylos.research.dead_code import EvidenceKind, EvidenceLedger, RootKind, infer_roots


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def _roots_by_qname(tmp_path: Path):
    roots = infer_roots(tmp_path)
    return {root.symbol.qualified_name: root for root in roots.roots}


def test_infers_fastapi_route_and_dependency_style_root(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/profile")
        async def read_profile():
            return {"ok": True}

        def helper():
            return "not a root"
        """,
    )

    roots = _roots_by_qname(tmp_path)

    assert roots["app.read_profile"].kind == RootKind.FRAMEWORK_ROUTE
    assert "app.helper" not in roots


def test_infers_flask_route_cli_and_imperative_registration(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        """
        from flask import Flask

        app = Flask(__name__)

        @app.route("/orders")
        def show_orders():
            return "orders"

        @app.cli.command("reindex")
        def reindex_orders():
            return None

        def healthcheck():
            return "ok"

        app.add_url_rule("/health", view_func=healthcheck)
        """,
    )

    roots = _roots_by_qname(tmp_path)

    assert roots["app.show_orders"].kind == RootKind.FRAMEWORK_ROUTE
    assert roots["app.reindex_orders"].kind == RootKind.CLI_COMMAND
    assert roots["app.healthcheck"].kind == RootKind.FRAMEWORK_ROUTE


def test_infers_task_test_validator_serializer_and_plugin_roots(tmp_path: Path):
    _write(
        tmp_path / "service.py",
        """
        from celery import shared_task
        import pytest
        from pydantic import BaseModel, field_validator, computed_field
        import pluggy

        hookimpl = pluggy.HookimplMarker("demo")

        @shared_task
        def rebuild_index():
            return True

        @pytest.fixture
        def account():
            return {"id": "acct_1"}

        def test_account(account):
            assert account["id"]

        class Account(BaseModel):
            name: str

            @field_validator("name")
            def normalize_name(cls, value):
                return value.strip()

            @computed_field
            def slug(self):
                return self.name.lower()

        @hookimpl
        def demo_plugin_hook():
            return None
        """,
    )

    roots = _roots_by_qname(tmp_path)

    assert roots["service.rebuild_index"].kind == RootKind.TASK
    assert roots["service.account"].kind == RootKind.TEST
    assert roots["service.test_account"].kind == RootKind.TEST
    assert roots["service.Account.normalize_name"].kind == RootKind.VALIDATOR
    assert roots["service.Account.slug"].kind == RootKind.SERIALIZER
    assert roots["service.demo_plugin_hook"].kind == RootKind.PLUGIN_HOOK


def test_infers_pyproject_package_entrypoint(tmp_path: Path):
    _write(
        tmp_path / "pyproject.toml",
        """
        [project.scripts]
        demo = "demo.cli:main"
        """,
    )
    _write(
        tmp_path / "demo" / "cli.py",
        """
        def main():
            return 0
        """,
    )

    roots = _roots_by_qname(tmp_path)

    assert roots["demo.cli.main"].kind == RootKind.PACKAGE_ENTRYPOINT
    assert roots["demo.cli.main"].reason == "pyproject script demo"


def test_root_set_applies_evidence_to_ledger(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        """
        app = object()

        @app.get("/")
        def index():
            return "ok"
        """,
    )
    roots = infer_roots(tmp_path)
    ledger = EvidenceLedger()

    roots.apply_to(ledger)

    symbol = next(root.symbol for root in roots.roots if root.symbol.qualified_name == "app.index")
    assert ledger.has_kind(symbol, EvidenceKind.FRAMEWORK_ROOT)
