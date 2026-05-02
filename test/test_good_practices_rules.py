from __future__ import annotations

import ast
import textwrap

from skylos.rules.quality.policy import analyze_repo_policy
from skylos.rules.quality.practices import (
    FrameworkPracticeRule,
    TypeAnnotationPracticeRule,
)


def _run_rule(rule, code: str, filename: str = "app.py") -> list[dict]:
    tree = ast.parse(textwrap.dedent(code))
    findings = rule.visit_node(tree, {"filename": filename})
    return findings or []


def test_type_annotation_rule_flags_public_typed_api_gaps():
    findings = _run_rule(
        TypeAnnotationPracticeRule(),
        """
        from typing import Any

        def load_user(user_id, include_deleted: bool):
            return {"id": user_id, "deleted": include_deleted}
        """,
    )

    rule_ids = {finding["rule_id"] for finding in findings}
    assert rule_ids == {"SKY-T101", "SKY-T102"}
    assert findings[0]["kind"] == "typing"


def test_type_annotation_rule_skips_untyped_script_modules():
    findings = _run_rule(
        TypeAnnotationPracticeRule(),
        """
        def quick_script(path):
            print(path)
        """,
    )

    assert findings == []


def test_type_annotation_rule_accepts_typed_public_function():
    findings = _run_rule(
        TypeAnnotationPracticeRule(),
        """
        def load_user(user_id: str) -> dict[str, str]:
            return {"id": user_id}
        """,
    )

    assert findings == []


def test_fastapi_route_requires_response_contract():
    findings = _run_rule(
        FrameworkPracticeRule(),
        """
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/users")
        def list_users():
            return []
        """,
    )

    assert [finding["rule_id"] for finding in findings] == ["SKY-F101"]
    assert findings[0]["kind"] == "framework"


def test_fastapi_route_accepts_response_model_contract():
    findings = _run_rule(
        FrameworkPracticeRule(),
        """
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/users", response_model=list[str])
        def list_users():
            return []
        """,
    )

    assert findings == []


def test_mutating_fastapi_route_requires_auth_guard():
    findings = _run_rule(
        FrameworkPracticeRule(),
        """
        from fastapi import APIRouter

        router = APIRouter()

        @router.post("/users")
        def create_user(payload: dict) -> dict:
            return payload
        """,
    )

    assert [finding["rule_id"] for finding in findings] == ["SKY-F102"]
    assert findings[0]["kind"] == "framework_security"


def test_mutating_fastapi_route_accepts_depends_guard():
    findings = _run_rule(
        FrameworkPracticeRule(),
        """
        from fastapi import APIRouter, Depends

        router = APIRouter()

        def require_admin():
            return True

        @router.post("/users")
        def create_user(payload: dict, user=Depends(require_admin)) -> dict:
            return payload
        """,
    )

    assert findings == []


def test_mutating_flask_route_accepts_login_required_guard():
    findings = _run_rule(
        FrameworkPracticeRule(),
        """
        from flask import Flask
        from flask_login import login_required

        app = Flask(__name__)

        @app.route("/users", methods=["POST"])
        @login_required
        def create_user():
            return {}
        """,
    )

    assert findings == []


def test_repo_policy_reports_missing_type_checker(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
        [tool.ruff]
        target-version = "py310"

        [tool.skylos.gate]
        max_quality = 10
        """,
        encoding="utf-8",
    )
    (tmp_path / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    findings = analyze_repo_policy(tmp_path, {})

    assert [finding["rule_id"] for finding in findings] == ["SKY-R101"]
    assert findings[0]["kind"] == "repo_policy"


def test_repo_policy_accepts_configured_type_checker(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
        [tool.mypy]
        python_version = "3.10"

        [tool.ruff]
        target-version = "py310"

        [tool.skylos.gate]
        max_quality = 10
        """,
        encoding="utf-8",
    )
    (tmp_path / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("def f() -> int:\n    return 1\n", encoding="utf-8")

    assert analyze_repo_policy(tmp_path, {}) == []
