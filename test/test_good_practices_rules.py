from __future__ import annotations

import ast
import textwrap

from skylos.rules.quality.policy import analyze_repo_policy
from skylos.rules.quality.practices import (
    FrameworkPracticeRule,
    TypeAnnotationPracticeRule,
)
from skylos.rules.quality._readability import OpaqueIdentifierRule


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


def test_opaque_identifier_flags_long_lived_semantic_rhs():
    findings = _run_rule(
        OpaqueIdentifierRule(),
        """
        def load_profile(request, repository, audit_log):
            x = request.args.get("user_id")
            if not x:
                audit_log.warning("missing user")
                return None
            audit_log.info("loading profile")
            profile = repository.fetch_profile(x)
            if profile.disabled:
                return {"status": "disabled", "id": x}
            return {"status": "active", "id": x}
        """,
    )

    assert [finding["rule_id"] for finding in findings] == ["SKY-Q806"]
    assert findings[0]["kind"] == "readability"
    assert findings[0]["name"] == "x"
    assert findings[0]["value"] == "user_id"


def test_opaque_identifier_accepts_coordinate_names():
    findings = _run_rule(
        OpaqueIdentifierRule(),
        """
        def area(point):
            x = point.get("x", 0)
            y = point.get("y", 0)
            return x * y
        """,
    )

    assert findings == []


def test_opaque_identifier_accepts_short_lived_temporary():
    findings = _run_rule(
        OpaqueIdentifierRule(),
        """
        def normalize(raw):
            tmp = raw.strip()
            return tmp
        """,
    )

    assert findings == []


def test_opaque_identifier_skips_test_files():
    findings = _run_rule(
        OpaqueIdentifierRule(),
        """
        def test_load_profile(request, repository):
            x = request.args.get("user_id")
            assert repository.fetch_profile(x)
            assert x
            assert x.startswith("user_")
        """,
        filename="tests/test_profiles.py",
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
    (tmp_path / "app.py").write_text(
        "def f() -> int:\n    return 1\n", encoding="utf-8"
    )

    assert analyze_repo_policy(tmp_path, {}) == []
