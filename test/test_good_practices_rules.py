from __future__ import annotations

import ast
import json
import sys
import textwrap

import pytest

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


def _run_policy_cli(monkeypatch, capsys, root, *args) -> dict:
    from skylos.cli import main

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            str(root),
            "--quality",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            *args,
        ],
    )
    main()
    return json.loads(capsys.readouterr().out)


def _repo_policy_findings(report: dict) -> list[dict]:
    return [
        finding
        for finding in report.get("quality", [])
        if finding.get("rule_id", "").startswith("SKY-R")
    ]


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


def test_repo_policy_skips_python_checks_on_typescript_project(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
        [tool.skylos]
        complexity = 10
        """,
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text('{"name": "ts-project"}', encoding="utf-8")
    (tmp_path / "index.ts").write_text('console.log("hello");', encoding="utf-8")

    findings = analyze_repo_policy(tmp_path, {})
    rule_ids = {f["rule_id"] for f in findings}
    assert "SKY-R101" not in rule_ids
    assert "SKY-R102" not in rule_ids


@pytest.mark.parametrize("suffix", [".pyi", ".pyw"])
def test_repo_policy_recognizes_python_stub_and_windowed_sources(tmp_path, suffix):
    (tmp_path / f"module{suffix}").write_text(
        "def api() -> int: ...\n", encoding="utf-8"
    )

    rule_ids = {finding["rule_id"] for finding in analyze_repo_policy(tmp_path)}
    assert {"SKY-R101", "SKY-R102"} <= rule_ids


def test_repo_policy_ignores_python_files_in_excluded_folders(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
        [tool.skylos]
        complexity = 10
        exclude = ["scripts"]
        """,
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text('{"name": "ts-project"}', encoding="utf-8")
    (tmp_path / "index.ts").write_text('console.log("hello");', encoding="utf-8")
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "build.py").write_text('print("build")', encoding="utf-8")

    findings = analyze_repo_policy(
        tmp_path,
        {"exclude": ["scripts"]},
        exclude_folders={"scripts"},
    )
    rule_ids = {f["rule_id"] for f in findings}
    assert "SKY-R101" not in rule_ids
    assert "SKY-R102" not in rule_ids


def test_repo_policy_ignores_python_only_in_excluded_env(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "package.json").write_text('{"name":"ts-only"}', encoding="utf-8")
    (tmp_path / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "helper.py").write_text("def helper(): return True\n", encoding="utf-8")

    report = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_quality=True,
            grep_verify=False,
            exclude_folders=["env"],
        )
    )

    assert report["analysis_summary"]["total_files"] == 1
    rule_ids = {finding["rule_id"] for finding in _repo_policy_findings(report)}
    assert {"SKY-R101", "SKY-R102"}.isdisjoint(rule_ids)


def test_repo_policy_ignores_marked_virtualenv_but_not_first_party_env(tmp_path):
    (tmp_path / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "helper.py").write_text("def helper(): return True\n", encoding="utf-8")

    first_party_ids = {finding["rule_id"] for finding in analyze_repo_policy(tmp_path)}
    assert {"SKY-R101", "SKY-R102"} <= first_party_ids

    (env_dir / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    virtualenv_ids = {finding["rule_id"] for finding in analyze_repo_policy(tmp_path)}
    assert {"SKY-R101", "SKY-R102"}.isdisjoint(virtualenv_ids)


def test_repo_policy_cli_ignores_marked_virtualenv(tmp_path, monkeypatch, capsys):
    (tmp_path / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (env_dir / "helper.py").write_text("def helper(): return True\n", encoding="utf-8")

    report = _run_policy_cli(monkeypatch, capsys, tmp_path)

    assert report["analysis_summary"]["total_files"] == 2
    rule_ids = {finding["rule_id"] for finding in _repo_policy_findings(report)}
    assert {"SKY-R101", "SKY-R102"}.isdisjoint(rule_ids)


def test_repo_policy_partial_typescript_scan_keeps_repo_python_policy(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "package.json").write_text('{"name":"mixed-project"}', encoding="utf-8")
    (tmp_path / "app.py").write_text("def app(): return True\n", encoding="utf-8")
    ts_file = tmp_path / "src" / "index.ts"
    ts_file.parent.mkdir()
    ts_file.write_text("export const value = 1;\n", encoding="utf-8")

    report = json.loads(
        analyze(str(ts_file), conf=0, enable_quality=True, grep_verify=False)
    )

    assert report["analysis_summary"]["total_files"] == 1
    rule_ids = {finding["rule_id"] for finding in _repo_policy_findings(report)}
    assert {"SKY-R101", "SKY-R102"} <= rule_ids


def test_repo_policy_from_direct_analyzer_ignores_config_excluded_python(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos]\nexclude = ["scripts"]\n', encoding="utf-8"
    )
    (tmp_path / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "helper.py").write_text(
        "def helper(): return True\n", encoding="utf-8"
    )

    report = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )
    rule_ids = {finding["rule_id"] for finding in _repo_policy_findings(report)}
    assert {"SKY-R101", "SKY-R102"}.isdisjoint(rule_ids)


def test_repo_policy_cli_config_exclusion_ignores_python(tmp_path, monkeypatch, capsys):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos]\nexclude = ["scripts"]\n', encoding="utf-8"
    )
    (tmp_path / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "helper.py").write_text(
        "def helper(): return True\n", encoding="utf-8"
    )

    report = _run_policy_cli(monkeypatch, capsys, tmp_path)

    assert report["analysis_summary"]["total_files"] == 1
    rule_ids = {finding["rule_id"] for finding in _repo_policy_findings(report)}
    assert {"SKY-R101", "SKY-R102"}.isdisjoint(rule_ids)


def test_repo_policy_scoped_cli_exclusion_keeps_other_same_named_package(
    tmp_path, monkeypatch, capsys
):
    excluded_package = tmp_path / "packages" / "excluded"
    included_package = tmp_path / "apps" / "excluded"
    for package in (excluded_package, included_package):
        package.mkdir(parents=True)
        (package / "package.json").write_text('{"name":"ts-package"}', encoding="utf-8")
        (package / "tsconfig.json").write_text("{}", encoding="utf-8")
        (package / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")

    report = _run_policy_cli(
        monkeypatch, capsys, tmp_path, "--exclude", "packages/excluded"
    )

    assert report["analysis_summary"]["total_files"] == 1
    r105_files = {
        finding["file"]
        for finding in _repo_policy_findings(report)
        if finding["rule_id"] == "SKY-R105"
    }
    assert r105_files == {str(included_package / "package.json")}


@pytest.mark.parametrize(
    "include_args",
    [("--include-folder", "vendor"), ("--no-default-excludes",)],
)
def test_repo_policy_cli_include_override_keeps_vendor_package(
    tmp_path, monkeypatch, capsys, include_args
):
    package = tmp_path / "vendor" / "pkg"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        '{"name":"included-vendor"}', encoding="utf-8"
    )
    (package / "tsconfig.json").write_text("{}", encoding="utf-8")
    (package / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")

    report = _run_policy_cli(monkeypatch, capsys, tmp_path, *include_args)

    assert report["analysis_summary"]["total_files"] == 1
    r105_files = {
        finding["file"]
        for finding in _repo_policy_findings(report)
        if finding["rule_id"] == "SKY-R105"
    }
    assert r105_files == {str(package / "package.json")}


def test_repo_policy_cli_include_overrides_config_exclusion(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos]\nexclude = ["scripts"]\n', encoding="utf-8"
    )
    package = tmp_path / "scripts" / "pkg"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        '{"name":"included-script"}', encoding="utf-8"
    )
    (package / "tsconfig.json").write_text("{}", encoding="utf-8")
    (package / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")

    report = _run_policy_cli(
        monkeypatch, capsys, tmp_path, "--include-folder", "scripts"
    )

    assert report["analysis_summary"]["total_files"] == 1
    r105_files = {
        finding["file"]
        for finding in _repo_policy_findings(report)
        if finding["rule_id"] == "SKY-R105"
    }
    assert r105_files == {str(package / "package.json")}
