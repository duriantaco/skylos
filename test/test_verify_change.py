from __future__ import annotations

import json

import pytest

from skylos.contracts import load_contract
from skylos.verify_change import (
    build_verify_change_response,
    parse_line_range,
    verify_change_stdin_payload,
    verify_change_path,
)


def test_build_verify_change_response_filters_to_ai_findings(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def handler(token):\n    return validate_token(token)\n")
    result = {
        "ai_defects": [
            {
                "rule_id": "SKY-L012",
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
                "severity": "CRITICAL",
                "file": str(app),
                "line": 2,
                "col": 11,
                "message": "Call to validate_token() is never defined.",
            },
        ],
        "quality": [
            {
                "rule_id": "SKY-Q302",
                "severity": "LOW",
                "file": str(app),
                "line": 1,
                "message": "Generic quality finding",
            },
        ],
    }

    payload = build_verify_change_response(result, project_root=tmp_path)

    assert payload["schema_version"] == 1
    assert payload["tool"] == "verify_change"
    assert payload["status"] == "fail"
    assert payload["summary"] == "1 AI-code issue found"
    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["rule_id"] == "SKY-L012"
    assert finding["vibe_category"] == "hallucinated_reference"
    assert finding["ai_likelihood"] == "high"
    assert finding["confidence"] == 90
    assert finding["range"]["file"] == "app.py"
    assert finding["range"]["start_line"] == 2
    assert finding["suggested_fix"]


def test_build_verify_change_response_keeps_diff_backed_ai_rules(tmp_path):
    app = tmp_path / ".github" / "workflows" / "ci.yml"
    app.parent.mkdir(parents=True)
    app.write_text("permissions: write-all\n", encoding="utf-8")

    payload = build_verify_change_response(
        {
            "ai_defects": [
                {
                    "rule_id": "SKY-A103",
                    "vibe_category": "ci_permission_expansion",
                    "severity": "HIGH",
                    "file": str(app),
                    "line": 1,
                    "message": "CI permissions expanded.",
                },
                {
                    "rule_id": "SKY-A104",
                    "vibe_category": "public_api_surface_drift",
                    "severity": "MEDIUM",
                    "file": str(app),
                    "line": 1,
                    "message": "Public CLI flag removed.",
                },
            ],
        },
        project_root=tmp_path,
    )

    assert payload["status"] == "fail"
    assert {finding["rule_id"] for finding in payload["findings"]} == {
        "SKY-A103",
        "SKY-A104",
    }


def test_build_verify_change_response_applies_rule_defaults(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("requests.get(url, verify=False)\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-L011",
                "severity": "HIGH",
                "file": str(app),
                "line": 1,
                "message": "TLS verification disabled.",
            }
        ]
    }

    payload = build_verify_change_response(result, project_root=tmp_path)

    finding = payload["findings"][0]
    assert finding["vibe_category"] == "disabled_security_control"
    assert finding["ai_likelihood"] == "medium"
    assert finding["confidence"] == 70


def test_build_verify_change_response_applies_api_signature_defaults(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("api.missing(arg=True)\n")
    result = {
        "ai_defects": [
            {
                "rule_id": "SKY-D224",
                "severity": "HIGH",
                "file": str(app),
                "line": 1,
                "message": "Installed API does not accept keyword.",
            }
        ]
    }

    payload = build_verify_change_response(result, project_root=tmp_path)

    finding = payload["findings"][0]
    assert finding["vibe_category"] == "api_signature_hallucination"
    assert finding["ai_likelihood"] == "high"
    assert finding["suggested_fix"]


def test_build_verify_change_response_applies_version_hallucination_defaults(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies": {"ghost": "9.9.9"}}\n')
    result = {
        "ai_defects": [
            {
                "rule_id": "SKY-D225",
                "severity": "HIGH",
                "file": str(manifest),
                "line": 1,
                "message": "Dependency version does not exist.",
            }
        ]
    }

    payload = build_verify_change_response(result, project_root=tmp_path)

    finding = payload["findings"][0]
    assert finding["vibe_category"] == "dependency_hallucination"
    assert finding["ai_likelihood"] == "high"


@pytest.mark.parametrize(
    ("finding", "clause"),
    [
        (
            {
                "rule_id": "SKY-L012",
                "simple_name": "verify_enterprise_auth",
                "message": "Call to verify_enterprise_auth() is never defined.",
            },
            "ai.phantom_symbols.names",
        ),
        (
            {
                "rule_id": "SKY-L023",
                "simple_name": "tenant_admin_required",
                "message": "Decorator is never defined.",
            },
            "ai.phantom_symbols.decorators",
        ),
        (
            {
                "rule_id": "SKY-D222",
                "message": "Package does not exist.",
                "metadata": {"package_name": "ghostpkg", "package_version": "1.0.0"},
            },
            "ai.dependencies.reject_nonexistent_packages",
        ),
        (
            {
                "rule_id": "SKY-D225",
                "message": "Version does not exist.",
                "metadata": {"package_name": "ghostpkg", "package_version": "9.9.9"},
            },
            "ai.dependencies.reject_impossible_versions",
        ),
        (
            {
                "rule_id": "SKY-D224",
                "message": "Installed API does not accept keyword argument 'timeout'.",
            },
            "ai.api_surface.reject_unknown_kwargs",
        ),
        (
            {
                "rule_id": "SKY-D224",
                "message": "Installed API does not expose this member.",
            },
            "ai.api_surface.reject_unknown_members",
        ),
        (
            {
                "rule_id": "SKY-A102",
                "message": "High-risk code changed without tests.",
            },
            "tests.high_risk_changes_require_tests",
        ),
        (
            {
                "rule_id": "SKY-A105",
                "message": "Route is missing a contract-required guard decorator.",
            },
            "security.routes.require_any_decorator",
        ),
    ],
)
def test_build_verify_change_response_adds_contract_metadata(
    tmp_path, finding, clause
):
    app = tmp_path / "app.py"
    app.write_text("pass\n", encoding="utf-8")
    contract_file = tmp_path / "ai-contract.yml"
    contract_file.write_text(
        "version: 1\n"
        "id: enterprise-auth-contract\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n"
        "    decorators: [tenant_admin_required]\n"
        "  dependencies:\n"
        "    reject_nonexistent_packages: true\n"
        "    reject_impossible_versions: true\n"
        "  api_surface:\n"
        "    reject_unknown_members: true\n"
        "    reject_unknown_kwargs: true\n"
        "security:\n"
        "  routes:\n"
        "    paths: [apps/api/**]\n"
        "    require_any_decorator: [login_required]\n"
        "tests:\n"
        "  high_risk_changes_require_tests: true\n",
        encoding="utf-8",
    )
    contract = load_contract(contract_file)
    finding = {
        "severity": "HIGH",
        "file": str(app),
        "line": 1,
        **finding,
    }

    payload = build_verify_change_response(
        {"ai_defects": [finding]},
        project_root=tmp_path,
        contract=contract,
    )

    normalized = payload["findings"][0]
    assert normalized["contract_id"] == "enterprise-auth-contract"
    assert normalized["contract_clause"] == clause
    assert normalized["contract_path"] == str(contract.path)
    assert normalized["contract_reason"]


def test_build_verify_change_response_skips_unmatched_contract_metadata(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("pass\n", encoding="utf-8")
    contract_file = tmp_path / "ai-contract.yml"
    contract_file.write_text(
        "version: 1\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n",
        encoding="utf-8",
    )
    contract = load_contract(contract_file)

    payload = build_verify_change_response(
        {
            "ai_defects": [
                {
                    "rule_id": "SKY-L012",
                    "severity": "HIGH",
                    "file": str(app),
                    "line": 1,
                    "simple_name": "validate_token",
                    "message": "Call to validate_token() is never defined.",
                }
            ]
        },
        project_root=tmp_path,
        contract=contract,
    )

    assert "contract_clause" not in payload["findings"][0]


def test_build_verify_change_response_skips_dependency_import_defaults(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("import requests\n", encoding="utf-8")
    result = {
        "danger": [
            {
                "rule_id": "SKY-D223",
                "severity": "MEDIUM",
                "file": str(app),
                "line": 1,
                "message": "Undeclared import 'requests'.",
            }
        ]
    }

    payload = build_verify_change_response(result, project_root=tmp_path)

    assert payload["findings"] == []


def test_build_verify_change_response_filters_target_file_and_range(tmp_path):
    app = tmp_path / "app.py"
    other = tmp_path / "other.py"
    app.write_text("def a():\n    return validate_token(token)\n")
    other.write_text("def b():\n    return require_admin(user)\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-L012",
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
                "file": str(app),
                "line": 2,
                "message": "app phantom",
            },
            {
                "rule_id": "SKY-L012",
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
                "file": str(other),
                "line": 2,
                "message": "other phantom",
            },
        ]
    }

    payload = build_verify_change_response(
        result,
        project_root=tmp_path,
        target_file="app.py",
        line_range="2:2",
    )

    assert [f["message"] for f in payload["findings"]] == ["app phantom"]
    assert payload["target"]["file"] == "app.py"
    assert payload["target"]["range"] == {"start_line": 2, "end_line": 2}


def test_parse_line_range_validation():
    assert parse_line_range("4:9") == (4, 9)
    assert parse_line_range("4-9") == (4, 9)
    assert parse_line_range("4") == (4, 4)
    with pytest.raises(ValueError):
        parse_line_range("9:4")


def test_verify_change_path_runs_existing_vibe_rules(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def handler(token):\n    return validate_token(token)\n")

    payload = verify_change_path(app, line_range="2:2")

    assert payload["status"] == "fail"
    assert any(f["rule_id"] == "SKY-L012" for f in payload["findings"])
    assert all(f["range"]["start_line"] == 2 for f in payload["findings"])


def test_verify_change_path_accepts_injected_analyzer_result(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def handler():\n    pass\n")
    seen = {}

    def fake_analyze(*_args, **kwargs):
        seen["kwargs"] = kwargs
        return json.dumps(
            {
                "quality": [
                    {
                        "rule_id": "SKY-L026",
                        "vibe_category": "incomplete_generation",
                        "ai_likelihood": "medium",
                        "file": str(app),
                        "line": 2,
                        "message": "Generated stub left behind.",
                    }
                ]
            }
        )

    payload = verify_change_path(app, analyze_func=fake_analyze)

    assert payload["status"] == "fail"
    assert payload["findings"][0]["vibe_category"] == "incomplete_generation"
    assert seen["kwargs"]["enable_ai_defects"] is True
    assert seen["kwargs"]["enable_dependency_hallucinations"] is False
    assert seen["kwargs"]["enable_danger"] is False
    assert seen["kwargs"]["changed_files"] == [str(app)]


def test_verify_change_path_can_include_dependency_hallucinations(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("import ghost_package\n")
    seen = {}

    def fake_analyze(*_args, **kwargs):
        seen["kwargs"] = kwargs
        return json.dumps({})

    payload = verify_change_path(
        app,
        include_dependency_hallucinations=True,
        analyze_func=fake_analyze,
    )

    assert payload["status"] == "pass"
    assert seen["kwargs"]["enable_ai_defects"] is True
    assert seen["kwargs"]["enable_dependency_hallucinations"] is True
    assert seen["kwargs"]["enable_danger"] is False
    assert seen["kwargs"]["changed_files"] == [str(app)]


def test_verify_change_path_contract_enables_project_vibe_override(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def handler(request):\n    return verify_enterprise_auth(request)\n")
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n",
        encoding="utf-8",
    )

    payload = verify_change_path(app, contract_path=contract)

    assert payload["status"] == "fail"
    contract_finding = next(
        finding
        for finding in payload["findings"]
        if finding["rule_id"] == "SKY-L012"
        and finding["vibe_category"] == "hallucinated_reference"
    )
    assert contract_finding["contract_clause"] == "ai.phantom_symbols.names"
    assert contract_finding["contract_path"] == str(contract.resolve())
    assert (
        "verify_enterprise_auth" in contract_finding["contract_reason"]
    )
    assert any(
        finding["rule_id"] == "SKY-L012"
        and finding["vibe_category"] == "hallucinated_reference"
        for finding in payload["findings"]
    )


def test_verify_change_path_auto_discovers_default_contract_from_parent(tmp_path):
    app = tmp_path / "src" / "app.py"
    app.parent.mkdir()
    app.write_text("def handler(request):\n    return verify_enterprise_auth(request)\n")
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n",
        encoding="utf-8",
    )
    seen = {}

    def fake_analyze(*_args, **kwargs):
        seen["kwargs"] = kwargs
        return json.dumps({})

    payload = verify_change_path(app, analyze_func=fake_analyze)

    assert payload["status"] == "pass"
    assert seen["kwargs"]["project_config_overrides"] == {
        "vibe": {"extra_phantom_names": ["verify_enterprise_auth"]}
    }


def test_verify_change_path_can_disable_auto_discovered_contract(tmp_path):
    app = tmp_path / "src" / "app.py"
    app.parent.mkdir()
    app.write_text("import requests\n")
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "ai:\n"
        "  dependencies:\n"
        "    reject_impossible_versions: true\n",
        encoding="utf-8",
    )
    seen = {}

    def fake_analyze(*_args, **kwargs):
        seen["kwargs"] = kwargs
        return json.dumps({})

    payload = verify_change_path(
        app,
        contract_enabled=False,
        analyze_func=fake_analyze,
    )

    assert payload["status"] == "pass"
    assert seen["kwargs"]["enable_dependency_hallucinations"] is False
    assert "project_config_overrides" not in seen["kwargs"]


def test_verify_change_path_rejects_explicit_contract_when_disabled(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("pass\n")
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text("version: 1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="contracts are disabled"):
        verify_change_path(app, contract_path=contract, contract_enabled=False)


def test_verify_change_path_resolves_relative_contract_from_cwd_for_file_target(
    tmp_path, monkeypatch
):
    app_dir = tmp_path / "src"
    app_dir.mkdir()
    app = app_dir / "app.py"
    app.write_text("def handler(request):\n    return verify_enterprise_auth(request)\n")
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    payload = verify_change_path(app, contract_path=".skylos/ai-contract.yml")

    assert payload["status"] == "fail"
    assert any(finding["rule_id"] == "SKY-L012" for finding in payload["findings"])


def test_verify_change_path_contract_options_pass_to_analyzer(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("import requests\n")
    contract = tmp_path / "ai-contract.yml"
    contract.write_text(
        "version: 1\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n"
        "  dependencies:\n"
        "    reject_impossible_versions: true\n",
        encoding="utf-8",
    )
    seen = {}

    def fake_analyze(*_args, **kwargs):
        seen["kwargs"] = kwargs
        return json.dumps({})

    payload = verify_change_path(app, contract_path=contract, analyze_func=fake_analyze)

    assert payload["status"] == "pass"
    assert seen["kwargs"]["enable_dependency_hallucinations"] is True
    assert seen["kwargs"]["project_config_overrides"] == {
        "vibe": {"extra_phantom_names": ["verify_enterprise_auth"]}
    }


def test_verify_change_path_contract_routes_require_guard_decorator(tmp_path):
    app = tmp_path / "apps" / "api" / "routes.py"
    app.parent.mkdir(parents=True)
    app.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/admin')\n"
        "def admin():\n"
        "    return {}\n",
        encoding="utf-8",
    )
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "security:\n"
        "  routes:\n"
        "    paths: [apps/api/**]\n"
        "    require_any_decorator: [login_required]\n",
        encoding="utf-8",
    )

    payload = verify_change_path(
        tmp_path,
        contract_path=contract,
        analyze_func=lambda *_args, **_kwargs: {},
    )

    assert payload["status"] == "fail"
    finding = next(
        finding
        for finding in payload["findings"]
        if finding["rule_id"] == "SKY-A105"
    )
    assert finding["vibe_category"] == "missing_contract_guardrail"
    assert finding["contract_clause"] == "security.routes.require_any_decorator"
    assert finding["range"]["file"] == "apps/api/routes.py"
    assert "@login_required" in finding["message"]


def test_verify_change_path_contract_routes_accept_custom_guard_decorator(tmp_path):
    app = tmp_path / "apps" / "api" / "routes.py"
    app.parent.mkdir(parents=True)
    app.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "def tenant_admin_required(fn):\n"
        "    return fn\n\n"
        "@app.route('/admin')\n"
        "@tenant_admin_required\n"
        "def admin():\n"
        "    return {}\n",
        encoding="utf-8",
    )
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "security:\n"
        "  routes:\n"
        "    paths: [apps/api/**]\n"
        "    require_any_decorator: [tenant_admin_required]\n",
        encoding="utf-8",
    )

    payload = verify_change_path(
        tmp_path,
        contract_path=contract,
        analyze_func=lambda *_args, **_kwargs: {},
    )

    assert not any(
        finding["rule_id"] == "SKY-A105"
        for finding in payload["findings"]
    )


def test_verify_change_path_contract_routes_respect_path_scope(tmp_path):
    app = tmp_path / "tools" / "routes.py"
    app.parent.mkdir(parents=True)
    app.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/admin')\n"
        "def admin():\n"
        "    return {}\n",
        encoding="utf-8",
    )
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "security:\n"
        "  routes:\n"
        "    paths: [apps/api/**]\n"
        "    require_any_decorator: [login_required]\n",
        encoding="utf-8",
    )

    payload = verify_change_path(
        tmp_path,
        contract_path=contract,
        analyze_func=lambda *_args, **_kwargs: {},
    )

    assert not any(
        finding["rule_id"] == "SKY-A105"
        for finding in payload["findings"]
    )


def test_verify_change_path_uses_target_file_for_changed_files(tmp_path):
    app = tmp_path / "src" / "app.py"
    app.parent.mkdir()
    app.write_text("def handler():\n    pass\n")
    seen = {}

    def fake_analyze(*_args, **kwargs):
        seen["kwargs"] = kwargs
        return json.dumps({})

    payload = verify_change_path(
        tmp_path,
        file="src/app.py",
        project_context=True,
        analyze_func=fake_analyze,
    )

    assert payload["status"] == "pass"
    assert seen["kwargs"]["changed_files"] == ["src/app.py"]


def test_verify_change_stdin_payload_uses_manifest_file_for_schema():
    payload = verify_change_stdin_payload(
        {
            "path": "/repo",
            "file": "src/app.py",
            "range": "2:2",
            "code": "def handler(token):\n    return validate_token(token)\n",
        }
    )

    assert payload["status"] == "fail"
    assert payload["target"]["path"] == "/repo"
    assert payload["target"]["file"] == "src/app.py"
    assert payload["target"]["range"] == {"start_line": 2, "end_line": 2}
    assert any(f["range"]["file"] == "src/app.py" for f in payload["findings"])


def test_verify_change_stdin_payload_discovers_contract_from_manifest_path(tmp_path):
    app = tmp_path / "src" / "app.py"
    app.parent.mkdir()
    contract = tmp_path / ".skylos" / "ai-contract.yml"
    contract.parent.mkdir()
    contract.write_text(
        "version: 1\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n",
        encoding="utf-8",
    )
    seen = {}

    def fake_analyze(*_args, **kwargs):
        seen["kwargs"] = kwargs
        return json.dumps({})

    payload = verify_change_stdin_payload(
        {
            "path": str(tmp_path),
            "file": "src/app.py",
            "code": "def handler(request):\n    return verify_enterprise_auth(request)\n",
        },
        analyze_func=fake_analyze,
    )

    assert payload["status"] == "pass"
    assert seen["kwargs"]["project_config_overrides"] == {
        "vibe": {"extra_phantom_names": ["verify_enterprise_auth"]}
    }


def test_verify_change_stdin_payload_rejects_absolute_manifest_file():
    with pytest.raises(ValueError):
        verify_change_stdin_payload({"file": "/tmp/app.py", "code": "pass\n"})
