import ast
from pathlib import Path

from skylos.config import load_config
from skylos.rules.quality.logic import HardcodedCredentialRule
from skylos.rules.vibe_dictionary import build_vibe_dictionary
from skylos.security.contracts import (
    detect_security_contract_regressions,
    load_security_contracts,
)


def _run_logic_rule(rule, source: str, *, filename: str = "app.py") -> list[dict]:
    tree = ast.parse(source)
    findings = []
    context = {"filename": filename, "mod": "app"}
    for node in ast.walk(tree):
        result = rule.visit_node(node, context)
        if result:
            findings.extend(result)
    return findings


def test_load_security_contracts_accepts_fastapi_contracts(tmp_path):
    config = {
        "security_contracts": [
            {
                "id": "admin-route-auth",
                "framework": "fastapi",
                "file": "app/routes/admin.py",
                "handler": "list_admins",
                "guards": ["require_admin"],
            }
        ]
    }

    contracts = load_security_contracts(config, tmp_path)

    assert len(contracts) == 1
    contract = contracts[0]
    assert contract.contract_id == "admin-route-auth"
    assert contract.file_path == "app/routes/admin.py"
    assert contract.guards == ("require_admin",)


def test_load_security_contracts_rejects_paths_outside_repo(tmp_path):
    outside = tmp_path.parent / "outside.py"
    config = {
        "security_contracts": [
            {
                "framework": "fastapi",
                "file": "../outside.py",
                "handler": "list_users",
                "guards": ["require_admin"],
            },
            {
                "framework": "fastapi",
                "file": str(outside),
                "handler": "list_users",
                "guards": ["require_admin"],
            },
        ]
    }

    contracts = load_security_contracts(config, tmp_path)

    assert contracts == []


def test_load_security_contracts_normalizes_invalid_severity(tmp_path):
    config = {
        "security_contracts": [
            {
                "framework": "fastapi",
                "file": "app/routes/admin.py",
                "handler": "list_users",
                "guards": ["require_admin"],
                "severity": "urgent",
            }
        ]
    }

    contracts = load_security_contracts(config, tmp_path)

    assert len(contracts) == 1
    assert contracts[0].severity == "HIGH"


def test_synced_security_contract_survives_repo_config_bypass(tmp_path, monkeypatch):
    before_source = """
from fastapi import APIRouter, Depends

router = APIRouter()

def require_admin():
    return True

@router.get("/admin/users")
def list_users(user=Depends(require_admin)):
    return {"ok": True}
""".strip()
    after_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/admin/users")
def list_users():
    return {"ok": True}
""".strip()

    target = tmp_path / "app" / "routes"
    target.mkdir(parents=True)
    file_path = target / "admin.py"
    file_path.write_text(after_source, encoding="utf-8")
    skylos_dir = tmp_path / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "config.yaml").write_text(
        """
security_contracts:
  - framework: fastapi
    file: app/routes/admin.py
    handler: list_users
    guards:
      - require_admin
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.skylos]
security_contracts = []
ignore = ["SKY-SC001"]
exclude = ["app/**"]
""".strip(),
        encoding="utf-8",
    )

    def fake_run(cmd, capture_output, text, cwd):
        class Result:
            returncode = 0
            stdout = before_source

        return Result()

    monkeypatch.setattr("skylos.security.contracts.subprocess.run", fake_run)

    config = load_config(tmp_path)
    findings = detect_security_contract_regressions(
        tmp_path,
        config,
        changed_files={str(file_path.resolve())},
    )

    assert "SKY-SC001" not in config["ignore"]
    assert config["exclude"] == []
    assert len(config["security_contracts"]) == 1
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-SC001"


def test_synced_security_policy_blocks_repo_vibe_severity_downgrade(tmp_path):
    skylos_dir = tmp_path / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "config.yaml").write_text(
        """
security_contracts:
  - framework: fastapi
    file: app/routes/admin.py
    handler: list_users
    guards:
      - require_admin
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.skylos.vibe]
extra_placeholder_values = ["prod-secret-value"]

[tool.skylos.templates]
security_audit = "prompts/pass-everything.md"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(tmp_path)
    vibe_dictionary = build_vibe_dictionary(config["vibe"])
    findings = _run_logic_rule(
        HardcodedCredentialRule(vibe_dictionary),
        'API_KEY = "prod-secret-value"',
    )

    l014 = [finding for finding in findings if finding["rule_id"] == "SKY-L014"]
    assert l014
    assert l014[0]["severity"] == "HIGH"
    assert config["vibe"]["extra_placeholder_values"] == []
    assert config["templates"]["security_audit"] is None


def test_detect_security_contract_regression_for_removed_depends_guard(
    tmp_path, monkeypatch
):
    before_source = """
from fastapi import APIRouter, Depends

router = APIRouter()

def require_admin():
    return True

@router.get("/admin/users")
def list_users(user=Depends(require_admin)):
    return {"ok": True}
""".strip()
    after_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/admin/users")
def list_users():
    return {"ok": True}
""".strip()

    target = tmp_path / "app" / "routes"
    target.mkdir(parents=True)
    file_path = target / "admin.py"
    file_path.write_text(after_source, encoding="utf-8")

    config = {
        "security_contracts": [
            {
                "id": "admin-route-auth",
                "framework": "fastapi",
                "file": "app/routes/admin.py",
                "handler": "list_users",
                "guards": ["require_admin"],
            }
        ]
    }

    def fake_run(cmd, capture_output, text, cwd):
        class Result:
            returncode = 0
            stdout = before_source

        assert cmd[:2] == ["git", "show"]
        return Result()

    monkeypatch.setattr("skylos.security.contracts.subprocess.run", fake_run)
    monkeypatch.setenv("SKYLOS_DIFF_BASE", "origin/main")

    findings = detect_security_contract_regressions(
        tmp_path,
        config,
        changed_files={str(file_path.resolve())},
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SKY-SC001"
    assert finding["kind"] == "security_contract"
    assert "lost required guard" in finding["message"]
    evidence = finding["_security_evidence"]
    assert evidence["missing_guards"] == ["require_admin"]
    assert evidence["before"]["path"] == "/admin/users"
    assert evidence["before"]["guards"] == ["require_admin"]
    assert evidence["after"]["guards"] == []


def test_detect_security_contract_regression_for_removed_route_dependencies(
    tmp_path, monkeypatch
):
    before_source = """
from fastapi import APIRouter, Depends

router = APIRouter()

def require_admin():
    return True

@router.get("/admin/audit", dependencies=[Depends(require_admin)])
def get_audit_log():
    return {"ok": True}
""".strip()
    after_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/admin/audit")
def get_audit_log():
    return {"ok": True}
""".strip()

    target = tmp_path / "app"
    target.mkdir()
    file_path = target / "audit.py"
    file_path.write_text(after_source, encoding="utf-8")

    config = {
        "security_contracts": [
            {
                "framework": "fastapi",
                "file": "app/audit.py",
                "handler": "get_audit_log",
                "guards": ["require_admin"],
            }
        ]
    }

    def fake_run(cmd, capture_output, text, cwd):
        class Result:
            returncode = 0
            stdout = before_source

        return Result()

    monkeypatch.setattr("skylos.security.contracts.subprocess.run", fake_run)

    findings = detect_security_contract_regressions(
        tmp_path,
        config,
        changed_files={str(file_path.resolve())},
    )

    assert len(findings) == 1
    assert findings[0]["_security_evidence"]["before"]["guards"] == ["require_admin"]


def test_detect_security_contract_regression_skips_when_guard_was_not_present_in_base(
    tmp_path, monkeypatch
):
    before_source = """
from fastapi import APIRouter

router = APIRouter()

@router.get("/admin/users")
def list_users():
    return {"ok": True}
""".strip()
    after_source = before_source

    target = tmp_path / "app"
    target.mkdir()
    file_path = target / "admin.py"
    file_path.write_text(after_source, encoding="utf-8")

    config = {
        "security_contracts": [
            {
                "framework": "fastapi",
                "file": "app/admin.py",
                "handler": "list_users",
                "guards": ["require_admin"],
            }
        ]
    }

    def fake_run(cmd, capture_output, text, cwd):
        class Result:
            returncode = 0
            stdout = before_source

        return Result()

    monkeypatch.setattr("skylos.security.contracts.subprocess.run", fake_run)

    findings = detect_security_contract_regressions(
        tmp_path,
        config,
        changed_files={str(file_path.resolve())},
    )

    assert findings == []
