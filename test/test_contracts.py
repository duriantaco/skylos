from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from skylos import cli
from skylos.commands import contract_cmd
from skylos.contracts import (
    ContractError,
    contract_enables_dependency_hallucinations,
    contract_project_config_overrides,
    load_contract,
)


def test_load_contract_parses_starter_sections(tmp_path):
    contract_file = tmp_path / ".skylos" / "ai-contract.yml"
    contract_file.parent.mkdir()
    contract_file.write_text(contract_cmd.starter_contract_text(), encoding="utf-8")

    contract = load_contract(contract_file)

    assert contract.version == 1
    assert "verify_enterprise_auth" in contract.ai.phantom_symbols.names
    assert "tenant_admin_required" in contract.ai.phantom_symbols.decorators
    assert contract.ai.dependencies.reject_nonexistent_packages is True
    assert contract.ai.api_surface.reject_unknown_kwargs is True
    assert contract.tests.high_risk_changes_require_tests is True


def test_contract_config_overrides_extend_vibe_dictionary(tmp_path):
    contract_file = tmp_path / "ai-contract.yml"
    contract_file.write_text(
        "version: 1\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n"
        "    decorators: [tenant_admin_required]\n",
        encoding="utf-8",
    )

    contract = load_contract(contract_file)

    assert contract_project_config_overrides(contract) == {
        "vibe": {
            "extra_phantom_names": ["verify_enterprise_auth"],
            "extra_phantom_decorators": ["tenant_admin_required"],
        }
    }
    assert contract_enables_dependency_hallucinations(contract) is False


def test_contract_dependency_or_api_surface_enables_dependency_scan(tmp_path):
    contract_file = tmp_path / "ai-contract.yml"
    contract_file.write_text(
        "version: 1\n"
        "ai:\n"
        "  api_surface:\n"
        "    reject_unknown_members: true\n",
        encoding="utf-8",
    )

    contract = load_contract(contract_file)

    assert contract_enables_dependency_hallucinations(contract) is True


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("version: 2\n", "version must be 1"),
        ("version: true\n", "version must be an integer"),
        ("version: 1\nunknown: true\n", "Unknown contract key: unknown"),
        (
            "version: 1\nsecurity:\n  routes:\n    paths: ['/tmp/app.py']\n",
            "security.routes.paths[0] must be relative",
        ),
        (
            "version: 1\nsecurity:\n  routes:\n    paths: ['../app.py']\n",
            "security.routes.paths[0] must stay inside the project",
        ),
    ],
)
def test_load_contract_rejects_invalid_contracts(tmp_path, text, message):
    contract_file = tmp_path / "ai-contract.yml"
    contract_file.write_text(text, encoding="utf-8")

    with pytest.raises(ContractError) as exc:
        load_contract(contract_file)
    assert message in str(exc.value)


def test_contract_init_creates_valid_starter_contract(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()
    dest = Path(".skylos") / "ai-contract.yml"

    exit_code = contract_cmd.init_contract(console, str(dest))

    assert exit_code == 0
    written = tmp_path / dest
    assert written.exists()
    assert contract_cmd.validate_contract(console, str(written)) == 0


def test_contract_init_refuses_to_overwrite_without_force(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()
    dest = tmp_path / "ai-contract.yml"
    dest.write_text("version: 1\n", encoding="utf-8")

    exit_code = contract_cmd.init_contract(console, str(dest))

    assert exit_code == 1
    assert dest.read_text(encoding="utf-8") == "version: 1\n"


def test_contract_init_rejects_paths_outside_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()

    exit_code = contract_cmd.init_contract(console, "../outside.yml")

    assert exit_code == 1
    assert not (tmp_path.parent / "outside.yml").exists()


def test_run_contract_command_validates_default_contract(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()

    assert (
        contract_cmd.run_contract_command(["init"], console_factory=lambda: console)
        == 0
    )
    assert (
        contract_cmd.run_contract_command(["validate"], console_factory=lambda: console)
        == 0
    )


def test_run_contract_command_inspects_contract_as_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()
    contract = Path("ai-contract.yml")
    contract.write_text(
        "version: 1\n"
        "id: enterprise-auth-contract\n"
        "ai:\n"
        "  phantom_symbols:\n"
        "    names: [verify_enterprise_auth]\n"
        "  dependencies:\n"
        "    reject_nonexistent_packages: true\n",
        encoding="utf-8",
    )

    exit_code = contract_cmd.run_contract_command(
        ["inspect", str(contract), "--json"],
        console_factory=lambda: console,
    )

    assert exit_code == 0
    payload = json.loads(console.print.call_args.args[0])
    assert payload["id"] == "enterprise-auth-contract"
    assert payload["clauses"]["ai.phantom_symbols.names"] == {
        "enabled": True,
        "values": ["verify_enterprise_auth"],
    }
    assert payload["analyzer_effects"]["dependency_hallucination_scan"] is True


def test_cli_contract_dispatch_preserves_argv(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["skylos", "contract", "validate", ".skylos/ai-contract.yml"],
    )

    with (
        patch(
            "skylos.commands.contract_cmd.run_contract_command", return_value=0
        ) as mock_contract,
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_contract.assert_called_once_with(
        ["validate", ".skylos/ai-contract.yml"],
        console_factory=Console,
    )
