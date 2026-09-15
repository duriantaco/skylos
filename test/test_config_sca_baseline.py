"""Synced policy provenance cannot be supplied or weakened by project TOML."""

import copy
import json

import pytest

from skylos import config as config_module
from skylos.config import dependency_baseline_policy_locked, load_config


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    root = tmp_path / "project"
    root.mkdir()
    return root


def _sync(project, yaml_text):
    directory = project / ".skylos"
    directory.mkdir(exist_ok=True)
    config_path = directory / "config.yaml"
    config_path.write_text(  # skylos: ignore[SKY-D324] all callers use the pytest project fixture
        yaml_text, encoding="utf-8"
    )


@pytest.mark.parametrize(
    "yaml_text",
    [
        "gate:\n  enabled: true\n",
        "gate:\n  enabled: false\n",
        "gate:\n  mode: advisory\n",
        "gate:\n  max_dependency_vulnerabilities: 0\n",
        "gate_enabled: true\n",
        "gate_enabled: false\n",
        "security_enabled: true\n",
        "secrets_enabled: true\n",
        "quality_enabled: true\n",
        "ai_defects_enabled: true\n",
        "security_contracts:\n  - name: required-policy\n",
    ],
)
@pytest.mark.parametrize("has_pyproject", [False, True])
def test_synced_policy_marks_loaded_config_on_each_success_path(
    project, yaml_text, has_pyproject
):
    _sync(project, yaml_text)
    if has_pyproject:
        config_path = project / "pyproject.toml"
        config_path.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
            "[tool.skylos]\ncomplexity = 17\n", encoding="utf-8"
        )

    config = load_config(project)

    assert dependency_baseline_policy_locked(config) is True
    assert isinstance(config, dict)
    assert config.dependency_baseline_locked is True


@pytest.mark.parametrize(
    "yaml_text",
    [
        "",
        "complexity: 7\n",
        "gate: {}\n",
        "security_enabled: false\nsecrets_enabled: false\n",
        "security_contracts: []\n",
        "dependency_baseline_locked: true\n",
        "_dependency_baseline_locked: true\n",
    ],
)
def test_synced_non_policy_config_does_not_lock_dependency_baseline(project, yaml_text):
    _sync(project, yaml_text)

    assert dependency_baseline_policy_locked(load_config(project)) is False


@pytest.mark.parametrize("has_pyproject", [False, True])
def test_without_synced_policy_local_configuration_is_not_locked(
    project, has_pyproject
):
    if has_pyproject:
        config_path = project / "pyproject.toml"
        config_path.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
            "[tool.skylos]\nsecurity_enabled = true\n"
            "[tool.skylos.gate]\nenabled = true\n",
            encoding="utf-8",
        )

    config = load_config(project)

    assert dependency_baseline_policy_locked(config) is False
    assert config.dependency_baseline_locked is False


@pytest.mark.parametrize("forged", ["true", "false"])
@pytest.mark.parametrize("synced", [False, True])
def test_repo_cannot_forge_or_disable_loader_owned_marker(project, forged, synced):
    if synced:
        _sync(project, "security_enabled: true\n")
    config_path = project / "pyproject.toml"
    config_path.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        "[tool.skylos]\n"
        f"dependency_baseline_locked = {forged}\n"
        f"_dependency_baseline_locked = {forged}\n"
        "security_enabled = false\n"
        "[tool.skylos.gate]\nenabled = false\n",
        encoding="utf-8",
    )

    config = load_config(project)

    assert config["dependency_baseline_locked"] is (forged == "true")
    assert config["_dependency_baseline_locked"] is (forged == "true")
    assert dependency_baseline_policy_locked(config) is synced
    assert config.dependency_baseline_locked is synced


def test_local_mutation_of_mapping_keys_does_not_change_loaded_marker(project):
    _sync(project, "gate:\n  enabled: true\n")
    config = load_config(project)
    config["dependency_baseline_locked"] = False
    config["_dependency_baseline_locked"] = False
    config["gate"] = {"enabled": False}

    assert dependency_baseline_policy_locked(config) is True
    with pytest.raises(AttributeError):
        config.dependency_baseline_locked = False


@pytest.mark.parametrize("synced", [False, True])
def test_invalid_implicit_toml_keeps_provenance_on_fallback_return(project, synced):
    if synced:
        _sync(project, "security_enabled: true\n")
    config_path = project / "pyproject.toml"
    config_path.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        "[tool.skylos\n", encoding="utf-8"
    )

    config = load_config(project)

    assert dependency_baseline_policy_locked(config) is synced


def test_explicit_config_cannot_override_synced_marker(project):
    _sync(project, "gate:\n  enabled: true\n")
    explicit = project / "scan.toml"
    explicit.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        "[skylos]\ndependency_baseline_locked = false\n"
        "_dependency_baseline_locked = false\n"
        "[skylos.gate]\nenabled = false\n",
        encoding="utf-8",
    )

    config = load_config(project, config_file=explicit)

    assert dependency_baseline_policy_locked(config) is True
    assert config["gate"]["enabled"] is True


@pytest.mark.parametrize("bad_yaml", ["- not-a-config\n", "[broken", "null\n"])
def test_invalid_synced_data_does_not_create_false_policy_provenance(project, bad_yaml):
    _sync(project, bad_yaml)

    assert dependency_baseline_policy_locked(load_config(project)) is False


def test_symlinked_sync_file_is_not_accepted_as_policy(project):
    policy = project / "other.yaml"
    policy.write_text(  # skylos: ignore[SKY-D324] literal fixture file written before any symlink exists
        "security_enabled: true\n", encoding="utf-8"
    )
    sync_dir = project / ".skylos"
    sync_dir.mkdir()
    (sync_dir / "config.yaml").symlink_to(policy)

    assert dependency_baseline_policy_locked(load_config(project)) is False


def test_non_policy_synced_values_do_not_make_repo_security_settings_trusted(project):
    _sync(project, "complexity: 7\n")
    config_path = project / "pyproject.toml"
    config_path.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        "[tool.skylos]\nsecurity_enabled = true\n[tool.skylos.gate]\nenabled = true\n",
        encoding="utf-8",
    )

    config = load_config(project)

    assert config["security_enabled"] is True
    assert config["gate"]["enabled"] is True
    assert dependency_baseline_policy_locked(config) is False


def test_marker_is_not_a_serialized_key_and_preserves_dict_compatibility(project):
    _sync(project, "gate:\n  enabled: true\n")
    config = load_config(project)

    assert "dependency_baseline_locked" not in config
    assert "_dependency_baseline_locked" not in config
    assert json.loads(json.dumps(config)) == dict(config)
    assert config == dict(config)
    assert dependency_baseline_policy_locked(copy.copy(config)) is True
    assert dependency_baseline_policy_locked(copy.deepcopy(config)) is True


def test_plain_mapping_cannot_supply_loaded_policy_provenance():
    class ForgedConfig(dict):
        dependency_baseline_locked = True

    for config in (
        {"dependency_baseline_locked": True},
        {"_dependency_baseline_locked": True},
        ForgedConfig(),
        None,
    ):
        assert dependency_baseline_policy_locked(config) is False


def test_generic_merge_failure_still_returns_synced_provenance(project, monkeypatch):
    _sync(project, "gate:\n  enabled: true\n")
    config_path = project / "pyproject.toml"
    config_path.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        "[tool.skylos]\n", encoding="utf-8"
    )

    def fail_toml(*args, **kwargs):
        raise RuntimeError("cannot read project config")

    monkeypatch.setattr(config_module, "_load_toml_user_config", fail_toml)

    config = load_config(project)

    assert dependency_baseline_policy_locked(config) is True
    assert config["gate"]["enabled"] is True
