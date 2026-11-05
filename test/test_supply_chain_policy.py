import textwrap

import pytest

from skylos.supply_chain.policy import (
    DEFAULT_HOOK_RELEASE_AGE_HOURS,
    load_supply_chain_policy,
)


def _repo(tmp_path, pyproject=None, synced=None):
    (tmp_path / ".git").mkdir()
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_text(textwrap.dedent(pyproject))
    if synced is not None:
        (tmp_path / ".skylos").mkdir()
        (tmp_path / ".skylos" / "config.yaml").write_text(textwrap.dedent(synced))
    return tmp_path


@pytest.fixture(autouse=True)
def _no_operator_policy(monkeypatch):
    monkeypatch.delenv("SKYLOS_SYNCED_POLICY_FILE", raising=False)


def test_unconfigured_repo_uses_defaults(tmp_path):
    policy = load_supply_chain_policy(_repo(tmp_path))
    assert policy.block_malware is True
    assert policy.check_provenance is True
    assert policy.min_release_age_hours is None
    assert policy.hook_release_age_hours() == DEFAULT_HOOK_RELEASE_AGE_HOURS
    assert policy.scan_release_age_hours() is None
    assert policy.sources == ()


def test_repo_can_turn_the_hook_hold_off_when_cloud_is_silent(tmp_path):
    root = _repo(
        tmp_path,
        pyproject="""
        [tool.skylos.supply_chain]
        min_release_age_hours = 0
        block_malware = false
        """,
    )
    policy = load_supply_chain_policy(root)
    assert policy.hook_release_age_hours() == 0
    assert policy.scan_release_age_hours() is None
    assert policy.block_malware is False
    assert policy.sources == ("pyproject",)


def test_repo_cannot_loosen_cloud_policy(tmp_path):
    root = _repo(
        tmp_path,
        pyproject="""
        [tool.skylos.supply_chain]
        min_release_age_hours = 0
        block_malware = false
        check_provenance = false
        internal_packages = ["local-*"]
        private_registries = ["https://attacker.example/simple"]
        trusted_registries = ["https://attacker.example/simple"]
        """,
        synced="""
        supply_chain:
          block_malware: true
          check_provenance: true
          min_release_age_hours: 48
          internal_packages: ["acme-*"]
          private_registries: ["https://pypi.acme.dev/simple"]
          trusted_registries: []
        """,
    )
    policy = load_supply_chain_policy(root)
    assert policy.block_malware is True
    assert policy.check_provenance is True
    assert policy.min_release_age_hours == 48
    assert policy.internal_packages == ("local-*", "acme-*")
    assert policy.private_registries == ("https://pypi.acme.dev/simple",)
    assert policy.trusted_registries == ()
    assert policy.sources == ("pyproject", "cloud")


def test_operator_policy_file_replaces_checkout_policy(tmp_path, monkeypatch):
    root = _repo(
        tmp_path,
        synced="""
        supply_chain:
          min_release_age_hours: 1
        """,
    )
    operator = tmp_path / "operator" / "config.yaml"
    operator.parent.mkdir()
    operator.write_text("supply_chain:\n  min_release_age_hours: 72\n")
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(operator))
    assert load_supply_chain_policy(root).min_release_age_hours == 72


@pytest.mark.parametrize(
    "value",
    ["24", -1, 24 * 365 + 1, True, 1.5],
)
def test_invalid_release_age_is_reported_and_ignored(tmp_path, value):
    if isinstance(value, str):
        rendered = f'"{value}"'
    elif isinstance(value, bool):
        rendered = str(value).lower()
    else:
        rendered = str(value)
    root = _repo(
        tmp_path,
        pyproject=f"[tool.skylos.supply_chain]\nmin_release_age_hours = {rendered}\n",
    )
    policy = load_supply_chain_policy(root)
    assert policy.min_release_age_hours is None
    assert policy.problems


def _commit(root, message):
    import subprocess

    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", message],
        cwd=root,
        check=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_pull_request_cannot_relax_the_base_branch_policy(tmp_path, monkeypatch):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos.supply_chain]\ninternal_packages = ["acme-*"]\nmin_release_age_hours = 48\n'
    )
    base = _commit(tmp_path, "base")
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n")
    _commit(tmp_path, "head relaxes policy")
    monkeypatch.setenv("SKYLOS_POLICY_BASE", base)

    policy = load_supply_chain_policy(tmp_path)

    assert policy.internal_packages == ("acme-*",)
    assert policy.min_release_age_hours == 48


def test_unreadable_operator_policy_file_stops_instead_of_dropping_cloud_policy(
    tmp_path, monkeypatch
):
    from skylos.config import ConfigError

    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(tmp_path / "missing" / "config.yaml"))
    with pytest.raises(ConfigError):
        load_supply_chain_policy(_repo(tmp_path))


def test_cloud_registry_lists_are_marked_even_when_empty(tmp_path):
    synced_empty = load_supply_chain_policy(
        _repo(tmp_path, synced="supply_chain:\n  trusted_registries: []\n")
    )
    assert synced_empty.registries_from_cloud is True
    assert synced_empty.trusted_registries == ()


def test_repo_registry_lists_are_not_cloud_lists(tmp_path):
    policy = load_supply_chain_policy(
        _repo(tmp_path, pyproject='[tool.skylos.supply_chain]\ntrusted_registries = ["https://m.example"]\n')
    )
    assert policy.registries_from_cloud is False
