"""Config discovery: monorepo inheritance and skylos.toml / .skylos.toml."""

import subprocess

import pytest

from skylos.config import (
    POLICY_BASE_ENV_VAR,
    describe_config_sources,
    load_config,
)
from skylos.core.cli_shared import load_addopts


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest fixture under tmp_path


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.delenv(POLICY_BASE_ENV_VAR, raising=False)
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    return root


def test_package_pyproject_without_skylos_table_inherits_root(repo):
    _write(
        repo / "pyproject.toml",
        '[tool.skylos]\nconfidence = 90\nexclude = ["legacy"]\n',
    )
    _write(repo / "packages/api/pyproject.toml", '[project]\nname = "api"\n')

    config = load_config(repo / "packages/api")

    assert config["confidence"] == 90
    assert config["exclude"] == ["legacy"]


def test_nearest_file_wins_per_key_and_root_is_the_base(repo):
    _write(
        repo / "pyproject.toml",
        '[tool.skylos]\nconfidence = 90\nexclude = ["legacy"]\n'
        "[tool.skylos.gate]\nmax_quality = 10\n",
    )
    _write(
        repo / "packages/api/pyproject.toml",
        "[tool.skylos]\ncomplexity = 20\n[tool.skylos.gate]\nmax_security = 0\n",
    )

    config = load_config(repo / "packages/api/src")

    assert config["complexity"] == 20
    assert config["confidence"] == 90
    assert config["exclude"] == ["legacy"]
    # Tables merge by key: both gate limits apply.
    assert config["gate"] == {"max_quality": 10, "max_security": 0}


def test_list_set_in_package_replaces_root_list(repo):
    _write(repo / "pyproject.toml", '[tool.skylos]\nexclude = ["legacy"]\n')
    _write(repo / "packages/api/skylos.toml", 'exclude = ["gen"]\n')

    assert load_config(repo / "packages/api")["exclude"] == ["gen"]


def test_root_true_stops_inheritance(repo):
    _write(repo / "pyproject.toml", "[tool.skylos]\nconfidence = 90\n")
    _write(repo / "vendor/lib/skylos.toml", "root = true\ncomplexity = 30\n")

    config = load_config(repo / "vendor/lib")

    assert config["complexity"] == 30
    assert "confidence" not in config
    assert "root" not in config


def test_root_true_does_not_hide_synced_policy(repo):
    _write(repo / ".skylos/config.yaml", "exclude_paths:\n  - generated/**\n")
    _write(repo / "vendor/lib/skylos.toml", 'root = true\nexclude = ["x"]\n')

    config = load_config(repo / "vendor/lib")

    # Synced (operator) exclude wins over the repository's.
    assert config["exclude"] == ["generated/**"]


def test_skylos_toml_top_level_keys_for_a_typescript_repo(repo):
    _write(
        repo / "skylos.toml",
        'exclude = ["generated"]\nconfidence = 70\n[gate]\nmax_security = 0\n',
    )
    _write(repo / "package.json", '{"name": "web"}\n')

    config = load_config(repo / "src")

    assert config["exclude"] == ["generated"]
    assert config["confidence"] == 70
    assert config["gate"] == {"max_security": 0}


def test_skylos_toml_accepts_skylos_and_tool_skylos_tables(repo):
    _write(repo / "skylos.toml", "[skylos]\ncomplexity = 12\n")
    assert load_config(repo)["complexity"] == 12

    _write(repo / "skylos.toml", "[tool.skylos]\ncomplexity = 13\n")
    assert load_config(repo)["complexity"] == 13


def test_one_file_per_folder_dot_skylos_toml_first(repo):
    _write(repo / ".skylos.toml", "complexity = 11\n")
    _write(repo / "skylos.toml", "complexity = 12\nnesting = 9\n")
    _write(repo / "pyproject.toml", "[tool.skylos]\ncomplexity = 13\nmax_args = 9\n")

    config = load_config(repo)

    assert config["complexity"] == 11
    assert config["nesting"] == 3  # skylos.toml in the same folder is not read
    assert config["max_args"] == 5
    sources = describe_config_sources(repo)
    used = [s["path"].name for s in sources if s["used"]]
    ignored = {s["path"].name: s["reason"] for s in sources if not s["used"]}
    assert used == [".skylos.toml"]
    assert "takes precedence" in ignored["skylos.toml"]
    assert "takes precedence" in ignored["pyproject.toml"]


def test_explicit_config_file_named_skylos_toml_with_top_level_keys(repo, monkeypatch):
    _write(repo / "pyproject.toml", "[tool.skylos]\ncomplexity = 99\n")
    _write(repo / "ci/skylos.toml", "complexity = 7\n")
    monkeypatch.chdir(repo)

    config = load_config(repo, config_file="ci/skylos.toml")

    assert config["complexity"] == 7


def test_discovery_stops_at_the_repository_root(tmp_path, monkeypatch):
    monkeypatch.delenv(POLICY_BASE_ENV_VAR, raising=False)
    _write(tmp_path / "pyproject.toml", "[tool.skylos]\nconfidence = 10\n")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(repo / "skylos.toml", "complexity = 15\n")

    config = load_config(repo / "src")

    assert config["complexity"] == 15
    assert "confidence" not in config


def test_symlinked_skylos_toml_is_not_read(repo, tmp_path):
    outside = tmp_path / "outside.toml"
    outside.write_text("complexity = 99\n", encoding="utf-8")
    (repo / "skylos.toml").symlink_to(outside)

    assert load_config(repo)["complexity"] == 10
    reasons = [s.get("reason", "") for s in describe_config_sources(repo)]
    assert any("symlink" in reason for reason in reasons)


def test_addopts_follow_the_same_discovery(repo):
    _write(repo / "skylos.toml", 'addopts = ["--quality"]\n')
    _write(repo / "packages/api/pyproject.toml", '[project]\nname = "api"\n')

    assert load_addopts(repo / "packages/api") == ["--quality"]


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def git_repo(tmp_path, monkeypatch):
    monkeypatch.delenv(POLICY_BASE_ENV_VAR, raising=False)
    repo = tmp_path / "gitrepo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def test_base_policy_uses_the_same_inheritance_and_ignores_new_files(
    git_repo, monkeypatch
):
    _write(git_repo / "skylos.toml", 'exclude = ["legacy"]\nconfidence = 90\n')
    _write(git_repo / "packages/api/pyproject.toml", '[project]\nname = "api"\n')
    _write(git_repo / "packages/api/app.py", "x = 1\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "base")
    base = subprocess.run(
        ["git", "-C", str(git_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    # The pull request adds a package config that would exclude everything.
    _write(git_repo / "packages/api/skylos.toml", 'exclude = ["**"]\n')
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "pr")

    monkeypatch.setenv(POLICY_BASE_ENV_VAR, base)
    config = load_config(git_repo / "packages/api")

    assert config["exclude"] == ["legacy"]
    assert config["confidence"] == 90

    monkeypatch.delenv(POLICY_BASE_ENV_VAR)
    assert load_config(git_repo / "packages/api")["exclude"] == ["**"]
