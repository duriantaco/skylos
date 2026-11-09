import json
from pathlib import Path

from rich.console import Console

from skylos.commands.sonar_cmd import run_sonar_command
from skylos.config import dependency_baseline_policy_locked, load_config
from skylos.integrations.sonar import (
    build_sonar_migration_plan,
    parse_sonar_properties,
    skylos_toml_text,
    split_sonar_list,
)

try:
    import tomllib
except ImportError:
    import tomli as tomllib


def test_parse_sonar_properties_handles_comments_and_lists(tmp_path: Path):
    props = tmp_path / "sonar-project.properties"
    props.write_text(
        "\n".join(
            [
                "# comment",
                "sonar.projectKey = acme-api",
                "sonar.sources=src,apps/api",
                "sonar.exclusions=**/generated/**, dist/**",
            ]
        ),
        encoding="utf-8",
    )

    parsed = parse_sonar_properties(props)

    assert parsed["sonar.projectKey"] == "acme-api"
    assert parsed["sonar.sources"] == "src,apps/api"
    assert split_sonar_list(parsed["sonar.exclusions"]) == [
        "**/generated/**",
        "dist/**",
    ]


def test_build_sonar_migration_plan_maps_sources_and_exclusions():
    plan = build_sonar_migration_plan(
        {
            "sonar.projectKey": "acme-api",
            "sonar.projectName": "Acme API",
            "sonar.sources": "apps/api",
            "sonar.tests": "apps/api/tests",
            "sonar.exclusions": "**/generated/**",
            "sonar.coverage.exclusions": "**/migrations/**",
        }
    )

    assert plan["sonar"]["project_key"] == "acme-api"
    assert (
        plan["skylos"]["recommended_command"]
        == "skylos apps/api --danger --quality --ai-defects --upload"
    )
    assert plan["skylos"]["suite_command"] == "skylos suite apps/api --upload"
    assert plan["skylos"]["config"]["exclude"] == [
        "**/generated/**",
        "**/migrations/**",
    ]


PROPERTIES = (
    "sonar.projectKey=acme\n"
    "sonar.sources=src\n"
    "sonar.exclusions=**/generated/**\n"
    "sonar.coverage.exclusions=**/migrations/**\n"
)
LOCAL_POLICY = (
    "[tool.skylos]\n"
    'exclude = ["legacy"]\n\n'
    "[tool.skylos.gate]\n"
    "max_high = 0\n"
    "max_quality = 2\n"
)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "sonar-project.properties").write_text(PROPERTIES, encoding="utf-8")
    return root


def _run(root: Path, *args: str, capsys) -> tuple[int, str]:
    code = run_sonar_command(
        ["import", str(root / "sonar-project.properties"), *args],
        console_factory=lambda: Console(width=100),
    )
    return code, capsys.readouterr().out


def test_write_config_never_replaces_local_gate_or_excludes(tmp_path, capsys):
    root = _repo(tmp_path)
    (root / "pyproject.toml").write_text(LOCAL_POLICY, encoding="utf-8")
    before = load_config(root)

    code, out = _run(root, "--write-config", capsys=capsys)
    after = load_config(root)

    assert code == 1
    assert not (root / ".skylos").exists()
    assert not (root / "skylos.toml").exists()
    assert after["gate"] == before["gate"] == {"max_high": 0, "max_quality": 2}
    assert after["exclude"] == ["legacy"]
    assert dependency_baseline_policy_locked(after) is False
    assert "Not written: Skylos settings already apply here" in out
    assert 'exclude = ["**/generated/**", "**/migrations/**"]' in out


def test_parent_settings_also_block_a_nearer_file(tmp_path, capsys):
    root = _repo(tmp_path)
    (root / "skylos.toml").write_text('exclude = ["legacy"]\n', encoding="utf-8")
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "sonar-project.properties").write_text(PROPERTIES, encoding="utf-8")

    code, _ = _run(nested, "--write-config", capsys=capsys)

    assert code == 1
    assert not (nested / "skylos.toml").exists()
    assert load_config(nested)["exclude"] == ["legacy"]


def test_write_config_creates_a_local_skylos_toml_when_none_applies(tmp_path, capsys):
    root = _repo(tmp_path)

    code, out = _run(root, "--write-config", capsys=capsys)
    config = load_config(root)

    assert code == 0
    assert (root / "skylos.toml").read_text(encoding="utf-8") == (
        'exclude = ["**/generated/**", "**/migrations/**"]\n'
    )
    assert not (root / ".skylos").exists()
    assert config["exclude"] == ["**/generated/**", "**/migrations/**"]
    assert dependency_baseline_policy_locked(config) is False
    report = json.loads(out[: out.rindex("}") + 1])
    assert report["skylos"]["config"] == {
        "exclude": ["**/generated/**", "**/migrations/**"]
    }
    assert any("[tool.skylos.gate]" in note for note in report["manual_review"])


def test_config_output_must_be_a_new_toml_file(tmp_path, capsys):
    root = _repo(tmp_path)
    existing = root / "custom.toml"
    existing.write_text("keep = true\n", encoding="utf-8")

    yaml_code, _ = _run(
        root,
        "--write-config",
        "--config-output",
        str(root / ".skylos/config.yaml"),
        capsys=capsys,
    )
    exists_code, _ = _run(
        root, "--write-config", "--config-output", str(existing), capsys=capsys
    )
    new_code, _ = _run(
        root,
        "--write-config",
        "--config-output",
        str(root / "sonar.toml"),
        capsys=capsys,
    )

    assert yaml_code == 2
    assert not (root / ".skylos").exists()
    assert exists_code == 1
    assert existing.read_text(encoding="utf-8") == "keep = true\n"
    assert new_code == 0
    assert (root / "sonar.toml").exists()


def test_toml_text_round_trips_awkward_patterns():
    patterns = ['a "quoted"\\dir/**', "tab\there", "del\x7fchar", "emoji-\U0001f600/**"]

    text = skylos_toml_text({"exclude": patterns})

    assert tomllib.loads(text) == {"exclude": patterns}
