from pathlib import Path

from skylos.sonar_import import (
    build_sonar_migration_plan,
    parse_sonar_properties,
    split_sonar_list,
)


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
    assert plan["skylos"]["recommended_command"] == "skylos apps/api --danger --quality --upload"
    assert plan["skylos"]["suite_command"] == "skylos suite apps/api --upload"
    assert plan["skylos"]["config"]["exclude"] == [
        "**/generated/**",
        "**/migrations/**",
    ]

