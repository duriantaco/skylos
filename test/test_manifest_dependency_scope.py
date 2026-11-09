"""File verification checks the selected manifest or install surface only."""

import json
from pathlib import Path

import pytest

from skylos.rules.ai_defect import manifest_dependency_hallucination as manifest


def _missing_version(_ecosystem, _name, _version, _cache):
    return manifest.STATUS_MISSING_VERSION


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("requirements.txt", "requests==999.0.0\n"),
        ("pyproject.toml", '[project]\ndependencies = ["requests==999.0.0"]\n'),
        ("package.json", '{"dependencies":{"ghost-lib":"99.0.0"}}'),
        ("go.mod", "module example.com/app\nrequire example.com/ghost v99.0.0\n"),
        ("Cargo.toml", '[dependencies]\nghost = "99.0.0"\n'),
        ("composer.json", '{"require":{"ghost/lib":"99.0.0"}}'),
        ("Gemfile", 'gem "ghost", "99.0.0"\n'),
        ("pubspec.yaml", "dependencies:\n  ghost: 99.0.0\n"),
        (
            "pom.xml",
            (
                "<project><dependencies><dependency><groupId>org.example</groupId>"
                "<artifactId>ghost</artifactId><version>99.0.0</version>"
                "</dependency></dependencies></project>"
            ),
        ),
        (
            "app.csproj",
            (
                '<Project><ItemGroup><PackageReference Include="Ghost" '
                'Version="99.0.0" /></ItemGroup></Project>'
            ),
        ),
        (
            "build.gradle",
            "dependencies {\n  implementation 'org.example:ghost:99.0.0'\n}\n",
        ),
        ("README.md", "```sh\npip install requests==999.0.0\n```\n"),
        ("deploy.sh", "pip install requests==999.0.0\n"),
        ("Dockerfile", "FROM python:3\nRUN pip install requests==999.0.0\n"),
        (
            ".github/workflows/install.yml",
            "jobs:\n  build:\n    steps:\n      - run: pip install requests==999.0.0\n",
        ),
    ],
)
def test_selected_manifest_or_install_surface_matches_full_finding(
    tmp_path, name, source
):
    selected = tmp_path / name
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_text(source)
    full = manifest.scan_manifest_dependency_hallucinations(
        tmp_path, status_checker=_missing_version
    )
    expected = [finding for finding in full if Path(finding["file"]) == selected]
    assert expected
    assert all(f["rule_id"] == manifest.RULE_ID_VERSION_HALLUCINATION for f in expected)
    targeted = manifest.scan_manifest_dependency_hallucinations(
        tmp_path, target_files=[selected], status_checker=_missing_version
    )
    assert targeted == expected


@pytest.mark.parametrize("targets", [[], ["app.py"], ["app.ts"]])
def test_selected_source_does_not_walk_or_check_unrelated_manifests(
    tmp_path, monkeypatch, targets
):
    (tmp_path / "package.json").write_text('{"dependencies":{"ghost-lib":"99.0.0"}}')
    (tmp_path / "app.py").write_text("import selected_dependency\n")
    (tmp_path / "app.ts").write_text('import value from "selected-dependency";\n')

    def unexpected(*args, **kwargs):
        raise AssertionError("selected source must not inspect unrelated manifests")

    monkeypatch.setattr(manifest.os, "walk", unexpected)
    monkeypatch.setattr(manifest, "_load_version_cache", unexpected)
    assert (
        manifest.scan_manifest_dependency_hallucinations(
            tmp_path, target_files=targets, status_checker=unexpected
        )
        == []
    )


def test_selected_manifest_is_not_confused_with_same_named_sibling_or_outside(tmp_path):
    root = tmp_path / "repo"
    selected = root / "selected/package.json"
    sibling = root / "sibling/package.json"
    outside = tmp_path / "outside/package.json"
    for path, package in [
        (selected, "selected-ghost"),
        (sibling, "sibling-ghost"),
        (outside, "outside-ghost"),
    ]:
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"dependencies": {package: "99.0.0"}}))
    calls = []

    def checker(ecosystem, name, version, cache):
        calls.append(name)
        return manifest.STATUS_MISSING_VERSION

    findings = manifest.scan_manifest_dependency_hallucinations(
        root,
        target_files=["selected/package.json", selected, outside],
        status_checker=checker,
    )
    assert calls == ["selected-ghost"]
    assert [f["metadata"]["package_name"] for f in findings] == ["selected-ghost"]
    assert [f["file"] for f in findings] == [str(selected)]


@pytest.mark.parametrize(
    ("name", "source", "context_name", "context"),
    [
        (
            "package.json",
            '{"dependencies":{"private-lib":"99.0.0"}}',
            ".npmrc",
            "registry=https://packages.example.invalid\n",
        ),
        (
            "requirements.txt",
            "--index-url https://packages.example.invalid/simple\nprivate-lib==99.0.0\n",
            None,
            None,
        ),
    ],
)
def test_selected_manifest_preserves_private_registry_context(
    tmp_path, name, source, context_name, context
):
    selected = tmp_path / "app" / name
    selected.parent.mkdir()
    selected.write_text(source)
    if context_name:
        (tmp_path / context_name).write_text(context)

    def unexpected(*args):
        raise AssertionError(
            "a private source is not evidence of a public missing version"
        )

    assert (
        manifest.scan_manifest_dependency_hallucinations(
            tmp_path, target_files=[selected], status_checker=unexpected
        )
        == []
    )


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("node_modules/package.json", '{"dependencies":{"ghost-lib":"99.0.0"}}'),
        ("a/b/c/d/package.json", '{"dependencies":{"ghost-lib":"99.0.0"}}'),
        ("a/b/c/d/e/f/install.sh", "pip install requests==999.0.0\n"),
    ],
)
def test_selected_file_preserves_full_scan_depth_and_excluded_directory_limits(
    tmp_path, name, source
):
    selected = tmp_path / name
    selected.parent.mkdir(parents=True)
    selected.write_text(source)
    assert (
        manifest.scan_manifest_dependency_hallucinations(
            tmp_path, status_checker=_missing_version
        )
        == []
    )
    assert (
        manifest.scan_manifest_dependency_hallucinations(
            tmp_path, target_files=[selected], status_checker=_missing_version
        )
        == []
    )


def test_selected_manifest_does_not_make_a_range_an_exact_pin(tmp_path):
    selected = tmp_path / "package.json"
    selected.write_text('{"dependencies":{"ghost-lib":"^99.0.0"}}')
    assert (
        manifest.scan_manifest_dependency_hallucinations(
            tmp_path, target_files=[selected], status_checker=_missing_version
        )
        == []
    )


def test_default_directory_scan_still_reports_all_manifest_files(tmp_path):
    for name, package in [
        ("one/package.json", "first-ghost"),
        ("two/package.json", "second-ghost"),
    ]:
        path = tmp_path / name
        path.parent.mkdir()
        path.write_text(json.dumps({"dependencies": {package: "99.0.0"}}))
    findings = manifest.scan_manifest_dependency_hallucinations(
        tmp_path, status_checker=_missing_version
    )
    assert {f["metadata"]["package_name"] for f in findings} == {
        "first-ghost",
        "second-ghost",
    }


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("a/b/c/package.json", '{"dependencies":{"ghost-lib":"99.0.0"}}'),
        ("a/b/c/d/e/install.sh", "pip install requests==999.0.0\n"),
    ],
)
def test_selected_files_at_depth_limits_keep_the_same_finding(tmp_path, name, source):
    path = tmp_path / name
    path.parent.mkdir(parents=True)
    path.write_text(source)
    full = manifest.scan_manifest_dependency_hallucinations(
        tmp_path, status_checker=_missing_version
    )
    assert len(full) == 1
    assert (
        manifest.scan_manifest_dependency_hallucinations(
            tmp_path, target_files=[path], status_checker=_missing_version
        )
        == full
    )


@pytest.mark.parametrize("directory_link", [False, True])
def test_selected_manifest_does_not_follow_file_or_directory_symlinks(
    tmp_path, directory_link
):
    root = tmp_path / "repo"
    root.mkdir()
    real = root / "real"
    real.mkdir()
    (real / "package.json").write_text('{"dependencies":{"ghost-lib":"99.0.0"}}')
    if directory_link:
        link = root / "linked"
        target = link / "package.json"
    else:
        link = root / "package.json"
        target = link
    try:
        link.symlink_to(
            real if directory_link else real / "package.json",
            target_is_directory=directory_link,
        )
    except OSError:
        pytest.skip("filesystem does not allow symlink creation")
    assert (
        manifest.scan_manifest_dependency_hallucinations(
            root, target_files=[target], status_checker=_missing_version
        )
        == []
    )
