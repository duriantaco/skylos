"""The rule handbook keeps up with the rule catalog and the CLI.

These checks read YAML, the rule catalog and the command parsers; they never
run a scan. A new catalog rule fails here until it has a page in
docs/handbook/rules/ or a reasoned entry in docs/handbook/pending.yaml.

The "Using Skylos Cloud" guide is checked against docs/handbook/cloud/manifest.yaml:
every Cloud destination listed there needs a section in the guide. With
SKYLOS_CLOUD_REPO pointing at a Skylos Cloud checkout, the manifest itself is
checked against that checkout's sidebar and settings pages.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
HANDBOOK_DIR = REPO_ROOT / "docs" / "handbook"
RULES_DIR = HANDBOOK_DIR / "rules"


@pytest.fixture(scope="module")
def builder():
    spec = importlib.util.spec_from_file_location(
        "build_handbook", REPO_ROOT / "scripts" / "build_handbook.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def catalog(builder):
    return builder.load_catalog()


@pytest.fixture(scope="module")
def aliases(builder, catalog):
    return builder.catalog_aliases(catalog)


@pytest.fixture(scope="module")
def pages():
    loaded = {}
    for path in sorted(RULES_DIR.glob("*.yaml")):
        loaded[path.stem] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded


@pytest.fixture(scope="module")
def pending(builder, catalog):
    return builder.load_pending(catalog)


def test_every_catalog_rule_has_a_page_or_a_pending_entry(
    catalog, aliases, pages, pending
):
    needed = set(catalog) - set(aliases)
    missing = sorted(needed - set(pages) - set(pending))
    assert not missing, (
        "Rules with neither a handbook page (docs/handbook/rules/<ID>.yaml) nor a "
        f"reasoned entry in docs/handbook/pending.yaml: {missing}"
    )


def test_pending_entries_name_catalog_rules_with_a_reason(builder, catalog):
    data = yaml.safe_load((HANDBOOK_DIR / "pending.yaml").read_text(encoding="utf-8"))
    for rule_id, entry in data["pending"].items():
        assert rule_id in catalog, (
            f"pending.yaml names {rule_id}, which is not in the catalog"
        )
        assert str((entry or {}).get("reason") or "").strip(), (
            f"{rule_id} needs a reason"
        )


def test_every_page_is_a_catalog_rule_and_not_a_renamed_go_id(catalog, aliases, pages):
    for rule_id, page in pages.items():
        assert page.get("id") == rule_id, f"{rule_id}.yaml has id {page.get('id')}"
        assert rule_id in catalog, (
            f"{rule_id}.yaml documents a rule that is not in the catalog"
        )
        assert rule_id not in aliases, (
            f"{rule_id} is reported as {aliases.get(rule_id)}; describe it on that page"
        )


def test_source_refs_still_exist(pages):
    for rule_id, page in pages.items():
        for ref in page.get("source_refs") or []:
            target = REPO_ROOT / ref["path"]
            assert target.is_file(), f"{rule_id}: {ref['path']} no longer exists"
            text = target.read_text(encoding="utf-8", errors="replace")
            assert ref["symbol"] in text, (
                f"{rule_id}: '{ref['symbol']}' is no longer in {ref['path']}"
            )


def test_related_rules_exist(catalog, pages):
    for rule_id, page in pages.items():
        for other in page.get("related") or []:
            assert other in catalog, (
                f"{rule_id}: related rule {other} is not in the catalog"
            )


def test_pages_pass_the_build_validation(builder, catalog):
    families = builder.load_families(catalog)
    _pages, problems = builder.load_pages(catalog, families, set())
    assert not problems["errors"], problems["errors"]


def test_every_top_level_command_is_in_a_chapter_or_the_command_reference(builder):
    reference = builder.command_reference()
    chapters = " ".join(
        path.read_text(encoding="utf-8")
        for path in sorted((HANDBOOK_DIR / "intro").glob("*.md"))
    )
    uncovered = []
    for command in reference["commands"]:
        key = command["key"]
        if not key:
            continue
        mentioned = f"skylos {key}" in chapters
        described = bool(command["entries"]) or command["parser"] is not None
        if not mentioned and not described:
            uncovered.append(key)
    assert not uncovered, (
        "These commands have no help-table entry, no parser the handbook can "
        f"read, and no chapter that mentions them: {uncovered}"
    )


def cloud_manifest():
    path = HANDBOOK_DIR / "cloud" / "manifest.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_every_cloud_destination_has_a_guide_section(builder):
    problems = builder.cloud_problems()
    assert not problems, problems


def test_cloud_guide_names_the_commit_it_was_verified_against(builder):
    manifest = cloud_manifest()
    text = builder.cloud_verified_text(manifest)
    assert str(manifest["verified_against"]["commit"]) in text
    first = sorted((HANDBOOK_DIR / "cloud").glob("*.md"))[0]
    assert "{{cloud_verified}}" in first.read_text(encoding="utf-8"), (
        f"{first.name} must print the verified commit with {{{{cloud_verified}}}}"
    )


def cloud_checkout_destinations(repo: Path) -> dict[str, set[str]]:
    navigation = (repo / "src/lib/dashboard-navigation.ts").read_text(encoding="utf-8")
    settings = (repo / "src/lib/settings-sections.ts").read_text(encoding="utf-8")
    sidebar = set(
        re.findall(r'\{ key: "\w+", href: "[^"]+", label: "([^"]+)" \}', navigation)
    )
    pages = set(re.findall(r'\[/\^[^\n]+?/, "([^"]+)"\]', navigation))
    setting_labels = set(re.findall(r'label: "([^"]+)"', settings))
    project = (repo / "src/lib/project-navigation.ts").read_text(encoding="utf-8")
    project_labels = set(re.findall(r'\{ key: "\w+", label: "([^"]+)"', project))
    project_labels |= set(re.findall(r'\{ segment: "[^"]+", label: "([^"]+)"', project))
    return {
        "sidebar": sidebar,
        "page": pages,
        "settings": setting_labels,
        "project": project_labels,
    }


def test_cloud_manifest_matches_the_cloud_checkout():
    checkout = os.environ.get("SKYLOS_CLOUD_REPO")
    if not checkout:
        pytest.skip(
            "set SKYLOS_CLOUD_REPO to a Skylos Cloud checkout to run this check"
        )
    repo = Path(checkout)
    manifest = cloud_manifest()
    listed: dict[str, set[str]] = {}
    for feature in manifest["features"]:
        listed.setdefault(feature.get("source", ""), set()).add(feature["label"])
    missing = []
    for source, labels in cloud_checkout_destinations(repo).items():
        assert labels, (
            f"no {source} destinations found in {repo}; the parser needs an update"
        )
        for label in sorted(labels - listed.get(source, set())):
            missing.append(f"{source}: {label}")
    assert not missing, (
        "Skylos Cloud destinations with no entry in docs/handbook/cloud/manifest.yaml: "
        f"{missing}"
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--short=8", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    verified = str(manifest["verified_against"]["commit"])
    assert head == verified, (
        f"the guide was verified against Skylos Cloud {verified} but the checkout is "
        f"at {head}: re-check the guide, retake the screenshots and update the manifest"
    )
