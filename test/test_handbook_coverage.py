"""The rule handbook keeps up with the rule catalog and the CLI.

These checks read YAML, the rule catalog and the command parsers; they never
run a scan. A new catalog rule fails here until it has a page in
docs/handbook/rules/ or a reasoned entry in docs/handbook/pending.yaml.
"""

from __future__ import annotations

import importlib.util
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
