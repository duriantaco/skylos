#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


RULE_ID_RE = re.compile(r"SKY-CIRC|SKY-[A-Z]+[0-9]{3}")


def main() -> int:
    """
    Check that documented rule IDs match the rule catalog.

    Calls: scripts/check_rule_docs_parity.py _default_rules_reference_path;
        skylos/rules/catalog.py get_rule_catalog.
        
    Called from: scripts/check_rule_docs_parity.py __main__.
    """
    parser = argparse.ArgumentParser(
        description="Check Skylos rule catalog IDs against docs/rules-reference.mdx."
    )
    parser.add_argument(
        "--rules-reference",
        type=Path,
        default=_default_rules_reference_path(),
        help="Path to skylos-docs/docs/rules-reference.mdx.",
    )
    parser.add_argument(
        "--allow-catalog-extra",
        action="store_true",
        help="Allow catalog IDs that are not yet documented.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))

    from skylos.rules.catalog import get_rule_catalog

    rules_reference = args.rules_reference.expanduser()
    if not rules_reference.is_file():
        print(f"Rules reference not found: {rules_reference}", file=sys.stderr)
        return 2

    docs_text = rules_reference.read_text(encoding="utf-8")
    docs_ids = set(RULE_ID_RE.findall(docs_text))
    catalog_ids = set()

    for item in get_rule_catalog():
        rule_id = str(item.get("id", ""))
        if rule_id:
            catalog_ids.add(rule_id)

    missing_from_catalog = sorted(docs_ids - catalog_ids)
    missing_from_docs = sorted(catalog_ids - docs_ids)

    print(f"Docs rule IDs: {len(docs_ids)}")
    print(f"Catalog rule IDs: {len(catalog_ids)}")

    failed = False

    if missing_from_catalog:
        failed = True
        print("Docs IDs missing from catalog:")
        for rule_id in missing_from_catalog:
            print(f"  {rule_id}")

    if missing_from_docs:
        if args.allow_catalog_extra:
            print("Catalog IDs not yet documented:")
        else:
            failed = True
            print("Catalog IDs missing from docs:")

        for rule_id in missing_from_docs:
            print(f"  {rule_id}")

    if failed:
        return 1

    print("Rule catalog and docs are in parity.")
    return 0


def _default_rules_reference_path() -> Path:
    configured = os.environ.get("SKYLOS_RULES_REFERENCE")
    if configured:
        return Path(configured)

    repo_root = Path(__file__).resolve().parents[1]
    return repo_root.parent / "skylos-docs" / "docs" / "rules-reference.mdx"


if __name__ == "__main__":
    raise SystemExit(main())
