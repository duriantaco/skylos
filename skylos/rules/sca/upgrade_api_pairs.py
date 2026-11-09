"""Which locked Python versions changed base to head, for the API comparison.

Lockfile pairs come from the upgrade review; ``==`` pins in requirements files are
added here. What cannot be paired is a could-not-check row.
"""

from __future__ import annotations

import importlib
from pathlib import Path, PurePosixPath

from skylos.rules.sca.supply_chain_diff import (
    _UPGRADE_PARSERS,
    MAX_REVIEW_PACKAGES,
    GitSides,
    unsupported_upgrade_path,
    upgrade_limitations,
    upgrade_pairs,
    upgrade_path,
)

_NOT_PUBLIC_REASONS = frozenset({"non_registry_source", "non_public_registry"})


def _requirements_file(path: str) -> bool:
    reason = unsupported_upgrade_path(path)
    return bool(reason) and reason.startswith("requirements")


def _requirement_pins(path: str, text: str) -> tuple[dict[str, tuple[str, int]], bool]:
    from skylos.core.python_requirements import parse_requirements_text
    from skylos.rules.sca.vulnerability_scanner import _extract_pinned_version

    parsed = parse_requirements_text(text, Path(path))
    pins: dict[str, tuple[str, int]] = {}
    for line in parsed.requirements:
        version = None
        if not line.url:
            version = _extract_pinned_version(line.spec)
        if version:
            pins[line.normalized] = (version, line.line)
    return pins, bool(parsed.private_index)


def _requirement_pairs(sides: GitSides) -> tuple[list[dict], list[dict]]:
    base, head = sides.files(_requirements_file)
    pairs: list[dict] = []
    limits: list[dict] = []
    for path, head_text in sorted(head.items()):
        base_text = base.get(path)
        if base_text is None or base_text == head_text:
            continue
        old_pins, _old_private = _requirement_pins(path, base_text)
        new_pins, new_private = _requirement_pins(path, head_text)
        changed = {
            name: value
            for name, value in new_pins.items()
            if name in old_pins and old_pins[name][0] != value[0]
        }
        if changed and new_private:
            limits.append(
                {
                    "subject": path,
                    "reason": "it sets a custom package index, so PyPI is not asked",
                }
            )
            continue
        pairs.extend(
            {
                "ecosystem": "pypi",
                "name": name,
                "old": old_pins[name][0],
                "new": version,
                "file": path,
                "line": line,
            }
            for name, (version, line) in sorted(changed.items())
        )
    return pairs, limits


def _not_public_entries(path: str, text: str | None) -> set[tuple[str, str]]:
    if text is None:
        return set()
    ecosystem, module_name, function_name = _UPGRADE_PARSERS[PurePosixPath(path).name]
    if ecosystem != "pypi":
        return set()
    parser = getattr(importlib.import_module(module_name), function_name)
    inventory = parser(Path(path), text=text, max_packages=MAX_REVIEW_PACKAGES)
    return {
        (str(item.get("name") or ""), str(item.get("version") or ""))
        for item in getattr(inventory, "not_checked", None) or []
        if isinstance(item, dict) and item.get("reason") in _NOT_PUBLIC_REASONS
    }


def _not_public_rows(sides: GitSides) -> list[dict]:
    base, head = sides.files(upgrade_path)
    rows = []
    for path, head_text in sorted(head.items()):
        base_text = base.get(path)
        if base_text == head_text:
            continue
        try:
            added = _not_public_entries(path, head_text) - _not_public_entries(
                path, base_text
            )
        except Exception as exc:  # noqa: BLE001 - advice only: a lockfile its parser rejects is a could-not-check row
            rows.append(
                {
                    "subject": path,
                    "reason": f"could not be parsed ({type(exc).__name__})",
                }
            )
            continue
        rows.extend(
            {
                "subject": f"{name} {version}".strip(),
                "reason": "it comes from a non-public source, so it is not looked up",
            }
            for name, version in sorted(added)
        )
    return rows


def api_pairs(sides: GitSides) -> tuple[list[dict], list[dict], int]:
    """(pairs to compare, could-not-check rows, newly added packages)."""
    locked, dropped = upgrade_pairs(sides)
    unread, unsupported = upgrade_limitations(sides)
    required, limits = _requirement_pairs(sides)
    rows = list(limits)
    for item in (*unread, *unsupported):
        if not _requirements_file(item["file"]):
            rows.append({"subject": item["file"], "reason": str(item["reason"])})
    for item in sides.unread_changes(_requirements_file):
        rows.append({"subject": item["file"], "reason": str(item["reason"])})
    rows.extend(_not_public_rows(sides))
    if dropped:
        rows.append(
            {
                "subject": f"{dropped} more dependency changes",
                "reason": "over the limit of the upgrade review",
            }
        )
    rows = list({(row["subject"], row["reason"]): row for row in rows}.values())
    pairs: dict[tuple[str, str, str | None, str], dict] = {}
    for pair in (*locked, *required):
        key = (pair["ecosystem"], pair["name"], pair["old"], pair["new"])
        pairs.setdefault(key, pair)
    added = sum(1 for pair in pairs.values() if pair["old"] is None)
    changed = [pair for pair in pairs.values() if pair["old"] is not None]
    return changed, rows, added
