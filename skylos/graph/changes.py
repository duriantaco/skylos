from __future__ import annotations

import collections
import logging
from datetime import datetime, timezone
from pathlib import Path

from skylos.changemap.review import (
    SAME_VERDICTS,
    VERDICT_BINDING,
    VERDICT_CHANGED,
    VERDICT_MOVED,
    VERDICT_NEW,
    VERDICT_REMOVED,
    VERDICT_SAME_DOCS,
    VERDICT_SAME_RENAMED,
    VERDICT_TEXT,
    verdict_for,
)
from skylos.graph.extract import code_hash
from skylos.graph.store import CHANGES_FILE, ensure_dir, write_json

logger = logging.getLogger(__name__)

__all__ = [
    "SAME_VERDICTS",
    "VERDICT_BINDING",
    "VERDICT_CHANGED",
    "VERDICT_MOVED",
    "VERDICT_NEW",
    "VERDICT_REMOVED",
    "VERDICT_SAME_DOCS",
    "VERDICT_SAME_RENAMED",
    "VERDICT_TEXT",
    "build_changes",
    "verdict_for",
]


def _reach_lines(entry: dict, index) -> list[str]:
    node_id = entry.get("node_id")
    verdict = entry["verdict"]
    if index is None or not node_id or verdict in SAME_VERDICTS or verdict == VERDICT_REMOVED:
        return []
    tests = index.tests_reaching(node_id)
    if not tests:
        return ["No test reaches this code."]
    expected = index.graph.get("expectations", {}).get(node_id, [])
    if expected and not entry.get("test_evidence"):
        return [f"{len(expected)} test check(s) with fixed answers cover it and were not edited. Run them to confirm they still pass."]
    return [f"{len(tests)} test(s) reach this code."]


def build_changes(root: str | Path, base: str, index=None) -> dict:
    from skylos.changemap import build_change_map

    root = Path(root).resolve()
    change_map = build_change_map(root, base)
    symbols = []
    for entry in change_map["symbols"]:
        node_id = None
        if index is not None and entry.get("full_name") in index.nodes:
            node_id = entry["full_name"]
        item = dict(entry)
        item["node_id"] = node_id
        item["evidence"] = list(entry.get("test_evidence") or []) + _reach_lines(item, index)
        before_code = (entry.get("before") or {}).get("code") or ""
        after_code = (entry.get("after") or {}).get("code") or ""
        item["change_key"] = f"{entry['id']}@{code_hash(before_code)}:{code_hash(after_code)}"
        symbols.append(item)
    counts = collections.Counter(s["verdict"] for s in symbols if not s["is_test"])
    review = change_map["review"]
    result = {
        "schema_version": 1,
        "base": base,
        "base_commit": change_map.get("base_commit"),
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "symbols": symbols,
        "read_first": change_map.get("read_first", []),
        "flagged": change_map.get("flagged", []),
        "counts": dict(counts),
        "review": {key: value for key, value in review.items() if key != "test_edits"},
        "test_edits": review["test_edits"],
        "coverage": change_map.get("coverage"),
    }
    ensure_dir(root)
    write_json(Path(root) / ".skylos" / "graph" / CHANGES_FILE, result)
    _remember_review(root, change_map)
    return result


def _remember_review(root: Path, change_map: dict) -> None:
    try:
        from skylos.graph.pipeline import save_review

        save_review(root, change_map)
    except Exception:
        logger.debug("could not save the review summary", exc_info=True)
