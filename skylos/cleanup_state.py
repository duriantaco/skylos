"""Local cleanup work history. Absence is an observation, never a test receipt."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

from skylos.core.safe_cache_io import (
    project_cache_lock,
    read_project_text_no_symlink,
    write_text_no_symlink,
)

STATE_PATH = ".skylos/cache/cleanup.json"
LOCK_PATH = ".skylos/cache/cleanup.lock"


def scope_identity(scope: dict) -> str:
    return sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()


def load_cleanup_state(root: Path) -> dict:
    for relative in (".skylos", ".skylos/cache", STATE_PATH):
        if (root / relative).is_symlink():
            raise ValueError(
                "Cleanup history path is unsafe; it was not read or replaced"
            )
    text = read_project_text_no_symlink(root, STATE_PATH, max_bytes=8_000_000)
    if text is None:
        if (root / STATE_PATH).exists() or (root / STATE_PATH).is_symlink():
            raise ValueError(
                "Cleanup history is unreadable or unsafe; it was not replaced"
            )
        return {"version": 1, "scopes": {}}
    try:
        state = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ValueError("Cleanup history is malformed; it was not replaced") from exc
    if (
        not isinstance(state, dict)
        or state.get("version") != 1
        or not isinstance(state.get("scopes"), dict)
    ):
        raise ValueError("Unsupported cleanup history; it was not replaced")
    return state


def update_cleanup_state(
    root: Path, scope: dict, plan: dict, *, disposition=None, receipt=None
) -> dict:
    """Reconcile only an identical scan scope and config, preserving uncertainty."""
    with project_cache_lock(root, LOCK_PATH) as acquired:
        if not acquired:
            raise ValueError("Cleanup history is locked or its path is unsafe")
        state = load_cleanup_state(root)
        key = scope_identity(scope)
        bucket = state["scopes"].setdefault(key, {"scope": scope, "tasks": {}})
        records = bucket["tasks"]
        if not isinstance(records, dict):
            raise ValueError("Cleanup task history is malformed")
        now = datetime.now(timezone.utc).isoformat()
        current = {
            task["id"]: task
            for task in plan.get("tasks", []) + plan.get("advisories", [])
        }
        for task_id, task in current.items():
            record = records.setdefault(
                task_id,
                {
                    "id": task_id,
                    "rule_id": task["rule_id"],
                    "file": task["file"],
                    "name": task.get("name", ""),
                    "first_seen": now,
                    "status": "open",
                    "history": [],
                },
            )
            if record["status"] in {
                "not_reported",
                "verified",
                "applied_unverified",
                "failed",
                "incomplete",
            }:
                _event(record, "reopened", now)
                record["status"] = "open"
            record["last_seen"] = now
            record["source_sha256"] = task.get("source_sha256")
        if plan.get("status") != "incomplete":
            for task_id, record in records.items():
                if task_id not in current and record["status"] == "open":
                    record["status"] = "not_reported"
                    _event(
                        record,
                        "not_reported",
                        now,
                        reason="Absent in a complete comparable scan; behavior is not verified",
                    )
        if disposition:
            task_id = _match(records, disposition["id"])
            record = records[task_id]
            record["status"] = disposition["status"]
            _event(
                record, disposition["status"], now, reason=disposition.get("reason", "")
            )
        if receipt:
            task_id = _match(records, receipt["task_id"])
            record = records[task_id]
            record["status"] = receipt["status"]
            record["verification"] = deepcopy(receipt)
            _event(record, receipt["status"], now)
        bucket["last_scan"] = {
            "at": now,
            "status": plan.get("status"),
            "complete": plan.get("status") != "incomplete",
        }
        if not write_text_no_symlink(
            root / STATE_PATH, json.dumps(state, sort_keys=True, indent=2) + "\n"
        ):
            raise ValueError("Cleanup history could not be safely written")
        return deepcopy(bucket)


def _match(records, prefix):
    matches = [key for key in records if key.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(
            "Task ID is unknown or ambiguous; use the full ID from cleanup JSON"
        )
    return matches[0]


def _event(record, status, at, **details):
    record.setdefault("history", []).append({"at": at, "status": status, **details})
    record["history"] = record["history"][-30:]
