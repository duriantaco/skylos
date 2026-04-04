from __future__ import annotations

import json
from pathlib import Path

from skylos.debt.result import DebtHotspot, DebtSnapshot
from skylos.debt.scoring import refresh_hotspot_priority

BASELINE_DIR = ".skylos"
BASELINE_FILE = "debt_baseline.json"
HISTORY_FILE = "debt_history.jsonl"


def _baseline_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / BASELINE_FILE


def _history_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / HISTORY_FILE


def _summary_for_project_persistence(snapshot: DebtSnapshot) -> dict:
    summary = dict(snapshot.summary or {})
    source_hotspots = snapshot.all_hotspots or snapshot.hotspots
    scope = dict(summary.get("scope") or {})
    if scope.get("hotspots") == "changed":
        scope["hotspots"] = "project"
        summary["scope"] = scope
        summary["visible_hotspot_count"] = len(source_hotspots)
        summary["project_hotspot_count"] = len(source_hotspots)
        summary.pop("baseline", None)
    return summary


def save_baseline(project_root: str | Path, snapshot: DebtSnapshot) -> Path:
    path = _baseline_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    source_hotspots = snapshot.all_hotspots or snapshot.hotspots

    payload = {
        "version": snapshot.version,
        "timestamp": snapshot.timestamp,
        "project": snapshot.project,
        "score": snapshot.score.to_dict(),
        "summary": _summary_for_project_persistence(snapshot),
        "hotspots": [
            {
                "fingerprint": hotspot.fingerprint,
                "file": hotspot.file,
                "score": hotspot.score,
                "signal_count": hotspot.signal_count,
            }
            for hotspot in source_hotspots
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline(project_root: str | Path) -> dict | None:
    path = _baseline_path(project_root)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def annotate_hotspots(
    hotspots: list[DebtHotspot],
    baseline: dict | None,
    *,
    count_resolved: bool = True,
) -> dict[str, int]:
    baseline_hotspots = {
        str(item.get("fingerprint")): float(item.get("score", 0.0))
        for item in (baseline or {}).get("hotspots", [])
    }
    current_hotspots = {hotspot.fingerprint for hotspot in hotspots}

    counts = {
        "new": 0,
        "worsened": 0,
        "improved": 0,
        "unchanged": 0,
        "resolved": len(set(baseline_hotspots) - current_hotspots)
        if count_resolved
        else 0,
    }

    for hotspot in hotspots:
        prior_score = baseline_hotspots.get(hotspot.fingerprint)
        if prior_score is None:
            hotspot.baseline_status = "new"
            hotspot.score_delta = round(hotspot.score, 2)
            counts["new"] += 1
            continue

        delta = round(hotspot.score - prior_score, 2)
        hotspot.score_delta = delta
        if delta > 1.0:
            hotspot.baseline_status = "worsened"
            counts["worsened"] += 1
        elif delta < -1.0:
            hotspot.baseline_status = "improved"
            counts["improved"] += 1
        else:
            hotspot.baseline_status = "unchanged"
            counts["unchanged"] += 1

    return counts


def compare_to_baseline(
    snapshot: DebtSnapshot, baseline: dict | None
) -> dict[str, int]:
    scope = ((snapshot.summary or {}).get("scope") or {}).get("hotspots", "project")
    counts = annotate_hotspots(
        snapshot.hotspots,
        baseline,
        count_resolved=scope == "project",
    )

    refresh_hotspot_priority(snapshot.hotspots)
    snapshot.summary["baseline"] = counts
    return counts


def append_history(project_root: str | Path, snapshot: DebtSnapshot) -> Path:
    path = _history_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": snapshot.timestamp,
        "project": snapshot.project,
        "score": snapshot.score.to_dict(),
        "summary": _summary_for_project_persistence(snapshot),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    return path
