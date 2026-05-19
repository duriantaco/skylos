from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from skylos.debt.result import DebtHotspot, DebtSnapshot
from skylos.debt.scoring import refresh_hotspot_priority

BASELINE_DIR = ".skylos"
BASELINE_FILE = "debt_baseline.json"
HISTORY_FILE = "debt_history.jsonl"
HISTORY_HOTSPOT_LIMIT = 5
HISTORY_MAX_BYTES = 5 * 1024 * 1024


def _baseline_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / BASELINE_FILE


def _history_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / HISTORY_FILE


def _safe_history_path(project_root: str | Path) -> Path | None:
    root = Path(project_root).resolve()
    path = _history_path(root)
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        return None

    if stat.S_ISLNK(path_stat.st_mode):
        raise ValueError(f"{path}: history file must not be a symlink")
    if not stat.S_ISREG(path_stat.st_mode):
        raise ValueError(f"{path}: history file must be a regular file")

    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{path}: history file must stay inside project root") from exc

    return path


def _read_history_text(path: Path) -> str:
    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow

    fd = os.open(  # skylos: ignore[SKY-D215] validated debt history path with no-follow checks
        path, flags
    )
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{path}: history file must be a regular file")
        if file_stat.st_size > HISTORY_MAX_BYTES:
            raise ValueError(f"{path}: history file is too large")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(HISTORY_MAX_BYTES + 1)
        if len(data) > HISTORY_MAX_BYTES:
            raise ValueError(f"{path}: history file is too large")
    finally:
        if fd >= 0:
            os.close(fd)

    return data.decode("utf-8")


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


def load_history(project_root: str | Path) -> list[dict]:
    path = _safe_history_path(project_root)
    if path is None:
        return []

    entries = []
    lines = _read_history_text(path).splitlines()
    for line_number, line in enumerate(lines, 1):
        raw = line.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
        if not isinstance(entry, dict):
            raise ValueError(f"{path}:{line_number}: expected JSON object")
        entries.append(entry)
    return entries


def _history_hotspots(snapshot: DebtSnapshot) -> list[dict]:
    source_hotspots = snapshot.all_hotspots or snapshot.hotspots
    ordered = sorted(
        source_hotspots,
        key=lambda hotspot: (
            -float(getattr(hotspot, "priority_score", hotspot.score)),
            -float(hotspot.score),
            hotspot.file,
        ),
    )
    return [
        {
            "file": hotspot.file,
            "score": hotspot.score,
            "priority_score": hotspot.priority_score,
            "signal_count": hotspot.signal_count,
            "primary_dimension": hotspot.primary_dimension,
        }
        for hotspot in ordered[:HISTORY_HOTSPOT_LIMIT]
    ]


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
        "hotspots": _history_hotspots(snapshot),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    return path
