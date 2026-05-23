from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from skylos.debt.result import DebtHotspot, DebtSnapshot
from skylos.debt.scoring import refresh_hotspot_priority

READ_CHUNK_BYTES = 64 * 1024
BASELINE_DIR = ".skylos"
BASELINE_FILE = "debt_baseline.json"
HISTORY_FILE = "debt_history.jsonl"
HISTORY_HOTSPOT_LIMIT = 5
BASELINE_MAX_BYTES = 10 * 1024 * 1024
HISTORY_MAX_BYTES = 5 * 1024 * 1024
BASELINE_LABEL = "baseline"
HISTORY_LABEL = "history"
HOTSPOTS_FIELD = "hotspots"
PROJECT_FIELD = "project"


def _has_multiple_links(path_stat: os.stat_result) -> bool:
    return getattr(path_stat, "st_nlink", 1) > 1


def _validate_regular_file(path: Path, path_stat: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(path_stat.st_mode):
        raise ValueError(f"{path}: {label} file must not be a symlink")
    if not stat.S_ISREG(path_stat.st_mode):
        raise ValueError(f"{path}: {label} file must be a regular file")
    if _has_multiple_links(path_stat):
        raise ValueError(f"{path}: {label} file must not be hard-linked")


def _read_text_no_follow(path: Path, *, label: str, max_bytes: int) -> str:
    try:
        path_stat = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{label.title()} file not found: {path}") from exc
    _validate_regular_file(path, path_stat, label)

    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow

    fd = os.open(  # skylos: ignore[SKY-D215] validated file with no-follow checks
        path, flags
    )
    try:
        _validate_regular_file(path, os.fstat(fd), label)
        data = _read_limited_bytes(fd, path, label=label, max_bytes=max_bytes)
    finally:
        os.close(fd)

    return _decode_utf8(data, path, label)


def _write_text_no_follow(
    path: Path,
    text: str,
    *,
    label: str,
    append: bool = False,
    max_total_bytes: int | None = None,
) -> Path:
    data = text.encode("utf-8")
    _reject_oversized_write(path, label, len(data), max_total_bytes)
    try:
        _validate_regular_file(path, path.lstat(), label)
    except FileNotFoundError:
        pass

    flags = os.O_WRONLY | os.O_CREAT
    if append:
        flags |= os.O_APPEND
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow

    fd = os.open(  # skylos: ignore[SKY-D215] validated file with no-follow checks
        path, flags, 0o600
    )
    try:
        file_stat = os.fstat(fd)
        _validate_regular_file(path, file_stat, label)
        if append:
            _reject_oversized_write(
                path,
                label,
                file_stat.st_size + len(data),
                max_total_bytes,
            )
        else:
            os.ftruncate(fd, 0)
        _write_all(fd, data)
    finally:
        os.close(fd)

    return path


def _read_limited_bytes(fd: int, path: Path, *, label: str, max_bytes: int) -> bytes:
    chunks = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(  # skylos: ignore[SKY-P401] bounded chunked read
            fd, min(READ_CHUNK_BYTES, remaining)
        )
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)

    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise ValueError(f"{path}: {label} file is too large")
    return data


def _decode_utf8(data: bytes, path: Path, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: {label} file must be valid UTF-8") from exc


def _reject_oversized_write(
    path: Path,
    label: str,
    byte_count: int,
    max_total_bytes: int | None,
) -> None:
    if max_total_bytes is not None and byte_count > max_total_bytes:
        raise ValueError(f"{path}: {label} file would be too large")


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written == 0:
            raise OSError("failed to write file")
        offset += written


def _baseline_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / BASELINE_FILE


def _history_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / HISTORY_FILE


def _outside_root_error(path: Path, label: str) -> str:
    return f"{path}: {label} file must stay inside project root"


def _validate_project_parent(root: Path, parent: Path, label: str) -> None:
    try:
        relative_parent = parent.relative_to(root)
    except ValueError as exc:
        raise ValueError(_outside_root_error(parent, label)) from exc

    current = root
    for part in relative_parent.parts:
        current = current / part
        try:
            path_stat = current.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"{current}: {label} parent directory is missing") from exc
        if stat.S_ISLNK(path_stat.st_mode):
            raise ValueError(f"{current}: {label} parent directory must not be a symlink")
        if not stat.S_ISDIR(path_stat.st_mode):
            raise ValueError(f"{current}: {label} parent path must be a directory")


def _validate_project_file_path(
    project_root: str | Path,
    path: Path,
    *,
    label: str,
    must_exist: bool,
) -> Path | None:
    root = Path(project_root).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(_outside_root_error(path, label)) from exc

    parent = path.parent
    if must_exist:
        try:
            parent.lstat()
        except FileNotFoundError:
            return None
    else:
        parent.mkdir(parents=True, exist_ok=True)
    _validate_project_parent(root, parent, label)

    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        if must_exist:
            return None
        return path

    _validate_regular_file(path, path_stat, label)

    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(_outside_root_error(path, label)) from exc

    return path


def _safe_debt_file_path(
    project_root: str | Path,
    filename: str,
    *,
    label: str,
    must_exist: bool,
) -> Path | None:
    root = Path(project_root).resolve()
    return _validate_project_file_path(
        root,
        root / BASELINE_DIR / filename,
        label=label,
        must_exist=must_exist,
    )


def _baseline_hotspot_scores(baseline: dict | None) -> dict[str, float]:
    if not isinstance(baseline, dict):
        return {}

    hotspots = baseline.get(HOTSPOTS_FIELD, [])
    if not isinstance(hotspots, list):
        return {}

    scores: dict[str, float] = {}
    for item in hotspots:
        if not isinstance(item, dict):
            continue
        fingerprint = item.get("fingerprint")
        if not fingerprint:
            continue
        try:
            scores[str(fingerprint)] = float(item.get("score", 0.0))
        except (TypeError, ValueError):
            continue
    return scores


def _summary_for_project_persistence(snapshot: DebtSnapshot) -> dict:
    summary = dict(snapshot.summary or {})
    source_hotspots = snapshot.all_hotspots or snapshot.hotspots
    scope = dict(summary.get("scope") or {})
    if scope.get(HOTSPOTS_FIELD) == "changed":
        scope[HOTSPOTS_FIELD] = PROJECT_FIELD
        summary["scope"] = scope
        summary["visible_hotspot_count"] = len(source_hotspots)
        summary["project_hotspot_count"] = len(source_hotspots)
        summary.pop(BASELINE_LABEL, None)
    return summary


def save_baseline(project_root: str | Path, snapshot: DebtSnapshot) -> Path:
    source_hotspots = snapshot.all_hotspots or snapshot.hotspots

    payload = {
        "version": snapshot.version,
        "timestamp": snapshot.timestamp,
        PROJECT_FIELD: snapshot.project,
        "score": snapshot.score.to_dict(),
        "summary": _summary_for_project_persistence(snapshot),
        HOTSPOTS_FIELD: [
            {
                "fingerprint": hotspot.fingerprint,
                "file": hotspot.file,
                "score": hotspot.score,
                "signal_count": hotspot.signal_count,
            }
            for hotspot in source_hotspots
        ],
    }
    root = Path(project_root).resolve()
    safe_path = _validate_project_file_path(
        root,
        _baseline_path(root),
        label=BASELINE_LABEL,
        must_exist=False,
    )
    if safe_path is None:
        raise ValueError(f"{_baseline_path(root)}: baseline file could not be prepared")
    return _write_text_no_follow(
        safe_path,
        json.dumps(payload, indent=2) + "\n",
        label=BASELINE_LABEL,
        max_total_bytes=BASELINE_MAX_BYTES,
    )


def load_baseline(project_root: str | Path) -> dict | None:
    path = _safe_debt_file_path(
        project_root,
        BASELINE_FILE,
        label=BASELINE_LABEL,
        must_exist=True,
    )
    if path is None:
        return None
    try:
        payload = json.loads(
            _read_text_no_follow(
                path,
                label=BASELINE_LABEL,
                max_bytes=BASELINE_MAX_BYTES,
            )
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected JSON object")
    return payload


def load_history(project_root: str | Path) -> list[dict]:
    path = _safe_debt_file_path(
        project_root,
        HISTORY_FILE,
        label=HISTORY_LABEL,
        must_exist=True,
    )
    if path is None:
        return []

    entries = []
    lines = _read_text_no_follow(
        path,
        label=HISTORY_LABEL,
        max_bytes=HISTORY_MAX_BYTES,
    ).splitlines()
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
    baseline_hotspots = _baseline_hotspot_scores(baseline)
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
    scope = ((snapshot.summary or {}).get("scope") or {}).get(
        HOTSPOTS_FIELD,
        PROJECT_FIELD,
    )
    counts = annotate_hotspots(
        snapshot.hotspots,
        baseline,
        count_resolved=scope == PROJECT_FIELD,
    )

    refresh_hotspot_priority(snapshot.hotspots)
    snapshot.summary[BASELINE_LABEL] = counts
    return counts


def append_history(project_root: str | Path, snapshot: DebtSnapshot) -> Path:
    entry = {
        "timestamp": snapshot.timestamp,
        PROJECT_FIELD: snapshot.project,
        "score": snapshot.score.to_dict(),
        "summary": _summary_for_project_persistence(snapshot),
        HOTSPOTS_FIELD: _history_hotspots(snapshot),
    }
    root = Path(project_root).resolve()
    safe_path = _validate_project_file_path(
        root,
        _history_path(root),
        label=HISTORY_LABEL,
        must_exist=False,
    )
    if safe_path is None:
        raise ValueError(f"{_history_path(root)}: history file could not be prepared")
    return _write_text_no_follow(
        safe_path,
        json.dumps(entry) + "\n",
        label=HISTORY_LABEL,
        append=True,
        max_total_bytes=HISTORY_MAX_BYTES,
    )
