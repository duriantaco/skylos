from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skylos.debt.result import DebtSignal, DebtSnapshot
from skylos.debt.scoring import build_hotspots, compute_debt_score
from skylos.file_discovery import find_git_root

DEBT_VERSION = "1.0"

_QUALITY_DIMENSION_MAP: dict[str, str] = {
    "SKY-Q301": "complexity",
    "SKY-Q302": "complexity",
    "SKY-Q306": "complexity",
    "SKY-C303": "complexity",
    "SKY-C304": "complexity",
    "SKY-Q501": "modularity",
    "SKY-Q701": "modularity",
    "SKY-Q702": "modularity",
    "SKY-Q802": "architecture",
    "SKY-Q803": "architecture",
    "SKY-Q804": "architecture",
}

_DEAD_CODE_RULE_IDS: dict[str, str] = {
    "unused_functions": "SKY-U001",
    "unused_imports": "SKY-U002",
    "unused_variables": "SKY-U003",
    "unused_classes": "SKY-U004",
    "unused_parameters": "SKY-U005",
}


def run_analyze(*args, **kwargs):
    from skylos.analyzer import analyze as run_analyze_impl

    return run_analyze_impl(*args, **kwargs)


def _project_root(path: Path) -> Path:
    git_root = find_git_root(path)
    if git_root is not None:
        return git_root.resolve()
    if path.is_file():
        return path.parent.resolve()
    return path.resolve()


def _relative_path(file_path: str, project_root: Path) -> str:
    if not file_path:
        return ""
    try:
        return str(Path(file_path).resolve().relative_to(project_root)).replace(
            "\\", "/"
        )
    except Exception:
        return str(file_path).replace("\\", "/")


def _normalize_changed_files(
    changed_files: list[str] | list[Path] | None,
    project_root: Path,
) -> set[str]:
    normalized: set[str] = set()
    for file_path in changed_files or []:
        normalized.add(_relative_path(str(file_path), project_root))
    return normalized


def _normalize_severity(raw: str | None, default: str = "LOW") -> str:
    value = str(raw or default).upper()
    if value == "WARNING":
        return "WARN"
    return value


def _dimension_for_quality(finding: dict[str, Any]) -> str:
    rule_id = str(finding.get("rule_id") or "")
    if rule_id in _QUALITY_DIMENSION_MAP:
        return _QUALITY_DIMENSION_MAP[rule_id]

    kind = str(finding.get("kind") or "").lower()
    if kind == "architecture":
        return "architecture"
    if kind in {"complexity", "nesting"}:
        return "complexity"
    return "maintainability"


def _signal_fingerprint(
    dimension: str,
    rule_id: str,
    file_path: str,
    line: int,
    subject: str,
) -> str:
    return f"{dimension}:{rule_id}:{file_path}:{line}:{subject}"


def _build_quality_signal(
    finding: dict[str, Any],
    *,
    file_path: str,
) -> DebtSignal:
    dimension = _dimension_for_quality(finding)
    rule_id = str(finding.get("rule_id") or "QUALITY")
    line = int(finding.get("line") or 1)
    subject = str(
        finding.get("name")
        or finding.get("simple_name")
        or Path(file_path).name
        or rule_id
    )
    message = str(finding.get("message") or rule_id)
    return DebtSignal(
        fingerprint=_signal_fingerprint(dimension, rule_id, file_path, line, subject),
        dimension=dimension,
        rule_id=rule_id,
        severity=_normalize_severity(finding.get("severity"), "LOW"),
        file=file_path,
        line=line,
        subject=subject,
        message=message,
        metric_value=finding.get("value"),
        threshold=finding.get("threshold"),
        source_category="quality",
        evidence={
            "kind": finding.get("kind"),
            "metric": finding.get("metric"),
            "length": finding.get("length"),
            "instability": finding.get("instability"),
            "abstractness": finding.get("abstractness"),
        },
    )


def _dead_code_severity(item: dict[str, Any]) -> str:
    confidence = int(item.get("confidence") or 0)
    if confidence >= 90:
        return "MEDIUM"
    if confidence >= 70:
        return "LOW"
    return "INFO"


def _build_dead_code_signal(
    item: dict[str, Any],
    *,
    category: str,
    rule_id: str,
    file_path: str,
) -> DebtSignal:
    line = int(item.get("line") or item.get("lineno") or 1)
    subject = str(item.get("name") or item.get("simple_name") or category)
    message = f"Unused {category.replace('unused_', '').replace('_', ' ')}: {subject}"
    return DebtSignal(
        fingerprint=_signal_fingerprint("dead_code", rule_id, file_path, line, subject),
        dimension="dead_code",
        rule_id=rule_id,
        severity=_dead_code_severity(item),
        file=file_path,
        line=line,
        subject=subject,
        message=message,
        metric_value=item.get("confidence"),
        threshold=None,
        source_category="dead_code",
        evidence={"confidence": item.get("confidence")},
    )


def collect_debt_signals(
    result: dict[str, Any],
    *,
    project_root: Path,
    changed_files: list[str] | list[Path] | None = None,
) -> list[DebtSignal]:
    signals: list[DebtSignal] = []
    changed = _normalize_changed_files(changed_files, project_root)
    changed_only = bool(changed)

    for finding in result.get("quality", []) or []:
        file_path = _relative_path(str(finding.get("file") or ""), project_root)
        if changed_only and file_path not in changed:
            continue
        signals.append(_build_quality_signal(finding, file_path=file_path))

    for category, rule_id in _DEAD_CODE_RULE_IDS.items():
        for item in result.get(category, []) or []:
            file_path = _relative_path(str(item.get("file") or ""), project_root)
            if changed_only and file_path not in changed:
                continue
            signals.append(
                _build_dead_code_signal(
                    item,
                    category=category,
                    rule_id=rule_id,
                    file_path=file_path,
                )
            )

    return signals


def run_debt_analysis(
    path: str | Path,
    *,
    exclude_folders: list[str] | set[str] | None = None,
    changed_files: list[str] | list[Path] | None = None,
    conf: int = 80,
) -> DebtSnapshot:
    target = Path(path).resolve()
    project_root = _project_root(target)

    raw = run_analyze(
        str(target),
        conf=conf,
        enable_quality=True,
        enable_danger=False,
        enable_secrets=False,
        exclude_folders=list(exclude_folders or []),
    )
    result = json.loads(raw) if isinstance(raw, str) else raw

    all_signals = collect_debt_signals(
        result,
        project_root=project_root,
    )
    changed = _normalize_changed_files(changed_files, project_root)
    all_hotspots = build_hotspots(all_signals, changed_files=changed)
    hotspots = (
        [hotspot for hotspot in all_hotspots if hotspot.file in changed]
        if changed
        else list(all_hotspots)
    )

    analysis_summary = result.get("analysis_summary") or {}
    total_loc = int(analysis_summary.get("total_loc") or 0)
    score = compute_debt_score(all_hotspots, total_loc=total_loc)

    dimension_counts: dict[str, int] = {}
    for signal in all_signals:
        dimension_counts[signal.dimension] = (
            dimension_counts.get(signal.dimension, 0) + 1
        )

    summary = {
        "dimensions": dimension_counts,
        "changed_files": sorted(changed),
        "architecture_metrics": result.get("architecture_metrics") or {},
        "scope": {
            "score": "project",
            "hotspots": "changed" if changed else "project",
        },
        "project_hotspot_count": len(all_hotspots),
        "visible_hotspot_count": len(hotspots),
    }

    return DebtSnapshot(
        version=DEBT_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        project=str(project_root),
        files_scanned=int(analysis_summary.get("total_files") or 0),
        total_loc=total_loc,
        score=score,
        hotspots=hotspots,
        all_hotspots=all_hotspots,
        summary=summary,
    )
