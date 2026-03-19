from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from skylos.analyzer import analyze as run_analyze
from skylos.baseline import load_baseline
from skylos.constants import parse_exclude_folders

STATE_DIR = ".skylos"
STATE_FILE = "agent_state.json"
SUPPORTED_EXTENSIONS = {".py", ".go", ".ts", ".tsx", ".js", ".jsx"}


def resolve_project_root(path: str | Path) -> Path:
    target = Path(path).resolve()
    if target.is_file():
        target = target.parent

    current = target
    while True:
        if (current / ".git").exists() or (current / "pyproject.toml").exists():
            return current
        parent = current.parent
        if parent == current:
            return target
        current = parent


def resolve_state_path(
    project_root: str | Path, state_file: str | Path | None = None
) -> Path:
    root = Path(project_root).resolve()
    if state_file is None:
        return root / STATE_DIR / STATE_FILE
    path = Path(state_file)
    if not path.is_absolute():
        path = root / path
    return path


def load_agent_state(
    project_root: str | Path, state_file: str | Path | None = None
) -> dict[str, Any] | None:
    path = resolve_state_path(project_root, state_file)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_agent_state(
    project_root: str | Path,
    state: dict[str, Any],
    state_file: str | Path | None = None,
) -> Path:
    path = resolve_state_path(project_root, state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return path


def snapshot_file_signatures(
    project_root: str | Path,
    *,
    exclude_folders: list[str] | set[str] | None = None,
) -> dict[str, dict[str, int]]:
    root = Path(project_root).resolve()
    excluded = set(exclude_folders or parse_exclude_folders(use_defaults=True))
    excluded.add(STATE_DIR)

    signatures: dict[str, dict[str, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in excluded]
        base = Path(dirpath)
        for filename in filenames:
            path = base / filename
            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            signatures[rel] = {
                "mtime_ns": int(stat.st_mtime_ns),
                "size": int(stat.st_size),
            }
    return signatures


def detect_changed_files(
    previous: dict[str, dict[str, int]] | None,
    current: dict[str, dict[str, int]],
) -> list[str]:
    if not previous:
        return sorted(current.keys())

    changed: set[str] = set()
    for rel_path, signature in current.items():
        if previous.get(rel_path) != signature:
            changed.add(rel_path)
    for rel_path in previous:
        if rel_path not in current:
            changed.add(rel_path)
    return sorted(changed)


def normalize_triage_map(raw: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    now = datetime.now(timezone.utc)
    triage: dict[str, dict[str, Any]] = {}
    for action_id, entry in (raw or {}).items():
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "").strip().lower()
        if status not in {"dismissed", "snoozed"}:
            continue
        normalized: dict[str, Any] = {
            "status": status,
            "updated_at": str(entry.get("updated_at") or utc_now()),
        }
        if status == "snoozed":
            snoozed_until = parse_utc_timestamp(entry.get("snoozed_until"))
            if snoozed_until is None or snoozed_until <= now:
                continue
            normalized["snoozed_until"] = snoozed_until.isoformat()
        triage[str(action_id)] = normalized
    return triage


def apply_triage_to_findings(
    findings: list[dict[str, Any]],
    triage: dict[str, dict[str, Any]] | None,
) -> dict[str, int]:
    dismissed = 0
    snoozed = 0
    triage_map = triage or {}
    for finding in findings:
        entry = triage_map.get(finding["fingerprint"]) or {}
        status = entry.get("status")
        finding["triage_status"] = status
        finding["snoozed_until"] = entry.get("snoozed_until")
        finding["is_dismissed"] = status == "dismissed"
        finding["is_snoozed"] = status == "snoozed"
        if finding["is_dismissed"]:
            dismissed += 1
        elif finding["is_snoozed"]:
            snoozed += 1
    return {"dismissed": dismissed, "snoozed": snoozed}


def compose_agent_state(
    project_root: str | Path,
    *,
    signatures: dict[str, dict[str, int]],
    findings: list[dict[str, Any]],
    changed_files: list[str],
    baseline_present: bool,
    triage: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized_triage = normalize_triage_map(triage)
    triage_counts = apply_triage_to_findings(findings, normalized_triage)
    actions = build_ranked_actions(findings, changed_files)
    summary = build_summary(
        findings,
        actions,
        changed_files,
        baseline_present,
        triage_counts=triage_counts,
    )

    return {
        "project_root": str(Path(project_root).resolve()),
        "generated_at": utc_now(),
        "state_version": 2,
        "file_signatures": signatures,
        "changed_files": changed_files,
        "baseline_present": baseline_present,
        "triage": normalized_triage,
        "summary": summary,
        "findings": findings,
        "actions": actions,
        "command_center": {
            "headline": summary["headline"],
            "subtitle": summary["subtitle"],
            "items": [
                {
                    "id": action["id"],
                    "title": action["title"],
                    "subtitle": action["subtitle"],
                    "file": action["file"],
                    "absolute_file": action["absolute_file"],
                    "line": action["line"],
                    "severity": action["severity"],
                    "category": action["category"],
                    "score": action["score"],
                    "reason": action["reason"],
                    "action_type": action["action_type"],
                    "command_hint": action["command_hint"],
                    "rule_id": action["rule_id"],
                    "message": action["message"],
                    "safe_fix": action["safe_fix"],
                }
                for action in actions[:10]
            ],
        },
    }


def rebuild_agent_state_from_existing(
    state: dict[str, Any],
    *,
    project_root: str | Path | None = None,
    triage: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = project_root or state.get("project_root") or "."
    findings: list[dict[str, Any]] = []
    for finding in state.get("findings", []) or []:
        clone = dict(finding)
        clone.pop("triage_status", None)
        clone.pop("snoozed_until", None)
        clone.pop("is_dismissed", None)
        clone.pop("is_snoozed", None)
        findings.append(clone)

    return compose_agent_state(
        root,
        signatures=state.get("file_signatures") or {},
        findings=findings,
        changed_files=list(state.get("changed_files") or []),
        baseline_present=bool(state.get("baseline_present")),
        triage=triage if triage is not None else state.get("triage"),
    )


def update_action_triage(
    path: str | Path,
    action_id: str,
    *,
    status: str,
    state_file: str | Path | None = None,
    snooze_hours: float | None = None,
) -> dict[str, Any]:
    project_root = resolve_project_root(path)
    state = load_agent_state(project_root, state_file=state_file)
    if state is None:
        state, _ = refresh_agent_state(project_root, state_file=state_file, force=True)

    triage = normalize_triage_map(state.get("triage") or {})
    normalized_status = str(status).strip().lower()
    if normalized_status not in {"dismissed", "snoozed"}:
        raise ValueError(f"Unsupported triage status: {status}")

    entry: dict[str, Any] = {
        "status": normalized_status,
        "updated_at": utc_now(),
    }
    if normalized_status == "snoozed":
        if snooze_hours is None or snooze_hours <= 0:
            raise ValueError("snooze_hours must be greater than 0")
        entry["snoozed_until"] = (
            datetime.now(timezone.utc) + timedelta(hours=snooze_hours)
        ).isoformat()

    triage[action_id] = entry
    rebuilt = rebuild_agent_state_from_existing(
        state, project_root=project_root, triage=triage
    )
    save_agent_state(project_root, rebuilt, state_file=state_file)
    return rebuilt


def clear_action_triage(
    path: str | Path,
    action_id: str,
    *,
    state_file: str | Path | None = None,
) -> dict[str, Any]:
    project_root = resolve_project_root(path)
    state = load_agent_state(project_root, state_file=state_file)
    if state is None:
        raise ValueError("No agent state exists yet")

    triage = normalize_triage_map(state.get("triage") or {})
    triage.pop(action_id, None)
    rebuilt = rebuild_agent_state_from_existing(
        state, project_root=project_root, triage=triage
    )
    save_agent_state(project_root, rebuilt, state_file=state_file)
    return rebuilt


def refresh_agent_state(
    path: str | Path,
    *,
    conf: int = 80,
    enable_secrets: bool = True,
    enable_danger: bool = True,
    enable_quality: bool = True,
    include_dead_code: bool = True,
    use_baseline: bool = True,
    state_file: str | Path | None = None,
    force: bool = False,
    exclude_folders: list[str] | set[str] | None = None,
) -> tuple[dict[str, Any], bool]:
    project_root = resolve_project_root(path)
    previous_state = load_agent_state(project_root, state_file=state_file) or {}
    triage = normalize_triage_map(previous_state.get("triage") or {})
    triage_changed = triage != (previous_state.get("triage") or {})
    signatures = snapshot_file_signatures(project_root, exclude_folders=exclude_folders)
    changed_files = detect_changed_files(
        previous_state.get("file_signatures"), signatures
    )

    if not force and previous_state and not changed_files:
        if triage_changed:
            rebuilt = rebuild_agent_state_from_existing(
                previous_state, project_root=project_root, triage=triage
            )
            save_agent_state(project_root, rebuilt, state_file=state_file)
            return rebuilt, True
        return previous_state, False

    raw = run_analyze(
        str(project_root),
        conf=conf,
        enable_secrets=enable_secrets,
        enable_danger=enable_danger,
        enable_quality=enable_quality,
        exclude_folders=list(
            exclude_folders or parse_exclude_folders(use_defaults=True)
        ),
    )
    result = json.loads(raw) if isinstance(raw, str) else raw

    normalized = normalize_findings(
        result, project_root, include_dead_code=include_dead_code
    )
    baseline = load_baseline(project_root) if use_baseline else None
    known = set((baseline or {}).get("fingerprints", []))

    previous_fingerprints = {
        finding.get("fingerprint", "")
        for finding in previous_state.get("findings", [])
        if finding.get("fingerprint")
    }

    for finding in normalized:
        fingerprint = finding["fingerprint"]
        finding["is_new_vs_baseline"] = fingerprint not in known if baseline else True
        finding["is_new_since_last_scan"] = fingerprint not in previous_fingerprints
        finding["is_in_changed_file"] = finding["file"] in changed_files

    state = compose_agent_state(
        project_root,
        signatures=signatures,
        findings=normalized,
        changed_files=changed_files,
        baseline_present=bool(baseline),
        triage=triage,
    )
    save_agent_state(project_root, state, state_file=state_file)
    return state, True


def watch_project(
    path: str | Path,
    *,
    interval: float = 5.0,
    cycles: int | None = None,
    once: bool = False,
    conf: int = 80,
    use_baseline: bool = True,
    state_file: str | Path | None = None,
    exclude_folders: list[str] | set[str] | None = None,
    enable_learning: bool = False,
) -> dict[str, Any]:
    iteration = 0
    latest_state: dict[str, Any] | None = None

    # Initialize grep cache for incremental re-analysis
    grep_cache = None
    try:
        from skylos.grep_cache import GrepCache

        grep_cache = GrepCache()
        project_root = resolve_project_root(path)
        grep_cache.load(str(project_root))
    except ImportError:
        pass

    # Initialize triage learner if enabled
    learner = None
    if enable_learning:
        try:
            from skylos.triage_learner import TriageLearner

            learner = TriageLearner()
            project_root = resolve_project_root(path)
            learner.load(str(project_root))
        except ImportError:
            pass

    previous_fingerprints: set[str] = set()

    while True:
        latest_state, _updated = refresh_agent_state(
            path,
            conf=conf,
            use_baseline=use_baseline,
            state_file=state_file,
            force=iteration == 0 or once,
            exclude_folders=exclude_folders,
        )

        # Track finding lifecycle events
        if latest_state and iteration > 0:
            current_fingerprints = {
                f.get("fingerprint", "")
                for f in latest_state.get("findings", [])
                if f.get("fingerprint")
            }
            appeared = current_fingerprints - previous_fingerprints
            resolved = previous_fingerprints - current_fingerprints
            if appeared:
                latest_state.setdefault("_events", []).append(
                    {
                        "type": "finding_appeared",
                        "count": len(appeared),
                        "iteration": iteration,
                    }
                )
            if resolved:
                latest_state.setdefault("_events", []).append(
                    {
                        "type": "finding_resolved",
                        "count": len(resolved),
                        "iteration": iteration,
                    }
                )
            previous_fingerprints = current_fingerprints
        elif latest_state:
            previous_fingerprints = {
                f.get("fingerprint", "")
                for f in latest_state.get("findings", [])
                if f.get("fingerprint")
            }

        # Save grep cache after each cycle
        if grep_cache and latest_state:
            try:
                grep_cache.save(str(resolve_project_root(path)))
            except Exception:
                pass

        iteration += 1
        if once:
            return latest_state
        if cycles is not None and iteration >= cycles:
            return latest_state
        time.sleep(interval)


def normalize_findings(
    result: dict[str, Any],
    project_root: str | Path,
    *,
    include_dead_code: bool = True,
) -> list[dict[str, Any]]:
    root = Path(project_root).resolve()
    findings: list[dict[str, Any]] = []

    if include_dead_code:
        _append_dead_code(
            findings,
            result.get("unused_functions") or [],
            root,
            "unused_function",
            "INFO",
        )
        _append_dead_code(
            findings, result.get("unused_imports") or [], root, "unused_import", "INFO"
        )
        _append_dead_code(
            findings, result.get("unused_classes") or [], root, "unused_class", "INFO"
        )
        _append_dead_code(
            findings,
            result.get("unused_variables") or [],
            root,
            "unused_variable",
            "INFO",
        )

    _append_findings(findings, result.get("danger") or [], root, "security", "HIGH")
    _append_findings(findings, result.get("secrets") or [], root, "secrets", "HIGH")
    _append_findings(findings, result.get("quality") or [], root, "quality", "MEDIUM")

    findings.sort(
        key=lambda item: (
            -severity_score(item["severity"]),
            item["file"],
            int(item["line"]),
            item["rule_id"],
            item["message"],
        )
    )
    return findings


def build_ranked_actions(
    findings: list[dict[str, Any]], changed_files: list[str]
) -> list[dict[str, Any]]:
    changed = set(changed_files)
    actions: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("is_dismissed") or finding.get("is_snoozed"):
            continue
        score = severity_score(finding["severity"]) * 100
        if finding.get("is_new_vs_baseline"):
            score += 220
        if finding.get("is_new_since_last_scan"):
            score += 140
        if finding["file"] in changed:
            score += 160
        if finding["category"] in {"security", "secrets"}:
            score += 60
        if finding["category"] == "dead_code":
            score -= 75
        if finding.get("confidence") is not None:
            score += min(int(finding["confidence"]), 100)

        actions.append(
            {
                "id": finding["fingerprint"],
                "title": build_action_title(finding),
                "subtitle": build_action_subtitle(finding),
                "reason": build_action_reason(finding),
                "file": finding["file"],
                "absolute_file": finding["absolute_file"],
                "line": finding["line"],
                "severity": finding["severity"],
                "category": finding["category"],
                "score": score,
                "action_type": infer_action_type(finding),
                "command_hint": f"open:{finding['absolute_file']}:{finding['line']}",
                "rule_id": finding["rule_id"],
                "message": finding["message"],
                "safe_fix": infer_safe_fix(finding),
            }
        )

    actions.sort(
        key=lambda item: (
            -int(item["score"]),
            item["file"],
            int(item["line"]),
            item["title"],
        )
    )
    return actions


def build_summary(
    findings: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    changed_files: list[str],
    baseline_present: bool,
    *,
    triage_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    critical = sum(
        1 for item in findings if str(item["severity"]).upper() == "CRITICAL"
    )
    high = sum(1 for item in findings if str(item["severity"]).upper() == "HIGH")
    medium = sum(
        1 for item in findings if str(item["severity"]).upper() in {"MEDIUM", "WARN"}
    )
    new_total = sum(1 for item in findings if item.get("is_new_vs_baseline"))
    changed_total = sum(1 for item in findings if item.get("is_in_changed_file"))
    changed_file_count = len(
        {item["file"] for item in findings if item.get("is_in_changed_file")}
    )
    dismissed = int((triage_counts or {}).get("dismissed", 0))
    snoozed = int((triage_counts or {}).get("snoozed", 0))

    headline = build_headline(
        critical=critical,
        high=high,
        new_total=new_total,
        changed_total=changed_total,
        baseline_present=baseline_present,
        total=len(findings),
    )

    subtitle_parts = []
    if changed_file_count:
        subtitle_parts.append(
            f"{changed_total} finding(s) in {changed_file_count} changed file(s)"
        )
    if baseline_present:
        subtitle_parts.append(f"{new_total} new vs baseline")
    if actions:
        subtitle_parts.append(f"{len(actions)} ranked action(s)")
    if snoozed:
        subtitle_parts.append(f"{snoozed} snoozed")
    if dismissed:
        subtitle_parts.append(f"{dismissed} dismissed")
    subtitle = " | ".join(subtitle_parts) if subtitle_parts else "No active actions"

    return {
        "headline": headline,
        "subtitle": subtitle,
        "total_findings": len(findings),
        "new_findings": new_total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "changed_file_count": changed_file_count,
        "changed_files": changed_files,
        "dismissed": dismissed,
        "snoozed": snoozed,
    }


def build_headline(
    *,
    critical: int,
    high: int,
    new_total: int,
    changed_total: int,
    baseline_present: bool,
    total: int,
) -> str:
    urgent = critical + high
    if urgent > 0 and changed_total > 0:
        return f"{urgent} urgent finding(s) need attention in changed code"
    if urgent > 0:
        return f"{urgent} urgent finding(s) need attention"
    if baseline_present and new_total > 0:
        return f"{new_total} new finding(s) since baseline"
    if changed_total > 0:
        return f"{changed_total} finding(s) in files you changed"
    if total > 0:
        return f"{total} tracked finding(s) in repository"
    return "No active findings"


def render_status_table(state: dict[str, Any], *, limit: int = 10) -> dict[str, Any]:
    summary = state.get("summary") or {}
    actions = state.get("actions") or []
    return {
        "headline": summary.get("headline", "No active findings"),
        "subtitle": summary.get("subtitle", ""),
        "actions": actions[:limit],
    }


def command_center_payload(state: dict[str, Any], *, limit: int = 10) -> dict[str, Any]:
    payload = dict(state.get("command_center") or {})
    payload["items"] = list((payload.get("items") or [])[:limit])
    return payload


def _append_findings(
    out: list[dict[str, Any]],
    items: list[dict[str, Any]],
    project_root: Path,
    category: str,
    default_severity: str,
) -> None:
    for item in items:
        file_path = item.get("file", "")
        rel = relative_path(file_path, project_root)
        line = int(item.get("line") or item.get("lineno") or 1)
        rule_id = str(item.get("rule_id") or item.get("rule") or category.upper())
        message = str(item.get("message") or item.get("summary") or rule_id)
        severity = normalize_severity(item.get("severity"), default_severity)
        absolute = str(resolve_file_path(file_path, project_root))
        confidence = item.get("confidence")
        out.append(
            {
                "fingerprint": finding_fingerprint(
                    category, rule_id, rel, line, message
                ),
                "rule_id": rule_id,
                "category": category,
                "severity": severity,
                "message": message,
                "file": rel,
                "absolute_file": absolute,
                "line": line,
                "confidence": confidence,
            }
        )


def _append_dead_code(
    out: list[dict[str, Any]],
    items: list[dict[str, Any]],
    project_root: Path,
    item_type: str,
    severity: str,
) -> None:
    for item in items:
        file_path = item.get("file", "")
        rel = relative_path(file_path, project_root)
        line = int(item.get("line") or item.get("lineno") or 1)
        name = str(item.get("name") or item.get("simple_name") or item_type)
        pretty_type = {
            "unused_function": "function",
            "unused_import": "import",
            "unused_variable": "variable",
            "unused_class": "class",
        }.get(item_type, item_type.replace("_", " "))
        message = f"Unused {pretty_type}: {name}"
        rule_id = dead_code_rule_id(item_type)
        absolute = str(resolve_file_path(file_path, project_root))
        confidence = item.get("confidence")
        out.append(
            {
                "fingerprint": finding_fingerprint(
                    "dead_code", rule_id, rel, line, message
                ),
                "rule_id": rule_id,
                "category": "dead_code",
                "severity": severity,
                "message": message,
                "file": rel,
                "absolute_file": absolute,
                "line": line,
                "confidence": confidence,
            }
        )


def dead_code_rule_id(item_type: str) -> str:
    mapping = {
        "unused_function": "SKY-U001",
        "unused_import": "SKY-U002",
        "unused_variable": "SKY-U003",
        "unused_class": "SKY-U004",
    }
    return mapping.get(item_type, "SKY-U000")


def finding_fingerprint(
    category: str, rule_id: str, file_path: str, line: int, message: str
) -> str:
    return f"{category}:{rule_id}:{file_path}:{line}:{message}"


def relative_path(file_path: str, project_root: Path) -> str:
    try:
        return str(Path(file_path).resolve().relative_to(project_root)).replace(
            "\\", "/"
        )
    except Exception:
        return str(file_path).replace("\\", "/")


def resolve_file_path(file_path: str, project_root: Path) -> Path:
    path = Path(file_path)
    if path.is_absolute():
        return path
    return (project_root / path).resolve()


def normalize_severity(raw: Any, default: str) -> str:
    value = str(raw or default).upper()
    if value == "WARNING":
        return "WARN"
    if value in {"CRITICAL", "HIGH", "MEDIUM", "WARN", "LOW", "INFO"}:
        return value
    return str(default).upper()


def severity_score(severity: str) -> int:
    normalized = str(severity).upper()
    if normalized == "CRITICAL":
        return 5
    if normalized == "HIGH":
        return 4
    if normalized in {"MEDIUM", "WARN"}:
        return 3
    if normalized == "LOW":
        return 2
    return 1


def build_action_title(finding: dict[str, Any]) -> str:
    if finding["category"] == "dead_code":
        return f"Clean up {finding['message']}"
    return f"Review {finding['severity']} {finding['rule_id']}"


def build_action_subtitle(finding: dict[str, Any]) -> str:
    location = f"{finding['file']}:{finding['line']}"
    return f"{finding['message']} ({location})"


def build_action_reason(finding: dict[str, Any]) -> str:
    reasons = []
    if finding.get("is_new_vs_baseline"):
        reasons.append("new vs baseline")
    if finding.get("is_new_since_last_scan"):
        reasons.append("new since last scan")
    if finding.get("is_in_changed_file"):
        reasons.append("in changed file")
    if not reasons:
        reasons.append("ranked by severity")
    return ", ".join(reasons)


def infer_action_type(finding: dict[str, Any]) -> str:
    if finding["category"] == "dead_code":
        return "cleanup"
    if finding["severity"] in {"CRITICAL", "HIGH"}:
        return "inspect_now"
    return "review"


def infer_safe_fix(finding: dict[str, Any]) -> str | None:
    if finding["category"] != "dead_code":
        return None
    if finding["rule_id"] == "SKY-U002":
        return "remove_import"
    if finding["rule_id"] == "SKY-U001":
        return "remove_function"
    return None


def parse_utc_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        normalized = str(value)
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
