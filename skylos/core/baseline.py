from __future__ import annotations
import json
from pathlib import Path

BASELINE_DIR = ".skylos"
BASELINE_FILE = "baseline.json"


def _baseline_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / BASELINE_FILE


def save_baseline(project_root: str | Path, result: dict) -> Path:
    path = _baseline_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)

    counts = {
        "unused_functions": len(result.get("unused_functions", [])),
        "unused_imports": len(result.get("unused_imports", [])),
        "unused_classes": len(result.get("unused_classes", [])),
        "unused_variables": len(result.get("unused_variables", [])),
        "danger": len(result.get("danger", [])),
        "quality": len(result.get("quality", [])),
        "secrets": len(result.get("secrets", [])),
    }

    fingerprints = set()
    for category in ["danger", "quality", "secrets"]:
        for finding in result.get(category, []):
            fp = f"{finding.get('rule_id', '')}:{finding.get('file', '')}:{finding.get('line', 0)}"
            fingerprints.add(fp)

    for category in [
        "unused_functions",
        "unused_imports",
        "unused_classes",
        "unused_variables",
    ]:
        for item in result.get(category, []):
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            fingerprints.add(f"dead:{category}:{name}")

    baseline = {
        "counts": counts,
        "fingerprints": sorted(fingerprints),
    }

    path.write_text(json.dumps(baseline, indent=2) + "\n")
    return path


def load_baseline(project_root: str | Path) -> dict | None:
    path = _baseline_path(project_root)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def filter_new_findings(result: dict, baseline: dict) -> dict:
    known = set(baseline.get("fingerprints", []))

    filtered = dict(result)

    for category in ["danger", "quality", "secrets"]:
        original = result.get(category, [])
        new_findings = []
        for finding in original:
            fp = f"{finding.get('rule_id', '')}:{finding.get('file', '')}:{finding.get('line', 0)}"
            if fp not in known:
                new_findings.append(finding)
        filtered[category] = new_findings

    for category in [
        "unused_functions",
        "unused_imports",
        "unused_classes",
        "unused_variables",
    ]:
        original = result.get(category, [])
        new_items = []
        for item in original:
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            fp = f"dead:{category}:{name}"
            if fp not in known:
                new_items.append(item)
        filtered[category] = new_items

    return filtered
