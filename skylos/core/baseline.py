from __future__ import annotations
import json
import os
import re
from pathlib import Path

from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    save_project_json_cache,
)
from skylos.core.sca_baseline import (
    dependency_snapshot,
    filter_dependency_findings,
    supply_chain_trust_rule,
)

BASELINE_DIR = ".skylos"
BASELINE_FILE = "baseline.json"
MAX_BASELINE_BYTES = 2_000_000

_FINDING_CATEGORIES = (
    "danger",
    "reliability",
    "ai_defects",
    "quality",
    "secrets",
    "unused_files",
)
_DEAD_CODE_CATEGORIES = (
    "unused_functions",
    "unused_imports",
    "unused_classes",
    "unused_variables",
)
_SUMMARY_COUNT_KEYS = {
    "unused_functions": "unused_functions_count",
    "unused_imports": "unused_imports_count",
    "unused_classes": "unused_classes_count",
    "unused_variables": "unused_variables_count",
    "unused_files": "unused_files_count",
    "danger": "danger_count",
    "reliability": "reliability_count",
    "ai_defects": "ai_defects_count",
    "quality": "quality_count",
    "secrets": "secrets_count",
    "dependency_vulnerabilities": "dependency_vulnerabilities_count",
}
_STALE_SUMMARY_AGGREGATES = (
    "by_directory",
    "dead_code_evidence",
    "grep_verify",
)
_STALE_RESULT_AGGREGATES = (
    "grade",
    "assessment",
    "ai_security_stats",
    "provenance_summary",
)


RULE_COVERAGE_VERSION = 1
_STABLE_PREFIX = "stable:"
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


def _stable_rules() -> frozenset[str]:
    from skylos.rules.config.agent_publish import AGENT_RULE_IDS, PUBLISH_RULE_IDS

    return AGENT_RULE_IDS | PUBLISH_RULE_IDS


def _identity(finding: dict) -> str:
    """The unredacted command digest ``agent_publish`` records; findings
    built elsewhere fall back to their rule, name and shown value."""
    from skylos.rules.config.agent_publish import IDENTITY_KEY, finding_identity

    value = finding.get(IDENTITY_KEY)
    if isinstance(value, str) and _HEX_DIGEST.fullmatch(value):
        return value
    return finding_identity(
        str(finding.get("rule_id") or ""),
        finding.get("name"),
        finding.get("value") or finding.get("name"),
    )


def _stable_file(finding: dict, project_root: str | Path) -> str | None:
    file = str(finding.get("file") or "")
    if not file:
        return None
    root = Path(project_root).resolve()
    for candidate in (Path(os.path.abspath(file)), Path(file).resolve()):
        try:
            return candidate.relative_to(root).as_posix()
        except ValueError:
            continue
    try:
        return Path(os.path.relpath(Path(file).resolve(), root)).as_posix()
    except (OSError, ValueError):
        return None


def _stable_fingerprint(finding: dict, project_root: str | Path | None) -> str | None:
    """A line-free identity for agent-config and publish-job findings.

    Their line moves when unrelated settings are edited, and an older
    baseline never recorded them, so they are matched by rule, file and a
    digest of the event or job name and the whole unredacted command: the
    shown value is redacted and shortened, so two different commands can
    look the same. Files outside the scanned folder (repository-level
    configs of a subfolder scan) are kept relative to it (``../``).
    """
    rule_id = str(finding.get("rule_id") or "")
    if rule_id not in _stable_rules():
        return None
    file = str(finding.get("file") or "")
    if project_root is not None:
        file = _stable_file(finding, project_root)
        if file is None:
            return None
    return f"{_STABLE_PREFIX}{rule_id}|{file}|{_identity(finding)}"


def _stable_known(
    finding: dict, stable: set[tuple[str, str, str]], project_root=None
) -> bool:
    rule_id = str(finding.get("rule_id") or "")
    if not stable or rule_id not in _stable_rules():
        return False
    file = Path(str(finding.get("file") or "")).as_posix()
    relative = None
    if project_root is not None:
        relative = _stable_file(finding, project_root)
    identity = _identity(finding)
    for known_rule, known_file, known_identity in stable:
        if known_rule != rule_id or known_identity != identity or not known_file:
            continue
        if known_file == relative or file == known_file:
            return True
        if not known_file.startswith("../") and file.endswith("/" + known_file):
            return True
    return False


def _known(finding: dict, fp: str, known: set[str], stable, project_root=None) -> bool:
    """Agent-config and publish-job findings match only by their stable
    identity: a hook whose command changed in place keeps its line, so a line
    match would hide the change."""
    if str(finding.get("rule_id") or "") in _stable_rules():
        return _stable_known(finding, stable, project_root)
    return fp in known


def _parse_stable(known: set[str]) -> set[tuple[str, str, str]]:
    parsed = set()
    for item in known:
        if not item.startswith(_STABLE_PREFIX):
            continue
        rule_id, _, rest = item[len(_STABLE_PREFIX) :].partition("|")
        file, _, identity = rest.rpartition("|")
        if rule_id and file and _HEX_DIGEST.fullmatch(identity):
            parsed.add((rule_id, file, identity))
    return parsed


def _fingerprints(baseline: dict | None) -> set[str]:
    if not isinstance(baseline, dict):
        return set()
    raw = baseline.get("fingerprints", [])
    if not isinstance(raw, list):
        return set()
    return {item for item in raw if isinstance(item, str)}


def _rule_coverage() -> dict:
    """Supply-chain config rules this environment's ca9 engine decides, so a
    later baseline comparison knows which of their findings the baseline saw."""
    from skylos.rules.config.agent_publish import available_rule_ids
    from skylos.rules.sca import supply_chain

    rules = available_rule_ids(supply_chain.load_ca9_api())
    return {"version": RULE_COVERAGE_VERSION, "rules": sorted(rules)}


def baseline_rule_coverage(baseline: dict | None) -> list[str] | None:
    """The covered rule IDs a baseline recorded; None for older baselines."""
    if not isinstance(baseline, dict):
        return None
    coverage = baseline.get("rule_coverage")
    if not isinstance(coverage, dict) or coverage.get("version") != RULE_COVERAGE_VERSION:
        return None
    rules = coverage.get("rules")
    if not isinstance(rules, list):
        return None
    return [str(rule) for rule in rules if isinstance(rule, str)][:200]


def _baseline_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / BASELINE_FILE


def save_baseline(project_root: str | Path, result: dict) -> Path:
    path = _baseline_path(project_root)

    counts = {
        "unused_functions": len(result.get("unused_functions", [])),
        "unused_imports": len(result.get("unused_imports", [])),
        "unused_classes": len(result.get("unused_classes", [])),
        "unused_variables": len(result.get("unused_variables", [])),
        "unused_files": len(result.get("unused_files", [])),
        "danger": len(result.get("danger", [])),
        "reliability": len(result.get("reliability", [])),
        "ai_defects": len(result.get("ai_defects", [])),
        "quality": len(result.get("quality", [])),
        "secrets": len(result.get("secrets", [])),
        "dependency_vulnerabilities": len(result.get("dependency_vulnerabilities", [])),
    }

    fingerprints = set()
    for category in _FINDING_CATEGORIES:
        for finding in result.get(category, []):
            fp = f"{finding.get('rule_id', '')}:{finding.get('file', '')}:{finding.get('line', 0)}"
            fingerprints.add(fp)
            stable = _stable_fingerprint(finding, project_root)
            if stable is not None:
                fingerprints.add(stable)

    for category in _DEAD_CODE_CATEGORIES:
        for item in result.get(category, []):
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            fingerprints.add(f"dead:{category}:{name}")

    baseline = {
        "counts": counts,
        "fingerprints": sorted(fingerprints),
        "rule_coverage": _rule_coverage(),
    }
    dependency_baseline = dependency_snapshot(result, project_root)
    if dependency_baseline is not None:
        baseline["dependency_baseline"] = dependency_baseline
    if (
        len((json.dumps(baseline, indent=2) + "\n").encode("utf-8"))
        > MAX_BASELINE_BYTES
    ):
        raise ValueError("baseline exceeds size limit")
    if not save_project_json_cache(
        project_root, Path(BASELINE_DIR) / BASELINE_FILE, baseline
    ):
        raise OSError("could not safely write baseline")
    return path


def load_baseline(project_root: str | Path) -> dict | None:
    text = read_project_text_no_symlink(
        project_root,
        Path(BASELINE_DIR) / BASELINE_FILE,
        max_bytes=MAX_BASELINE_BYTES,
    )
    if text is None:
        return None
    try:
        baseline = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return baseline if isinstance(baseline, dict) else None


def filter_new_findings(
    result: dict,
    baseline: dict,
    *,
    project_root: str | Path | None = None,
    dependency_baseline: dict | None = None,
    dependency_disabled_reason: str | None = None,
    dependency_source: dict | None = None,
    policy_base: bool = False,
    policy_baseline: dict | None = None,
) -> dict:
    """Drop findings the baseline already holds.

    With ``policy_base`` (``SKYLOS_POLICY_BASE`` set: pull-request CI), the
    working-tree baseline can come from the pull request itself, so a
    supply-chain trust-boundary finding (``supply_chain_trust_rule``) counts
    as known only when ``policy_baseline``, the baseline committed on the
    policy base, holds it too. Other rules keep using the working-tree
    baseline alone.
    """
    known = _fingerprints(baseline)
    base_known = _fingerprints(policy_baseline)

    filtered = dict(result)
    stable = _parse_stable(known)
    base_stable = _parse_stable(base_known)
    not_honoured = 0

    for category in _FINDING_CATEGORIES:
        original = result.get(category, [])
        new_findings = []
        for finding in original:
            fp = f"{finding.get('rule_id', '')}:{finding.get('file', '')}:{finding.get('line', 0)}"
            matched = _known(finding, fp, known, stable, project_root)
            if (
                matched
                and policy_base
                and supply_chain_trust_rule(finding)
                and not _known(finding, fp, base_known, base_stable, project_root)
            ):
                matched = False
                not_honoured += 1
            # A control removed in this comparison is a new regression, even
            # when a PR adds its fingerprint to the local debt baseline.
            if (
                not matched
                or (
                    finding.get("rule_id") == "SKY-L021"
                    and finding.get("kind") == "security_regression"
                )
                # Reviewer settings changed or a scanner marker added in this
                # comparison (SKY-A122/A125): the change cannot excuse itself.
                or finding.get("kind") == "guardrail_tamper"
            ):
                new_findings.append(finding)
        filtered[category] = new_findings

    for category in _DEAD_CODE_CATEGORIES:
        original = result.get(category, [])
        new_items = []
        for item in original:
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            fp = f"dead:{category}:{name}"
            if fp not in known:
                new_items.append(item)
        filtered[category] = new_items

    if "dependency_vulnerabilities" in result or "dependency_baseline" in baseline:
        filtered = filter_dependency_findings(
            filtered,
            dependency_baseline if dependency_baseline is not None else baseline,
            project_root=project_root,
            disabled_reason=dependency_disabled_reason,
            source=dependency_source,
            policy_base=policy_base,
            policy_baseline=policy_baseline,
        )
        dependency_receipt = (filtered.get("analysis_summary") or {}).get(
            "dependency_baseline"
        )
        if isinstance(dependency_receipt, dict):
            not_honoured += int(dependency_receipt.get("policy_base_not_honoured") or 0)

    if "analysis_summary" in filtered:
        summary = dict(filtered.get("analysis_summary") or {})
        grep_verify = summary.get("grep_verify")
        incomplete_grep_verify = (
            grep_verify
            if isinstance(grep_verify, dict) and grep_verify.get("complete") is False
            else None
        )
        for section, count_key in _SUMMARY_COUNT_KEYS.items():
            if section in result or count_key in summary:
                summary[count_key] = len(filtered.get(section) or [])
        for key in _STALE_SUMMARY_AGGREGATES:
            summary.pop(key, None)
        if incomplete_grep_verify is not None:
            summary["grep_verify"] = incomplete_grep_verify
        filtered["analysis_summary"] = summary
    if policy_base:
        summary = dict(filtered.get("analysis_summary") or {})
        summary["baseline_policy_base"] = {"not_honoured": not_honoured}
        filtered["analysis_summary"] = summary

    for key in _STALE_RESULT_AGGREGATES:
        filtered.pop(key, None)

    return filtered
