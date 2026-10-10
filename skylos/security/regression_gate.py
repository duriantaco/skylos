"""Recheck changed controls before accepting a compared CI input report."""

from pathlib import Path
import json
import os

from skylos.config import ConfigError, POLICY_BASE_ENV_VAR
from skylos.constants import parse_exclude_folders
from skylos.core.file_discovery import should_exclude_path
from skylos.core.git_context import GitContext
from skylos.security.regression_diff import (
    SOURCE_SUFFIXES,
    changed_sources,
    compare_source_controls,
)


def _selected_change(change, root, targets, excludes):
    # Base scope governs an existing control, including a move into tests or
    # an excluded folder. A PR cannot waive it merely by renaming its file.
    candidate = root / (change.base_path or change.path)
    current = root / change.path
    if not any(
        item == target or (target.is_dir() and item.is_relative_to(target))
        for item in (candidate, current)
        for target in targets
    ):
        return False
    return candidate.suffix.lower() in SOURCE_SUFFIXES and not should_exclude_path(
        candidate, root, sorted(excludes)
    )


def _merge_findings(result, generated):
    merged = dict(result)
    quality = list(result.get("quality") or [])
    seen = {json.dumps(item, sort_keys=True) for item in quality}
    for finding in generated:
        key = json.dumps(finding, sort_keys=True)
        if key not in seen:
            quality.append(finding)
            seen.add(key)
    merged["quality"] = quality
    summary = merged.get("analysis_summary")
    if isinstance(summary, dict):
        merged["analysis_summary"] = {**summary, "quality_count": len(quality)}
    return merged


def collect_control_regressions(path, config, base):
    """Read changed controls even when a rename leaves no discoverable source."""
    if "SKY-L021" in (config.get("ignore") or []):
        return []
    requested = path if isinstance(path, (list, tuple)) else [path]
    targets = [Path(item).expanduser().resolve() for item in requested]
    context = GitContext.from_path(targets[0])
    excludes = parse_exclude_folders(config_exclude_folders=config.get("exclude"))
    generated = []
    for change in changed_sources(context, base).values():
        if _selected_change(change, context.root, targets, excludes):
            generated.extend(compare_source_controls(context, base, change))
    return generated


def recheck_control_regressions(result, path, config):
    """Merge scanner-owned findings; report omissions cannot waive controls."""
    base = os.environ.get(POLICY_BASE_ENV_VAR)
    if not base:
        raise ConfigError("Compared gate requires a resolved policy base")
    return _merge_findings(result, collect_control_regressions(path, config, base))
