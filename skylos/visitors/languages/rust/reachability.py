"""Bounded Rust function reachability after project-wide reference collection."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
import re


@dataclass
class RustReachabilityReport:
    unreachable_keys: set[str] = field(default_factory=set)
    original_refs: dict[str, int] = field(default_factory=dict)
    _targets: dict[tuple[str, int, str], str] = field(default_factory=dict)
    _facts: dict[str, dict] = field(default_factory=dict)
    _owner_keys: dict[tuple[str, str], str] = field(default_factory=dict)

    def filter_grep_results(self, finding, results):
        if not self.unreachable_keys:
            return results
        try:
            file = str(Path(finding.get("file", "")).resolve())
        except (OSError, RuntimeError, ValueError):
            return results
        name = finding.get("simple_name", finding.get("name", ""))
        target = self._targets.get((file, finding.get("line"), name))
        if target not in self.unreachable_keys:
            return results
        return {
            strategy: [value for value in values if self._keep_hit(value, target)]
            if isinstance(values, list)
            else values
            for strategy, values in results.items()
        }

    def _keep_hit(self, value, target):
        if not isinstance(value, str):
            return True
        from skylos.core.grep_verify_common import (
            _grep_line_content,
            _grep_line_number,
            _grep_line_path,
        )

        file, line = _grep_line_path(value), _grep_line_number(value)
        if not file or line is None:
            return True
        try:
            file = str(Path(file).resolve())
        except (OSError, RuntimeError, ValueError):
            return True
        facts = self._facts[target]
        if file != facts["file"]:
            return True
        content = _grep_line_content(value).rstrip("\r\n")
        if content != facts["source_lines"].get(str(line)):
            return True
        sites = [site for site in facts["sites"] if site["line"] == line]
        declaration_count = int(line == facts["declaration_line"])
        if (
            len(re.findall(rf"\b{re.escape(facts['name'])}\b", content))
            != len(sites) + declaration_count
        ):
            return True
        return any(
            self._owner_keys.get((file, site["owner"])) not in self.unreachable_keys
            for site in sites
        )


def analyze_rust_reachability(
    definitions, project_root, analysis_scope, analysis_errors
):
    report = RustReachabilityReport()
    if (
        analysis_errors
        or not project_root
        or not isinstance(analysis_scope, dict)
        or not analysis_scope.get("complete_repository")
    ):
        return report
    try:
        root = Path(project_root).resolve()
    except (OSError, RuntimeError, ValueError):
        return report
    candidates = {}
    digests = {}
    for key, definition in definitions.items():
        facts = getattr(definition, "rust_reference_facts", None)
        if not isinstance(facts, dict) or definition.type != "function":
            continue
        try:
            path = Path(definition.filename)
            if path.suffix != ".rs" or path.is_symlink():
                continue
            file = str(path.resolve())
            path.resolve().relative_to(root)
            if file not in digests:
                digests[file] = sha256(path.read_bytes()).hexdigest()
        except (OSError, RuntimeError, ValueError):
            continue
        if facts.get("sha256") != digests[file] or facts.get("name") != definition.name:
            continue
        normalized = dict(facts, file=file)
        candidates[key] = definition
        report._facts[key] = normalized
        report._owner_keys[(file, definition.name)] = key
        report._targets[(file, definition.line, definition.simple_name)] = key
    roots = set()
    edges = {key: set() for key in candidates}
    for key, definition in candidates.items():
        facts = report._facts[key]
        owned = facts["owned_counts"]
        owned_count = sum(owned.values())
        if (
            definition.is_exported
            or facts.get("guarded")
            or definition.references > owned_count
            or definition.references < owned_count
            or definition.heuristic_refs
            or definition.dynamic_signals
            or definition.framework_signals
        ):
            roots.add(key)
        for owner in owned:
            caller = report._owner_keys.get((facts["file"], owner))
            if caller is None:
                roots.add(key)
            else:
                edges[caller].add(key)
    live = set()
    pending = list(roots)
    while pending:
        key = pending.pop()
        if key in live:
            continue
        live.add(key)
        pending.extend(edges[key] - live)
    for key, definition in candidates.items():
        if key not in live:
            report.unreachable_keys.add(key)
            if definition.references > 0:
                report.original_refs[key] = definition.references
    return report
