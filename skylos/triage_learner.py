from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TRIAGE_DIR = ".skylos"
TRIAGE_FILE = "triage_patterns.json"

MIN_OBSERVATIONS_SUGGEST = 3
MIN_OBSERVATIONS_AUTO = 5
MIN_CONFIDENCE_SUGGEST = 0.7
MIN_CONFIDENCE_AUTO = 0.85


@dataclass
class TriagePattern:
    pattern_type: str
    pattern: str
    rule_id: str
    action: str
    confidence: float = 0.0
    observations: int = 0
    last_updated: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TriagePattern:
        return cls(
            pattern_type=data.get("pattern_type", ""),
            pattern=data.get("pattern", ""),
            rule_id=data.get("rule_id", ""),
            action=data.get("action", ""),
            confidence=data.get("confidence", 0.0),
            observations=data.get("observations", 0),
            last_updated=data.get("last_updated", 0.0),
        )


def _pattern_key(pattern: TriagePattern) -> str:
    return (
        f"{pattern.pattern_type}:{pattern.pattern}:{pattern.rule_id}:{pattern.action}"
    )


class TriageLearner:
    def __init__(self) -> None:
        self._patterns: dict[str, TriagePattern] = {}

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    def load(self, project_root: str | Path) -> None:
        path = Path(project_root) / TRIAGE_DIR / TRIAGE_FILE
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for entry in data.get("patterns", []):
                pattern = TriagePattern.from_dict(entry)
                key = _pattern_key(pattern)
                self._patterns[key] = pattern
            logger.debug("Loaded %d triage patterns", len(self._patterns))
        except Exception as e:
            logger.debug("Failed to load triage patterns: %s", e)

    def save(self, project_root: str | Path) -> None:
        """Save patterns to disk."""
        path = Path(project_root) / TRIAGE_DIR / TRIAGE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "patterns": [p.to_dict() for p in self._patterns.values()],
        }
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.debug("Failed to save triage patterns: %s", e)

    def learn_from_triage(
        self,
        finding: dict[str, Any],
        action: str,
    ) -> list[TriagePattern]:
        if action not in ("dismiss", "accept"):
            return []

        updated: list[TriagePattern] = []
        candidates = self._extract_patterns(finding, action)

        for candidate in candidates:
            key = _pattern_key(candidate)
            existing = self._patterns.get(key)

            if existing is not None:
                existing.observations += 1
                existing.last_updated = time.time()
                existing.confidence = existing.observations / (
                    existing.observations + 1
                )
                updated.append(existing)
            else:
                candidate.observations = 1
                candidate.confidence = 0.5
                candidate.last_updated = time.time()
                self._patterns[key] = candidate
                updated.append(candidate)

        return updated

    def _extract_patterns(
        self,
        finding: dict[str, Any],
        action: str,
    ) -> list[TriagePattern]:
        patterns: list[TriagePattern] = []
        rule_id = finding.get("rule_id", "")
        file_path = finding.get("file", "")
        name = finding.get("simple_name", finding.get("name", ""))

        if not rule_id:
            return patterns

        if file_path:
            parts = file_path.replace("\\", "/").split("/")
            if len(parts) > 1:
                dir_pattern = parts[0] + "/**"
                patterns.append(
                    TriagePattern(
                        pattern_type="file_glob",
                        pattern=dir_pattern,
                        rule_id=rule_id,
                        action=action,
                    )
                )

            if "." in file_path:
                ext = "." + file_path.rsplit(".", 1)[-1]
                if any(
                    marker in file_path
                    for marker in ("test_", "_test.", "tests/", "test/")
                ):
                    patterns.append(
                        TriagePattern(
                            pattern_type="file_glob",
                            pattern=f"**/test_*{ext}",
                            rule_id=rule_id,
                            action=action,
                        )
                    )

        if name:
            if name.startswith("test_"):
                patterns.append(
                    TriagePattern(
                        pattern_type="name_pattern",
                        pattern="test_*",
                        rule_id=rule_id,
                        action=action,
                    )
                )
            elif name.startswith("__") and name.endswith("__"):
                patterns.append(
                    TriagePattern(
                        pattern_type="name_pattern",
                        pattern="__*__",
                        rule_id=rule_id,
                        action=action,
                    )
                )
            elif name.startswith("_"):
                patterns.append(
                    TriagePattern(
                        pattern_type="name_pattern",
                        pattern="_*",
                        rule_id=rule_id,
                        action=action,
                    )
                )

        decorators = finding.get("decorators", [])
        if isinstance(decorators, list):
            for dec in decorators:
                dec_str = str(dec).strip()
                if dec_str:
                    patterns.append(
                        TriagePattern(
                            pattern_type="decorator",
                            pattern=dec_str,
                            rule_id=rule_id,
                            action=action,
                        )
                    )

        return patterns

    def predict_triage(
        self,
        finding: dict[str, Any],
    ) -> tuple[str, float] | None:
        best_match: tuple[str, float] | None = None
        best_confidence = 0.0

        for pattern in self._patterns.values():
            if pattern.observations < MIN_OBSERVATIONS_SUGGEST:
                continue
            if pattern.confidence < MIN_CONFIDENCE_SUGGEST:
                continue

            if self._matches(finding, pattern):
                if pattern.confidence > best_confidence:
                    best_confidence = pattern.confidence
                    best_match = (pattern.action, pattern.confidence)

        return best_match

    def get_auto_triage_candidates(
        self,
        findings: list[dict[str, Any]],
    ) -> list[tuple[dict[str, Any], str, float]]:
        candidates: list[tuple[dict[str, Any], str, float]] = []

        for finding in findings:
            prediction = self.predict_triage(finding)
            if prediction is None:
                continue
            action, confidence = prediction
            if confidence >= MIN_CONFIDENCE_AUTO:
                matching_patterns = [
                    p
                    for p in self._patterns.values()
                    if (
                        p.observations >= MIN_OBSERVATIONS_AUTO
                        and p.confidence >= MIN_CONFIDENCE_AUTO
                        and self._matches(finding, p)
                    )
                ]
                if matching_patterns:
                    candidates.append((finding, action, confidence))

        return candidates

    def _matches(self, finding: dict[str, Any], pattern: TriagePattern) -> bool:
        rule_id = finding.get("rule_id", "")
        if pattern.rule_id and pattern.rule_id != rule_id:
            return False

        if pattern.pattern_type == "file_glob":
            file_path = finding.get("file", "")
            return _glob_match(file_path, pattern.pattern)

        elif pattern.pattern_type == "name_pattern":
            name = finding.get("simple_name", finding.get("name", ""))
            return _glob_match(name, pattern.pattern)

        elif pattern.pattern_type == "decorator":
            decorators = finding.get("decorators", [])
            if isinstance(decorators, list):
                return any(str(d).strip() == pattern.pattern for d in decorators)
            return False

        elif pattern.pattern_type == "rule_type":
            return True  # rule_id already matched above

        return False

    def get_patterns(self) -> list[TriagePattern]:
        return list(self._patterns.values())


def _glob_match(text: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(text, pattern)
