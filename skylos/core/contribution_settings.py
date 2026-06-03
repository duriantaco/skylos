from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.config import load_config


@dataclass(frozen=True)
class ContributionSettings:
    collect_local_signals: bool
    contribute_public_corpus: bool
    structural_signatures_only: bool
    include_source: bool

    @property
    def local_only(self) -> bool:
        if not self.collect_local_signals:
            return False
        if self.contribute_public_corpus:
            return False
        return True


def load_contribution_settings(
    project_root: str | Path,
    *,
    config_file: str | Path | None = None,
) -> ContributionSettings:
    config = load_config(project_root, config_file=config_file)
    return contribution_settings_from_config(config)


def contribution_settings_from_config(config: dict[str, Any]) -> ContributionSettings:
    contribution = config.get("contribution")
    if not isinstance(contribution, dict):
        contribution = {}

    return ContributionSettings(
        collect_local_signals=_bool_value(contribution, "collect_local_signals"),
        contribute_public_corpus=_bool_value(contribution, "contribute_public_corpus"),
        structural_signatures_only=_bool_value(
            contribution,
            "structural_signatures_only",
            default=True,
        ),
        include_source=False,
    )


def _bool_value(
    config: dict[str, Any],
    key: str,
    *,
    default: bool = False,
) -> bool:
    value = config.get(key)
    if isinstance(value, bool):
        return value
    return default
