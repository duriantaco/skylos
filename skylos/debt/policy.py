from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

VALID_FAIL_ON_STATUS = {"new", "worsened", "new_or_worsened"}
POLICY_FILENAMES = (
    "skylos-debt.yaml",
    "skylos-debt.yml",
    ".skylos-debt.yaml",
    ".skylos-debt.yml",
)


@dataclass
class DebtPolicy:
    gate_min_score: Optional[int] = None
    gate_fail_on_status: Optional[str] = None
    report_top: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "gate": {
                "min_score": self.gate_min_score,
                "fail_on_status": self.gate_fail_on_status,
            },
            "report": {"top": self.report_top},
        }


def find_policy_path(start_path: str | Path | None = None) -> Path | None:
    current = Path(start_path or ".").resolve()
    if current.is_file():
        current = current.parent

    while True:
        for filename in POLICY_FILENAMES:
            candidate = current / filename
            if candidate.exists():
                return candidate
        if current.parent == current:
            return None
        current = current.parent


def load_policy(
    path: str | Path | None = None,
    *,
    start_path: str | Path | None = None,
) -> Optional[DebtPolicy]:
    if path is not None:
        policy_path = Path(path)
    else:
        policy_path = find_policy_path(start_path)
        if policy_path is None:
            return None

    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    if not YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required for policy files. Install with: pip install pyyaml"
        )

    raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"Invalid policy file: expected a YAML mapping, got {type(raw).__name__}"
        )
    return _parse_policy(raw)


def _parse_policy(raw: dict) -> DebtPolicy:
    gate = raw.get("gate", {})
    report = raw.get("report", {})

    min_score = None
    fail_on_status = None
    top = None

    if isinstance(gate, dict):
        min_score = gate.get("min_score")
        if min_score is not None:
            min_score = int(min_score)
            if not 0 <= min_score <= 100:
                raise ValueError(f"gate.min_score must be 0-100, got {min_score}")

        fail_on_status = gate.get("fail_on_status")
        if (
            fail_on_status is not None
            and fail_on_status not in VALID_FAIL_ON_STATUS
        ):
            raise ValueError(
                f"Invalid gate.fail_on_status '{fail_on_status}'. "
                f"Valid: {', '.join(sorted(VALID_FAIL_ON_STATUS))}"
            )

    if isinstance(report, dict):
        top = report.get("top")
        if top is not None:
            top = int(top)
            if top <= 0:
                raise ValueError(f"report.top must be > 0, got {top}")

    return DebtPolicy(
        gate_min_score=min_score,
        gate_fail_on_status=fail_on_status,
        report_top=top,
    )
