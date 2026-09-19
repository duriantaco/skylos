"""Reuse Skylos's strict GPU fleet contract parser for preflight."""

from __future__ import annotations

from pathlib import Path

from skylos.preflight.models import GpuFleetProfile, GpuFleetTarget
from skylos.rules.config.gpu.compatibility import _load_profile


def load_gpu_fleet_profile(
    project_root: str | Path,
) -> tuple[GpuFleetProfile | None, dict[str, str] | None]:
    """Load ``.skylos/gpu-targets.yml`` without weakening scan semantics."""
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except OSError:
        return None, {
            "code": "invalid_project_root",
            "message": "Project root does not exist or is unreadable.",
        }
    if not root.is_dir():
        return None, {
            "code": "invalid_project_root",
            "message": "Project root must be a directory.",
        }
    loaded = _load_profile(root)
    if loaded.profile is None:
        if loaded.error:
            return None, {
                "code": "invalid_gpu_target_contract",
                "message": loaded.error,
            }
        return None, {
            "code": "missing_gpu_target_contract",
            "message": (
                "Preflight requires .skylos/gpu-targets.yml to declare the fleet."
            ),
        }
    return (
        GpuFleetProfile(
            path=loaded.profile.path,
            targets=tuple(
                GpuFleetTarget(
                    name=target.name,
                    driver=target.driver,
                    driver_branch=target.driver_branch,
                    compute_capability=target.compute_capability,
                    normalized_compute_capability=(
                        target.normalized_compute_capability
                    ),
                    platform=target.platform,
                )
                for target in loaded.profile.targets
            ),
        ),
        None,
    )
