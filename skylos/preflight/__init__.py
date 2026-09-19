"""Release artifact preflight verification.

The public entry point is intentionally small. It consumes an exact artifact
identity plus bounded static inspection facts and never starts target code.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.integrations.trivy_image import _IMAGE_REFERENCE
from skylos.preflight.evaluator import evaluate_gpu_inventory
from skylos.preflight.inspector import inspect_local_cuda_artifact
from skylos.preflight.models import (
    ArtifactInventory,
    CudaCodeObject,
    GpuFleetProfile,
    GpuFleetTarget,
    InventoryError,
    inventory_from_mapping,
)
from skylos.preflight.profile import load_gpu_fleet_profile


MAX_RELEASE_RECEIPT_BYTES = 64 * 1024
MAX_ARTIFACT_REFERENCE_LENGTH = 4096
RELEASE_RECEIPT = Path(".skylos/release.json")

__all__ = [
    "ArtifactInventory",
    "CudaCodeObject",
    "GpuFleetProfile",
    "GpuFleetTarget",
    "InventoryError",
    "evaluate_gpu_inventory",
    "inspect_local_cuda_artifact",
    "inventory_from_mapping",
    "load_gpu_fleet_profile",
    "run_preflight",
]


def run_preflight(
    target: str | Path | None = None,
    project_root: str | Path = Path.cwd(),
    *,
    inventory: ArtifactInventory | Mapping[str, object] | None = None,
    cuobjdump: str | Path | None = None,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Verify one exact artifact against ``.skylos/gpu-targets.yml``.

    OCI references are never pulled. Their facts must come from a trusted
    caller through ``inventory``. Local regular files/directories may be
    inspected statically with a trusted system ``cuobjdump`` executable.
    """
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except OSError:
        return _unknown_report(
            target,
            "invalid_project_root",
            "Project root does not exist or is unreadable.",
        )
    if not root.is_dir():
        return _unknown_report(
            target,
            "invalid_project_root",
            "Project root must be a directory.",
        )

    artifact_source = "argument"
    if target is None:
        target, receipt_error = _load_release_receipt(root)
        artifact_source = "release_receipt"
        if receipt_error is not None:
            return _unknown_report(
                None,
                receipt_error["code"],
                receipt_error["message"],
                profile_path=RELEASE_RECEIPT,
                artifact_source=artifact_source,
            )

    artifact, artifact_kind, artifact_error = _normalize_artifact(
        target,
        root,
        require_within_root=artifact_source == "release_receipt",
    )
    if artifact_error is not None:
        return _unknown_report(
            str(target) if target is not None else None,
            "invalid_artifact",
            artifact_error,
            artifact_source=artifact_source,
        )

    profile, profile_error = load_gpu_fleet_profile(root)
    if profile_error is not None or profile is None:
        error = profile_error or {
            "code": "invalid_gpu_target_contract",
            "message": "GPU target contract could not be loaded.",
        }
        return _unknown_report(
            artifact,
            error["code"],
            error["message"],
            profile_path=Path(".skylos/gpu-targets.yml"),
            artifact_source=artifact_source,
        )

    normalized_inventory: ArtifactInventory
    if inventory is not None:
        try:
            if isinstance(inventory, ArtifactInventory):
                normalized_inventory = inventory_from_mapping(inventory.to_dict())
            elif isinstance(inventory, Mapping):
                normalized_inventory = inventory_from_mapping(inventory)
            else:
                raise InventoryError("artifact inventory must be an object")
        except (InventoryError, TypeError, ValueError) as exc:
            return _unknown_report(
                artifact,
                "invalid_artifact_inventory",
                str(exc),
                profile_path=_relative_path(profile.path, root),
                profile_valid=True,
                artifact_source=artifact_source,
            )
    elif artifact_kind == "local":
        normalized_inventory = inspect_local_cuda_artifact(
            artifact,
            project_root=root,
            cuobjdump=cuobjdump,
            timeout_seconds=timeout_seconds,
        )
    else:
        normalized_inventory = ArtifactInventory(
            artifact=artifact,
            identity=artifact,
            identity_verified=False,
            inspection_complete=False,
            source="none",
            errors=(
                "No trusted artifact inventory was supplied; Skylos did not pull "
                "or execute the remote image.",
            ),
        )

    return evaluate_gpu_inventory(
        profile,
        normalized_inventory,
        requested_artifact=artifact,
        project_root=root,
        artifact_source=artifact_source,
    )


def _load_release_receipt(
    root: Path,
) -> tuple[str | None, dict[str, str] | None]:
    path = root / RELEASE_RECEIPT
    source = read_project_text_no_symlink(
        root,
        path,
        max_bytes=MAX_RELEASE_RECEIPT_BYTES,
        encoding="utf-8",
    )
    if source is None:
        return None, {
            "code": "missing_or_unsafe_release_receipt",
            "message": (
                "Preflight requires a bounded, regular .skylos/release.json when "
                "no artifact argument is supplied."
            ),
        }
    try:
        raw = json.loads(
            source,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        return None, {
            "code": "invalid_release_receipt",
            "message": "Release receipt must contain valid JSON with unique keys.",
        }
    if not isinstance(raw, dict) or set(raw) != {"version", "artifact"}:
        return None, {
            "code": "invalid_release_receipt",
            "message": (
                "Release receipt must contain exactly version and artifact fields."
            ),
        }
    if type(raw.get("version")) is not int or raw["version"] != 1:
        return None, {
            "code": "invalid_release_receipt",
            "message": "Release receipt version must be exactly 1.",
        }
    artifact = raw.get("artifact")
    if not isinstance(artifact, str):
        return None, {
            "code": "invalid_release_receipt",
            "message": "Release receipt artifact must be a string.",
        }
    return artifact, None


def _normalize_artifact(
    target: str | Path | None,
    root: Path,
    *,
    require_within_root: bool,
) -> tuple[str, str | None, str | None]:
    if target is None:
        return "", None, "Artifact identity is required."
    raw = str(target)
    if (
        not raw
        or len(raw) > MAX_ARTIFACT_REFERENCE_LENGTH
        or raw != raw.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        return "", None, "Artifact identity is empty, oversized, or malformed."
    if _IMAGE_REFERENCE.fullmatch(raw):
        return raw, "oci", None

    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        if candidate.is_symlink():
            return "", None, "Local artifact must not be a symbolic link."
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return (
            "",
            None,
            "Artifact must be a digest-pinned OCI reference or an existing local artifact.",
        )
    if require_within_root:
        try:
            relative = candidate.relative_to(root)
            resolved.relative_to(root)
        except ValueError:
            return "", None, "Release receipt local artifact must stay within the project."
        current = root
        try:
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    return "", None, (
                        "Release receipt local artifact path must not traverse symlinks."
                    )
        except OSError:
            return "", None, "Release receipt local artifact path is unreadable."
    if not (resolved.is_file() or resolved.is_dir()):
        return "", None, "Local artifact must be a regular file or directory."
    return str(resolved), "local", None


def _unknown_report(
    artifact: str | Path | None,
    code: str,
    message: str,
    *,
    profile_path: Path | None = None,
    profile_valid: bool = False,
    artifact_source: str = "argument",
) -> dict[str, Any]:
    reference = str(artifact) if artifact is not None else None
    return {
        "schema_version": 1,
        "kind": "gpu_artifact_preflight",
        "status": "UNKNOWN",
        "artifact": {
            "reference": reference,
            "target": reference,
            "identity": None,
            "identity_verified": False,
            "source": artifact_source,
        },
        "profile": {
            "path": str(profile_path) if profile_path is not None else None,
            "valid": profile_valid,
            "target_count": 0,
        },
        "inventory": {},
        "targets": [],
        "errors": [{"code": code, "message": message}],
    }


def _unique_object(pairs) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _relative_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path
