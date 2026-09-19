"""Typed inputs for deterministic release preflight evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


MAX_CODE_OBJECTS = 4096
MAX_ARCHITECTURES = 4096
MAX_TOTAL_ARCHITECTURES = 16_384
MAX_ERRORS = 128
MAX_TEXT_LENGTH = 4096

_ARCHITECTURE_RE = re.compile(
    r"(?i)^(?P<prefix>sm|compute)_(?P<architecture>\d{2,3})(?P<suffix>[a-z])?$"
)
_PLATFORM_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*"
    r"(?:/[a-z0-9][a-z0-9._-]*)?$"
)
_CUDA_VERSION_RE = re.compile(r"^\d{1,2}(?:\.\d{1,3}){0,2}$")


class InventoryError(ValueError):
    """Raised when supplied artifact facts are malformed or ambiguous."""


@dataclass(frozen=True)
class CudaCodeObject:
    """CUDA code carried by one binary in the inspected artifact.

    ``required`` is deliberately three-state. ``None`` means static inspection
    could not establish whether the binary is loaded on the target, so an
    uncovered object produces UNKNOWN rather than a definitive FAIL.
    """

    path: str
    cubins: tuple[str, ...] = ()
    ptx: tuple[str, ...] = ()
    required: bool | None = True
    inspection_complete: bool = True
    errors: tuple[str, ...] = ()
    cuda_runtime_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "cubins": list(self.cubins),
            "ptx": list(self.ptx),
            "required": self.required,
            "inspection_complete": self.inspection_complete,
            "errors": list(self.errors),
            "cuda_runtime_version": self.cuda_runtime_version,
        }


@dataclass(frozen=True)
class ArtifactInventory:
    """Bounded facts collected from one exact release artifact."""

    artifact: str
    identity: str | None = None
    identity_verified: bool = False
    platform: str | None = None
    cuda_runtime_version: str | None = None
    code_objects: tuple[CudaCodeObject, ...] = ()
    inspection_complete: bool = True
    source: str = "provided"
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "identity": self.identity,
            "identity_verified": self.identity_verified,
            "platform": self.platform,
            "cuda_runtime_version": self.cuda_runtime_version,
            "inspection_complete": self.inspection_complete,
            "source": self.source,
            "code_objects": [item.to_dict() for item in self.code_objects],
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class GpuFleetTarget:
    name: str
    driver: str | None
    driver_branch: int | None
    compute_capability: str | None
    normalized_compute_capability: str | None
    platform: str | None


@dataclass(frozen=True)
class GpuFleetProfile:
    path: Path
    targets: tuple[GpuFleetTarget, ...]


def normalize_architecture(value: str, *, kind: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 32:
        raise InventoryError(f"invalid {kind} architecture")
    match = _ARCHITECTURE_RE.fullmatch(value.strip())
    if match is None:
        raise InventoryError(f"invalid {kind} architecture: {value!r}")
    prefix = match.group("prefix").lower()
    expected = "sm" if kind == "cubin" else "compute"
    # cuobjdump names listed PTX records with sm_* in some toolkit releases.
    if kind == "cubin" and prefix != "sm":
        raise InventoryError(f"cubin architecture must use sm_: {value!r}")
    suffix = (match.group("suffix") or "").lower()
    return f"{expected}_{int(match.group('architecture'))}{suffix}"


def inventory_from_mapping(raw: Mapping[str, object]) -> ArtifactInventory:
    """Strictly normalize an inventory supplied by an inspector or test harness."""
    if not isinstance(raw, Mapping):
        raise InventoryError("artifact inventory must be an object")
    allowed = {
        "artifact",
        "identity",
        "identity_verified",
        "platform",
        "cuda_runtime_version",
        "code_objects",
        "cubins",
        "ptx",
        "inspection_complete",
        "source",
        "errors",
    }
    unknown = sorted(str(key) for key in set(raw) - allowed)
    if unknown:
        raise InventoryError(
            "artifact inventory contains unsupported fields: " + ", ".join(unknown)
        )

    artifact = _required_text(raw.get("artifact"), "artifact")
    identity = _optional_text(raw.get("identity"), "identity")
    platform = _optional_text(raw.get("platform"), "platform")
    if platform is not None:
        platform = platform.lower()
        if _PLATFORM_RE.fullmatch(platform) is None:
            raise InventoryError("platform must be os/architecture[/variant]")
    runtime = _optional_text(
        raw.get("cuda_runtime_version"), "cuda_runtime_version"
    )
    if runtime is not None and _CUDA_VERSION_RE.fullmatch(runtime) is None:
        raise InventoryError("cuda_runtime_version must be numeric, such as 12.4")

    identity_verified = _boolean(
        raw.get("identity_verified", False), "identity_verified"
    )
    inspection_complete = _boolean(
        raw.get("inspection_complete", False), "inspection_complete"
    )
    source = _optional_text(raw.get("source", "provided"), "source") or "provided"
    errors = _text_tuple(raw.get("errors", ()), "errors", limit=MAX_ERRORS)
    if errors and inspection_complete:
        raise InventoryError(
            "inspection_complete cannot be true when inventory errors are present"
        )

    raw_objects = raw.get("code_objects", ())
    top_cubins = raw.get("cubins", ())
    top_ptx = raw.get("ptx", ())
    if (top_cubins or top_ptx) and raw_objects:
        raise InventoryError(
            "use either top-level cubins/ptx or code_objects, not both"
        )
    if top_cubins or top_ptx:
        raw_objects = (
            {
                "path": "<artifact>",
                "cubins": top_cubins,
                "ptx": top_ptx,
                "required": True,
                "inspection_complete": inspection_complete,
                "cuda_runtime_version": runtime,
            },
        )
    if not isinstance(raw_objects, (list, tuple)) or len(raw_objects) > MAX_CODE_OBJECTS:
        raise InventoryError(
            f"code_objects must be a list with at most {MAX_CODE_OBJECTS} entries"
        )
    total_architectures = 0
    for item in raw_objects:
        if not isinstance(item, Mapping):
            raise InventoryError("each code object must be an object")
        for field in ("cubins", "ptx"):
            values = item.get(field, ())
            if not isinstance(values, (list, tuple)):
                raise InventoryError(f"code_objects.{field} must be a list")
            total_architectures += len(values)
            if total_architectures > MAX_TOTAL_ARCHITECTURES:
                raise InventoryError(
                    "artifact inventory exceeds the total CUDA architecture "
                    f"entry limit of {MAX_TOTAL_ARCHITECTURES}"
                )
    code_objects = tuple(_code_object_from_mapping(item) for item in raw_objects)
    return ArtifactInventory(
        artifact=artifact,
        identity=identity,
        identity_verified=identity_verified,
        platform=platform,
        cuda_runtime_version=runtime,
        code_objects=code_objects,
        inspection_complete=inspection_complete,
        source=source,
        errors=errors,
    )


def _code_object_from_mapping(raw: object) -> CudaCodeObject:
    if not isinstance(raw, Mapping):
        raise InventoryError("each code object must be an object")
    allowed = {
        "path",
        "cubins",
        "ptx",
        "required",
        "inspection_complete",
        "errors",
        "cuda_runtime_version",
    }
    unknown = sorted(str(key) for key in set(raw) - allowed)
    if unknown:
        raise InventoryError(
            "code object contains unsupported fields: " + ", ".join(unknown)
        )
    path = _required_text(raw.get("path"), "code_objects.path")
    cubins = _architectures(raw.get("cubins", ()), kind="cubin")
    ptx = _architectures(raw.get("ptx", ()), kind="ptx")
    required = raw.get("required", True)
    if required is not None and type(required) is not bool:
        raise InventoryError("code_objects.required must be true, false, or null")
    complete = _boolean(
        raw.get("inspection_complete", False), "code_objects.inspection_complete"
    )
    errors = _text_tuple(
        raw.get("errors", ()), "code_objects.errors", limit=MAX_ERRORS
    )
    if errors and complete:
        raise InventoryError(
            "code_objects.inspection_complete cannot be true when errors are present"
        )
    runtime = _optional_text(
        raw.get("cuda_runtime_version"), "code_objects.cuda_runtime_version"
    )
    if runtime is not None and _CUDA_VERSION_RE.fullmatch(runtime) is None:
        raise InventoryError(
            "code_objects.cuda_runtime_version must be numeric, such as 12.4"
        )
    return CudaCodeObject(
        path=path,
        cubins=cubins,
        ptx=ptx,
        required=required,
        inspection_complete=complete,
        errors=errors,
        cuda_runtime_version=runtime,
    )


def _architectures(raw: object, *, kind: str) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)) or len(raw) > MAX_ARCHITECTURES:
        raise InventoryError(
            f"{kind} architectures must be a list with at most {MAX_ARCHITECTURES} entries"
        )
    return tuple(sorted({normalize_architecture(item, kind=kind) for item in raw}))


def _required_text(raw: object, field: str) -> str:
    value = _optional_text(raw, field)
    if value is None or not value.strip():
        raise InventoryError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_text(raw: object, field: str) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or len(raw) > MAX_TEXT_LENGTH:
        raise InventoryError(
            f"{field} must be a string with at most {MAX_TEXT_LENGTH} characters"
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise InventoryError(f"{field} contains control characters")
    return raw.strip()


def _text_tuple(raw: object, field: str, *, limit: int) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)) or len(raw) > limit:
        raise InventoryError(f"{field} must be a list with at most {limit} entries")
    return tuple(_required_text(item, field) for item in raw)


def _boolean(raw: object, field: str) -> bool:
    if type(raw) is not bool:
        raise InventoryError(f"{field} must be boolean")
    return raw
