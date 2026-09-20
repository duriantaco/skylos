"""Deterministic GPU artifact-to-fleet compatibility evaluation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from skylos.preflight.models import (
    ArtifactInventory,
    CudaCodeObject,
    GpuFleetProfile,
    GpuFleetTarget,
)

_ARCH_RE = re.compile(r"^(?:sm|compute)_(?P<number>\d{2,3})(?P<suffix>[a-z]?)$")
_PINNED_IMAGE_RE = re.compile(r"^.+@(?P<digest>sha256:[0-9a-f]{64})$")
_CONTENT_ID_RE = re.compile(r"^(?:sha256|tree-sha256):[0-9a-f]{64}$")
_STATUS_RANK = {"PASS": 0, "UNKNOWN": 1, "FAIL": 2}
_MAX_CHECK_EVIDENCE = 256
_MAX_TARGET_EVIDENCE = 512
# Versioned from NVIDIA's published current and legacy hardware architectures. Unknown
# numeric values fail closed so a profile typo cannot inherit same-major SASS
# compatibility. Additions require an explicit data update and regression test.
_NVIDIA_COMPUTE_CAPABILITIES_V1 = frozenset(
    {
        "10",
        "11",
        "12",
        "13",
        "20",
        "21",
        "30",
        "32",
        "35",
        "37",
        "50",
        "52",
        "53",
        "60",
        "61",
        "62",
        "70",
        "72",
        "75",
        "80",
        "86",
        "87",
        "89",
        "90",
        "100",
        "103",
        "110",
        "120",
        "121",
    }
)
_CUDA_FAMILY_DRIVER_RANGE = {
    "linux": {
        11: ((450, 36, 6), (450, 80, 2)),
        12: ((525, 60, 13), (525, 60, 13)),
        13: ((580, 0, 0), (580, 0, 0)),
    },
    "windows": {
        11: ((451, 22, 0), (452, 39, 0)),
        12: ((525, 41, 0), (528, 33, 0)),
        13: ((580, 0, 0), (580, 0, 0)),
    },
}


def evaluate_gpu_inventory(
    profile: GpuFleetProfile,
    inventory: ArtifactInventory,
    *,
    requested_artifact: str | None = None,
    project_root: str | Path | None = None,
    artifact_source: str = "argument",
) -> dict[str, Any]:
    """Compare inspected CUDA facts with every declared fleet target.

    The evaluator is pure: it reads no files, starts no process, and performs no
    network access. A failed check wins over UNKNOWN so a proved incompatibility
    remains actionable even when another part of inspection was incomplete.
    """
    target_results = [
        _evaluate_target(target, inventory, requested_artifact=requested_artifact)
        for target in profile.targets
    ]
    status = _aggregate(item["status"] for item in target_results)
    profile_path = _display_path(profile.path, project_root)
    inventory_document = inventory.to_dict()
    inventory_document["cubin_architectures"] = sorted(
        {arch for item in inventory.code_objects for arch in item.cubins}
    )
    inventory_document["ptx_architectures"] = sorted(
        {arch for item in inventory.code_objects for arch in item.ptx}
    )
    errors = [
        {"code": "artifact_inspection_incomplete", "message": message}
        for message in inventory.errors
    ]
    return {
        "schema_version": 1,
        "kind": "gpu_artifact_preflight",
        "scope": (
            "static artifact identity, platform, selected executable-fatbin "
            "identifier/architecture coverage, packaged CUDA runtime route, "
            "and documented driver-family compatibility"
        ),
        "limitations": [
            "Nonselected and relocatable fatbins are outside the version-1 PASS scope.",
            "Per-kernel symbol parity across architecture records was not established.",
            "CUDA runtime evidence is a static packaged $ORIGIN route; loader environment "
            "overrides and hardware-capability directory selection were not tested.",
            "Runtime execution, workload correctness, memory demand, and performance were not tested.",
        ],
        "status": status,
        "artifact": {
            "reference": requested_artifact or inventory.artifact,
            "target": requested_artifact or inventory.artifact,
            "identity": inventory.identity,
            "identity_verified": inventory.identity_verified,
            "source": artifact_source,
            "inspection_source": inventory.source,
        },
        "profile": {
            "path": profile_path,
            "valid": True,
            "target_count": len(profile.targets),
        },
        "inventory": inventory_document,
        "targets": target_results,
        "errors": errors,
    }


def _evaluate_target(
    target: GpuFleetTarget,
    inventory: ArtifactInventory,
    *,
    requested_artifact: str | None,
) -> dict[str, Any]:
    identity_check = _identity_check(inventory, requested_artifact)
    if identity_check["status"] != "PASS":
        checks = [
            identity_check,
            _not_evaluated_check("artifact_inventory"),
            _not_evaluated_check("platform"),
            _not_evaluated_check("cuda_architecture"),
            _not_evaluated_check("cuda_driver"),
        ]
    else:
        checks = [
            identity_check,
            _inventory_completeness_check(inventory),
            _platform_check(target, inventory),
            _architecture_check(target, inventory),
            _driver_check(target, inventory),
        ]
    status = _aggregate(check["status"] for check in checks)
    decisive = next(
        (check for check in checks if check["status"] == "FAIL"),
        next((check for check in checks if check["status"] == "UNKNOWN"), None),
    )
    message = (
        decisive["message"]
        if decisive is not None
        else "All declared artifact compatibility checks completed."
    )
    evidence = []
    seen: set[tuple[str, str, str | None]] = set()
    for check in checks:
        for item in check["evidence"]:
            key = (item["kind"], item["value"], item.get("source"))
            if key not in seen and len(evidence) < _MAX_TARGET_EVIDENCE:
                seen.add(key)
                evidence.append(item)
    reasons = [
        check["message"] for check in checks if check["status"] != "PASS"
    ]
    return {
        "name": target.name,
        "status": status,
        "message": message,
        "platform": target.platform,
        "driver": target.driver,
        "compute_capability": target.compute_capability,
        "checks": checks,
        "reasons": reasons,
        "evidence": evidence,
        "limitations": [
            "Coverage is limited to identifiers and architectures in cuobjdump's selected executable fatbin.",
            "Nonselected or relocatable fatbins and per-kernel symbol parity were not tested.",
            "Runtime execution, workload correctness, memory demand, and performance were not tested."
        ],
    }


def _identity_check(
    inventory: ArtifactInventory, requested_artifact: str | None
) -> dict[str, Any]:
    evidence = [
        _evidence("inventory_artifact", inventory.artifact, inventory.source)
    ]
    if requested_artifact is not None:
        evidence.append(_evidence("requested_artifact", requested_artifact))
        if inventory.artifact != requested_artifact:
            return _check(
                "artifact_identity",
                "UNKNOWN",
                "The inspection inventory describes a different artifact.",
                evidence,
            )
    if not inventory.identity_verified:
        return _check(
            "artifact_identity",
            "UNKNOWN",
            "Artifact identity was not independently verified.",
            evidence,
        )
    if not inventory.identity:
        return _check(
            "artifact_identity",
            "UNKNOWN",
            "Artifact inspection did not provide a cryptographic content identity.",
            evidence,
        )
    if _CONTENT_ID_RE.fullmatch(inventory.identity) is None:
        evidence.append(_evidence("artifact_identity", inventory.identity))
        return _check(
            "artifact_identity",
            "UNKNOWN",
            "Artifact identity is not a version-1 lowercase SHA-256 content identifier.",
            evidence,
        )
    expected_image = _PINNED_IMAGE_RE.fullmatch(requested_artifact or "")
    if expected_image is not None and inventory.identity != expected_image.group("digest"):
        evidence.append(_evidence("artifact_identity", inventory.identity))
        return _check(
            "artifact_identity",
            "UNKNOWN",
            "Inventory content digest does not match the requested OCI digest.",
            evidence,
        )
    evidence.append(_evidence("artifact_identity", inventory.identity))
    return _check(
        "artifact_identity",
        "PASS",
        "Inspection evidence is bound to the requested artifact.",
        evidence,
    )


def _inventory_completeness_check(
    inventory: ArtifactInventory,
) -> dict[str, Any]:
    evidence = [
        _evidence(
            "inspection_complete",
            "true" if inventory.inspection_complete else "false",
            inventory.source,
        )
    ]
    if not inventory.inspection_complete or inventory.errors:
        return _check(
            "artifact_inventory",
            "UNKNOWN",
            "Artifact inspection did not complete within its declared scope.",
            evidence,
        )
    return _check(
        "artifact_inventory",
        "PASS",
        "Artifact inspection completed within its declared scope.",
        evidence,
    )


def _platform_check(
    target: GpuFleetTarget, inventory: ArtifactInventory
) -> dict[str, Any]:
    evidence = []
    if target.platform:
        evidence.append(_evidence("target_platform", target.platform, target.name))
    if inventory.platform:
        evidence.append(
            _evidence("artifact_platform", inventory.platform, inventory.source)
        )
    if target.platform is None:
        return _check(
            "platform",
            "UNKNOWN",
            "The fleet target does not declare an operating system/platform.",
            evidence,
        )
    if inventory.platform is None:
        return _check(
            "platform",
            "UNKNOWN",
            "Artifact inspection did not establish its operating system/platform.",
            evidence,
        )
    declared = target.platform.lower()
    actual = inventory.platform.lower()
    compatible = actual == declared or (
        "/" not in declared and actual.split("/", 1)[0] == declared
    )
    if not compatible:
        return _check(
            "platform",
            "FAIL",
            f"Artifact platform {actual} does not match declared target {declared}.",
            evidence,
        )
    return _check(
        "platform",
        "PASS",
        f"Artifact platform {actual} matches the fleet target.",
        evidence,
    )


def _architecture_check(
    target: GpuFleetTarget, inventory: ArtifactInventory
) -> dict[str, Any]:
    evidence = []
    if target.compute_capability:
        evidence.append(
            _evidence(
                "target_compute_capability",
                target.compute_capability,
                target.name,
            )
        )
    for code_object in inventory.code_objects:
        for cubin in code_object.cubins:
            _append_evidence(evidence, _evidence("cubin", cubin, code_object.path))
        for ptx in code_object.ptx:
            _append_evidence(evidence, _evidence("ptx", ptx, code_object.path))

    target_arch = target.normalized_compute_capability
    if target_arch is None:
        return _check(
            "cuda_architecture",
            "UNKNOWN",
            "The fleet target does not declare a CUDA compute capability.",
            evidence,
        )
    if target_arch not in _NVIDIA_COMPUTE_CAPABILITIES_V1:
        return _check(
            "cuda_architecture",
            "UNKNOWN",
            "The declared compute capability is not in Skylos's version-1 "
            "NVIDIA architecture registry.",
            evidence,
        )
    if not inventory.code_objects:
        return _check(
            "cuda_architecture",
            "UNKNOWN",
            "No CUDA cubin or PTX inventory was established for the artifact.",
            evidence,
        )

    uncovered_required: list[str] = []
    uncovered_unknown: list[str] = []
    incomplete: list[str] = []
    ptx_only: list[str] = []
    considered = 0
    routes: list[str] = []
    for code_object in inventory.code_objects:
        if code_object.required is False:
            continue
        considered += 1
        if not code_object.inspection_complete or code_object.errors:
            if len(incomplete) < 8:
                incomplete.append(code_object.path)
            continue
        route = _compatible_native_route(code_object, target_arch)
        if route is not None:
            if len(routes) < 8:
                routes.append(f"{code_object.path}: {route}")
            continue
        ptx_route = _compatible_ptx_route(code_object, target_arch)
        if ptx_route is not None:
            if len(ptx_only) < 8:
                ptx_only.append(f"{code_object.path}: {ptx_route}")
            continue
        if _has_specialized_architecture(code_object):
            if len(incomplete) < 8:
                incomplete.append(
                    f"{code_object.path} (architecture suffix requires a richer target contract)"
                )
            continue
        if code_object.required is None:
            if len(uncovered_unknown) < 8:
                uncovered_unknown.append(code_object.path)
        else:
            if len(uncovered_required) < 8:
                uncovered_required.append(code_object.path)

    if uncovered_required:
        return _check(
            "cuda_architecture",
            "FAIL",
            "Required CUDA code has no compatible cubin or PTX path: "
            + ", ".join(uncovered_required[:8]),
            evidence,
        )
    if incomplete or uncovered_unknown:
        affected = incomplete + uncovered_unknown
        return _check(
            "cuda_architecture",
            "UNKNOWN",
            "CUDA coverage could not be established for: "
            + ", ".join(affected[:8]),
            evidence,
        )
    if ptx_only:
        return _check(
            "cuda_architecture",
            "UNKNOWN",
            "Only PTX JIT coverage is available for: "
            + ", ".join(ptx_only[:8])
            + ". PTX compiler/ISA-to-driver compatibility was not established.",
            evidence,
        )
    if considered == 0:
        return _check(
            "cuda_architecture",
            "UNKNOWN",
            "The inventory contains no required CUDA code objects.",
            evidence,
        )
    return _check(
        "cuda_architecture",
        "PASS",
        "Every observed selected-fatbin identifier has a native architecture route ("
        + "; ".join(routes[:8])
        + ").",
        evidence,
    )


def _driver_check(
    target: GpuFleetTarget, inventory: ArtifactInventory
) -> dict[str, Any]:
    evidence = []
    if target.driver:
        evidence.append(_evidence("target_driver", target.driver, target.name))
    if target.driver_branch is None:
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "The fleet target does not declare an NVIDIA driver version.",
            evidence,
        )
    considered = [item for item in inventory.code_objects if item.required is not False]
    if not considered:
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "The inventory contains no required CUDA code objects whose runtime can be checked.",
            evidence,
        )
    missing_runtime: list[str] = []
    runtime_versions: set[str] = set()
    for code_object in considered:
        runtime = code_object.cuda_runtime_version
        if not code_object.inspection_complete or code_object.errors or runtime is None:
            if len(missing_runtime) < 8:
                missing_runtime.append(code_object.path)
            continue
        runtime_versions.add(runtime)
        _append_evidence(
            evidence,
            _evidence("cuda_runtime_version", runtime, code_object.path),
        )
    if missing_runtime:
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "CUDA runtime binding was not established for every required code object: "
            + ", ".join(missing_runtime),
            evidence,
        )
    if not runtime_versions:
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "Artifact inspection did not establish a bound CUDA runtime.",
            evidence,
        )
    if (
        inventory.cuda_runtime_version is not None
        and inventory.cuda_runtime_version not in runtime_versions
    ):
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "Artifact-wide and per-object CUDA runtime evidence disagree.",
            evidence,
        )

    platform = target.platform or inventory.platform
    if not platform:
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "Driver compatibility requires a declared target platform.",
            evidence,
        )
    family = platform.split("/", 1)[0].lower()
    driver_bounds = _driver_version_bounds(target.driver)
    if driver_bounds is None:
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "Declared NVIDIA driver version could not be interpreted precisely.",
            evidence,
        )
    driver_version, driver_upper_bound = driver_bounds
    ambiguous: list[str] = []
    checked_majors: list[int] = []
    for runtime in sorted(runtime_versions):
        try:
            cuda_major = int(runtime.split(".", 1)[0])
        except (TypeError, ValueError):
            return _check(
                "cuda_driver",
                "UNKNOWN",
                f"CUDA runtime version {runtime!r} could not be interpreted.",
                evidence,
            )
        driver_range = _CUDA_FAMILY_DRIVER_RANGE.get(family, {}).get(cuda_major)
        if driver_range is None:
            return _check(
                "cuda_driver",
                "UNKNOWN",
                f"Skylos has no driver compatibility floor for CUDA {cuda_major} on {family}.",
                evidence,
            )
        possible_minimum, family_minimum = driver_range
        possible_text = ".".join(str(part) for part in possible_minimum)
        family_text = ".".join(str(part) for part in family_minimum)
        _append_evidence(
            evidence,
            _evidence("minimum_possible_driver_version", possible_text, f"CUDA {cuda_major}"),
        )
        _append_evidence(
            evidence,
            _evidence("full_family_driver_version", family_text, f"CUDA {cuda_major}"),
        )
        if driver_upper_bound < possible_minimum:
            return _check(
                "cuda_driver",
                "FAIL",
                f"CUDA {runtime} requires NVIDIA driver {possible_text} or newer "
                f"on {family}; target has {target.driver}.",
                evidence,
            )
        if driver_version < possible_minimum:
            ambiguous.append(
                f"driver {target.driver} lacks enough version precision to prove "
                f"the CUDA {runtime} minimum {possible_text}"
            )
        elif driver_version < family_minimum:
            ambiguous.append(
                f"CUDA {runtime} may require up to driver {family_text}"
            )
        checked_majors.append(cuda_major)
    if ambiguous:
        return _check(
            "cuda_driver",
            "UNKNOWN",
            "The artifact exposes only CUDA ABI-level runtime evidence, so the "
            "declared driver is in an ambiguous toolkit-minor range: "
            + "; ".join(ambiguous),
            evidence,
        )
    return _check(
        "cuda_driver",
        "PASS",
        f"Driver {target.driver} satisfies the CUDA family floor for "
        + ", ".join(str(value) for value in sorted(set(checked_majors)))
        + "; "
        "runtime feature use remains untested.",
        evidence,
    )


def _compatible_native_route(
    code_object: CudaCodeObject, target_architecture: str
) -> str | None:
    target_value = int(target_architecture)
    target_major = target_value // 10
    for cubin in code_object.cubins:
        parsed = _parse_arch(cubin)
        if parsed is None:
            continue
        value, suffix = parsed
        # Feature-specific code such as sm_90a cannot be proved compatible from
        # the version-1 fleet contract, which records only numeric capability.
        if not suffix and value // 10 == target_major and value <= target_value:
            return f"native {cubin}"
    return None


def _has_specialized_architecture(code_object: CudaCodeObject) -> bool:
    return any(
        parsed is not None and bool(parsed[1])
        for value in (*code_object.cubins, *code_object.ptx)
        if (parsed := _parse_arch(value)) is not None
    )


def _driver_version_bounds(
    value: str | None,
) -> tuple[tuple[int, int, int], tuple[int, int, int]] | None:
    if value is None:
        return None
    match = re.fullmatch(
        r"\s*[rR]?(?P<major>\d{3,4})"
        r"(?:\.(?P<minor>\d+))?"
        r"(?:\.(?P<patch>\d+))?\s*",
        value,
    )
    if match is None:
        return None
    lower = (
        int(match.group("major")),
        int(match.group("minor") or 0),
        int(match.group("patch") or 0),
    )
    if match.group("minor") is None:
        upper = (lower[0], 999_999, 999_999)
    elif match.group("patch") is None:
        upper = (lower[0], lower[1], 999_999)
    else:
        upper = lower
    return lower, upper


def _compatible_ptx_route(
    code_object: CudaCodeObject, target_architecture: str
) -> str | None:
    target_value = int(target_architecture)
    for ptx in code_object.ptx:
        parsed = _parse_arch(ptx)
        if parsed is None:
            continue
        value, suffix = parsed
        if not suffix and value <= target_value:
            return f"JIT from {ptx}"
    return None


def _parse_arch(value: str) -> tuple[int, str] | None:
    match = _ARCH_RE.fullmatch(value)
    if match is None:
        return None
    return int(match.group("number")), match.group("suffix")


def _check(
    check_id: str,
    status: str,
    message: str,
    evidence: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": status,
        "message": message,
        "evidence": evidence[:_MAX_CHECK_EVIDENCE],
    }


def _not_evaluated_check(check_id: str) -> dict[str, Any]:
    return _check(
        check_id,
        "UNKNOWN",
        "Not evaluated because the inventory is not bound to the requested artifact.",
        [],
    )


def _evidence(kind: str, value: str, source: str | None = None) -> dict[str, str]:
    result = {"kind": kind, "value": value}
    if source:
        result["source"] = source
    return result


def _append_evidence(
    evidence: list[dict[str, str]], item: dict[str, str]
) -> None:
    if len(evidence) < _MAX_CHECK_EVIDENCE:
        evidence.append(item)


def _aggregate(statuses) -> str:
    return max(statuses, key=lambda item: _STATUS_RANK.get(item, 1), default="UNKNOWN")


def _display_path(path: Path, project_root: str | Path | None) -> str:
    if project_root is None:
        return str(path)
    try:
        root = Path(project_root).resolve(strict=True)
        return str(path.resolve(strict=False).relative_to(root))
    except (OSError, ValueError):
        return str(path)
