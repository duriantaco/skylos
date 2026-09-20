"""Release preflight verdicts from bounded, static artifact evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.preflight import run_preflight


IMAGE = "registry.example.com/team/app@sha256:" + "a" * 64
OTHER_IMAGE = "registry.example.com/team/app@sha256:" + "b" * 64


def _write_profile(
    root: Path,
    *,
    driver: str = "535.104.05",
    platform: str = "linux/amd64",
) -> Path:
    profile = root / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        (
            "version: 1",
            "targets:",
            "  - name: t4",
            "    vendor: nvidia",
            f'    driver: "{driver}"',
            '    compute_capability: "7.5"',
            f'    platform: "{platform}"',
            "",
        )
    )
    assert write_text_no_symlink(
        profile,
        content,
        encoding="utf-8",
    )
    return profile


def _inventory(**overrides) -> dict:
    inventory = {
        "artifact": IMAGE,
        "identity": "sha256:" + "a" * 64,
        "identity_verified": True,
        "platform": "linux/amd64",
        "cuda_runtime_version": "12.4",
        "cubins": ["sm_75"],
        "ptx": [],
        "inspection_complete": True,
        "source": "test",
    }
    inventory.update(overrides)
    return inventory


@pytest.fixture(autouse=True)
def no_execution_or_network(monkeypatch):
    """Preflight consumes supplied evidence without running target-controlled code."""

    def forbidden(*_args, **_kwargs):
        pytest.fail("release preflight must remain static and offline in these tests")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def _assert_result_shape(result: dict, expected_status: str) -> dict:
    assert result["schema_version"] == 1
    assert result["status"] == expected_status
    assert isinstance(result["artifact"], dict)
    assert isinstance(result["profile"], dict)
    assert isinstance(result["inventory"], dict)
    assert isinstance(result["targets"], list)
    assert isinstance(result["errors"], list)
    return result


def _only_target(result: dict, expected_status: str) -> dict:
    assert len(result["targets"]) == 1
    target = result["targets"][0]
    assert target["name"] == "t4"
    assert target["status"] == expected_status
    assert isinstance(target["reasons"], list)
    assert isinstance(target["evidence"], list)
    return target


def test_pinned_digest_with_complete_native_inventory_passes(tmp_path):
    _write_profile(tmp_path)

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=_inventory())

    _assert_result_shape(result, "PASS")
    assert result["artifact"]["reference"] == IMAGE
    _only_target(result, "PASS")


@pytest.mark.parametrize(
    ("inventory", "driver", "expected_status"),
    [
        (_inventory(), "535.104.05", "PASS"),
        (_inventory(cubins=["sm_89"]), "535.104.05", "FAIL"),
        (_inventory(), "450.80.02", "FAIL"),
        (
            _inventory(
                identity_verified=False,
                platform=None,
                cuda_runtime_version=None,
                cubins=[],
                inspection_complete=False,
            ),
            "535.104.05",
            "UNKNOWN",
        ),
    ],
    ids=["pass", "architecture-fail", "driver-fail", "incomplete-unknown"],
)
def test_preflight_reports_pass_fail_or_unknown_per_target(
    tmp_path, inventory, driver, expected_status
):
    _write_profile(tmp_path, driver=driver)

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=inventory)

    _assert_result_shape(result, expected_status)
    target = _only_target(result, expected_status)
    if expected_status != "PASS":
        assert target["reasons"]


@pytest.mark.parametrize(
    "target",
    [
        "registry.example.com/team/app:latest",
        "registry.example.com/team/app@sha256:" + "a" * 63,
        "registry.example.com/team/app@sha256:" + "A" * 64,
        IMAGE + "; touch should-not-exist",
        "$(touch should-not-exist)",
    ],
    ids=["tag", "short-digest", "uppercase-digest", "shell-suffix", "substitution"],
)
def test_mutable_or_malicious_artifact_identity_is_unknown(tmp_path, target):
    _write_profile(tmp_path)

    result = run_preflight(target, project_root=tmp_path, inventory=_inventory())

    _assert_result_shape(result, "UNKNOWN")
    assert result["errors"]
    assert result["targets"] == []


def test_inventory_for_another_digest_cannot_prove_requested_artifact(tmp_path):
    _write_profile(tmp_path)

    result = run_preflight(
        IMAGE,
        project_root=tmp_path,
        inventory=_inventory(artifact=OTHER_IMAGE),
    )

    _assert_result_shape(result, "UNKNOWN")
    target = _only_target(result, "UNKNOWN")
    assert target["reasons"]


def test_identity_mismatch_prevents_downstream_fail_verdicts(tmp_path):
    _write_profile(tmp_path, driver="450.80.02")
    hostile_evidence = _inventory(
        artifact=OTHER_IMAGE,
        cubins=["sm_89"],
        cuda_runtime_version="12.4",
    )

    result = run_preflight(
        IMAGE,
        project_root=tmp_path,
        inventory=hostile_evidence,
    )

    _assert_result_shape(result, "UNKNOWN")
    target = _only_target(result, "UNKNOWN")
    checks = {item["id"]: item["status"] for item in target["checks"]}
    assert checks == {
        "artifact_identity": "UNKNOWN",
        "artifact_inventory": "UNKNOWN",
        "platform": "UNKNOWN",
        "cuda_architecture": "UNKNOWN",
        "cuda_driver": "UNKNOWN",
    }


@pytest.mark.parametrize(
    "identity",
    [
        "sha256:not-a-digest",
        "sha256:" + "A" * 64,
        "tree-sha256:" + "a" * 63,
    ],
)
def test_verified_identity_requires_v1_digest_syntax(tmp_path, identity):
    _write_profile(tmp_path)

    result = run_preflight(
        IMAGE,
        project_root=tmp_path,
        inventory=_inventory(identity=identity),
    )

    _assert_result_shape(result, "UNKNOWN")
    checks = {item["id"]: item for item in _only_target(result, "UNKNOWN")["checks"]}
    assert checks["artifact_identity"]["status"] == "UNKNOWN"
    assert "SHA-256" in checks["artifact_identity"]["message"]


def test_total_architecture_inventory_limit_fails_closed(tmp_path):
    _write_profile(tmp_path)
    oversized_inventory = _inventory(
        cubins=[],
        code_objects=[
            {
                "path": f"object-{index}.so",
                "cubins": ["sm_75"] * 4096,
                "ptx": [],
            }
            for index in range(5)
        ],
    )

    result = run_preflight(
        IMAGE,
        project_root=tmp_path,
        inventory=oversized_inventory,
    )

    _assert_result_shape(result, "UNKNOWN")
    assert result["targets"] == []
    assert result["errors"][0]["code"] == "invalid_artifact_inventory"


def test_unknown_numeric_compute_capability_cannot_inherit_compatibility(tmp_path):
    _write_profile(tmp_path)
    profile = tmp_path / ".skylos" / "gpu-targets.yml"
    profile.write_text(
        profile.read_text(encoding="utf-8").replace('"7.5"', '"7.6"'),
        encoding="utf-8",
    )

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=_inventory())

    _assert_result_shape(result, "UNKNOWN")
    target = _only_target(result, "UNKNOWN")
    architecture = next(
        check for check in target["checks"] if check["id"] == "cuda_architecture"
    )
    assert architecture["status"] == "UNKNOWN"
    assert "architecture registry" in architecture["message"]


def test_per_object_runtime_survives_public_inventory_normalization(tmp_path):
    _write_profile(tmp_path)
    inventory = _inventory(
        cubins=[],
        cuda_runtime_version="12",
        code_objects=[
            {
                "path": "app.so#kernel",
                "cubins": ["sm_75"],
                "ptx": [],
                "required": True,
                "inspection_complete": True,
                "errors": [],
                "cuda_runtime_version": "12",
            }
        ],
    )

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=inventory)

    _assert_result_shape(result, "PASS")
    assert result["inventory"]["code_objects"][0]["cuda_runtime_version"] == "12"


def test_one_bound_runtime_cannot_hide_an_unbound_code_object(tmp_path):
    _write_profile(tmp_path)
    inventory = _inventory(
        cubins=[],
        cuda_runtime_version="12",
        code_objects=[
            {
                "path": "bound.so#kernel",
                "cubins": ["sm_75"],
                "cuda_runtime_version": "12",
                "inspection_complete": True,
            },
            {
                "path": "unbound.so#kernel",
                "cubins": ["sm_75"],
                "cuda_runtime_version": None,
                "inspection_complete": True,
            },
        ],
    )

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=inventory)

    _assert_result_shape(result, "UNKNOWN")
    checks = {item["id"]: item for item in _only_target(result, "UNKNOWN")["checks"]}
    assert checks["cuda_architecture"]["status"] == "PASS"
    assert checks["cuda_driver"]["status"] == "UNKNOWN"
    assert "every required code object" in checks["cuda_driver"]["message"]


def test_ptx_only_evidence_never_claims_static_compatibility(tmp_path):
    _write_profile(tmp_path)
    inventory = _inventory(cubins=[], ptx=["compute_75"])

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=inventory)

    _assert_result_shape(result, "UNKNOWN")
    checks = {item["id"]: item for item in _only_target(result, "UNKNOWN")["checks"]}
    assert checks["cuda_architecture"]["status"] == "UNKNOWN"
    assert "PTX" in checks["cuda_architecture"]["message"]


def test_specialized_architecture_suffix_requires_richer_target_contract(tmp_path):
    _write_profile(tmp_path)
    inventory = _inventory(cubins=["sm_75a"])

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=inventory)

    _assert_result_shape(result, "UNKNOWN")
    checks = {item["id"]: item for item in _only_target(result, "UNKNOWN")["checks"]}
    assert checks["cuda_architecture"]["status"] == "UNKNOWN"
    assert "richer target contract" in checks["cuda_architecture"]["message"]


def test_partial_driver_version_does_not_create_false_failure(tmp_path):
    _write_profile(tmp_path, driver="525.60")

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=_inventory())

    _assert_result_shape(result, "UNKNOWN")
    checks = {item["id"]: item for item in _only_target(result, "UNKNOWN")["checks"]}
    assert checks["cuda_driver"]["status"] == "UNKNOWN"
    assert "version precision" in checks["cuda_driver"]["message"]


@pytest.mark.parametrize(
    ("driver", "expected"),
    [
        ("525.40.99", "FAIL"),
        ("525.41.0", "UNKNOWN"),
        ("528.33.0", "PASS"),
    ],
)
def test_windows_cuda12_abi_major_driver_boundaries(tmp_path, driver, expected):
    _write_profile(tmp_path, driver=driver, platform="windows/amd64")
    inventory = _inventory(platform="windows/amd64")

    result = run_preflight(IMAGE, project_root=tmp_path, inventory=inventory)

    _assert_result_shape(result, expected)
    checks = {item["id"]: item for item in _only_target(result, expected)["checks"]}
    assert checks["cuda_driver"]["status"] == expected


def test_pinned_remote_image_without_trusted_inventory_stays_unknown(tmp_path):
    _write_profile(tmp_path)

    result = run_preflight(IMAGE, project_root=tmp_path)

    _assert_result_shape(result, "UNKNOWN")
    _only_target(result, "UNKNOWN")


def test_missing_local_inspection_tool_produces_unknown_verdict(
    tmp_path, monkeypatch
):
    from skylos.preflight import inspector

    _write_profile(tmp_path)
    artifact = tmp_path / "kernel.so"
    artifact.write_bytes(b"static artifact fixture")
    monkeypatch.setattr(inspector.shutil, "which", lambda _name: None)

    result = run_preflight(artifact, project_root=tmp_path)

    _assert_result_shape(result, "UNKNOWN")
    target = _only_target(result, "UNKNOWN")
    assert target["reasons"]
    assert any("cuobjdump is unavailable" in item["message"] for item in result["errors"])


def test_release_receipt_discovers_exact_artifact(tmp_path):
    _write_profile(tmp_path)
    receipt = tmp_path / ".skylos" / "release.json"
    receipt.write_text(
        json.dumps({"version": 1, "artifact": IMAGE}),
        encoding="utf-8",
    )

    result = run_preflight(None, project_root=tmp_path, inventory=_inventory())

    _assert_result_shape(result, "PASS")
    assert result["artifact"]["reference"] == IMAGE
    assert result["artifact"]["source"] == "release_receipt"
    _only_target(result, "PASS")


@pytest.mark.parametrize(
    "receipt_text",
    [
        "{not-json",
        json.dumps({"version": 2, "artifact": IMAGE}),
        json.dumps({"version": 1, "image": IMAGE}),
        '{"version":1,"artifact":"first","artifact":"second"}',
        json.dumps(
            {"version": 1, "artifact": IMAGE, "command": "touch pwned"}
        ),
        "x" * 1_100_000,
    ],
    ids=[
        "malformed",
        "wrong-version",
        "wrong-artifact-key",
        "duplicate-key",
        "unknown-key",
        "oversized",
    ],
)
def test_invalid_or_unbounded_release_receipt_fails_closed(
    tmp_path, receipt_text
):
    _write_profile(tmp_path)
    receipt = tmp_path / ".skylos" / "release.json"
    receipt.write_text(receipt_text, encoding="utf-8")

    result = run_preflight(None, project_root=tmp_path, inventory=_inventory())

    _assert_result_shape(result, "UNKNOWN")
    assert result["errors"]
    assert result["targets"] == []
    assert not (tmp_path / "pwned").exists()


def test_symlinked_release_receipt_fails_closed(tmp_path):
    _write_profile(tmp_path)
    outside = tmp_path / "outside-release.json"
    outside.write_text(
        json.dumps({"version": 1, "artifact": IMAGE}), encoding="utf-8"
    )
    receipt = tmp_path / ".skylos" / "release.json"
    receipt.symlink_to(outside)

    result = run_preflight(None, project_root=tmp_path, inventory=_inventory())

    _assert_result_shape(result, "UNKNOWN")
    assert result["errors"]
    assert result["targets"] == []
