import json
from pathlib import Path

import pytest

import skylos.cli as cli
import skylos.rules.config.gpu.compatibility as gpu_compatibility
from skylos.analyzer import analyze
from skylos.cicd.review import filter_findings_to_diff
from skylos.rules.config import scan_config_files
from skylos.rules.config.gpu.compatibility import scan_gpu_compatibility


def _write_profile(tmp_path: Path, targets: list[dict[str, str]]) -> Path:
    profile = tmp_path / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir(parents=True, exist_ok=True)
    lines = ["version: 1", "targets:"]
    for target in targets:
        lines.append(f"  - name: {target['name']}")
        lines.append(f"    vendor: {target.get('vendor', 'nvidia')}")
        if driver := target.get("driver"):
            lines.append(f'    driver: "{driver}"')
        if compute_capability := target.get("compute_capability"):
            lines.append(f'    compute_capability: "{compute_capability}"')
        if platform := target.get("platform"):
            lines.append(f'    platform: "{platform}"')
    profile.write_text(  # skylos: ignore[SKY-D324] all callers pass pytest tmp_path
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    return profile


def _write_cuda_dockerfile(
    tmp_path: Path,
    *,
    cuda: str = "12.4.1",
    body: str = "",
) -> Path:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(  # skylos: ignore[SKY-D324] all callers pass pytest tmp_path
        f"FROM nvidia/cuda:{cuda}-runtime-ubuntu22.04\n{body}",
        encoding="utf-8",
    )
    return dockerfile


def _write_heterogeneous_profile(tmp_path: Path) -> Path:
    return _write_profile(
        tmp_path,
        [
            {
                "name": "a100",
                "driver": "535.104.05",
                "compute_capability": "8.0",
            },
            {
                "name": "rtx-a6000",
                "driver": "535.104.05",
                "compute_capability": "8.6",
            },
        ],
    )


def _write_tensorrt_builder(
    tmp_path: Path,
    *,
    compatibility: str = "",
    artifact: str = "model.engine",
) -> Path:
    source = tmp_path / "build_engine.py"
    source.write_text(  # skylos: ignore[SKY-D324] all callers pass pytest tmp_path
        f"""import tensorrt as trt

{compatibility}
serialized = builder.build_serialized_network(network, config)
with open("{artifact}", "wb") as output:
    output.write(serialized)
""",
        encoding="utf-8",
    )
    return source


def _write_packaged_engine(
    tmp_path: Path,
    *,
    artifact: str = "model.engine",
) -> Path:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(  # skylos: ignore[SKY-D324] all callers pass pytest tmp_path
        f"FROM python:3.12-slim\nCOPY {artifact} /models/{artifact}\n",
        encoding="utf-8",
    )
    return dockerfile


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _finding(findings, rule_id: str):
    return next(finding for finding in findings if finding["rule_id"] == rule_id)


def _assert_gpu_shape(finding, rule_id: str) -> None:
    assert {
        "rule_id": rule_id,
        "kind": "config",
        "category": "RELIABILITY",
        "domain": "gpu",
        "provider": "nvidia",
        "type": "gpu_compatibility",
    }.items() <= finding.items()
    assert finding["severity"] == "HIGH"
    assert isinstance(finding.get("metadata"), dict)
    assert finding["metadata"]


def test_cuda_12_image_rejects_target_driver_510(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(tmp_path)

    findings = scan_gpu_compatibility(tmp_path)

    finding = _finding(findings, "SKY-GPU001")
    _assert_gpu_shape(finding, "SKY-GPU001")
    assert "510" in finding["message"]
    assert "525" in finding["message"]
    assert finding["metadata"]["cuda_version"] == "12.4"
    assert finding["metadata"]["minimum_driver_branch"] == 525
    assert finding["metadata"]["incompatible_targets"][0]["name"] == ("legacy-node")


def test_cuda_12_image_accepts_target_driver_535(tmp_path):
    _write_profile(
        tmp_path,
        [
            {
                "name": "supported-node",
                "driver": "535.104.05",
                "compute_capability": "8.6",
            }
        ],
    )
    _write_cuda_dockerfile(tmp_path)

    assert "SKY-GPU001" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_cuda_12_uses_windows_driver_branch_floor_when_declared(tmp_path):
    _write_profile(
        tmp_path,
        [
            {
                "name": "windows-node",
                "driver": "527.99",
                "compute_capability": "8.6",
                "platform": "windows/amd64",
            }
        ],
    )
    _write_cuda_dockerfile(tmp_path)

    finding = _finding(scan_gpu_compatibility(tmp_path), "SKY-GPU001")

    assert finding["metadata"]["minimum_driver_branch"] == 528
    assert finding["metadata"]["incompatible_targets"][0]["platform"] == (
        "windows/amd64"
    )


def test_cuda_compat_text_does_not_silently_waive_driver_contract(tmp_path):
    _write_profile(
        tmp_path,
        [
            {
                "name": "legacy-node",
                "driver": "510.47.03",
                "compute_capability": "7.5",
            }
        ],
    )
    _write_cuda_dockerfile(
        tmp_path,
        body="RUN apt-get update && apt-get install -y cuda-compat-12-4\n",
    )

    assert "SKY-GPU001" in _rule_ids(scan_gpu_compatibility(tmp_path))


@pytest.mark.parametrize(
    "body",
    [
        "ENV NOTE=cuda-compat-12-4\n",
        "RUN apt-get install -y cuda-compat-11-8\n",
        (
            "RUN apt-get install -y cuda-compat-12-4 && "
            "apt-get purge -y cuda-compat-12-4\n"
        ),
    ],
)
def test_unproved_cuda_compat_variants_do_not_suppress_driver_mismatch(tmp_path, body):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(tmp_path, body=body)

    assert "SKY-GPU001" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_cuda_compat_comment_does_not_suppress_driver_mismatch(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(
        tmp_path,
        body="# TODO: consider cuda-compat-12-4\n",
    )

    assert "SKY-GPU001" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_ignore_text_inside_docker_value_does_not_suppress_driver_mismatch(
    tmp_path,
):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    (tmp_path / "Dockerfile").write_text(
        'ENV NOTE="skylos: ignore[SKY-GPU001]"\n'
        "FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04\n",
        encoding="utf-8",
    )

    assert "SKY-GPU001" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_explicit_docker_comment_can_waive_driver_contract(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04 # skylos: ignore[SKY-GPU001]\n",
        encoding="utf-8",
    )

    assert "SKY-GPU001" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_cuda_version_arg_is_resolved_in_base_image(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    (tmp_path / "Dockerfile").write_text(
        """ARG CUDA_VERSION=12.4.1
FROM nvidia/cuda:${CUDA_VERSION}-runtime-ubuntu22.04
""",
        encoding="utf-8",
    )

    assert "SKY-GPU001" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_unused_cuda_intermediate_stage_is_not_runtime_driver_evidence(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    (tmp_path / "Dockerfile").write_text(
        """FROM nvidia/cuda:12.4.1-devel-ubuntu22.04 AS unused
RUN nvcc --version
FROM python:3.12-slim
COPY app.py /app.py
""",
        encoding="utf-8",
    )

    assert "SKY-GPU001" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_cuda_from_inside_run_heredoc_is_not_a_docker_stage(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    (tmp_path / "Dockerfile").write_text(
        """FROM python:3.12-slim
RUN <<'SCRIPT'
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04
SCRIPT
""",
        encoding="utf-8",
    )

    assert "SKY-GPU001" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_missing_compiled_compute_capability_is_reported(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    # -real deliberately proves that this build has no forward-compatible PTX.
    (tmp_path / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES 75-real)\n",
        encoding="utf-8",
    )

    finding = _finding(scan_gpu_compatibility(tmp_path), "SKY-GPU002")

    _assert_gpu_shape(finding, "SKY-GPU002")
    assert "8.6" in finding["message"]
    assert finding["metadata"]["compiled_architectures"] == ["75"]
    assert (
        finding["metadata"]["missing_targets"][0]["normalized_compute_capability"]
        == "86"
    )


def test_unsuffixed_cmake_architecture_includes_forward_compatible_ptx(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES 75)\n",
        encoding="utf-8",
    )

    assert "SKY-GPU002" not in _rule_ids(scan_gpu_compatibility(tmp_path))


@pytest.mark.parametrize(
    "architecture",
    ["86-virtual", "86-real", "86"],
)
def test_newer_architecture_or_ptx_does_not_cover_older_target(tmp_path, architecture):
    _write_profile(
        tmp_path,
        [{"name": "turing-node", "compute_capability": "7.5"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        f"set(CMAKE_CUDA_ARCHITECTURES {architecture})\n",
        encoding="utf-8",
    )

    assert "SKY-GPU002" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_compute_capability_is_normalized_to_cmake_architecture(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES 86)\n",
        encoding="utf-8",
    )

    assert "SKY-GPU002" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_ptx_fallback_suppresses_missing_compiled_architecture(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        """set(CMAKE_CUDA_ARCHITECTURES 75)
set(TORCH_CUDA_ARCH_LIST "7.5+PTX")
""",
        encoding="utf-8",
    )

    assert "SKY-GPU002" not in _rule_ids(scan_gpu_compatibility(tmp_path))


@pytest.mark.parametrize("dynamic_arch", ["native", "all"])
def test_dynamic_cmake_architecture_suppresses_static_missing_arch(
    tmp_path, dynamic_arch
):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        f"""set(CMAKE_CUDA_ARCHITECTURES 75)
if(USE_LOCAL_GPU_TARGETS)
  set(CMAKE_CUDA_ARCHITECTURES {dynamic_arch})
endif()
""",
        encoding="utf-8",
    )

    assert "SKY-GPU002" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_native_cmake_architecture_emits_incomplete_release_proof(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES native)\n",
        encoding="utf-8",
    )

    assert "SKY-GPU000" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_conditional_cmake_architecture_emits_incomplete_release_proof(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        """if(BUILD_LEGACY)
  set(CMAKE_CUDA_ARCHITECTURES 75-real)
endif()
""",
        encoding="utf-8",
    )

    assert "SKY-GPU000" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_multiple_architecture_evidence_files_do_not_form_a_false_union(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES 75-real)\n",
        encoding="utf-8",
    )
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES 86-real)\n",
        encoding="utf-8",
    )

    findings = scan_gpu_compatibility(tmp_path)

    assert "SKY-GPU000" in _rule_ids(findings)
    assert "SKY-GPU002" not in _rule_ids(findings)


def test_dynamic_torch_architecture_suppresses_static_missing_arch(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "build.sh").write_text(
        """export CMAKE_CUDA_ARCHITECTURES=75
export TORCH_CUDA_ARCH_LIST=$RELEASE_CUDA_ARCHES
""",
        encoding="utf-8",
    )

    assert "SKY-GPU002" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_bracketed_nvcc_compute_code_is_a_ptx_fallback(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        """set(CMAKE_CUDA_ARCHITECTURES 75)
set(CUDA_NVCC_FLAGS
    "-gencode=arch=compute_75,code=[sm_75,compute_75]")
""",
        encoding="utf-8",
    )

    assert "SKY-GPU002" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_packaged_tensorrt_engine_for_heterogeneous_targets_is_reported(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path)
    _write_packaged_engine(tmp_path)

    finding = _finding(scan_gpu_compatibility(tmp_path), "SKY-GPU003")

    _assert_gpu_shape(finding, "SKY-GPU003")
    assert "8.0" in finding["message"]
    assert "8.6" in finding["message"]
    assert finding["metadata"]["target_compute_capabilities"] == {
        "a100": "80",
        "rtx-a6000": "86",
    }
    assert finding["metadata"]["builder_file"].endswith("build_engine.py")
    assert finding["metadata"]["package_file"].endswith("Dockerfile")


def test_tensorrt_hardware_compatibility_flags_suppress_portability_finding(
    tmp_path,
):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(
        tmp_path,
        compatibility=(
            "config.hardware_compatibility_level = "
            "trt.HardwareCompatibilityLevel.AMPERE_PLUS"
        ),
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_tensorrt_cpp_compatibility_setter_suppresses_portability_finding(
    tmp_path,
):
    _write_heterogeneous_profile(tmp_path)
    (tmp_path / "build_engine.cpp").write_text(
        """#include <NvInfer.h>
config->setHardwareCompatibilityLevel(
    nvinfer1::HardwareCompatibilityLevel::kAMPERE_PLUS);
auto serialized = builder->buildSerializedNetwork(*network, *config);
std::ofstream output("model.engine", std::ios::binary);
output.write(serialized->data(), serialized->size());
""",
        encoding="utf-8",
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_same_compute_compatibility_does_not_cover_different_capabilities(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(
        tmp_path,
        compatibility=(
            "config.hardware_compatibility_level = "
            "trt.HardwareCompatibilityLevel.SAME_COMPUTE_CAPABILITY"
        ),
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_ampere_compatibility_does_not_cover_pre_ampere_target(tmp_path):
    _write_profile(
        tmp_path,
        [
            {"name": "t4", "compute_capability": "7.5"},
            {"name": "a100", "compute_capability": "8.0"},
        ],
    )
    _write_tensorrt_builder(
        tmp_path,
        compatibility=(
            "config.hardware_compatibility_level = "
            "trt.HardwareCompatibilityLevel.AMPERE_PLUS"
        ),
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_ampere_hardware_compatibility_does_not_cover_multiple_platforms(tmp_path):
    _write_profile(
        tmp_path,
        [
            {
                "name": "x86-node",
                "compute_capability": "8.0",
                "platform": "linux/amd64",
            },
            {
                "name": "arm-node",
                "compute_capability": "8.0",
                "platform": "linux/arm64",
            },
        ],
    )
    _write_tensorrt_builder(
        tmp_path,
        compatibility=(
            "config.hardware_compatibility_level = "
            "trt.HardwareCompatibilityLevel.AMPERE_PLUS"
        ),
    )
    _write_packaged_engine(tmp_path)

    finding = _finding(scan_gpu_compatibility(tmp_path), "SKY-GPU003")

    assert "different runtime platforms" in finding["message"]
    assert finding["metadata"]["target_platforms"] == {
        "x86-node": "linux/amd64",
        "arm-node": "linux/arm64",
    }


def test_bare_hardware_compatibility_token_does_not_suppress_finding(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(
        tmp_path,
        compatibility="# TODO: consider HardwareCompatibilityLevel.AMPERE_PLUS",
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_python_docstring_is_not_tensorrt_builder_evidence(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    (tmp_path / "build_engine.py").write_text(
        '''"""Example only:
serialized = builder.build_serialized_network(network, config)
with open("model.engine", "wb") as output:
    output.write(serialized)
"""
''',
        encoding="utf-8",
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_ampere_assignment_after_build_does_not_suppress_finding(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    (tmp_path / "build_engine.py").write_text(
        """import tensorrt as trt

serialized = builder.build_serialized_network(network, config)
config.hardware_compatibility_level = trt.HardwareCompatibilityLevel.AMPERE_PLUS
with open("model.engine", "wb") as output:
    output.write(serialized)
""",
        encoding="utf-8",
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_ampere_assignment_on_unrelated_config_does_not_suppress_finding(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    (tmp_path / "build_engine.py").write_text(
        """import tensorrt as trt

other.hardware_compatibility_level = trt.HardwareCompatibilityLevel.AMPERE_PLUS
serialized = builder.build_serialized_network(network, config)
with open("model.engine", "wb") as output:
    output.write(serialized)
""",
        encoding="utf-8",
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_commented_tensorrt_build_call_is_not_release_evidence(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    (tmp_path / "build_engine.py").write_text(
        """serialized = None  # builder.build_serialized_network(network, config)
with open("model.engine", "wb") as output:
    output.write(b"")
""",
        encoding="utf-8",
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_tensorrt_engine_not_packaged_is_not_reported(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path)

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_tensorrt_copy_in_unused_stage_is_not_release_packaging(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path)
    (tmp_path / "Dockerfile").write_text(
        """FROM python:3.12-slim AS unused
COPY model.engine /models/model.engine
FROM python:3.12-slim
COPY app.py /app.py
""",
        encoding="utf-8",
    )

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_tensorrt_copy_inside_run_heredoc_is_not_packaging(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path)
    (tmp_path / "Dockerfile").write_text(
        """FROM python:3.12-slim
RUN <<'SCRIPT'
COPY model.engine /models/model.engine
SCRIPT
""",
        encoding="utf-8",
    )

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_unrelated_tensorrt_artifact_is_not_correlated(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path, artifact="encoder.engine")
    _write_packaged_engine(tmp_path, artifact="decoder.engine")

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_same_basename_in_fixture_directory_is_not_correlated(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path, artifact="model.engine")
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\nCOPY fixtures/model.engine /models/model.engine\n",
        encoding="utf-8",
    )

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_tensorrt_engine_for_homogeneous_targets_is_not_reported(tmp_path):
    _write_profile(
        tmp_path,
        [
            {"name": "node-a", "compute_capability": "8.6"},
            {"name": "node-b", "compute_capability": "8.6"},
        ],
    )
    _write_tensorrt_builder(tmp_path)
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


@pytest.mark.parametrize(
    "profile_text",
    [
        "version: [not valid\n",
        """version: 2
targets:
  - name: legacy-node
    vendor: nvidia
    driver: "510.47.03"
""",
    ],
    ids=["malformed", "unknown-version"],
)
def test_invalid_target_profiles_fail_closed(tmp_path, profile_text):
    profile = tmp_path / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir()
    profile.write_text(profile_text, encoding="utf-8")
    _write_cuda_dockerfile(tmp_path)

    findings = scan_gpu_compatibility(tmp_path)

    finding = _finding(findings, "SKY-GPU000")
    _assert_gpu_shape(finding, "SKY-GPU000")
    assert "cannot prove GPU release compatibility" in finding["message"]


def test_oversized_target_profile_fails_closed(tmp_path):
    profile = tmp_path / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir()
    profile.write_text("x" * (1024 * 1024 + 1), encoding="utf-8")
    _write_cuda_dockerfile(tmp_path)

    assert "SKY-GPU000" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_symlinked_target_profile_fails_closed(tmp_path):
    outside = tmp_path / "outside-profile.yml"
    outside.write_text(
        """version: 1
targets:
  - name: legacy-node
    vendor: nvidia
    driver: "510.47.03"
""",
        encoding="utf-8",
    )
    profile = tmp_path / "repo" / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir(parents=True)
    profile.symlink_to(outside)
    _write_cuda_dockerfile(tmp_path / "repo")

    assert "SKY-GPU000" in _rule_ids(scan_gpu_compatibility(tmp_path / "repo"))


@pytest.mark.parametrize(
    "profile_text",
    [
        "version: 1\ntargets: []\n",
        (
            "version: 1\ntargets:\n  - name: node\n    vendor: nvidia\n"
            "    drivers: '510.47.03'\n"
        ),
        (
            "version: 1\ntargets:\n  - name: node\n    vendor: nvidia\n"
            "    driver: not-a-driver\n"
        ),
        (
            "version: 1\ntargets:\n  - name: node\n    vendor: nvidia\n"
            "    driver: '510.47.03'\n    driver: '535.104.05'\n"
        ),
    ],
    ids=["empty", "unknown-key", "bad-driver", "duplicate-key"],
)
def test_ambiguous_gpu_contract_emits_blocking_contract_finding(tmp_path, profile_text):
    profile = tmp_path / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir()
    profile.write_text(profile_text, encoding="utf-8")

    findings = scan_gpu_compatibility(tmp_path)

    assert _rule_ids(findings) == {"SKY-GPU000"}


def test_deleted_gpu_contract_emits_contract_finding_in_changed_scan(tmp_path):
    deleted_profile = tmp_path / ".skylos" / "gpu-targets.yml"

    findings = scan_gpu_compatibility(
        tmp_path,
        changed_files={str(deleted_profile)},
    )

    finding = _finding(findings, "SKY-GPU000")
    assert "deleted" in finding["message"]
    assert Path(finding["file"]) == deleted_profile


def test_repository_without_target_profile_has_no_gpu_findings(tmp_path):
    _write_cuda_dockerfile(tmp_path)
    (tmp_path / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES 75)\n",
        encoding="utf-8",
    )
    _write_tensorrt_builder(tmp_path)

    assert scan_gpu_compatibility(tmp_path) == []


def test_truncated_gpu_evidence_emits_incomplete_contract_finding(
    tmp_path, monkeypatch
):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    _write_cuda_dockerfile(tmp_path)
    (tmp_path / "build.sh").write_text(
        "export TORCH_CUDA_ARCH_LIST='8.6'\n", encoding="utf-8"
    )
    monkeypatch.setattr(gpu_compatibility, "MAX_CANDIDATE_FILES", 1)

    findings = scan_gpu_compatibility(tmp_path)

    finding = _finding(findings, "SKY-GPU000")
    assert "exceeded 1 candidate files" in finding["message"]


def test_ignore_suppresses_gpu_rule(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(tmp_path)

    assert scan_gpu_compatibility(tmp_path, ignore={"SKY-GPU001"}) == []


def test_changed_files_outside_root_do_not_activate_gpu_scan(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    _write_profile(
        repo,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(repo)
    outside_dockerfile = _write_cuda_dockerfile(outside)

    findings = scan_gpu_compatibility(
        repo,
        changed_files={str(outside_dockerfile), "../outside/Dockerfile"},
    )

    assert findings == []


def test_unrelated_python_change_does_not_surface_preexisting_driver_finding(
    tmp_path,
):
    _write_profile(
        tmp_path,
        [
            {
                "name": "legacy-node",
                "driver": "510.47.03",
                "compute_capability": "7.5",
            }
        ],
    )
    _write_cuda_dockerfile(tmp_path)
    unrelated = tmp_path / "app.py"
    unrelated.write_text("value = 1\n", encoding="utf-8")

    findings = scan_gpu_compatibility(
        tmp_path,
        changed_files={str(unrelated)},
    )

    assert findings == []


def test_changed_target_profile_activates_whole_contract_and_anchors_finding(
    tmp_path,
):
    profile = _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(tmp_path)

    findings = scan_gpu_compatibility(tmp_path, changed_files={str(profile)})

    finding = _finding(findings, "SKY-GPU001")
    assert Path(finding["file"]).resolve() == profile.resolve()
    assert finding["line"] == 5
    assert {
        "file": str(profile),
        "start_line": 5,
        "end_line": 5,
    } in finding["related_locations"]


def test_changed_compute_capability_has_exact_profile_related_location(tmp_path):
    profile = _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "CMakeLists.txt").write_text(
        "set(CMAKE_CUDA_ARCHITECTURES 75-real)\n",
        encoding="utf-8",
    )

    finding = _finding(
        scan_gpu_compatibility(tmp_path, changed_files={str(profile)}),
        "SKY-GPU002",
    )

    assert finding["line"] == 5
    assert {
        "file": str(profile),
        "start_line": 5,
        "end_line": 5,
    } in finding["related_locations"]


def test_config_registry_includes_gpu_compatibility_findings(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(tmp_path)

    findings = scan_config_files(tmp_path)

    assert "SKY-GPU001" in _rule_ids(findings)


def test_analyzer_json_includes_gpu_compatibility_with_danger_enabled(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(tmp_path)

    result = json.loads(analyze(str(tmp_path), enable_danger=True))

    finding = _finding(result["reliability"], "SKY-GPU001")
    _assert_gpu_shape(finding, "SKY-GPU001")
    assert finding["evidence_contract"]["proof_state"] == "candidate"
    assert result.get("danger", []) == []
    assert result["analysis_summary"]["reliability_count"] == len(result["reliability"])


def test_analyzer_with_source_keeps_gpu_finding_out_of_security(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    _write_cuda_dockerfile(tmp_path)
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    result = json.loads(analyze(str(tmp_path), enable_danger=True))

    assert _finding(result["reliability"], "SKY-GPU001")
    assert all(
        finding.get("rule_id") != "SKY-GPU001" for finding in result.get("danger", [])
    )
    assert result["analysis_summary"].get("danger_count", 0) == len(
        result.get("danger", [])
    )
    assert result["analysis_summary"]["reliability_count"] == len(result["reliability"])
    rollups = result["analysis_summary"]["by_directory"]
    assert sum(item.get("reliability", 0) for item in rollups) >= 1


def test_unknown_gpu_platform_fails_closed_as_invalid_contract(tmp_path):
    _write_profile(
        tmp_path,
        [
            {
                "name": "unknown-node",
                "driver": "510.47.03",
                "platform": "moon/quantum",
            }
        ],
    )
    _write_cuda_dockerfile(tmp_path)

    assert _rule_ids(scan_gpu_compatibility(tmp_path)) == {"SKY-GPU000"}


def test_nvcc_real_architecture_shorthand_also_provides_ptx(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "build.sh").write_text(
        "nvcc -arch=sm_75 kernel.cu -o kernel\n",
        encoding="utf-8",
    )

    assert scan_gpu_compatibility(tmp_path) == []


def test_quoted_nvcc_example_is_not_release_architecture_evidence(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "ampere-node", "compute_capability": "8.6"}],
    )
    (tmp_path / "build.sh").write_text(
        "echo 'example: nvcc -arch=sm_86'\n",
        encoding="utf-8",
    )

    assert _rule_ids(scan_gpu_compatibility(tmp_path)) == {"SKY-GPU000"}


@pytest.mark.parametrize(
    "between_flag_and_build",
    [
        "config.hardware_compatibility_level = trt.HardwareCompatibilityLevel.NONE",
        "config = make_new_config()",
    ],
    ids=["compatibility-reset", "config-rebound"],
)
def test_tensorrt_ampere_state_is_invalidated_before_build(
    tmp_path, between_flag_and_build
):
    _write_heterogeneous_profile(tmp_path)
    (tmp_path / "build_engine.py").write_text(
        f"""import tensorrt as trt

config.hardware_compatibility_level = trt.HardwareCompatibilityLevel.AMPERE_PLUS
{between_flag_and_build}
serialized = builder.build_serialized_network(network, config)
with open("model.engine", "wb") as output:
    output.write(serialized)
""",
        encoding="utf-8",
    )
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


@pytest.mark.parametrize(
    "source",
    [
        """import tensorrt as trt
serialized = builder.build_serialized_network(network, config, logger)
with open("model.engine", "wb") as output:
    output.write(serialized)
""",
        """from .tensorrt import Builder
serialized = builder.build_serialized_network(network, config)
with open("model.engine", "wb") as output:
    output.write(serialized)
""",
        """import tensorrt as trt
serialized = builder.build_serialized_network(network, config)
serialized = b"not-the-engine"
with open("model.engine", "wb") as output:
    output.write(serialized)
""",
    ],
    ids=["extra-argument", "relative-import", "overwritten-result"],
)
def test_invalid_tensorrt_builder_evidence_is_not_correlated(tmp_path, source):
    _write_heterogeneous_profile(tmp_path)
    (tmp_path / "build_engine.py").write_text(source, encoding="utf-8")
    _write_packaged_engine(tmp_path)

    assert "SKY-GPU003" not in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_final_stage_inherits_cuda_base_image_evidence(tmp_path):
    _write_profile(
        tmp_path,
        [{"name": "legacy-node", "driver": "510.47.03"}],
    )
    (tmp_path / "Dockerfile").write_text(
        """FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04 AS cuda_base
FROM cuda_base AS final
""",
        encoding="utf-8",
    )

    assert "SKY-GPU001" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_final_stage_inherits_packaged_tensorrt_engine(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path)
    (tmp_path / "Dockerfile").write_text(
        """FROM python:3.12-slim AS packaged
COPY model.engine /models/model.engine
FROM packaged AS final
COPY app.py /app.py
""",
        encoding="utf-8",
    )

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


def test_absolute_cross_stage_copy_correlates_tensorrt_engine(tmp_path):
    _write_heterogeneous_profile(tmp_path)
    _write_tensorrt_builder(tmp_path)
    (tmp_path / "Dockerfile").write_text(
        """FROM python:3.12-slim AS builder
COPY . /workspace
FROM python:3.12-slim AS final
COPY --from=builder /workspace/model.engine /models/model.engine
""",
        encoding="utf-8",
    )

    assert "SKY-GPU003" in _rule_ids(scan_gpu_compatibility(tmp_path))


@pytest.mark.parametrize(
    ("filename", "target"),
    [
        ("Dockerfile", {"name": "legacy-node", "driver": "510.47.03"}),
        (
            "CMakeLists.txt",
            {"name": "ampere-node", "compute_capability": "8.6"},
        ),
    ],
    ids=["dockerfile", "cmake"],
)
def test_deleted_gpu_evidence_keeps_contract_finding_in_diff(
    tmp_path, filename, target
):
    _write_profile(tmp_path, [target])
    evidence = tmp_path / filename
    evidence.write_text(  # skylos: ignore[SKY-D215,SKY-D324] literal pytest filename under tmp_path
        (
            "FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04\n"
            if filename == "Dockerfile"
            else "set(CMAKE_CUDA_ARCHITECTURES 86-real)\n"
        ),
        encoding="utf-8",
    )
    evidence.unlink()  # skylos: ignore[SKY-D215] literal pytest filename under tmp_path

    finding = _finding(
        scan_gpu_compatibility(tmp_path, changed_files={str(evidence)}),
        "SKY-GPU000",
    )
    changed_ranges = [{"file": filename, "start": 1, "end": 1}]

    assert filter_findings_to_diff([finding], changed_ranges) == [finding]


def test_explicit_gpu_selection_requires_target_contract(tmp_path):
    assert scan_gpu_compatibility(tmp_path) == []
    assert _rule_ids(scan_gpu_compatibility(tmp_path, require_contract=True)) == {
        "SKY-GPU000"
    }


def test_config_registry_requires_contract_for_selected_gpu_rule(tmp_path):
    _write_cuda_dockerfile(tmp_path)

    findings = scan_config_files(tmp_path, required_rules=["SKY-GPU001"])

    assert _rule_ids(findings) == {"SKY-GPU000"}


def test_config_registry_normalizes_string_rule_selection(tmp_path):
    _write_cuda_dockerfile(tmp_path)

    findings = scan_config_files(tmp_path, required_rules="SKY-GPU001")

    assert _rule_ids(findings) == {"SKY-GPU000"}


def test_analyzer_requires_contract_for_selected_gpu_rule(tmp_path):
    _write_cuda_dockerfile(tmp_path)

    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            required_config_rules=["SKY-GPU001"],
        )
    )

    assert _rule_ids(result["reliability"]) == {"SKY-GPU000"}


@pytest.mark.parametrize("with_source", [False, True], ids=["config-only", "source"])
def test_analyzer_reports_config_scanner_failure_as_incomplete(
    tmp_path, monkeypatch, with_source
):
    _write_cuda_dockerfile(tmp_path)
    if with_source:
        (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    def fail_config_scan(*_args, **_kwargs):
        raise RuntimeError("forced config scanner failure")

    monkeypatch.setattr(
        "skylos.rules.config.scan_config_files",
        fail_config_scan,
    )

    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            required_config_rules=["SKY-GPU001"],
        )
    )

    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result["analysis_errors"][0]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert result["analysis_errors"][0]["kind"] == "config_scan_error"


def test_selected_gpu_scan_through_symlink_is_incomplete(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_cuda_dockerfile(repository)
    linked_repository = tmp_path / "linked-repository"
    linked_repository.symlink_to(repository, target_is_directory=True)

    result = json.loads(
        analyze(
            str(linked_repository),
            enable_danger=True,
            required_config_rules=["SKY-GPU001"],
        )
    )

    assert result.get("reliability", []) == []
    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result["analysis_errors"][0]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert result["analysis_errors"][0]["kind"] == "symlink_scan_root"


def test_cli_gpu_release_gate_blocks_missing_contract(tmp_path, monkeypatch, capsys):
    _write_cuda_dockerfile(tmp_path)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "--select",
            "SKY-GPU000,SKY-GPU001,SKY-GPU002,SKY-GPU003",
            "--gate",
            "--format",
            "concise",
            "--no-provenance",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    assert "SKY-GPU000" in capsys.readouterr().out


def test_cli_leaf_gpu_gate_keeps_invalid_contract_prerequisite(
    tmp_path, monkeypatch, capsys
):
    profile = tmp_path / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir(parents=True)
    profile.write_text(
        """version: 1
targets:
  - name: invalid-target
    vendor: nvidia
    driver: "510.47.03"
    platform: moon/quantum
""",
        encoding="utf-8",
    )
    _write_cuda_dockerfile(tmp_path)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "--select",
            "SKY-GPU001",
            "--gate",
            "--format",
            "concise",
            "--no-provenance",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    assert "SKY-GPU000" in capsys.readouterr().out
