"""Safety bounds for static inspection of local CUDA artifacts."""

from __future__ import annotations

from hashlib import sha256
import io
from pathlib import Path
import struct
import subprocess

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.preflight import inspector, run_preflight


def _tool(tmp_path: Path, project: Path) -> Path:
    tool = tmp_path / "trusted-tools" / "cuobjdump"
    tool.parent.mkdir(exist_ok=True)
    assert write_text_no_symlink(
        tool,
        "test fixture; never executed\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    assert not tool.resolve().is_relative_to(project.resolve())
    return tool


def _profile(project: Path, *, include_l4: bool = False) -> None:
    profile = project / ".skylos" / "gpu-targets.yml"
    profile.parent.mkdir(parents=True, exist_ok=True)
    l4 = """
  - name: l4
    vendor: nvidia
    driver: "535.104.05"
    compute_capability: "8.9"
    platform: "linux/amd64"
""" if include_l4 else ""
    content = """version: 1
targets:
  - name: t4
    vendor: nvidia
    driver: "535.104.05"
    compute_capability: "7.5"
    platform: "linux/amd64"
""" + l4
    assert write_text_no_symlink(
        profile,
        content,
        encoding="utf-8",
    )


def _elf(
    machine: int,
    *,
    soname: str | None = None,
    needed: tuple[str, ...] = (),
    runpath: str | None = None,
    shared: bool = True,
) -> bytes:
    """Build a bounded ELF64 fixture with enough dynamic metadata for inspection."""
    data = bytearray(0x400)
    data[:16] = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3 if shared else 2,
        machine,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        2,
        0,
        0,
        0,
    )
    strings = bytearray(b"\0")

    def add_string(value: str) -> int:
        offset = len(strings)
        strings.extend(value.encode("ascii") + b"\0")
        return offset

    tags = [(1, add_string(value)) for value in needed]
    if soname is not None:
        tags.append((14, add_string(soname)))
    if runpath is not None:
        tags.append((29, add_string(runpath)))
    dynamic = [(5, 0x400300), (10, len(strings)), *tags, (0, 0)]
    dynamic_size = len(dynamic) * 16
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        5,
        0,
        0x400000,
        0x400000,
        len(data),
        len(data),
        0x1000,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        120,
        2,
        6,
        0x200,
        0x400200,
        0x400200,
        dynamic_size,
        dynamic_size,
        8,
    )
    for index, (tag, value) in enumerate(dynamic):
        struct.pack_into("<qQ", data, 0x200 + index * 16, tag, value)
    data[0x300 : 0x300 + len(strings)] = strings
    return bytes(data)


def _bundle_popen(
    monkeypatch,
    *,
    elf=b"ELF file 1: kernel.sm_75.cubin\n",
):
    calls = []

    class FakeProcess:
        def __init__(self, argv, kwargs):
            path = Path(argv[-1])
            if "libcudart" in path.name:
                output = b""
                error = (
                    f"cuobjdump info : File '{path}' does not contain device code\n"
                ).encode()
                self.returncode = 1
            elif "--list-elf" in argv:
                output = elf
                error = b""
                self.returncode = 0
            else:
                output = b""
                error = b""
                self.returncode = 0
            self.stdout = io.BytesIO(output)
            self.stderr = io.BytesIO(error)
            calls.append((list(argv), kwargs, self))

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            return None

    monkeypatch.setattr(
        inspector.subprocess,
        "Popen",
        lambda argv, **kwargs: FakeProcess(argv, kwargs),
    )
    return calls


def _recording_popen(
    monkeypatch,
    *,
    elf=b"ELF file 1: kernel.sm_75.cubin\n",
    ptx=b"PTX file 1: kernel.compute_75.ptx\n",
    stderr=b"",
    returncode=0,
    on_start=None,
):
    calls = []

    class FakeProcess:
        def __init__(self, argv, kwargs):
            output = elf if "--list-elf" in argv else ptx
            self.stdout = io.BytesIO(output)
            self.stderr = io.BytesIO(stderr)
            self.killed = False
            self.wait_timeouts = []
            calls.append((list(argv), kwargs, self))

        def wait(self, timeout=None):
            self.wait_timeouts.append(timeout)
            return returncode

        def kill(self):
            self.killed = True

    def fake_popen(argv, **kwargs):
        if on_start is not None:
            on_start(argv)
        return FakeProcess(argv, kwargs)

    monkeypatch.setattr(inspector.subprocess, "Popen", fake_popen)
    return calls


def test_local_file_inventory_uses_bounded_non_shell_cuobjdump(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "kernel.so"
    content = _elf(62)
    artifact.write_bytes(content)
    tool = _tool(tmp_path, project)
    monkeypatch.setenv("CUDA_INJECTION", "must-not-reach-scanner")
    monkeypatch.setenv("LD_PRELOAD", "/attacker/library.so")
    calls = _recording_popen(monkeypatch)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
        timeout_seconds=7,
    )

    assert inventory.inspection_complete is False
    assert inventory.identity_verified is True
    assert inventory.identity == "sha256:" + sha256(content).hexdigest()
    assert len(inventory.code_objects) == 1
    assert inventory.code_objects[0].cubins == ("sm_75",)
    assert inventory.code_objects[0].ptx == ("compute_75",)
    assert inventory.code_objects[0].cuda_runtime_version is None
    assert any("runtime binding" in error for error in inventory.errors)
    assert len(calls) == 2
    for argv, options, process in calls:
        assert argv[0] == str(tool.resolve())
        assert "--all-fatbin" not in argv
        inspected = Path(argv[-1])
        assert inspected.name.endswith("kernel.so")
        assert not inspected.is_relative_to(project)
        assert inspected != artifact.resolve()
        assert options["shell"] is False
        assert options["stdin"] is subprocess.DEVNULL
        assert Path(options["cwd"]).resolve() != project.resolve()
        assert options["env"]["LC_ALL"] == "C"
        assert "CUDA_INJECTION" not in options["env"]
        assert "LD_PRELOAD" not in options["env"]
        assert len(process.wait_timeouts) == 1
        assert 0 < process.wait_timeouts[0] <= 7


def test_local_directory_with_complete_static_inventory_passes(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project)
    (bundle / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN")
    )
    (bundle / "libcudart.so.12.4").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    (bundle / "libcudart.so.12").symlink_to("libcudart.so.12.4")
    tool = _tool(tmp_path, project)
    calls = _bundle_popen(monkeypatch)

    result = run_preflight(
        bundle,
        project_root=project,
        cuobjdump=tool,
    )

    assert result["status"] == "PASS"
    assert result["inventory"]["platform"] == "linux/amd64"
    assert result["inventory"]["cuda_runtime_version"] == "12"
    assert result["inventory"]["identity_verified"] is True
    assert result["inventory"]["identity"].startswith("tree-sha256:")
    assert result["targets"][0]["status"] == "PASS"
    inspected_names = {Path(argv[-1]).name for argv, _options, _process in calls}
    assert any(name.endswith("app.so") for name in inspected_names)
    assert any(name.endswith("libcudart.so.12.4") for name in inspected_names)
    assert all(not Path(argv[-1]).is_relative_to(project) for argv, _, _ in calls)


def test_origin_parent_lib_layout_proves_packaged_runtime(tmp_path, monkeypatch):
    project = tmp_path / "project"
    bundle = project / "bundle"
    binary_directory = bundle / "bin"
    library_directory = bundle / "lib"
    binary_directory.mkdir(parents=True)
    library_directory.mkdir()
    _profile(project)
    (binary_directory / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN/../lib")
    )
    (library_directory / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "PASS"
    assert result["inventory"]["cuda_runtime_version"] == "12"


def test_origin_search_cannot_escape_artifact(tmp_path, monkeypatch):
    project = tmp_path / "project"
    bundle = project / "bundle"
    binary_directory = bundle / "bin"
    binary_directory.mkdir(parents=True)
    _profile(project)
    (binary_directory / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN/../..")
    )
    (project / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["cuda_runtime_version"] is None
    assert any("escapes the artifact" in item["message"] for item in result["errors"])


def test_slash_bearing_needed_path_cannot_prove_packaged_runtime(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    binary_directory = bundle / "bin"
    library_directory = bundle / "lib"
    binary_directory.mkdir(parents=True)
    library_directory.mkdir()
    _profile(project)
    (binary_directory / "app.so").write_bytes(
        _elf(
            62,
            needed=("../lib/libcudart.so.12",),
            runpath="$ORIGIN/../lib",
        )
    )
    (library_directory / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["cuda_runtime_version"] is None
    assert any("DT_NEEDED contains a path" in item["message"] for item in result["errors"])


def test_origin_search_uses_first_resolvable_entry(tmp_path, monkeypatch):
    project = tmp_path / "project"
    bundle = project / "bundle"
    binary_directory = bundle / "bin"
    library_directory = bundle / "lib"
    binary_directory.mkdir(parents=True)
    library_directory.mkdir()
    _profile(project)
    (binary_directory / "app.so").write_bytes(
        _elf(
            62,
            needed=("libcudart.so.12",),
            runpath="$ORIGIN/missing:$ORIGIN/../lib",
        )
    )
    (library_directory / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "PASS"


@pytest.mark.parametrize(
    "runpath",
    ("/usr/local/cuda/lib64:$ORIGIN", ":$ORIGIN"),
)
def test_unverified_search_entry_before_origin_keeps_binding_unknown(
    tmp_path, monkeypatch, runpath
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project)
    (bundle / "app.so").write_bytes(
        _elf(
            62,
            needed=("libcudart.so.12",),
            runpath=runpath,
        )
    )
    (bundle / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["cuda_runtime_version"] is None
    assert any("not anchored to $ORIGIN" in item["message"] for item in result["errors"])


def test_unmodeled_loader_token_in_origin_path_keeps_binding_unknown(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    token_directory = bundle / "bin" / "$LIB"
    token_directory.mkdir(parents=True)
    _profile(project)
    (bundle / "bin" / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN/$LIB")
    )
    (token_directory / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["cuda_runtime_version"] is None
    assert any("unmodeled dynamic loader token" in item["message"] for item in result["errors"])


def test_origin_search_rejects_symlink_that_leaves_and_reenters_artifact(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    binary_directory = bundle / "bin"
    library_directory = bundle / "lib"
    external = tmp_path / "external"
    binary_directory.mkdir(parents=True)
    library_directory.mkdir()
    external.mkdir()
    _profile(project)
    (binary_directory / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN/hop")
    )
    (library_directory / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    (external / "back").symlink_to(library_directory)
    (binary_directory / "hop").symlink_to(external / "back")
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["cuda_runtime_version"] is None
    assert any("escapes the artifact" in item["message"] for item in result["errors"])


def test_selected_fatbin_multiarch_identifier_passes_t4_and_l4(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project, include_l4=True)
    (bundle / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN")
    )
    (bundle / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(
        monkeypatch,
        elf=(
            b"ELF file 1: kernel.sm_75.cubin\n"
            b"ELF file 2: kernel.sm_89.cubin\n"
        ),
    )

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "PASS"
    assert {target["name"]: target["status"] for target in result["targets"]} == {
        "t4": "PASS",
        "l4": "PASS",
    }
    assert result["inventory"]["code_objects"][0]["cubins"] == ["sm_75", "sm_89"]
    assert any("relocatable fatbins" in item for item in result["limitations"])
    assert any("symbol parity" in item for item in result["limitations"])


def test_each_selected_fatbin_identifier_requires_target_coverage(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project, include_l4=True)
    (bundle / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN")
    )
    (bundle / "libcudart.so.12").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(
        monkeypatch,
        elf=(
            b"ELF file 1: older.sm_75.cubin\n"
            b"ELF file 2: newer.sm_89.cubin\n"
        ),
    )

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert {item["path"] for item in result["inventory"]["code_objects"]} == {
        "app.so#older",
        "app.so#newer",
    }
    for target in result["targets"]:
        architecture = next(
            check for check in target["checks"] if check["id"] == "cuda_architecture"
        )
        assert architecture["status"] == "UNKNOWN"


def test_unbound_bundled_runtime_keeps_driver_verdict_unknown(tmp_path, monkeypatch):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project)
    (bundle / "app.so").write_bytes(_elf(62))
    (bundle / "libcudart.so.12.4").write_bytes(
        _elf(62, soname="libcudart.so.12")
    )
    (bundle / "libcudart.so.12").symlink_to("libcudart.so.12.4")
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["identity_verified"] is True
    checks = {item["id"]: item for item in result["targets"][0]["checks"]}
    assert checks["cuda_driver"]["status"] == "UNKNOWN"
    assert any("runtime binding" in item["message"] for item in result["errors"])


def test_runtime_filename_without_elf_soname_cannot_prove_version(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project)
    (bundle / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN")
    )
    (bundle / "libcudart.so.12").write_bytes(_elf(62))
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["cuda_runtime_version"] is None
    assert any("DT_SONAME" in item["message"] for item in result["errors"])


def test_runtime_provider_platform_must_match_cuda_consumer(tmp_path, monkeypatch):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project)
    (bundle / "app.so").write_bytes(
        _elf(62, needed=("libcudart.so.12",), runpath="$ORIGIN")
    )
    (bundle / "libcudart.so.12").write_bytes(
        _elf(183, soname="libcudart.so.12")
    )
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(bundle, project_root=project, cuobjdump=tool)

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["cuda_runtime_version"] is None
    assert any("multiple host platforms" in item["message"] for item in result["errors"])


@pytest.mark.parametrize(
    "malformation", ["class", "relocatable", "osabi", "elf-version"]
)
def test_cuda_consumer_requires_loadable_elf_class_and_type(
    tmp_path, monkeypatch, malformation
):
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "kernel.so"
    malformed = bytearray(_elf(62))
    if malformation == "class":
        malformed[4] = 1  # ELFCLASS32 cannot carry EM_X86_64 here.
    elif malformation == "relocatable":
        malformed[16:18] = (1).to_bytes(2, "little")  # ET_REL is not loadable.
    elif malformation == "osabi":
        malformed[7] = 9  # FreeBSD must not be inferred as Linux.
    else:
        malformed[20:24] = (0).to_bytes(4, "little")
    artifact.write_bytes(malformed)
    tool = _tool(tmp_path, project)
    _recording_popen(monkeypatch, ptx=b"")

    inventory = inspector.inspect_local_cuda_artifact(
        artifact, project_root=project, cuobjdump=tool
    )

    assert inventory.platform is None
    assert inventory.inspection_complete is False
    assert any("host platform" in error for error in inventory.errors)


def test_mixed_host_platform_directory_is_unknown(tmp_path, monkeypatch):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project)
    (bundle / "amd64.so").write_bytes(_elf(62))
    (bundle / "arm64.so").write_bytes(_elf(183))
    tool = _tool(tmp_path, project)
    _bundle_popen(monkeypatch)

    result = run_preflight(
        bundle,
        project_root=project,
        cuobjdump=tool,
    )

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["platform"] is None
    assert result["inventory"]["inspection_complete"] is False
    assert any(
        "multiple host platforms" in item["message"].lower()
        for item in result["errors"]
    )


def test_symlink_artifact_is_rejected_before_tool_resolution(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.so"
    outside.write_bytes(b"outside")
    artifact = project / "kernel.so"
    artifact.symlink_to(outside)

    def forbidden(*_args, **_kwargs):
        pytest.fail("a symlinked artifact must not start an inspector")

    monkeypatch.setattr(inspector.shutil, "which", forbidden)
    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
    )

    assert inventory.inspection_complete is False
    assert inventory.identity_verified is False
    assert any("symbolic link" in error for error in inventory.errors)


def test_directory_inspection_does_not_follow_symlinked_files(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    artifact = project / "bundle"
    artifact.mkdir(parents=True)
    local = artifact / "local.so"
    local.write_bytes(b"local")
    outside = tmp_path / "outside.so"
    outside.write_bytes(b"outside")
    (artifact / "linked.so").symlink_to(outside)
    tool = _tool(tmp_path, project)
    calls = _recording_popen(monkeypatch)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
    )

    inspected_paths = {Path(argv[-1]) for argv, _options, _process in calls}
    assert all(not path.is_relative_to(project) for path in inspected_paths)
    assert all(path.name.endswith("local.so") for path in inspected_paths)
    assert outside.resolve() not in inspected_paths
    assert [item.path for item in inventory.code_objects] == ["local.so#kernel"]
    assert inventory.inspection_complete is False
    assert inventory.identity_verified is False


def test_out_of_tree_nonbinary_symlink_invalidates_directory_identity(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    bundle = project / "bundle"
    bundle.mkdir(parents=True)
    _profile(project)
    (bundle / "app.so").write_bytes(_elf(62))
    outside = tmp_path / "outside-notes.txt"
    outside.write_text("outside", encoding="utf-8")
    (bundle / "metadata").symlink_to(outside)
    tool = _tool(tmp_path, project)
    calls = _bundle_popen(monkeypatch)

    result = run_preflight(
        bundle,
        project_root=project,
        cuobjdump=tool,
    )

    assert result["status"] == "UNKNOWN"
    assert result["inventory"]["inspection_complete"] is False
    assert result["inventory"]["identity_verified"] is False
    assert result["inventory"]["identity"] is None
    assert outside.resolve() not in {
        Path(argv[-1]).resolve() for argv, _options, _process in calls
    }
    assert any("symlink" in item["message"].lower() for item in result["errors"])


def test_project_local_cuobjdump_is_not_trusted(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "kernel.so"
    artifact.write_bytes(b"artifact")
    local_tool = project / "cuobjdump"
    local_tool.write_text("untrusted\n", encoding="utf-8")
    local_tool.chmod(0o755)
    monkeypatch.setattr(inspector.shutil, "which", lambda _name: str(local_tool))

    def forbidden(*_args, **_kwargs):
        pytest.fail("a project-controlled cuobjdump must not be launched")

    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
    )

    assert inventory.inspection_complete is False
    assert any("outside the scanned project" in error for error in inventory.errors)


def test_cuobjdump_inside_explicit_external_artifact_is_not_executed(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    project.mkdir()
    external_bundle = tmp_path / "external-artifact"
    external_bundle.mkdir()
    artifact = external_bundle / "app.so"
    artifact.write_bytes(_elf(62))
    local_tool = external_bundle / "cuobjdump"
    local_tool.write_text("artifact controlled\n", encoding="utf-8")
    local_tool.chmod(0o755)

    def forbidden(*_args, **_kwargs):
        pytest.fail("an artifact-controlled cuobjdump must not be launched")

    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=local_tool,
    )

    assert inventory.inspection_complete is False
    assert any("outside the scanned project" in error for error in inventory.errors)


def test_opaque_archive_magic_fails_closed_before_scanner(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "extensionless-package"
    artifact.write_bytes(b"PK\x03\x04" + b"opaque payload")
    tool = _tool(tmp_path, project)

    def forbidden(*_args, **_kwargs):
        pytest.fail("an opaque archive must not be passed to cuobjdump")

    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
    )

    assert inventory.inspection_complete is False
    assert any("Opaque packaged artifact" in error for error in inventory.errors)


def test_missing_cuobjdump_returns_incomplete_inventory(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "kernel.so"
    artifact.write_bytes(b"artifact")
    monkeypatch.setattr(inspector.shutil, "which", lambda _name: None)

    def forbidden(*_args, **_kwargs):
        pytest.fail("no subprocess may start when cuobjdump is unavailable")

    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
    )

    assert inventory.inspection_complete is False
    assert inventory.identity_verified is False
    assert any("cuobjdump is unavailable" in error for error in inventory.errors)


def test_candidate_file_limit_fails_closed(tmp_path, monkeypatch):
    project = tmp_path / "project"
    artifact = project / "bundle"
    nested = artifact / "nested"
    nested.mkdir(parents=True)
    (artifact / "a.so").write_bytes(b"a")
    (artifact / "b.so").write_bytes(b"b")
    (nested / "c.so").write_bytes(b"c")
    tool = _tool(tmp_path, project)
    calls = _recording_popen(monkeypatch)
    monkeypatch.setattr(inspector, "MAX_CANDIDATE_FILES", 1)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
    )

    assert inventory.inspection_complete is False
    assert len({argv[-1] for argv, _options, _process in calls}) <= 1
    assert any("candidate binaries" in error for error in inventory.errors)


def test_walked_directory_limit_fails_closed(tmp_path, monkeypatch):
    project = tmp_path / "project"
    artifact = project / "bundle"
    (artifact / "one" / "two").mkdir(parents=True)
    tool = _tool(tmp_path, project)
    monkeypatch.setattr(inspector, "MAX_WALKED_DIRECTORIES", 1)

    def forbidden(*_args, **_kwargs):
        pytest.fail("a directory-only fixture must not start cuobjdump")

    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
    )

    assert inventory.inspection_complete is False
    assert any("directories" in error for error in inventory.errors)


def test_overall_deadline_bounds_directory_discovery(tmp_path, monkeypatch):
    project = tmp_path / "project"
    artifact = project / "bundle"
    artifact.mkdir(parents=True)
    tool = _tool(tmp_path, project)
    clock = iter((10.0, 12.0))
    monkeypatch.setattr(inspector.time, "monotonic", lambda: next(clock, 12.0))

    def forbidden(*_args, **_kwargs):
        pytest.fail("expired discovery must not start cuobjdump")

    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
        timeout_seconds=1,
    )

    assert inventory.inspection_complete is False
    assert any("overall time limit" in error for error in inventory.errors)


def test_artifact_mutation_during_cuobjdump_fails_closed(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "kernel.so"
    artifact.write_bytes(b"original artifact")
    tool = _tool(tmp_path, project)
    mutated = False

    def mutate_once(_argv):
        nonlocal mutated
        if not mutated:
            mutated = True
            artifact.write_bytes(b"replacement artifact with a different size")

    calls = _recording_popen(monkeypatch, on_start=mutate_once)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
    )

    assert calls
    assert inventory.inspection_complete is False
    assert inventory.identity_verified is False
    assert inventory.code_objects
    assert all(Path(argv[-1]) != artifact for argv, _options, _process in calls)
    assert any("changed" in error for error in inventory.errors)


def test_single_file_size_limit_prevents_scanner_execution(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    artifact = project / "kernel.so"
    artifact.write_bytes(b"too large")
    tool = _tool(tmp_path, project)
    monkeypatch.setattr(inspector, "MAX_ARTIFACT_FILE_BYTES", 1)

    def forbidden(*_args, **_kwargs):
        pytest.fail("an oversized artifact must not start cuobjdump")

    monkeypatch.setattr(inspector.subprocess, "Popen", forbidden)

    inventory = inspector.inspect_local_cuda_artifact(
        artifact,
        project_root=project,
        cuobjdump=tool,
    )

    assert inventory.inspection_complete is False
    assert any("size limit" in error for error in inventory.errors)


def test_scanner_output_is_truncated_and_reported_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(inspector, "MAX_SCANNER_OUTPUT_BYTES", 8)
    calls = _recording_popen(monkeypatch, elf=b"sm_75 plus excess output", ptx=b"")

    returncode, output, problem = inspector._run_bounded(
        ["/trusted/cuobjdump", "--list-elf", "/artifact"],
        timeout=4,
    )

    assert returncode == 0
    assert len(output.encode("utf-8")) <= 8
    assert problem == "cuobjdump output exceeded the safety limit"
    assert calls[0][2].killed is True


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected"),
    [
        (b"arch = sm_75\n", b"", "unrecognized record format"),
        (
            b"ELF file 1: kernel.sm_75.cubin\n",
            b"warning: sm_89\n",
            "unexpected diagnostics",
        ),
    ],
)
def test_cuobjdump_parser_rejects_spoofed_or_ambiguous_output(
    tmp_path, monkeypatch, stdout, stderr, expected
):
    artifact = tmp_path / "snapshot.so"
    artifact.write_bytes(_elf(62))
    _recording_popen(monkeypatch, elf=stdout, ptx=b"", stderr=stderr)

    records, error = inspector._list_architectures(
        "/trusted/cuobjdump",
        artifact,
        "--list-elf",
        kind="cubin",
        deadline=inspector.time.monotonic() + 2,
    )

    assert records == {}
    assert error is not None and expected in error


def test_cuobjdump_parser_groups_multiarch_records_by_strict_identifier(
    tmp_path, monkeypatch
):
    artifact = tmp_path / "snapshot.so"
    artifact.write_bytes(_elf(62))
    _recording_popen(
        monkeypatch,
        elf=(
            b"ELF file 1: kernel.sm_75.cubin\n"
            b"ELF file 2: kernel.sm_89.cubin\n"
        ),
        ptx=b"",
    )

    records, error = inspector._list_architectures(
        "/trusted/cuobjdump",
        artifact,
        "--list-elf",
        kind="cubin",
        deadline=inspector.time.monotonic() + 2,
    )

    assert error is None
    assert records == {"kernel": ("sm_75", "sm_89")}


def test_no_device_diagnostic_must_name_exact_private_snapshot(tmp_path, monkeypatch):
    artifact = tmp_path / "snapshot.so"
    artifact.write_bytes(_elf(62))
    diagnostic = b"cuobjdump info : File '/attacker/sm_75' does not contain device code\n"
    _recording_popen(
        monkeypatch,
        elf=b"",
        ptx=b"",
        stderr=diagnostic,
        returncode=1,
    )

    records, error = inspector._list_architectures(
        "/trusted/cuobjdump",
        artifact,
        "--list-elf",
        kind="cubin",
        deadline=inspector.time.monotonic() + 2,
    )

    assert records == {}
    assert error is not None and "failed with exit code" in error


def test_elf_string_table_must_fit_one_unambiguous_load_segment():
    assert inspector._virtual_range_to_file_offset(95, 10, [(0, 0, 100)]) is None
    assert (
        inspector._virtual_range_to_file_offset(
            10,
            5,
            [(0, 0, 100), (0, 200, 100)],
        )
        is None
    )


def test_elf_dynamic_segment_must_be_inside_one_load_segment(tmp_path):
    artifact = tmp_path / "runtime.so"
    malformed = bytearray(_elf(62, soname="libcudart.so.12"))
    malformed[96:104] = (0x180).to_bytes(8, "little")
    artifact.write_bytes(malformed)
    candidate = inspector._candidate(
        artifact,
        artifact.stat(follow_symlinks=False),
    )

    metadata, error = inspector._elf_dynamic_metadata(candidate)

    assert metadata is None
    assert error is not None and "not mapped" in error


def test_scanner_timeout_kills_process_and_returns_incomplete(monkeypatch):
    calls = []

    class TimeoutProcess:
        def __init__(self, argv, kwargs):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.killed = False
            self.wait_count = 0
            calls.append((argv, kwargs, self))

        def wait(self, timeout=None):
            self.wait_count += 1
            if self.wait_count == 1:
                raise subprocess.TimeoutExpired("cuobjdump", timeout)
            return -9

        def kill(self):
            self.killed = True

    monkeypatch.setattr(
        inspector.subprocess,
        "Popen",
        lambda argv, **kwargs: TimeoutProcess(argv, kwargs),
    )

    returncode, _output, problem = inspector._run_bounded(
        ["/trusted/cuobjdump", "--list-elf", "/artifact"],
        timeout=3,
    )

    assert returncode is None
    assert problem == "cuobjdump timed out"
    _argv, options, process = calls[0]
    assert options["shell"] is False
    assert process.killed is True
    assert process.wait_count == 2
