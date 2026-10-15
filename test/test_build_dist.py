"""Release artefact checks shared by publish.yml and dist-check.yml."""

from __future__ import annotations

import importlib.util
import io
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
RELEASE = REPO / "tools" / "release"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RELEASE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bgw = _load("build_go_wheels")
bd = _load("build_dist")


# Minimal executable headers for each GOOS/GOARCH the release builds.
def _elf(machine):
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def _macho(cpu):
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + bytes(24)


def _pe(machine):
    data = bytearray(0x100)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    return bytes(data)


BINARIES = {
    "linux/amd64": _elf(0x3E),
    "linux/arm64": _elf(0xB7),
    "darwin/amd64": _macho(0x01000007),
    "darwin/arm64": _macho(0x0100000C),
    "windows/amd64": _pe(0x8664),
    "windows/arm64": _pe(0xAA64),
}


def _pure_wheel(dist: Path, *, with_engine=False) -> Path:
    path = dist / "skylos-9.9.9-py3-none-any.whl"
    files = {
        "skylos/__init__.py": b"__version__ = '9.9.9'\n",
        "skylos-9.9.9.dist-info/METADATA": b"Name: skylos\nVersion: 9.9.9\n",
        "skylos-9.9.9.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
        ),
    }
    if with_engine:
        files["skylos/engines/go/skylos-go"] = BINARIES["linux/amd64"]
    record = "".join(
        f"{name},{bgw._record_hash(data)},{len(data)}\n" for name, data in files.items()
    ) + "skylos-9.9.9.dist-info/RECORD,,\n"
    with zipfile.ZipFile(path, "w") as wheel:
        for name, data in files.items():
            wheel.writestr(name, data)
        wheel.writestr("skylos-9.9.9.dist-info/RECORD", record)
    return path


def _sdist(dist: Path, *, with_engine=False) -> Path:
    path = dist / "skylos-9.9.9.tar.gz"
    with tarfile.open(path, "w:gz") as sdist:
        names = ["skylos-9.9.9/pyproject.toml"]
        if with_engine:
            names.append("skylos-9.9.9/skylos/engines/go/skylos-go")
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = 3
            sdist.addfile(info, io.BytesIO(b"abc"))
    return path


def _dist(tmp_path, *, binaries=None, skip=(), pure_engine=False, sdist_engine=False):
    dist = tmp_path / "dist"
    dist.mkdir()
    pure = _pure_wheel(dist, with_engine=pure_engine)
    _sdist(dist, with_engine=sdist_engine)
    binaries = {**BINARIES, **(binaries or {})}
    for target in bgw.default_targets("go1.22.12"):
        if target.label in skip:
            continue
        engine = tmp_path / f"engine-{target.goos}-{target.goarch}"
        engine.write_bytes(binaries[target.label])  # skylos: ignore[SKY-D324] pytest fixture under tmp_path
        bgw.make_platform_wheel(pure, engine, target, dist)
    return dist


def test_complete_dist_verifies(tmp_path):
    lines = bd.verify(_dist(tmp_path))

    assert len(lines) == 8
    assert all(line.startswith("ok  ") for line in lines)
    assert any("(linux/amd64 engine)" in line for line in lines)
    assert any("(windows/arm64 engine)" in line for line in lines)
    assert lines[-1].endswith("(no engine binary)")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        # A darwin/arm64 wheel carrying the x86_64 engine.
        ({"binaries": {"darwin/arm64": BINARIES["darwin/amd64"]}}, "expected ('Mach-O', 'arm64')"),
        # A Linux wheel carrying a Windows binary.
        ({"binaries": {"linux/amd64": BINARIES["windows/amd64"]}}, "expected ('ELF', 'x86_64')"),
        ({"binaries": {"windows/amd64": b"not a binary"}}, "is not an executable"),
        ({"skip": ("windows/arm64",)}, "no platform wheel for windows/arm64"),
        ({"pure_engine": True}, "the pure wheel must not contain a Go engine"),
        ({"sdist_engine": True}, "the sdist must not contain"),
    ],
)
def test_broken_dist_is_rejected_with_the_reason(tmp_path, kwargs, message):
    with pytest.raises(bd.DistError) as raised:
        bd.verify(_dist(tmp_path, **kwargs))
    assert message in str(raised.value)


def test_tampered_wheel_fails_its_record_check(tmp_path):
    dist = _dist(tmp_path)
    wheel = next(dist.glob("*win_amd64.whl"))
    with zipfile.ZipFile(wheel) as source:
        members = {name: source.read(name) for name in source.namelist()}
    members["skylos/__init__.py"] = b"tampered = True\n"
    with zipfile.ZipFile(wheel, "w") as target:
        for name, data in members.items():
            target.writestr(name, data)

    with pytest.raises(bd.DistError, match="RECORD does not match skylos/__init__.py"):
        bd.verify(dist)


@pytest.mark.parametrize(
    ("tags", "target"),
    [
        (["manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64"], "linux/amd64"),
        (["manylinux_2_17_aarch64", "manylinux2014_aarch64"], "linux/arm64"),
        (["macosx_10_15_x86_64"], "darwin/amd64"),
        (["macosx_11_0_arm64"], "darwin/arm64"),
        (["win_amd64"], "windows/amd64"),
        (["win_arm64"], "windows/arm64"),
    ],
)
def test_platform_tags_name_one_target(tags, target):
    assert bd.target_for_tags(tags) == target


def test_mixed_platform_tags_are_rejected():
    with pytest.raises(bd.DistError):
        bd.target_for_tags(["manylinux2014_x86_64", "win_amd64"])


def test_cli_reports_a_broken_dist_with_exit_one(tmp_path, capsys):
    dist = _dist(tmp_path, skip=("linux/arm64",))
    assert bd.main(["verify", "--dist", str(dist)]) == 1
    assert "no platform wheel for linux/arm64" in capsys.readouterr().err


# --- workflows --------------------------------------------------------------


def _workflow(name):
    return yaml.safe_load((REPO / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def _on(workflow):
    return workflow.get("on", workflow.get(True))


def _steps(job):
    return [step.get("run", "") or step.get("uses", "") for step in job["steps"]]


def test_dist_check_runs_on_packaging_pull_requests_without_secrets():
    workflow = _workflow("dist-check.yml")
    paths = _on(workflow)["pull_request"]["paths"]
    for path in (
        ".github/workflows/publish.yml",
        ".github/workflows/dist-check.yml",
        "tools/release/**",
        "pyproject.toml",
        "MANIFEST.in",
        "skylos/engines/go/**",
    ):
        assert path in paths
    assert workflow["permissions"] == {"contents": "read"}
    text = (REPO / ".github" / "workflows" / "dist-check.yml").read_text(encoding="utf-8")
    assert "secrets." not in text
    assert "twine upload" not in text
    assert "id-token" not in text


def test_dist_check_and_publish_share_the_build_script():
    check = _workflow("dist-check.yml")
    publish = _workflow("publish.yml")
    build = check["jobs"]["build"]
    names = [step.get("name") for step in build["steps"]]
    assert names.index("Set up Go") < names.index("Build sdist and wheels")
    assert names.index("Build sdist and wheels") < names.index("Smoke test the bundled Go engine")
    check_runs = "\n".join(_steps(build))
    assert "python tools/release/build_dist.py build --out dist" in check_runs
    assert "python tools/release/build_dist.py smoke --dist dist" in check_runs
    assert "twine check dist/*" in check_runs

    publish_steps = publish["jobs"]["build"]["steps"]
    publish_names = [step.get("name") for step in publish_steps]
    publish_runs = "\n".join(_steps(publish["jobs"]["build"]))
    assert "python tools/release/build_dist.py build --out dist" in publish_runs
    assert "python tools/release/build_dist.py smoke --dist dist" in publish_runs
    assert (
        publish_names.index("Set up Go")
        < publish_names.index("Build sdist and wheels")
        < publish_names.index("Smoke test the bundled Go engine")
        < publish_names.index("Check dist contents")
    )
    # Same toolchains in both.
    def uses(steps, prefix):
        return [s["uses"] for s in steps if str(s.get("uses", "")).startswith(prefix)]

    assert uses(build["steps"], "actions/setup-go@") == uses(publish_steps, "actions/setup-go@")
    go_version = [s["with"]["go-version"] for s in build["steps"] if s.get("name") == "Set up Go"]
    assert go_version == [
        s["with"]["go-version"] for s in publish_steps if s.get("name") == "Set up Go"
    ]


def test_dist_check_installs_the_wheels_on_macos_and_windows():
    install = _workflow("dist-check.yml")["jobs"]["install"]
    assert install["needs"] == "build"
    assert install["strategy"]["matrix"]["os"] == ["macos-latest", "windows-latest"]
    assert "python tools/release/build_dist.py smoke --dist dist" in "\n".join(_steps(install))


def test_every_action_in_dist_check_is_pinned_to_a_commit():
    for job in _workflow("dist-check.yml")["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                ref = step["uses"].split("@", 1)[1]
                assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)


def test_dist_check_passes_the_skylos_actions_audit():
    from skylos.rules.config.cicd.github_actions import scan_github_actions_file

    path = REPO / ".github" / "workflows" / "dist-check.yml"
    assert scan_github_actions_file(str(path), root=str(REPO)) == []
