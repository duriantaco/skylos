"""Platform wheels bundle the skylos-go engine (tools/release/build_go_wheels.py)."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "tools" / "release" / "build_go_wheels.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("build_go_wheels", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve their module through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bgw = _load_module()


def _pure_wheel(tmp_path: Path) -> Path:
    path = tmp_path / "skylos-9.9.9-py3-none-any.whl"
    files = {
        "skylos/__init__.py": b"__version__ = '9.9.9'\n",
        "skylos/engines/go_runner.py": b"# runner\n",
        "skylos-9.9.9.dist-info/METADATA": b"Name: skylos\nVersion: 9.9.9\n",
        "skylos-9.9.9.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: setuptools\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n\n"
        ),
    }
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for name, data in files.items():
        writer.writerow((name, bgw._record_hash(data), len(data)))
    writer.writerow(("skylos-9.9.9.dist-info/RECORD", "", ""))
    with zipfile.ZipFile(path, "w") as wheel:
        for name, data in files.items():
            wheel.writestr(name, data)
        wheel.writestr("skylos-9.9.9.dist-info/RECORD", record.getvalue())
    return path


def _record(wheel: zipfile.ZipFile) -> dict[str, tuple[str, str]]:
    name = next(n for n in wheel.namelist() if n.endswith(".dist-info/RECORD"))
    rows = csv.reader(io.StringIO(wheel.read(name).decode("utf-8")))
    return {row[0]: (row[1], row[2]) for row in rows}


@pytest.mark.parametrize(
    ("target", "engine_name"),
    [
        (bgw.Target("linux", "amd64", ("manylinux2014_x86_64",)), "skylos-go"),
        (bgw.Target("windows", "amd64", ("win_amd64",)), "skylos-go.exe"),
    ],
)
def test_platform_wheel_carries_executable_engine_and_valid_record(
    tmp_path, target, engine_name
):
    pure = _pure_wheel(tmp_path)
    binary = tmp_path / "engine-bin"
    binary.write_bytes(b"\x7fELF fake engine")

    out = bgw.make_platform_wheel(pure, binary, target, tmp_path)

    assert out.name == f"skylos-9.9.9-py3-none-{target.platform_tags[0]}.whl"
    with zipfile.ZipFile(out) as wheel:
        arcname = f"skylos/engines/go/{engine_name}"
        assert wheel.read(arcname) == b"\x7fELF fake engine"
        assert (wheel.getinfo(arcname).external_attr >> 16) & 0o777 == 0o755
        metadata = wheel.read("skylos-9.9.9.dist-info/WHEEL").decode()
        assert "Root-Is-Purelib: false" in metadata
        assert f"Tag: py3-none-{target.platform_tags[0]}" in metadata
        assert "py3-none-any" not in metadata
        # Every file is listed with the hash and size of its new content.
        record = _record(wheel)
        for name in wheel.namelist():
            if name.endswith("/RECORD"):
                assert record[name] == ("", "")
                continue
            data = wheel.read(name)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            assert record[name] == (
                "sha256=" + digest.rstrip(b"=").decode(),
                str(len(data)),
            )
        assert wheel.namelist()[-1].endswith(".dist-info/RECORD")


def test_compressed_tag_set_names_every_platform(tmp_path):
    pure = _pure_wheel(tmp_path)
    tags = ("manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64")
    binary = tmp_path / "engine-bin"
    binary.write_bytes(b"engine")

    out = bgw.make_platform_wheel(pure, binary, bgw.Target("linux", "amd64", tags), tmp_path)

    assert out.name == "skylos-9.9.9-py3-none-" + ".".join(tags) + ".whl"
    with zipfile.ZipFile(out) as wheel:
        metadata = wheel.read("skylos-9.9.9.dist-info/WHEEL").decode()
    assert [line for line in metadata.splitlines() if line.startswith("Tag:")] == [
        f"Tag: py3-none-{tag}" for tag in tags
    ]


def test_refuses_a_symlinked_engine(tmp_path):
    real = tmp_path / "real-engine"
    real.write_bytes(b"engine")
    link = tmp_path / "engine-link"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        bgw.make_platform_wheel(
            _pure_wheel(tmp_path),
            link,
            bgw.Target("linux", "amd64", ("manylinux2014_x86_64",)),
            tmp_path,
        )


def test_refuses_a_wheel_that_is_not_pure(tmp_path):
    impure = tmp_path / "skylos-9.9.9-py3-none-win_amd64.whl"
    impure.write_bytes(b"")
    with pytest.raises(ValueError):
        bgw.platform_wheel_name(impure, ("win_amd64",))


@pytest.mark.parametrize(
    ("go_version", "goarch", "expected"),
    [
        ("go1.22.12", "amd64", "10_15"),
        ("go1.22.12", "arm64", "11_0"),
        ("go1.24.3", "amd64", "11_0"),
        ("go1.26.5", "amd64", "12_0"),
        ("go1.26.5", "arm64", "12_0"),
    ],
)
def test_macos_tag_matches_the_go_toolchain_minimum(go_version, goarch, expected):
    assert bgw.macos_minimum(go_version, goarch) == expected


def test_every_default_target_has_platform_tags():
    targets = bgw.default_targets("go1.22.12")
    assert {target.label for target in targets} == {
        "linux/amd64",
        "linux/arm64",
        "darwin/amd64",
        "darwin/arm64",
        "windows/amd64",
        "windows/arm64",
    }
    assert all(target.platform_tags for target in targets)


@pytest.mark.skipif(shutil.which("go") is None, reason="needs a Go toolchain")
def test_cross_compiled_linux_engine_builds(tmp_path):
    target = bgw.Target("linux", "amd64", ("manylinux2014_x86_64",))
    binary = bgw.build_engine(REPO / "skylos" / "engines" / "go", target, tmp_path)
    assert binary.stat().st_size > 0
    assert binary.read_bytes()[:4] == b"\x7fELF"


def test_release_build_script_builds_the_platform_wheels():
    # publish.yml and dist-check.yml call build_dist.py (see
    # test_build_dist.py), which builds the platform wheels with this script.
    build_dist = (REPO / "tools" / "release" / "build_dist.py").read_text(encoding="utf-8")
    assert "build_go_wheels.main(" in build_dist
    assert '"--go-source"' in build_dist


def test_script_help_runs():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "--wheel" in result.stdout
