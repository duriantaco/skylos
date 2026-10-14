"""Build, verify and smoke-test the release artefacts in one place.

Both ``.github/workflows/publish.yml`` (on a release tag) and
``.github/workflows/dist-check.yml`` (on pull requests that touch packaging)
run this script, so the PR check builds exactly what a release publishes.

    python tools/release/build_dist.py build --out dist   # sdist, pure wheel, platform wheels, then verify
    python tools/release/build_dist.py verify --dist dist  # check what is in dist/
    python tools/release/build_dist.py smoke --dist dist   # install the best wheel for this machine, run doctor

``build`` needs a Go toolchain on PATH and the ``build`` package. ``smoke``
needs network access for the runtime dependencies; it never uploads anything.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_go_wheels  # noqa: E402

PURE_SUFFIX = "-py3-none-any.whl"
ENGINE_NAMES = (build_go_wheels.ENGINE_ARCNAME, build_go_wheels.ENGINE_ARCNAME + ".exe")
EXPECTED_TARGETS = {
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64",
    "windows/arm64",
}
# (format, CPU) of a binary built for each GOOS/GOARCH.
EXPECTED_BINARY = {
    "linux/amd64": ("ELF", "x86_64"),
    "linux/arm64": ("ELF", "aarch64"),
    "darwin/amd64": ("Mach-O", "x86_64"),
    "darwin/arm64": ("Mach-O", "arm64"),
    "windows/amd64": ("PE", "amd64"),
    "windows/arm64": ("PE", "arm64"),
}
_ELF_MACHINES = {0x3E: "x86_64", 0xB7: "aarch64"}
_MACHO_CPUS = {0x01000007: "x86_64", 0x0100000C: "arm64"}
_PE_MACHINES = {0x8664: "amd64", 0xAA64: "arm64"}


class DistError(Exception):
    """A problem with the built artefacts, phrased for the build log."""


# --- binary identification --------------------------------------------------


def binary_kind(data: bytes) -> tuple[str, str] | None:
    """(format, CPU) of an executable, or None when it is not one we build."""
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        if data[4] != 2 or data[5] != 1:  # 64-bit, little-endian
            return ("ELF", "unsupported")
        machine = struct.unpack_from("<H", data, 18)[0]
        return ("ELF", _ELF_MACHINES.get(machine, f"0x{machine:x}"))
    if data[:4] == b"\xcf\xfa\xed\xfe" and len(data) >= 8:  # MH_MAGIC_64, LE
        cpu = struct.unpack_from("<I", data, 4)[0]
        return ("Mach-O", _MACHO_CPUS.get(cpu, f"0x{cpu:x}"))
    if data[:2] == b"MZ" and len(data) >= 0x40:
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[offset : offset + 4] == b"PE\0\0" and len(data) >= offset + 6:
            machine = struct.unpack_from("<H", data, offset + 4)[0]
            return ("PE", _PE_MACHINES.get(machine, f"0x{machine:x}"))
    return None


def target_for_tags(platform_tags: list[str]) -> str:
    """The GOOS/GOARCH a wheel's platform tags stand for."""
    labels = set()
    for tag in platform_tags:
        if tag.startswith(("manylinux", "musllinux")):
            if tag.endswith("_x86_64"):
                labels.add("linux/amd64")
            elif tag.endswith("_aarch64"):
                labels.add("linux/arm64")
            else:
                labels.add(f"linux/{tag}")
        elif tag.startswith("macosx_"):
            if tag.endswith("_x86_64"):
                labels.add("darwin/amd64")
            elif tag.endswith("_arm64"):
                labels.add("darwin/arm64")
            else:
                labels.add(f"darwin/{tag}")
        elif tag == "win_amd64":
            labels.add("windows/amd64")
        elif tag == "win_arm64":
            labels.add("windows/arm64")
        else:
            labels.add(f"unknown/{tag}")
    if len(labels) != 1:
        raise DistError(f"platform tags {platform_tags} do not name one target")
    return labels.pop()


# --- wheel checks -----------------------------------------------------------


def _wheel_tags(name: str) -> tuple[str, list[str]]:
    stem = name[: -len(".whl")]
    parts = stem.split("-")
    if len(parts) < 5:
        raise DistError(f"{name}: not a wheel filename")
    python_tag, abi_tag, platform = parts[-3], parts[-2], parts[-1]
    if (python_tag, abi_tag) != ("py3", "none"):
        raise DistError(f"{name}: expected py3-none tags")
    return platform, platform.split(".")


def _check_record(wheel: zipfile.ZipFile, name: str) -> None:
    record_name = next((n for n in wheel.namelist() if n.endswith(".dist-info/RECORD")), None)
    if record_name is None:
        raise DistError(f"{name}: no RECORD")
    rows = {row[0]: row for row in csv.reader(io.StringIO(wheel.read(record_name).decode("utf-8"))) if row}
    for member in wheel.namelist():
        if member.endswith("/") or member == record_name:
            continue
        row = rows.get(member)
        data = wheel.read(member)
        if row is None or row[1] != build_go_wheels._record_hash(data) or row[2] != str(len(data)):
            raise DistError(f"{name}: RECORD does not match {member}")


def _wheel_metadata_tags(wheel: zipfile.ZipFile, name: str) -> list[str]:
    wheel_name = next((n for n in wheel.namelist() if n.endswith(".dist-info/WHEEL")), None)
    if wheel_name is None:
        raise DistError(f"{name}: no WHEEL metadata")
    text = wheel.read(wheel_name).decode("utf-8")
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("Tag:")]


def verify_wheel(path: Path) -> str | None:
    """Check one wheel; return its GOOS/GOARCH target (None for the pure wheel)."""
    name = path.name
    platform, platform_tags = _wheel_tags(name)
    with zipfile.ZipFile(path) as wheel:
        engines = [member for member in wheel.namelist() if member in ENGINE_NAMES]
        tags = _wheel_metadata_tags(wheel, name)
        if sorted(tags) != sorted(f"py3-none-{tag}" for tag in platform_tags):
            raise DistError(f"{name}: WHEEL tags {tags} do not match the filename")
        _check_record(wheel, name)
        if platform == "any":
            if engines:
                raise DistError(f"{name}: the pure wheel must not contain a Go engine")
            return None
        target = target_for_tags(platform_tags)
        if target not in EXPECTED_BINARY:
            raise DistError(f"{name}: unexpected platform {target}")
        expected_member = build_go_wheels.ENGINE_ARCNAME + (".exe" if target.startswith("windows/") else "")
        if engines != [expected_member]:
            raise DistError(f"{name}: expected exactly {expected_member}, found {engines or 'no engine'}")
        info = wheel.getinfo(expected_member)
        if (info.external_attr >> 16) & 0o111 == 0 and not target.startswith("windows/"):
            raise DistError(f"{name}: {expected_member} is not executable")
        kind = binary_kind(wheel.read(expected_member))
        if kind != EXPECTED_BINARY[target]:
            raise DistError(
                f"{name}: {expected_member} is {kind or 'not an executable'}, "
                f"expected {EXPECTED_BINARY[target]} for {target}"
            )
        return target


def verify_sdist(path: Path) -> None:
    import tarfile

    with tarfile.open(path) as sdist:
        for member in sdist.getmembers():
            base = member.name.rsplit("/", 1)[-1]
            if base in ("skylos-go", "skylos-go.exe"):
                raise DistError(f"{path.name}: the sdist must not contain {member.name}")


def verify(dist: Path) -> list[str]:
    """Check every artefact in ``dist``; return one line per artefact."""
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    pure = [wheel for wheel in wheels if wheel.name.endswith(PURE_SUFFIX)]
    if len(pure) != 1:
        raise DistError(f"expected one pure wheel in {dist}, found {len(pure)}")
    if len(sdists) != 1:
        raise DistError(f"expected one sdist in {dist}, found {len(sdists)}")
    lines = []
    seen: dict[str, str] = {}
    for wheel in wheels:
        target = verify_wheel(wheel)
        if target is not None:
            if target in seen:
                raise DistError(f"two wheels for {target}: {seen[target]}, {wheel.name}")
            seen[target] = wheel.name
        lines.append(f"ok  {wheel.name}" + (f"  ({target} engine)" if target else "  (pure)"))
    missing = EXPECTED_TARGETS - set(seen)
    if missing:
        raise DistError(f"no platform wheel for {', '.join(sorted(missing))}")
    verify_sdist(sdists[0])
    lines.append(f"ok  {sdists[0].name}  (no engine binary)")
    return lines


# --- build and smoke --------------------------------------------------------


def build(out: Path, go: str = "go") -> list[str]:
    """sdist + pure wheel with ``python -m build``, then the platform wheels."""
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(out)],
        cwd=REPO_ROOT,
        check=True,
    )
    pure = [wheel for wheel in out.glob("*" + PURE_SUFFIX)]
    if len(pure) != 1:
        raise DistError(f"python -m build left {len(pure)} pure wheels in {out}")
    build_go_wheels.main(
        [
            "--wheel",
            str(pure[0]),
            "--go-source",
            str(REPO_ROOT / "skylos" / "engines" / "go"),
            "--out",
            str(out),
            "--go",
            go,
        ]
    )
    return verify(out)


def _venv_bin(venv: Path, name: str) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / f"{name}.exe"
    return venv / "bin" / name


def _version(pure_wheel: Path) -> str:
    return pure_wheel.name.split("-")[1]


def smoke(dist: Path) -> dict:
    """Install the wheel pip picks for this machine and check its Go engine."""
    pure = sorted(dist.glob("*" + PURE_SUFFIX))
    if len(pure) != 1:
        raise DistError(f"expected one pure wheel in {dist}")
    # Windows can hold a just-exited venv's files briefly; cleanup errors there
    # must not fail a smoke test that already passed.
    with tempfile.TemporaryDirectory(
        prefix="skylos-dist-smoke-", ignore_cleanup_errors=True
    ) as scratch:
        venv = Path(scratch) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        python = _venv_bin(venv, "python")
        # Runtime dependencies come from the index with the pure wheel; then
        # pip picks the most specific local wheel for this platform.
        subprocess.run([str(python), "-m", "pip", "install", "--quiet", str(pure[0])], check=True)
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--quiet",
                "--force-reinstall",
                "--no-deps",
                "--no-index",
                "--find-links",
                str(dist),
                f"skylos=={_version(pure[0])}",
            ],
            check=True,
        )
        report = subprocess.run(
            [str(_venv_bin(venv, "skylos")), "doctor", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "SKYLOS_NO_UPDATE_CHECK": "1", "HOME": scratch, "USERPROFILE": scratch},
        )
        engine = json.loads(report.stdout)["checks"]["go_engine"]
        if engine.get("status") != "available" or engine.get("configured_by") != "bundled":
            raise DistError(f"installed wheel has no working bundled Go engine: {engine}")
        return engine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build", help="build the sdist and every wheel, then verify")
    build_parser.add_argument("--out", type=Path, default=Path("dist"))
    build_parser.add_argument("--go", default="go")
    for name in ("verify", "smoke"):
        sub.add_parser(name).add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            lines = build(args.out, args.go)
        elif args.command == "verify":
            lines = verify(args.dist)
        else:
            engine = smoke(args.dist)
            lines = [f"ok  bundled Go engine runs: {engine.get('binary')}"]
    except DistError as exc:
        print(f"build_dist: {exc}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
