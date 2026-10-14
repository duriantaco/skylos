"""Build platform wheels that bundle the native ``skylos-go`` engine.

The pure ``py3-none-any`` wheel cannot carry a native binary, so a ``pip
install skylos`` had no Go dead-code or security analysis. The publish
workflow runs this after ``python -m build``: for each target it
cross-compiles ``skylos/engines/go`` with ``CGO_ENABLED=0`` (a static binary,
no libc dependency), copies the pure wheel, adds the binary at
``skylos/engines/go/skylos-go`` (``.exe`` on Windows), rewrites ``WHEEL`` and
``RECORD``, and names the wheel with that platform's tags. The pure wheel
stays as the fallback for every other platform; ``skylos doctor`` explains
how to get the engine there.

Usage (from the repository root)::

    python tools/release/build_go_wheels.py --wheel dist/skylos-X-py3-none-any.whl \
        --go-source skylos/engines/go --out dist
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

ENGINE_ARCNAME = "skylos/engines/go/skylos-go"
EXECUTABLE_ZIP_MODE = 0o100755 << 16
REGULAR_ZIP_MODE = 0o100644 << 16
PURE_TAG = "py3-none-any"
_GO_VERSION = re.compile(r"go(\d+)\.(\d+)")


@dataclass(frozen=True)
class Target:
    goos: str
    goarch: str
    platform_tags: tuple[str, ...]

    @property
    def exe_suffix(self) -> str:
        return ".exe" if self.goos == "windows" else ""

    @property
    def label(self) -> str:
        return f"{self.goos}/{self.goarch}"


def macos_minimum(go_version: str, goarch: str) -> str:
    """Oldest macOS the Go toolchain's binaries run on, as a wheel tag part.

    Go 1.21 and 1.22 need macOS 10.15, Go 1.23 and 1.24 need macOS 11, and
    Go 1.25+ needs macOS 12. Apple silicon starts at macOS 11.
    """
    match = _GO_VERSION.match(go_version.strip())
    if not match:
        raise ValueError(f"unrecognised Go version: {go_version!r}")
    major, minor = int(match.group(1)), int(match.group(2))
    if (major, minor) < (1, 21):
        raise ValueError(f"Go {major}.{minor} is older than the engine supports")
    if (major, minor) >= (1, 25):
        version = (12, 0)
    elif (major, minor) >= (1, 23):
        version = (11, 0)
    else:
        version = (10, 15)
    if goarch == "arm64":
        version = max(version, (11, 0))
    return f"{version[0]}_{version[1]}"


def default_targets(go_version: str) -> tuple[Target, ...]:
    return (
        Target(
            "linux",
            "amd64",
            (
                "manylinux_2_17_x86_64",
                "manylinux2014_x86_64",
                "musllinux_1_1_x86_64",
            ),
        ),
        Target(
            "linux",
            "arm64",
            (
                "manylinux_2_17_aarch64",
                "manylinux2014_aarch64",
                "musllinux_1_1_aarch64",
            ),
        ),
        Target(
            "darwin",
            "amd64",
            (f"macosx_{macos_minimum(go_version, 'amd64')}_x86_64",),
        ),
        Target(
            "darwin",
            "arm64",
            (f"macosx_{macos_minimum(go_version, 'arm64')}_arm64",),
        ),
        Target("windows", "amd64", ("win_amd64",)),
        Target("windows", "arm64", ("win_arm64",)),
    )


def go_version(go: str = "go") -> str:
    return subprocess.run(
        [go, "env", "GOVERSION"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def build_engine(go_source: Path, target: Target, out_dir: Path, go: str = "go") -> Path:
    """Cross-compile one static engine binary for ``target``."""
    output = out_dir / f"skylos-go-{target.goos}-{target.goarch}{target.exe_suffix}"
    env = dict(os.environ)
    env.update(
        {
            "CGO_ENABLED": "0",
            "GOOS": target.goos,
            "GOARCH": target.goarch,
            "GOFLAGS": "-buildvcs=false",
        }
    )
    subprocess.run(
        [
            go,
            "build",
            "-trimpath",
            "-ldflags=-s -w",
            "-o",
            str(output),
            "./cmd/skylos-go",
        ],
        cwd=go_source,
        env=env,
        check=True,
    )
    return output


MAX_ENGINE_BYTES = 200 * 1024 * 1024


def _read_engine(engine_binary: Path) -> bytes:
    """Read the freshly built engine: a regular file, never a symlink, capped."""
    if engine_binary.is_symlink() or not engine_binary.is_file():
        raise ValueError(f"{engine_binary} is not a regular file")
    with engine_binary.open("rb") as handle:
        data = handle.read(MAX_ENGINE_BYTES + 1)
    if len(data) > MAX_ENGINE_BYTES:
        raise ValueError(f"{engine_binary} is larger than {MAX_ENGINE_BYTES} bytes")
    return data


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _wheel_metadata(text: str, platform_tags: tuple[str, ...]) -> str:
    lines = []
    tags_written = False
    for line in text.splitlines():
        if line.startswith("Root-Is-Purelib:"):
            # A wheel with a native binary installs into platlib.
            lines.append("Root-Is-Purelib: false")
        elif line.startswith("Tag:"):
            if line.strip() != f"Tag: {PURE_TAG}":
                raise ValueError(f"expected a pure {PURE_TAG} wheel, found {line!r}")
            if not tags_written:
                lines.extend(f"Tag: py3-none-{tag}" for tag in platform_tags)
                tags_written = True
        else:
            lines.append(line)
    if not tags_written:
        raise ValueError("WHEEL metadata has no Tag line")
    return "\n".join(lines) + "\n"


def platform_wheel_name(pure_wheel: Path, platform_tags: tuple[str, ...]) -> str:
    name = pure_wheel.name
    suffix = f"-{PURE_TAG}.whl"
    if not name.endswith(suffix):
        raise ValueError(f"{name} is not a pure {PURE_TAG} wheel")
    return name[: -len(suffix)] + "-py3-none-" + ".".join(platform_tags) + ".whl"


def make_platform_wheel(
    pure_wheel: Path,
    engine_binary: Path,
    target: Target,
    out_dir: Path,
) -> Path:
    """Copy ``pure_wheel`` with ``engine_binary`` inside, tagged for ``target``."""
    out_path = out_dir / platform_wheel_name(pure_wheel, target.platform_tags)
    engine_arcname = ENGINE_ARCNAME + target.exe_suffix
    engine_bytes = _read_engine(engine_binary)

    with zipfile.ZipFile(pure_wheel) as source:
        infos = source.infolist()
        dist_info = {
            info.filename.split("/", 1)[0]
            for info in infos
            if info.filename.split("/", 1)[0].endswith(".dist-info")
        }
        if len(dist_info) != 1:
            raise ValueError(f"{pure_wheel.name} must hold one .dist-info folder")
        dist_info_dir = dist_info.pop()
        record_name = f"{dist_info_dir}/RECORD"
        wheel_name = f"{dist_info_dir}/WHEEL"

        entries: list[tuple[zipfile.ZipInfo, bytes]] = []
        for info in infos:
            if info.filename in (record_name,) or info.filename == engine_arcname:
                continue
            data = source.read(info.filename)
            if info.filename == wheel_name:
                data = _wheel_metadata(
                    data.decode("utf-8"), target.platform_tags
                ).encode("utf-8")
            entries.append((info, data))

    engine_info = zipfile.ZipInfo(engine_arcname, date_time=(1980, 1, 1, 0, 0, 0))
    engine_info.external_attr = EXECUTABLE_ZIP_MODE
    engine_info.compress_type = zipfile.ZIP_DEFLATED
    # Payload first, .dist-info last, RECORD at the very end (wheel convention).
    payload = [item for item in entries if not item[0].filename.startswith(dist_info_dir + "/")]
    metadata = [item for item in entries if item[0].filename.startswith(dist_info_dir + "/")]
    ordered = [*payload, (engine_info, engine_bytes), *metadata]

    record_rows = []
    for info, data in ordered:
        if info.is_dir():
            continue
        record_rows.append((info.filename, _record_hash(data), str(len(data))))
    record_rows.append((record_name, "", ""))
    record_buffer = io.StringIO()
    csv.writer(record_buffer, lineterminator="\n").writerows(record_rows)

    tmp_path = out_path.with_suffix(".whl.tmp")
    with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as target_zip:
        for info, data in ordered:
            new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            new_info.external_attr = info.external_attr or REGULAR_ZIP_MODE
            new_info.compress_type = zipfile.ZIP_DEFLATED
            target_zip.writestr(new_info, data)
        record_info = zipfile.ZipInfo(record_name, date_time=(1980, 1, 1, 0, 0, 0))
        record_info.external_attr = REGULAR_ZIP_MODE
        record_info.compress_type = zipfile.ZIP_DEFLATED
        target_zip.writestr(record_info, record_buffer.getvalue())
    tmp_path.replace(out_path)
    return out_path


def _select_targets(targets: tuple[Target, ...], wanted: str | None) -> tuple[Target, ...]:
    if not wanted:
        return targets
    labels = {label.strip() for label in wanted.split(",") if label.strip()}
    selected = tuple(target for target in targets if target.label in labels)
    unknown = labels - {target.label for target in selected}
    if unknown:
        raise SystemExit(f"unknown target(s): {', '.join(sorted(unknown))}")
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wheel", required=True, type=Path, help="pure py3-none-any wheel")
    parser.add_argument("--go-source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--go", default="go", help="Go toolchain to use")
    parser.add_argument(
        "--targets",
        help="comma-separated GOOS/GOARCH list (default: every supported target)",
    )
    args = parser.parse_args(argv)

    version = go_version(args.go)
    targets = _select_targets(default_targets(version), args.targets)
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="skylos-go-wheels-") as scratch:
        scratch_dir = Path(scratch)
        for target in targets:
            binary = build_engine(args.go_source.resolve(), target, scratch_dir, args.go)
            wheel = make_platform_wheel(args.wheel, binary, target, args.out)
            print(f"{target.label}: {wheel.name} ({wheel.stat().st_size:,} bytes)")
    print(f"Built with {version}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
