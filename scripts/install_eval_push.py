#!/usr/bin/env python3
"""Install a pinned Git pre-push eval gate; never install agent callbacks."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
MARKER = "# skylos-eval-pre-push: v1"
RUNTIME_FILES = (
    "scripts/eval_pre_push.py",
    "skylos/benchmarks/eval_push.py",
    "skylos/benchmarks/security.py",
    "skylos/benchmarks/dead_code.py",
    "skylos/benchmarks/_analysis_validation.py",
    "skylos/benchmarks/eval_workflow.py",
    "skylos/benchmarks/eval_identity.py",
    "skylos/benchmarks/eval_report.py",
)
CASE_IDS = {
    "security": ("ssrf-tainted-host", "ssrf-fixed-host-path"),
    "dead_code": ("fastapi-route-used",),
}
_GIT_LOCAL = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_NAMESPACE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
}


@dataclass(frozen=True)
class FileState:
    content: bytes | None
    mode: int | None


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _encode(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def _git(repo: Path, *args: str) -> str:
    # A parent hook may export a different repository. Keep global/system
    # configuration so shared hooksPath settings are still discovered/refused.
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in _GIT_LOCAL
        and not name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
    }
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("pre-push installation requires a valid Git checkout")
    return result.stdout.strip()


def _regular(path: Path) -> FileState:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return FileState(None, None)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(
            f"expected a regular file, not a symlink or special file: {path}"
        )
    return FileState(path.read_bytes(), stat.S_IMODE(info.st_mode))


def _safe_path(path: Path, roots: tuple[Path, ...]) -> Path:
    path = Path(os.path.abspath(path))

    def within(candidate: Path) -> bool:
        return any(candidate.is_relative_to(root) for root in roots)

    if not within(path):
        raise ValueError(
            f"refusing shared/global hook path outside this project: {path}"
        )
    for candidate in (path, *path.parents):
        if candidate in roots:
            break
        if candidate.is_symlink():
            raise ValueError(f"symlinked installation path is unsupported: {candidate}")
    if not within(path.resolve(strict=False)):
        raise ValueError(f"installation path escapes the project: {path}")
    return path


def _writable(path: Path, state: FileState) -> None:
    if state.mode is not None and not state.mode & 0o222:
        raise PermissionError(f"refusing to replace read-only file: {path}")


def _atomic_write(path: Path, content: bytes, expected: FileState, mode: int) -> None:
    if _regular(path) != expected:
        raise ValueError(f"installation file changed concurrently: {path}")
    _writable(path, expected)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, filename = tempfile.mkstemp(prefix=".skylos-install-", dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if _regular(path) != expected:
            raise ValueError(f"installation file changed concurrently: {path}")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _source_file(path: Path, root: Path) -> bytes:
    _safe_path(path, (root,))
    state = _regular(path)
    if state.content is None:
        raise ValueError(f"trusted push runtime is missing: {path}")
    return state.content


def _bundle_files(source: Path) -> dict[str, bytes]:
    """Pin the controller, graders and only the three reviewed fixture cases."""
    files = {name: _source_file(source / name, source) for name in RUNTIME_FILES}
    files.update({"skylos/__init__.py": b"", "skylos/benchmarks/__init__.py": b""})
    for suite, selected_ids in CASE_IDS.items():
        relative_manifest = f"benchmarks/{suite}/manifest.json"
        original = json.loads(_source_file(source / relative_manifest, source))
        if not isinstance(original, dict) or original.get("version") != 1:
            raise ValueError("trusted smoke manifest must be version 1")
        cases = original.get("cases")
        if not isinstance(cases, list) or any(
            not isinstance(case, dict) for case in cases
        ):
            raise ValueError("trusted smoke manifest cases must be objects")
        selected = []
        for case_id in selected_ids:
            matches = [case for case in cases if case.get("id") == case_id]
            if len(matches) != 1:
                raise ValueError(
                    f"trusted smoke case is missing or duplicated: {case_id}"
                )
            case = matches[0]
            value = case.get("path")
            relative = Path(value) if isinstance(value, str) else Path("/")
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                raise ValueError(f"unsafe trusted smoke fixture path: {case_id}")
            manifest_root = source / "benchmarks" / suite
            fixture = _safe_path(manifest_root / relative, (manifest_root,))
            entries = [fixture] if fixture.is_file() else sorted(fixture.rglob("*"))
            count = 0
            for entry in entries:
                _safe_path(entry, (manifest_root,))
                if entry.is_dir():
                    continue
                files[entry.relative_to(source).as_posix()] = _source_file(
                    entry, source
                )
                count += 1
            if not count:
                raise ValueError(f"trusted smoke fixture has no files: {case_id}")
            selected.append(case)
        files[relative_manifest] = _encode({"version": 1, "cases": selected})
    return files


def _bundle_identity(files: dict[str, bytes]) -> tuple[str, dict[str, str]]:
    hashes = {name: _hash(data) for name, data in sorted(files.items())}
    return _hash(_encode(hashes)), hashes


def _verify_bundle(path: Path, files: dict[str, bytes], manifest: bytes) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"pinned bundle is not a regular directory: {path}")
    expected, observed = {**files, "bundle.json": manifest}, set()
    for entry in path.rglob("*"):
        if entry.is_symlink():
            raise ValueError("pinned bundle contains a symlink")
        if entry.is_dir():
            continue
        name = entry.relative_to(path).as_posix()
        observed.add(name)
        if name not in expected or _regular(entry).content != expected[name]:
            raise ValueError(f"pinned bundle was modified: {entry}")
    if observed != set(expected):
        raise ValueError("pinned bundle is incomplete")


def _create_bundle(path: Path, files: dict[str, bytes], manifest: bytes) -> None:
    if path.exists():
        _verify_bundle(path, files, manifest)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".bundle-", dir=path.parent))
    try:
        for name, data in {**files, "bundle.json": manifest}.items():
            output = temporary / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            output.chmod(0o444)
        try:
            os.rename(temporary, path)
        except FileExistsError:
            _verify_bundle(path, files, manifest)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _wrapper(
    python: Path, bundle: Path, hashes: dict[str, str], prior: dict | None
) -> bytes:
    code = f"""import errno
import hashlib
import os
from pathlib import Path
import subprocess
import sys

BUNDLE = Path({str(bundle)!r})
HASHES = {hashes!r}
PRIOR = {prior!r}
PYTHON = {str(python)!r}

def main():
    data = sys.stdin.buffer.read()
    if PRIOR and PRIOR["executable"]:
        original = Path(PRIOR["path"])
        if original.is_symlink() or not original.is_file() or hashlib.sha256(original.read_bytes()).hexdigest() != PRIOR["sha256"]:
            raise ValueError("Existing pre-push backup changed; review/reinstall")
        command = [str(original), *sys.argv[1:]]
        try:
            previous = subprocess.run(command, input=data, check=False)
        except OSError as error:
            if error.errno != errno.ENOEXEC:
                raise
            previous = subprocess.run(["/bin/sh", *command], input=data, check=False)
        if previous.returncode:
            return previous.returncode if previous.returncode > 0 else 128 - previous.returncode
    if BUNDLE.is_symlink() or not BUNDLE.is_dir():
        raise ValueError("Pinned pre-push runtime is missing or redirected")
    found = set()
    for entry in BUNDLE.rglob("*"):
        if entry.is_symlink():
            raise ValueError("Pinned pre-push runtime contains a symlink")
        if entry.is_dir():
            continue
        name = entry.relative_to(BUNDLE).as_posix()
        found.add(name)
        if name not in HASHES or hashlib.sha256(entry.read_bytes()).hexdigest() != HASHES[name]:
            raise ValueError("Pinned pre-push runtime changed; reinstall from reviewed source")
    if found != set(HASHES):
        raise ValueError("Pinned pre-push runtime is incomplete")
    return subprocess.run([PYTHON, "-B", str(BUNDLE / "scripts/eval_pre_push.py"), "--repo", os.getcwd(), "--", *sys.argv[1:]], input=data, check=False).returncode

try:
    raise SystemExit(main())
except Exception as error:
    print("Skylos pre-push gate could not run: " + str(error), file=sys.stderr)
    raise SystemExit(1)
"""
    return (
        "#!/bin/sh\n"
        + MARKER
        + "\nexec "
        + shlex.quote(str(python))
        + " -B -c "
        + shlex.quote(code)
        + ' "$@"\n'
    ).encode()


def install_push(
    repo: Path, python: Path, *, source: Path = ROOT, dry_run: bool = False
) -> dict:
    if os.name != "posix":
        raise ValueError("the local pre-push installer currently requires macOS/Linux")
    repo, source = Path(repo).resolve(strict=True), Path(source).resolve(strict=True)
    python = Path(os.path.abspath(python))  # Preserve the venv spelling.
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("--python must be an executable interpreter")
    if Path(_git(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
        raise ValueError("--repo must be a non-bare Git checkout root")
    common = Path(
        _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    ).resolve()
    gitdir = Path(_git(repo, "rev-parse", "--absolute-git-dir")).resolve()
    allowed = (repo, common, gitdir)
    hook = _safe_path(
        Path(
            _git(
                repo,
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "hooks/pre-push",
            )
        ),
        allowed,
    )
    if hook.is_relative_to(repo) and _git(
        repo, "ls-files", "--", hook.relative_to(repo).as_posix()
    ):
        raise ValueError(
            "private pre-push destination is Git-tracked; refusing to overwrite it"
        )
    state_path = _safe_path(
        common / "skylos-evals" / ("pre-push-" + _hash(str(hook).encode()) + ".json"),
        allowed,
    )
    exclude = _safe_path(
        Path(
            _git(
                repo,
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "info/exclude",
            )
        ),
        allowed,
    )
    hook_before, state_before, exclude_before = (
        _regular(hook),
        _regular(state_path),
        _regular(exclude),
    )
    _writable(hook, hook_before)
    files = _bundle_files(source)
    bundle_id, hashes = _bundle_identity(files)
    local = _safe_path(repo / ".skylos/evals/pre-push", (repo,))
    bundle = _safe_path(local / "bundles" / bundle_id, (repo,))
    manifest = _encode({"schema_version": 1, "bundle_id": bundle_id, "files": hashes})
    runtime_hashes = {**hashes, "bundle.json": _hash(manifest)}
    if bundle.exists():
        _verify_bundle(bundle, files, manifest)
    prior = None
    if state_before.content is not None:
        metadata = json.loads(state_before.content)
        if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
            raise ValueError("existing pre-push installation metadata is invalid")
        if hook_before.content is None or _hash(hook_before.content) != metadata.get(
            "installed_sha256"
        ):
            raise ValueError(
                "pre-push hook changed since its previous installation; review before replacing"
            )
        prior = metadata.get("prior")
        if prior:
            prior_path = _safe_path(Path(prior["path"]), allowed)
            if (
                _regular(prior_path).content is None
                or _hash(prior_path.read_bytes()) != prior["sha256"]
            ):
                raise ValueError("previous pre-push backup is missing or modified")
    elif hook_before.content is not None:
        if MARKER.encode() in hook_before.content:
            raise ValueError(
                "existing Skylos pre-push hook has no installation metadata"
            )
        prior_path = _safe_path(
            hook.with_name("pre-push.skylos-prior-" + _hash(hook_before.content)[:16]),
            allowed,
        )
        existing_prior = _regular(prior_path)
        if existing_prior.content is not None and existing_prior != hook_before:
            raise ValueError("pre-push backup name is occupied by different bytes")
        prior = {
            "path": str(prior_path),
            "sha256": _hash(hook_before.content),
            "mode": hook_before.mode,
            "executable": os.access(hook, os.X_OK),
        }
    installed = _wrapper(python, bundle, runtime_hashes, prior)
    metadata_bytes = _encode(
        {
            "schema_version": 1,
            "hook": str(hook),
            "installed_sha256": _hash(installed),
            "bundle_id": bundle_id,
            "bundle": str(bundle),
            "python": str(python),
            "prior": prior,
        }
    )
    lines = ["/.skylos/evals/pre-push/"]
    for path in (hook, Path(prior["path"]) if prior else None):
        if path is not None and path.is_relative_to(repo):
            lines.append("/" + path.relative_to(repo).as_posix())
    current_exclude = (exclude_before.content or b"").decode()
    missing = [line for line in lines if line not in current_exclude.splitlines()]
    exclude_bytes = exclude_before.content or b""
    if missing:
        exclude_bytes += (
            "" if not current_exclude or current_exclude.endswith("\n") else "\n"
        ).encode()
        exclude_bytes += ("\n".join(missing) + "\n").encode()
    changed = (
        hook_before.content != installed
        or hook_before.mode != 0o755
        or state_before.content != metadata_bytes
    )
    if changed:
        _writable(state_path, state_before)
    if exclude_bytes != exclude_before.content:
        _writable(exclude, exclude_before)
    report = {
        "repository": str(repo),
        "hook_path": str(hook),
        "bundle": str(bundle),
        "bundle_id": bundle_id,
        "fixture_cases": {key: list(value) for key, value in CASE_IDS.items()},
        "changed": changed,
        "exclude_changed": exclude_bytes != exclude_before.content,
        "dry_run": dry_run,
        "backup_directory": None,
        "chains_existing_hook": bool(prior and prior["executable"]),
        "native_agent_callbacks_installed": False,
    }
    if dry_run:
        return report
    if _bundle_files(source) != files:
        raise ValueError("trusted runtime or fixtures changed during setup")
    if exclude_bytes != exclude_before.content:
        _atomic_write(
            exclude, exclude_bytes, exclude_before, exclude_before.mode or 0o600
        )
    _create_bundle(bundle, files, manifest)
    if not changed:
        return report
    backup = _safe_path(
        local / "setup" / f"{time.time_ns()}-{uuid.uuid4().hex[:8]}", (repo,)
    )
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name, state in (
        ("pre-push.before", hook_before),
        ("metadata.before", state_before),
        ("exclude.before", exclude_before),
    ):
        if state.content is not None:
            _atomic_write(backup / name, state.content, FileState(None, None), 0o600)
    if prior and _regular(Path(prior["path"])).content is None:
        _atomic_write(
            Path(prior["path"]),
            hook_before.content,
            FileState(None, None),
            prior["mode"],
        )
    _atomic_write(hook, installed, hook_before, 0o755)
    try:
        _atomic_write(state_path, metadata_bytes, state_before, 0o600)
    except BaseException:
        if _regular(hook).content == installed:
            if hook_before.content is None:
                hook.unlink()
            else:
                _atomic_write(
                    hook,
                    hook_before.content,
                    FileState(installed, 0o755),
                    hook_before.mode,
                )
        raise
    report["backup_directory"] = str(backup)
    _atomic_write(
        backup / "receipt.json", _encode(report), FileState(None, None), 0o600
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = install_push(
            args.repo, args.python, source=args.source, dry_run=args.dry_run
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Eval pre-push gate was not installed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
