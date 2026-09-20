"""Bounded static CUDA inventory collection for local release artifacts."""

from __future__ import annotations

from collections import deque
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from skylos.preflight.models import (
    MAX_CODE_OBJECTS,
    MAX_TOTAL_ARCHITECTURES,
    ArtifactInventory,
    CudaCodeObject,
)


MAX_CANDIDATE_FILES = 512
MAX_WALKED_DIRECTORIES = 4096
MAX_ARTIFACT_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_CANDIDATE_BYTES = 4 * 1024 * 1024 * 1024
MAX_TREE_FILES = 20_000
MAX_TREE_BYTES = 8 * 1024 * 1024 * 1024
MAX_SCANNER_OUTPUT_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 60

_CUDA_SUFFIXES = {
    ".a",
    ".bin",
    ".cubin",
    ".dll",
    ".exe",
    ".fatbin",
    ".lib",
    ".o",
    ".obj",
    ".so",
}
_OPAQUE_PACKAGE_SUFFIXES = {
    ".deb",
    ".engine",
    ".gz",
    ".plan",
    ".ptx",
    ".rpm",
    ".tar",
    ".tgz",
    ".whl",
    ".xz",
    ".zip",
}
_ELF_LIST_RE = re.compile(
    r"^\s*ELF file\s+\d+\s*:\s*(?P<identifier>[A-Za-z0-9_.+-]{1,256})\.sm_"
    r"(?P<architecture>\d{2,3}[a-z]?)\.cubin\s*$",
    re.I,
)
_PTX_LIST_RE = re.compile(
    r"^\s*PTX file\s+\d+\s*:\s*(?P<identifier>[A-Za-z0-9_.+-]{1,256})\.(?:sm|compute)_"
    r"(?P<architecture>\d{2,3}[a-z]?)\.ptx\s*$",
    re.I,
)
_CUDART_SONAME_RE = re.compile(
    r"^libcudart\.so\.(?P<major>\d{1,2})(?:\.\d+)*$"
)
MAX_ELF_PROGRAM_HEADERS = 4096
MAX_ELF_DYNAMIC_BYTES = 1024 * 1024
MAX_ELF_STRING_TABLE_BYTES = 4 * 1024 * 1024
_NO_DEVICE_CODE_RE = re.compile(
    r"\Acuobjdump\s+(?:info|error|fatal)\s*:\s*File\s+'(?P<path>[^'\r\n]+)'"
    r"\s+does not contain device code\.?\s*\Z",
    re.I,
)
MAX_CUOBJDUMP_RECORDS = 4096


@dataclass(frozen=True)
class _Candidate:
    path: Path
    device: int
    inode: int
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class _TreeEntry:
    path: Path
    mode: int
    device: int
    inode: int
    size: int
    mtime_ns: int

    @property
    def st_mode(self) -> int:
        return self.mode

    @property
    def st_dev(self) -> int:
        return self.device

    @property
    def st_ino(self) -> int:
        return self.inode

    @property
    def st_size(self) -> int:
        return self.size

    @property
    def st_mtime_ns(self) -> int:
        return self.mtime_ns


@dataclass(frozen=True)
class _ElfDynamicMetadata:
    soname: str | None
    needed: tuple[str, ...]
    search_paths: tuple[str, ...]


def _fingerprint(file_stat: os.stat_result) -> tuple[int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        file_stat.st_mtime_ns,
    )


def inspect_local_cuda_artifact(
    target: str | Path,
    *,
    project_root: str | Path,
    cuobjdump: str | Path | None = None,
    timeout_seconds: int = 10,
) -> ArtifactInventory:
    """List embedded cubin/PTX records without loading or executing the target."""
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        return _incomplete_inventory(
            str(target),
            f"Inspection timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.",
        )
    deadline = time.monotonic() + timeout_seconds
    artifact_path, path_error = _resolve_artifact_path(target, project_root)
    artifact_name = str(artifact_path) if artifact_path is not None else str(target)
    if path_error:
        return _incomplete_inventory(artifact_name, path_error)
    scanner, scanner_error = _resolve_cuobjdump(
        cuobjdump,
        Path(project_root),
        artifact_path=artifact_path,
    )
    if scanner_error:
        return _incomplete_inventory(artifact_name, scanner_error)

    candidates, discovery_errors, _ = _discover_candidates(
        artifact_path, deadline=deadline
    )
    is_single_file = artifact_path.is_file()
    code_objects: list[CudaCodeObject] = []
    errors = list(discovery_errors)
    platforms: set[str] = set()
    candidate_digests: dict[Path, str] = {}
    runtime_versions: set[str] = set()
    total_architecture_entries = 0
    with tempfile.TemporaryDirectory(prefix="skylos-artifact-snapshot-") as snapshot_dir:
        snapshots: dict[Path, _Candidate] = {}
        for index, candidate in enumerate(candidates):
            snapshot, content_digest, snapshot_error = _snapshot_candidate(
                candidate,
                Path(snapshot_dir),
                index=index,
                deadline=deadline,
            )
            if snapshot_error or snapshot is None or content_digest is None:
                errors.append(
                    f"{candidate.path.name}: "
                    f"{snapshot_error or 'artifact snapshot failed'}"
                )
                continue
            snapshots[candidate.path] = snapshot
            candidate_digests[candidate.path] = content_digest

        runtime_by_soname, runtime_errors = _runtime_sonames_from_snapshots(
            candidates, snapshots
        )
        errors.extend(runtime_errors)
        for candidate in candidates:
            snapshot = snapshots.get(candidate.path)
            if snapshot is None:
                continue
            path = candidate.path
            if time.monotonic() >= deadline:
                errors.append("Artifact inspection exceeded its overall time limit.")
                break
            platform = _platform_from_binary(snapshot)
            if platform:
                platforms.add(platform)
            bound_runtime, binding_error = _bound_runtime_for_snapshot(
                candidate,
                snapshot,
                runtime_by_soname,
                artifact_root=artifact_path if artifact_path.is_dir() else artifact_path.parent,
            )
            cubin_records, cubin_error = _list_architectures(
                scanner,
                snapshot.path,
                "--list-elf",
                kind="cubin",
                deadline=deadline,
            )
            ptx_records, ptx_error = _list_architectures(
                scanner,
                snapshot.path,
                "--list-ptx",
                kind="ptx",
                deadline=deadline,
            )
            snapshot_digest, snapshot_hash_error = _hash_regular_file(
                snapshot.path,
                expected=snapshot,
                deadline=deadline,
            )
            mutation_error = None
            if snapshot_hash_error or snapshot_digest != candidate_digests[path]:
                cubin_records = {}
                ptx_records = {}
                mutation_error = "private artifact snapshot changed during inspection"
            item_error_values = [
                error
                for error in (cubin_error, ptx_error, mutation_error, binding_error)
                if error is not None
            ]
            groups = sorted(set(cubin_records) | set(ptx_records))
            runtime_binding_unknown = bool(groups) and bound_runtime is None
            if groups and platform is None:
                item_error_values.append(
                    "host platform could not be established for CUDA-bearing binary"
                )
            item_errors = tuple(item_error_values)
            if not cubin_records and not ptx_records and not item_errors:
                continue
            display_path = (
                path.name
                if is_single_file
                else _relative_display_path(path, artifact_path)
            )
            if item_errors:
                errors.extend(f"{display_path}: {error}" for error in item_errors)
            if runtime_binding_unknown:
                errors.append(
                    f"{display_path}: CUDA runtime binding could not be established"
                )
            if not groups:
                groups = ["<inspection>"]
            added_architectures = sum(
                len(cubin_records.get(group, ())) + len(ptx_records.get(group, ()))
                for group in groups
            )
            if (
                len(code_objects) + len(groups) > MAX_CODE_OBJECTS
                or total_architecture_entries + added_architectures
                > MAX_TOTAL_ARCHITECTURES
            ):
                errors.append(
                    "Artifact CUDA inventory exceeds the aggregate object or "
                    "architecture entry limit."
                )
                break
            for group in groups:
                code_objects.append(
                    CudaCodeObject(
                        path=f"{display_path}#{group}",
                        cubins=cubin_records.get(group, ()),
                        ptx=ptx_records.get(group, ()),
                        required=True if is_single_file else None,
                        inspection_complete=not item_errors,
                        errors=item_errors,
                        cuda_runtime_version=bound_runtime,
                    )
                )
                if bound_runtime:
                    runtime_versions.add(bound_runtime)
            total_architecture_entries += added_architectures

    runtime = next(iter(runtime_versions)) if len(runtime_versions) == 1 else None
    if len(runtime_versions) > 1:
        errors.append("CUDA code objects bind multiple runtime ABI majors.")

    if len(platforms) > 1:
        errors.append(
            "Candidate binaries contain multiple host platforms: "
            + ", ".join(sorted(platforms))
        )
    platform = next(iter(platforms)) if len(platforms) == 1 else None

    identity = None
    identity_verified = False
    if is_single_file:
        digest, digest_error = _hash_regular_file(
            artifact_path,
            expected=candidates[0] if candidates else None,
            deadline=deadline,
        )
        if digest_error:
            errors.append(digest_error)
        elif not candidates or digest != candidate_digests.get(candidates[0].path):
            errors.append("Artifact content changed after static inspection.")
        else:
            identity = f"sha256:{digest}"
            identity_verified = True
    else:
        stable_candidates, stable_errors, _ = _discover_candidates(
            artifact_path, deadline=deadline
        )
        if stable_errors:
            errors.extend(stable_errors)
        elif _candidate_snapshots(candidates) != _candidate_snapshots(
            stable_candidates
        ):
            errors.append("Artifact candidate set changed during inspection.")
        else:
            digest, digest_error = _hash_directory_tree(
                artifact_path, deadline=deadline
            )
            if digest_error:
                errors.append(digest_error)
            else:
                final_candidates, final_errors, _ = _discover_candidates(
                    artifact_path, deadline=deadline
                )
                digest_errors = _verify_candidate_digests(
                    final_candidates,
                    candidate_digests,
                    deadline=deadline,
                )
                if final_errors or digest_errors:
                    errors.extend(final_errors)
                    errors.extend(digest_errors)
                elif _candidate_snapshots(candidates) != _candidate_snapshots(
                    final_candidates
                ):
                    errors.append("Artifact candidates changed after identity hashing.")
                else:
                    identity = f"tree-sha256:{digest}"
                    identity_verified = True
    return ArtifactInventory(
        artifact=artifact_name,
        identity=identity,
        identity_verified=identity_verified,
        platform=platform,
        cuda_runtime_version=runtime,
        code_objects=tuple(code_objects),
        inspection_complete=not errors,
        source="local_cuobjdump",
        errors=tuple(errors[:128]),
    )


def _resolve_artifact_path(
    target: str | Path, project_root: str | Path
) -> tuple[Path | None, str | None]:
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except OSError:
        return None, "Project root does not exist or is unreadable."
    raw = Path(target).expanduser()
    if not raw.is_absolute():
        raw = root / raw
    try:
        if raw.is_symlink():
            return None, "Local artifact must not be a symbolic link."
        resolved = raw.resolve(strict=True)
        mode = resolved.stat(follow_symlinks=False).st_mode
    except OSError:
        return None, "Local artifact does not exist or is unreadable."
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return None, "Local artifact must be a regular file or directory."
    return resolved, None


def _resolve_cuobjdump(
    requested: str | Path | None,
    project_root: Path,
    *,
    artifact_path: Path,
) -> tuple[str, str | None]:
    candidate = str(requested) if requested is not None else shutil.which("cuobjdump")
    if not candidate:
        return "", (
            "cuobjdump is unavailable; install the NVIDIA CUDA binary utilities "
            "or supply a trusted inspection inventory."
        )
    try:
        executable = Path(candidate).expanduser().resolve(strict=True)
        root = project_root.expanduser().resolve(strict=True)
        first_stat = executable.stat(follow_symlinks=False)
        resolved_again = executable.resolve(strict=True)
        second_stat = resolved_again.stat(follow_symlinks=False)
        artifact_root = (
            artifact_path if artifact_path.is_dir() else artifact_path.parent
        )
        if (
            resolved_again != executable
            or _fingerprint(first_stat) != _fingerprint(second_stat)
            or not stat.S_ISREG(second_stat.st_mode)
            or not os.access(executable, os.X_OK)
            or executable.is_relative_to(root)
            or executable == artifact_path
            or executable.is_relative_to(artifact_root)
        ):
            raise OSError
        for ancestor in (root, *root.parents):
            if (ancestor / ".git").exists() and executable.is_relative_to(ancestor):
                raise OSError
    except (OSError, RuntimeError, ValueError):
        return "", (
            "cuobjdump must resolve to an executable regular file outside the "
            "scanned project."
        )
    return str(executable), None


def _snapshot_tree(
    root: Path,
    *,
    deadline: float,
) -> tuple[list[_TreeEntry], list[str]]:
    """Take a bounded, no-follow metadata snapshot without ``os.walk`` lists."""
    entries: list[_TreeEntry] = []
    stack = [root]
    walked_directories = 0
    while stack:
        if time.monotonic() >= deadline:
            return entries, ["Artifact discovery exceeded its overall time limit."]
        base = stack.pop()
        walked_directories += 1
        if walked_directories > MAX_WALKED_DIRECTORIES:
            return entries, [
                f"Artifact exceeds {MAX_WALKED_DIRECTORIES} directories."
            ]
        current: list[_TreeEntry] = []
        try:
            with os.scandir(base) as iterator:
                for directory_entry in iterator:
                    if time.monotonic() >= deadline:
                        return entries, [
                            "Artifact discovery exceeded its overall time limit."
                        ]
                    if len(entries) + len(current) >= MAX_TREE_FILES:
                        return entries, [
                            f"Artifact exceeds {MAX_TREE_FILES} content-tree entries."
                        ]
                    file_stat = directory_entry.stat(follow_symlinks=False)
                    current.append(
                        _TreeEntry(
                            path=base / directory_entry.name,
                            mode=file_stat.st_mode,
                            device=file_stat.st_dev,
                            inode=file_stat.st_ino,
                            size=file_stat.st_size,
                            mtime_ns=file_stat.st_mtime_ns,
                        )
                    )
        except OSError as exc:
            return entries, [
                f"Artifact directory could not be enumerated: {base.name} ({exc.__class__.__name__})."
            ]
        current.sort(key=lambda item: item.path.name)
        entries.extend(current)
        children = [
            entry.path
            for entry in current
            if stat.S_ISDIR(entry.mode) and not stat.S_ISLNK(entry.mode)
        ]
        stack.extend(reversed(children))
    return entries, []


def _discover_candidates(
    artifact: Path,
    *,
    deadline: float,
) -> tuple[list[_Candidate], list[str], str | None]:
    if artifact.is_file():
        try:
            file_stat = artifact.stat(follow_symlinks=False)
        except OSError:
            return [], ["Artifact became unreadable during inspection."], None
        if file_stat.st_size > MAX_ARTIFACT_FILE_BYTES:
            return [], ["Artifact exceeds the local inspection size limit."], None
        if _is_opaque_package(artifact, file_stat):
            return [], ["Opaque packaged artifact requires a dedicated inspector."], None
        return [_candidate(artifact, file_stat)], [], None

    candidates_by_path: dict[Path, _Candidate] = {}
    entries, errors = _snapshot_tree(artifact, deadline=deadline)
    if errors:
        return [], errors, None
    total_bytes = 0

    def record_candidate(path: Path, file_stat: os.stat_result) -> str | None:
        nonlocal total_bytes
        try:
            canonical = path.resolve(strict=True)
            canonical.relative_to(artifact)
        except (OSError, RuntimeError, ValueError):
            return f"Candidate binary escapes the artifact tree: {path.name}"
        if canonical in candidates_by_path:
            return None
        if file_stat.st_size > MAX_ARTIFACT_FILE_BYTES:
            return f"Artifact file exceeds inspection size limit: {path.name}"
        if len(candidates_by_path) >= MAX_CANDIDATE_FILES:
            return f"Artifact exceeds {MAX_CANDIDATE_FILES} candidate binaries."
        if total_bytes + file_stat.st_size > MAX_TOTAL_CANDIDATE_BYTES:
            return "Artifact candidate binaries exceed the total size limit."
        total_bytes += file_stat.st_size
        candidates_by_path[canonical] = _candidate(canonical, file_stat)
        return None

    for entry in entries:
        if time.monotonic() >= deadline:
            errors.append("Artifact discovery exceeded its overall time limit.")
            break
        path = entry.path
        if stat.S_ISDIR(entry.mode):
            continue
        if stat.S_ISLNK(entry.mode):
            resolved, symlink_error = _resolve_in_tree_symlink(path, artifact)
            if symlink_error:
                errors.append(symlink_error)
                continue
            if resolved is None or not resolved.is_file():
                continue
            try:
                target_stat = resolved.stat(follow_symlinks=False)
            except OSError:
                errors.append(
                    f"Artifact symlink target became unreadable: {path.name}"
                )
                continue
            if _is_opaque_package(resolved, target_stat):
                errors.append(
                    f"Opaque packaged artifact requires a dedicated inspector: {path.name}"
                )
                continue
            if not _looks_like_binary(resolved, target_stat):
                continue
            candidate_error = record_candidate(resolved, target_stat)
            if candidate_error:
                errors.append(candidate_error)
            continue
        if not stat.S_ISREG(entry.mode):
            errors.append(f"Artifact contains unsupported special file: {path.name}")
            continue
        if _is_opaque_package(path, entry):
            errors.append(
                f"Opaque packaged artifact requires a dedicated inspector: {path.name}"
            )
            continue
        file_stat = entry
        if not _looks_like_binary(path, file_stat):
            continue
        candidate_error = record_candidate(path, file_stat)
        if candidate_error:
            errors.append(candidate_error)
        if errors and (
            len(candidates_by_path) >= MAX_CANDIDATE_FILES
            or total_bytes >= MAX_TOTAL_CANDIDATE_BYTES
        ):
            break
    candidates = [candidates_by_path[path] for path in sorted(candidates_by_path)]
    return candidates, errors, None


def _resolve_in_tree_symlink(
    path: Path, root: Path
) -> tuple[Path | None, str | None]:
    resolved, resolution = _resolve_path_within_tree(path, root)
    if resolution is not None:
        return None, f"Artifact symlink escapes the artifact tree: {path.name}"
    return resolved, None


def _resolve_path_within_tree(
    path: Path, root: Path
) -> tuple[Path | None, str | None]:
    """Resolve a path while rejecting every symlink hop outside ``root``."""
    try:
        canonical_root = root.resolve(strict=True)
        relative = path.relative_to(canonical_root)
    except (OSError, RuntimeError, ValueError):
        return None, "outside"

    pending = deque(relative.parts)
    current = canonical_root
    followed_links = 0
    while pending:
        part = pending.popleft()
        if part in {"", os.curdir}:
            continue
        if part == os.pardir:
            if current == canonical_root:
                return None, "outside"
            current = current.parent
            continue
        candidate = current / part
        try:
            file_stat = candidate.stat(follow_symlinks=False)
        except FileNotFoundError:
            return None, "missing"
        except OSError:
            return None, "unreadable"
        if not stat.S_ISLNK(file_stat.st_mode):
            current = candidate
            continue

        followed_links += 1
        if followed_links > 40:
            return None, "symlink_loop"
        try:
            target = Path(os.readlink(candidate))
        except OSError:
            return None, "unreadable"
        if target.is_absolute():
            try:
                target = target.relative_to(canonical_root)
            except ValueError:
                return None, "outside"
            current = canonical_root
        for target_part in reversed(target.parts):
            pending.appendleft(target_part)
    return current, None


def _candidate(path: Path, file_stat: os.stat_result | _TreeEntry) -> _Candidate:
    return _Candidate(path, *_fingerprint(file_stat))


def _candidate_is_unchanged(candidate: _Candidate) -> bool:
    try:
        if candidate.path.is_symlink():
            return False
        file_stat = candidate.path.stat(follow_symlinks=False)
    except OSError:
        return False
    return _fingerprint(file_stat) == (
        candidate.device,
        candidate.inode,
        candidate.size,
        candidate.mtime_ns,
    )


def _candidate_snapshots(
    candidates: list[_Candidate],
) -> tuple[tuple[str, int, int, int, int], ...]:
    return tuple(
        sorted(
            (
                str(item.path),
                item.device,
                item.inode,
                item.size,
                item.mtime_ns,
            )
            for item in candidates
        )
    )


def _snapshot_candidate(
    candidate: _Candidate,
    destination: Path,
    *,
    index: int,
    deadline: float,
) -> tuple[_Candidate | None, str | None, str | None]:
    """Copy one exact candidate into a private directory before parsing it."""
    safe_name = re.sub(r"[^A-Za-z0-9_.+-]", "_", candidate.path.name)[:128]
    snapshot_path = destination / f"{index:04d}-{safe_name or 'artifact'}"
    source_descriptor = None
    destination_descriptor = None
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        destination_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        destination_flags |= os.O_CLOEXEC
    try:
        source_descriptor = os.open(  # skylos: ignore[SKY-D215] no-follow and inode-verified
            candidate.path, flags
        )
        source_stat = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_stat.st_mode) or _fingerprint(source_stat) != (
            candidate.device,
            candidate.inode,
            candidate.size,
            candidate.mtime_ns,
        ):
            return None, None, "artifact changed before private snapshotting"
        destination_descriptor = os.open(  # skylos: ignore[SKY-D215] private exclusive snapshot
            snapshot_path,
            destination_flags,
            0o600,
        )
        copied = 0
        while copied < source_stat.st_size:
            if time.monotonic() >= deadline:
                return None, None, "artifact snapshotting exceeded the overall time limit"
            chunk = os.read(source_descriptor, min(1024 * 1024, source_stat.st_size - copied))
            if not chunk:
                return None, None, "artifact changed while it was being snapshotted"
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    return None, None, "private artifact snapshot could not be written"
                offset += written
            copied += len(chunk)
        if os.read(source_descriptor, 1):
            return None, None, "artifact grew while it was being snapshotted"
        final_source_stat = os.fstat(source_descriptor)
        if _fingerprint(final_source_stat) != _fingerprint(source_stat):
            return None, None, "artifact changed while it was being snapshotted"
        os.fsync(destination_descriptor)
    except OSError:
        return None, None, "artifact could not be copied into a private snapshot"
    finally:
        for descriptor in (source_descriptor, destination_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    if not _candidate_is_unchanged(candidate):
        return None, None, "artifact changed while it was being snapshotted"
    try:
        snapshot_stat = snapshot_path.stat(follow_symlinks=False)
    except OSError:
        return None, None, "private artifact snapshot became unreadable"
    return _candidate(snapshot_path, snapshot_stat), digest.hexdigest(), None


def _verify_candidate_digests(
    candidates: list[_Candidate],
    expected: dict[Path, str],
    *,
    deadline: float,
) -> list[str]:
    errors: list[str] = []
    actual_paths = {candidate.path for candidate in candidates}
    if actual_paths != set(expected):
        return ["Artifact candidate set changed after static inspection."]
    for candidate in candidates:
        digest, error = _hash_regular_file(
            candidate.path,
            expected=candidate,
            deadline=deadline,
        )
        if error or digest != expected[candidate.path]:
            errors.append(
                f"Artifact candidate changed after static inspection: {candidate.path.name}"
            )
            if len(errors) >= 16:
                break
    return errors


def _looks_like_binary(path: Path, file_stat: os.stat_result) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in _CUDA_SUFFIXES or ".so." in name:
        return True
    candidate = _candidate(path, file_stat)
    header, error = _read_binary_header(candidate)
    if error or header is None:
        return False
    return header.startswith((b"\x7fELF", b"MZ", b"!<arch>\n", b"\x50\xed\x55\xba"))


def _is_opaque_package(
    path: Path, file_stat: os.stat_result | _TreeEntry
) -> bool:
    name = path.name.lower()
    if any(name.endswith(suffix) for suffix in _OPAQUE_PACKAGE_SUFFIXES):
        return True
    header, error = _read_binary_header(_candidate(path, file_stat))
    if error or header is None:
        return False
    return (
        header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
        or header.startswith(b"\x1f\x8b")
        or header.startswith(b"\xfd7zXZ\x00")
        or header.startswith(b"BZh")
        or header.startswith(b"\x28\xb5\x2f\xfd")
        or header.startswith(b"7z\xbc\xaf\x27\x1c")
        or (len(header) >= 262 and header[257:262] == b"ustar")
    )


def _runtime_sonames_from_snapshots(
    candidates: list[_Candidate],
    snapshots: dict[Path, _Candidate],
) -> tuple[dict[str, tuple[tuple[str, Path, str], ...]], list[str]]:
    runtimes: dict[str, list[tuple[str, Path, str]]] = {}
    errors: list[str] = []
    for candidate in candidates:
        snapshot = snapshots.get(candidate.path)
        if snapshot is None:
            continue
        metadata, metadata_error = _elf_dynamic_metadata(snapshot)
        lowered_name = candidate.path.name.lower()
        runtime_like = lowered_name.startswith("libcudart.so")
        if metadata_error:
            if runtime_like:
                errors.append(f"{candidate.path.name}: {metadata_error}")
            elif lowered_name.startswith("cudart64_") and lowered_name.endswith(
                ".dll"
            ):
                errors.append(
                    "CUDA runtime import proof for PE files is not implemented: "
                    f"{candidate.path.name}"
                )
            continue
        if metadata is None or metadata.soname is None:
            if runtime_like:
                errors.append(
                    f"{candidate.path.name}: ELF DT_SONAME does not prove a CUDA runtime ABI major"
                )
            continue
        match = _CUDART_SONAME_RE.fullmatch(metadata.soname)
        if match is None:
            if runtime_like:
                errors.append(
                    f"{candidate.path.name}: ELF DT_SONAME does not prove a CUDA runtime ABI major"
                )
            continue
        platform = _platform_from_binary(snapshot)
        if platform is None or not _elf_is_shared_object(snapshot):
            errors.append(
                f"{candidate.path.name}: CUDA runtime provider is not a supported host shared object"
            )
            continue
        runtimes.setdefault(metadata.soname, []).append(
            (str(int(match.group("major"))), candidate.path, platform)
        )
    return {
        soname: tuple(sorted(entries, key=lambda item: str(item[1])))
        for soname, entries in runtimes.items()
    }, errors


def _bound_runtime_for_snapshot(
    original: _Candidate,
    snapshot: _Candidate,
    runtimes: dict[str, tuple[tuple[str, Path, str], ...]],
    *,
    artifact_root: Path,
) -> tuple[str | None, str | None]:
    """Bind an ELF import to one bundled runtime through an ORIGIN search path."""
    metadata, metadata_error = _elf_dynamic_metadata(snapshot)
    if metadata_error or metadata is None:
        return None, None
    consumer_platform = _platform_from_binary(snapshot)
    if consumer_platform is None:
        return None, None
    matches: set[str] = set()
    for needed in metadata.needed:
        needed_name = needed.replace("\\", "/").rsplit("/", 1)[-1]
        if _CUDART_SONAME_RE.fullmatch(needed_name) is None:
            continue
        if "/" in needed or "\\" in needed:
            return None, (
                "CUDA runtime DT_NEEDED contains a path; its packaged binding "
                "cannot be established statically"
            )
        providers = runtimes.get(needed, ())
        for search_path in metadata.search_paths:
            directory, path_error = _origin_search_directory(
                search_path,
                consumer_directory=original.path.parent,
                artifact_root=artifact_root,
            )
            if path_error:
                return None, path_error
            if directory is None:
                continue
            lookup = directory / needed
            resolved, resolution = _resolve_path_within_tree(lookup, artifact_root)
            if resolution == "missing":
                continue
            if resolution is not None or resolved is None:
                return None, "CUDA runtime search path could not be resolved safely"
            matched = {
                major
                for major, provider, provider_platform in providers
                if resolved == provider and provider_platform == consumer_platform
            }
            if not matched:
                return None, (
                    "CUDA runtime search resolves to an unverified or "
                    "platform-incompatible object"
                )
            matches.update(matched)
            break
    if len(matches) > 1:
        return None, "CUDA runtime import resolves to multiple ABI majors"
    return (next(iter(matches)), None) if matches else (None, None)


def _origin_search_directory(
    search_path: str,
    *,
    consumer_directory: Path,
    artifact_root: Path,
) -> tuple[Path | None, str | None]:
    """Resolve a strict ELF ``$ORIGIN`` entry inside the inspected artifact."""
    suffix: str | None = None
    for token in ("$ORIGIN", "${ORIGIN}"):
        if search_path == token:
            suffix = ""
            break
        if search_path.startswith(f"{token}/"):
            suffix = search_path[len(token) + 1 :]
            break
    if suffix is None:
        return None, (
            "CUDA runtime search uses a path that is not anchored to $ORIGIN; "
            "its packaged binding cannot be established statically"
        )
    if "$" in suffix:
        return None, (
            "CUDA runtime search uses an unmodeled dynamic loader token; "
            "its packaged binding cannot be established statically"
        )
    relative = Path(suffix)
    if relative.is_absolute():
        return None, "CUDA runtime $ORIGIN search path is absolute"
    resolved, resolution = _resolve_path_within_tree(
        consumer_directory / relative,
        artifact_root,
    )
    if resolution == "missing":
        return None, None
    if resolution is not None or resolved is None:
        return None, "CUDA runtime $ORIGIN search path escapes the artifact"
    try:
        if not resolved.is_dir():
            return None, None
    except OSError:
        return None, "CUDA runtime $ORIGIN search path could not be read safely"
    return resolved, None


def _elf_dynamic_metadata(
    candidate: _Candidate,
) -> tuple[_ElfDynamicMetadata | None, str | None]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = None
    result: _ElfDynamicMetadata | None = None
    try:
        descriptor = os.open(  # skylos: ignore[SKY-D215] private verified snapshot
            candidate.path, flags
        )
        file_stat = os.fstat(descriptor)
        if _fingerprint(file_stat) != (
            candidate.device,
            candidate.inode,
            candidate.size,
            candidate.mtime_ns,
        ):
            return None, "artifact changed before ELF metadata inspection"
        header = _read_at(descriptor, 0, 64, file_stat.st_size)
        if header is None or len(header) < 52 or header[:4] != b"\x7fELF":
            return None, "candidate is not a supported ELF file"
        elf_class = header[4]
        byte_order = "little" if header[5] == 1 else "big" if header[5] == 2 else None
        if byte_order is None or elf_class not in {1, 2}:
            return None, "ELF encoding is unsupported"
        if elf_class == 2:
            if len(header) < 64:
                return None, "ELF header is truncated"
            program_offset = int.from_bytes(header[32:40], byte_order)
            program_entry_size = int.from_bytes(header[54:56], byte_order)
            program_count = int.from_bytes(header[56:58], byte_order)
            required_entry_size = 56
        else:
            program_offset = int.from_bytes(header[28:32], byte_order)
            program_entry_size = int.from_bytes(header[42:44], byte_order)
            program_count = int.from_bytes(header[44:46], byte_order)
            required_entry_size = 32
        if program_count == 0:
            return _ElfDynamicMetadata(None, (), ()), None
        if (
            program_count > MAX_ELF_PROGRAM_HEADERS
            or program_entry_size < required_entry_size
        ):
            return None, "ELF program headers are unsupported"
        table_size = program_count * program_entry_size
        if table_size > MAX_ELF_DYNAMIC_BYTES:
            return None, "ELF program header table exceeds the safety limit"
        program_table = _read_at(
            descriptor, program_offset, table_size, file_stat.st_size
        )
        if program_table is None:
            return None, "ELF program header table is out of bounds"

        load_segments: list[tuple[int, int, int]] = []
        dynamic_segment: tuple[int, int] | None = None
        for index in range(program_count):
            entry = program_table[
                index * program_entry_size : (index + 1) * program_entry_size
            ]
            segment_type = int.from_bytes(entry[0:4], byte_order)
            if elf_class == 2:
                file_offset = int.from_bytes(entry[8:16], byte_order)
                virtual_address = int.from_bytes(entry[16:24], byte_order)
                file_size = int.from_bytes(entry[32:40], byte_order)
            else:
                file_offset = int.from_bytes(entry[4:8], byte_order)
                virtual_address = int.from_bytes(entry[8:12], byte_order)
                file_size = int.from_bytes(entry[16:20], byte_order)
            if file_offset > file_stat.st_size or file_size > file_stat.st_size - file_offset:
                return None, "ELF segment is out of file bounds"
            if segment_type == 1:
                load_segments.append((virtual_address, file_offset, file_size))
            elif segment_type == 2:
                if dynamic_segment is not None:
                    return None, "ELF contains multiple dynamic segments"
                dynamic_segment = (file_offset, file_size)
        if dynamic_segment is None:
            return _ElfDynamicMetadata(None, (), ()), None
        dynamic_offset, dynamic_size = dynamic_segment
        if not _file_range_in_unique_load(
            dynamic_offset, dynamic_size, load_segments
        ):
            return None, "ELF dynamic segment is not mapped by one load segment"
        if dynamic_size > MAX_ELF_DYNAMIC_BYTES:
            return None, "ELF dynamic metadata exceeds the safety limit"
        dynamic = _read_at(descriptor, dynamic_offset, dynamic_size, file_stat.st_size)
        if dynamic is None:
            return None, "ELF dynamic metadata is out of bounds"

        entry_size = 16 if elf_class == 2 else 8
        width = 8 if elf_class == 2 else 4
        string_addresses: set[int] = set()
        string_sizes: set[int] = set()
        soname_offsets: list[int] = []
        needed_offsets: list[int] = []
        rpath_offsets: list[int] = []
        runpath_offsets: list[int] = []
        terminated = False
        for offset in range(0, len(dynamic) - entry_size + 1, entry_size):
            item = dynamic[offset : offset + entry_size]
            tag = int.from_bytes(item[:width], byte_order, signed=True)
            value = int.from_bytes(item[width : width * 2], byte_order)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                needed_offsets.append(value)
            elif tag == 5:
                string_addresses.add(value)
            elif tag == 10:
                string_sizes.add(value)
            elif tag == 14:
                soname_offsets.append(value)
            elif tag == 15:
                rpath_offsets.append(value)
            elif tag == 29:
                runpath_offsets.append(value)
        if not terminated:
            return None, "ELF dynamic metadata is not terminated"
        if (
            len(needed_offsets) > 4096
            or len(soname_offsets) > 1
            or len(rpath_offsets) > 1
            or len(runpath_offsets) > 1
            or len(string_addresses) > 1
            or len(string_sizes) > 1
        ):
            return None, "ELF dynamic metadata is ambiguous or exceeds its limits"
        if not string_addresses and not string_sizes and not (
            soname_offsets or needed_offsets or rpath_offsets or runpath_offsets
        ):
            return _ElfDynamicMetadata(None, (), ()), None
        if len(string_addresses) != 1 or len(string_sizes) != 1:
            return None, "ELF dynamic string table is missing"
        string_address = next(iter(string_addresses))
        string_size = next(iter(string_sizes))
        if string_size <= 0 or string_size > MAX_ELF_STRING_TABLE_BYTES:
            return None, "ELF string table exceeds the safety limit"
        string_file_offset = _virtual_range_to_file_offset(
            string_address, string_size, load_segments
        )
        if string_file_offset is None:
            return None, "ELF string table could not be resolved"
        string_table = _read_at(
            descriptor, string_file_offset, string_size, file_stat.st_size
        )
        if string_table is None:
            return None, "ELF string table is out of bounds"
        soname = None
        if soname_offsets:
            soname, error = _elf_string(string_table, soname_offsets[0])
            if error:
                return None, error
        needed: list[str] = []
        for value_offset in needed_offsets:
            value, error = _elf_string(string_table, value_offset)
            if error:
                return None, error
            needed.append(value or "")
        selected_search_offsets = runpath_offsets or rpath_offsets
        search_paths: list[str] = []
        if selected_search_offsets:
            value, error = _elf_string(string_table, selected_search_offsets[0])
            if error:
                return None, error
            # Empty ELF search entries refer to the process working directory.
            # Preserve them so runtime binding stays UNKNOWN instead of skipping
            # a location that could shadow a later bundled library.
            search_paths.extend((value or "").split(":"))
        result = _ElfDynamicMetadata(soname, tuple(needed), tuple(search_paths))
    except OSError:
        return None, "ELF dynamic metadata could not be read"
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not _candidate_is_unchanged(candidate):
        return None, "artifact changed during ELF metadata inspection"
    return result, None


def _elf_string(table: bytes, offset: int) -> tuple[str | None, str | None]:
    if offset < 0 or offset >= len(table):
        return None, "ELF dynamic string offset is out of bounds"
    tail = table[offset:]
    terminator = tail.find(b"\0")
    if terminator < 0 or terminator > 4096:
        return None, "ELF dynamic string is invalid"
    try:
        return tail[:terminator].decode("ascii"), None
    except UnicodeDecodeError:
        return None, "ELF dynamic string is not ASCII"


def _elf_is_shared_object(candidate: _Candidate) -> bool:
    header, error = _read_binary_header(candidate)
    if error or header is None or len(header) < 20 or header[:4] != b"\x7fELF":
        return False
    byte_order = "little" if header[5] == 1 else "big" if header[5] == 2 else None
    return byte_order is not None and int.from_bytes(header[16:18], byte_order) == 3


def _read_at(
    descriptor: int, offset: int, size: int, file_size: int
) -> bytes | None:
    if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
        return None
    if hasattr(os, "pread"):
        data = os.pread(descriptor, size, offset)
    else:  # pragma: no cover - Windows fallback
        os.lseek(descriptor, offset, os.SEEK_SET)
        data = os.read(descriptor, size)
    return data if len(data) == size else None


def _virtual_range_to_file_offset(
    address: int,
    size: int,
    load_segments: list[tuple[int, int, int]],
) -> int | None:
    if size <= 0:
        return None
    matches = []
    for virtual_address, file_offset, file_size in load_segments:
        if (
            virtual_address <= address
            and address - virtual_address <= file_size
            and size <= file_size - (address - virtual_address)
        ):
            matches.append(file_offset + (address - virtual_address))
    return matches[0] if len(matches) == 1 else None


def _file_range_in_unique_load(
    offset: int,
    size: int,
    load_segments: list[tuple[int, int, int]],
) -> bool:
    if size <= 0:
        return False
    matches = 0
    for _virtual_address, file_offset, file_size in load_segments:
        if (
            file_offset <= offset
            and offset - file_offset <= file_size
            and size <= file_size - (offset - file_offset)
        ):
            matches += 1
    return matches == 1


def _list_architectures(
    scanner: str,
    artifact: Path,
    option: str,
    *,
    kind: str,
    deadline: float,
) -> tuple[dict[str, tuple[str, ...]], str | None]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {}, "artifact inspection exceeded its overall time limit"
    returncode, stdout, stderr, problem = _run_bounded_capture(
        [scanner, option, str(artifact)], timeout=remaining
    )
    if problem:
        return {}, problem
    if returncode != 0:
        nonempty = [value.strip() for value in (stdout, stderr) if value.strip()]
        diagnostic = nonempty[0] if len(nonempty) == 1 else ""
        no_code = _NO_DEVICE_CODE_RE.fullmatch(diagnostic)
        if no_code is not None and no_code.group("path") == str(artifact):
            return {}, None
        return {}, f"cuobjdump {option} failed with exit code {returncode}"
    if stderr.strip():
        return {}, f"cuobjdump {option} emitted unexpected diagnostics"
    prefix = "sm" if kind == "cubin" else "compute"
    record_re = _ELF_LIST_RE if kind == "cubin" else _PTX_LIST_RE
    records: dict[str, set[str]] = {}
    record_count = 0
    for line in stdout.splitlines():
        if not line.strip():
            continue
        match = record_re.fullmatch(line)
        if match is None:
            return {}, f"cuobjdump {option} output used an unrecognized record format"
        records.setdefault(match.group("identifier"), set()).add(
            f"{prefix}_{match.group('architecture').lower()}"
        )
        record_count += 1
        if record_count > MAX_CUOBJDUMP_RECORDS:
            return {}, f"cuobjdump {option} output exceeds the record limit"
    return {
        identifier: tuple(sorted(architectures))
        for identifier, architectures in sorted(records.items())
    }, None


def _run_bounded(
    argv: list[str], *, timeout: float
) -> tuple[int | None, str, str | None]:
    returncode, stdout, _stderr, problem = _run_bounded_capture(
        argv, timeout=timeout
    )
    return returncode, stdout, problem


def _run_bounded_capture(
    argv: list[str], *, timeout: float
) -> tuple[int | None, str, str, str | None]:
    deadline = time.monotonic() + max(0.001, timeout)
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    byte_count = 0
    overflow = False
    read_error = False
    lock = threading.Lock()
    with tempfile.TemporaryDirectory(prefix="skylos-cuobjdump-") as temp_dir:
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed trusted executable/argv
                argv,
                cwd=temp_dir,
                env=_scanner_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError:
            return None, "", "", "cuobjdump could not be started"

        def drain(stream, destination: list[bytes]) -> None:
            nonlocal byte_count, overflow, read_error
            if stream is None:
                return
            while True:
                try:
                    chunk = stream.read(65536)
                except OSError:
                    with lock:
                        read_error = True
                    break
                if not chunk:
                    break
                with lock:
                    remaining = MAX_SCANNER_OUTPUT_BYTES - byte_count
                    if remaining > 0:
                        destination.append(chunk[:remaining])
                        byte_count += min(len(chunk), remaining)
                    if len(chunk) > remaining:
                        overflow = True
                        try:
                            process.kill()
                        except OSError:
                            pass
                        break

        threads = [
            threading.Thread(
                target=drain, args=(process.stdout, stdout_chunks), daemon=True
            ),
            threading.Thread(
                target=drain, args=(process.stderr, stderr_chunks), daemon=True
            ),
        ]
        for thread in threads:
            thread.start()
        try:
            returncode = process.wait(
                timeout=max(0.001, deadline - time.monotonic())
            )
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
            for thread in threads:
                thread.join(timeout=0.05)
            return (
                None,
                b"".join(stdout_chunks).decode("utf-8", "replace"),
                b"".join(stderr_chunks).decode("utf-8", "replace"),
                "cuobjdump timed out",
            )
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        stdout = b"".join(stdout_chunks).decode("utf-8", "replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", "replace")
        if overflow:
            return (
                returncode,
                stdout,
                stderr,
                "cuobjdump output exceeded the safety limit",
            )
        if read_error or any(thread.is_alive() for thread in threads):
            try:
                process.kill()
            except OSError:
                pass
            return (
                returncode,
                stdout,
                stderr,
                "cuobjdump output could not be drained safely",
            )
        return returncode, stdout, stderr, None


def _scanner_environment() -> dict[str, str]:
    allowed = {"LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment["LC_ALL"] = "C"
    return environment


def _platform_from_binary(candidate: _Candidate) -> str | None:
    header, error = _read_binary_header(candidate)
    if error or header is None:
        return None
    if len(header) >= 24 and header[:4] == b"\x7fELF":
        byte_order = "little" if header[5] == 1 else "big" if header[5] == 2 else None
        if (
            byte_order is None
            or header[6] != 1
            or header[7] not in {0, 3}
            or int.from_bytes(header[20:24], byte_order) != 1
        ):
            return None
        elf_class = header[4]
        object_type = int.from_bytes(header[16:18], byte_order)
        machine = int.from_bytes(header[18:20], byte_order)
        if object_type not in {2, 3}:
            return None
        supported = {
            (1, "little", 3): "linux/386",
            (1, "little", 40): "linux/arm",
            (2, "little", 62): "linux/amd64",
            (2, "little", 183): "linux/arm64",
            (2, "little", 21): "linux/ppc64le",
        }
        return supported.get((elf_class, byte_order, machine))
    if len(header) >= 64 and header[:2] == b"MZ":
        pe_offset = int.from_bytes(header[60:64], "little")
        if 0 <= pe_offset <= len(header) - 6 and header[pe_offset : pe_offset + 4] == b"PE\0\0":
            machine = int.from_bytes(header[pe_offset + 4 : pe_offset + 6], "little")
            return {
                0x14C: "windows/386",
                0x8664: "windows/amd64",
                0xAA64: "windows/arm64",
            }.get(machine)
    return None


def _read_binary_header(
    candidate: _Candidate,
) -> tuple[bytes | None, str | None]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = None
    try:
        descriptor = os.open(  # skylos: ignore[SKY-D215] no-follow and inode-verified
            candidate.path, flags
        )
        file_stat = os.fstat(descriptor)
        if _fingerprint(file_stat) != (
            candidate.device,
            candidate.inode,
            candidate.size,
            candidate.mtime_ns,
        ):
            return None, "Artifact changed before platform inspection."
        header = os.read(descriptor, 4096)
    except OSError:
        return None, "Artifact header could not be read."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not _candidate_is_unchanged(candidate):
        return None, "Artifact changed during platform inspection."
    return header, None


def _hash_regular_file(
    path: Path,
    *,
    expected: _Candidate | None,
    deadline: float,
) -> tuple[str | None, str | None]:
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = None
    try:
        descriptor = os.open(  # skylos: ignore[SKY-D215] bounded verified file
            path, flags
        )
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            return None, "Artifact identity source is not a regular file."
        if file_stat.st_size > MAX_ARTIFACT_FILE_BYTES:
            return None, "Artifact exceeds the identity hashing size limit."
        if expected is not None and _fingerprint(file_stat) != (
            expected.device,
            expected.inode,
            expected.size,
            expected.mtime_ns,
        ):
            return None, "Artifact changed before identity hashing."
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                if time.monotonic() >= deadline:
                    return None, "Artifact hashing exceeded the overall time limit."
                digest.update(chunk)
    except OSError:
        return None, "Artifact identity could not be hashed."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if expected is not None and not _candidate_is_unchanged(expected):
        return None, "Artifact changed during identity hashing."
    return digest.hexdigest(), None


def _hash_directory_tree(
    root: Path,
    *,
    deadline: float,
) -> tuple[str | None, str | None]:
    """Bind inspection to every bounded regular file and safe symlink in a tree."""
    first, error = _hash_directory_tree_once(root, deadline=deadline)
    if error or first is None:
        return None, error or "Artifact content-tree hashing failed."
    second, error = _hash_directory_tree_once(root, deadline=deadline)
    if error or second is None:
        return None, error or "Artifact content-tree verification failed."
    if first != second:
        return None, "Artifact content tree changed during identity hashing."
    return first, None


def _hash_directory_tree_once(
    root: Path,
    *,
    deadline: float,
) -> tuple[str | None, str | None]:
    digest = hashlib.sha256(b"skylos-preflight-content-tree-v1\0")
    entries, errors = _snapshot_tree(root, deadline=deadline)
    if errors:
        return None, errors[0]
    total_bytes = 0
    for entry in sorted(entries, key=lambda item: _tree_relative(item.path, root)):
        if time.monotonic() >= deadline:
            return None, "Content-tree hashing exceeded the overall time limit."
        path = entry.path
        relative = _tree_relative(path, root)
        if stat.S_ISLNK(entry.mode):
            error = _hash_symlink_entry(digest, path, root, relative)
            if error:
                return None, error
            continue
        if stat.S_ISDIR(entry.mode):
            _hash_tree_record(
                digest,
                "directory",
                relative,
                str(stat.S_IMODE(entry.mode)),
            )
            continue
        if not stat.S_ISREG(entry.mode):
            return None, f"Artifact contains unsupported special file: {relative}"
        if entry.size > MAX_ARTIFACT_FILE_BYTES:
            return None, f"Artifact file exceeds identity size limit: {relative}"
        total_bytes += entry.size
        if total_bytes > MAX_TREE_BYTES:
            return None, "Artifact content tree exceeds the total identity size limit."
        candidate = _candidate(path, entry)
        file_digest, error = _hash_regular_file(
            path,
            expected=candidate,
            deadline=deadline,
        )
        if error or file_digest is None:
            return None, error or f"Artifact file could not be hashed: {relative}"
        _hash_tree_record(
            digest,
            "file",
            relative,
            str(stat.S_IMODE(entry.mode)),
            str(entry.size),
            file_digest,
        )
    return digest.hexdigest(), None


def _hash_symlink_entry(
    digest,
    path: Path,
    root: Path,
    relative: str,
) -> str | None:
    resolved, error = _resolve_in_tree_symlink(path, root)
    if error or resolved is None:
        return error or f"Artifact symlink is invalid: {relative}"
    try:
        link_target = os.readlink(path)
    except OSError:
        return f"Artifact symlink became unreadable: {relative}"
    _hash_tree_record(digest, "symlink", relative, link_target)
    return None


def _hash_tree_record(digest, kind: str, *values: str) -> None:
    digest.update(kind.encode("ascii"))
    digest.update(b"\0")
    for value in values:
        digest.update(value.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")


def _tree_relative(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace(os.sep, "/")


def _relative_display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _incomplete_inventory(artifact: str, message: str) -> ArtifactInventory:
    return ArtifactInventory(
        artifact=artifact,
        identity_verified=False,
        inspection_complete=False,
        source="local_cuobjdump",
        errors=(message,),
    )
