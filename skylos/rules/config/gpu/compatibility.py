# skylos: ignore[SKY-Q502] Cross-file GPU compatibility needs one contract scanner.
from __future__ import annotations

import ast
import fnmatch
import json
import logging
import os
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.config.findings import config_finding

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency.
    yaml = None


if yaml is not None:

    class _UniqueKeySafeLoader(yaml.SafeLoader):
        pass

    def _construct_unique_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError(f"duplicate YAML key: {key}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    _UniqueKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_unique_mapping,
    )


logger = logging.getLogger(__name__)

PROFILE_NAMES = ("gpu-targets.yml", "gpu-targets.yaml")
MAX_PROFILE_BYTES = 1_000_000
MAX_EVIDENCE_BYTES = 1_000_000
MAX_TOTAL_EVIDENCE_BYTES = 64_000_000
MAX_CANDIDATE_FILES = 5_000
MAX_WALKED_DIRECTORIES = 10_000
MAX_TARGETS = 256
MAX_YAML_GRAPH_DEPTH = 100
MAX_YAML_GRAPH_NODES = 50_000

SKIP_DIR_NAMES = {
    ".cache",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "cache",
    "dist",
    "node_modules",
    "target",
    "venv",
}

EVIDENCE_SUFFIXES = {
    ".bash",
    ".bazel",
    ".bzl",
    ".c",
    ".cc",
    ".cmake",
    ".cpp",
    ".cu",
    ".cuh",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".make",
    ".mk",
    ".py",
    ".sh",
    ".yaml",
    ".yml",
    ".zsh",
}
EVIDENCE_NAMES = {"cmakelists.txt", "gnumakefile", "makefile"}

# Source/update point: NVIDIA CUDA minor-version compatibility table.
# https://docs.nvidia.com/deploy/cuda-compatibility/minor-version-compatibility.html
CUDA_MINIMUM_DRIVER_BRANCH = {
    "linux": {11: 450, 12: 525, 13: 580},
    "windows": {11: 452, 12: 528, 13: 580},
}
CUDA_IMAGE_RE = re.compile(
    r"(?i)(?:^|/)(?:nvidia/cuda):"
    r"(?P<major>11|12|13)(?:\.(?P<minor>\d+))?(?=\.|[-@]|$)"
)
DOCKER_INSTRUCTION_RE = re.compile(
    r"^\s*(?P<instruction>[A-Za-z]+)(?:\s+(?P<body>.*))?$",
    re.IGNORECASE,
)
DOCKER_ARG_BODY_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>\S+)\s*$"
)
BUILD_ARG_REFERENCE_RE = re.compile(
    r"\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}"
    r"|\$(?P<plain>[A-Za-z_][A-Za-z0-9_]*)"
)
SUPPORTED_PLATFORM_RE = re.compile(r"(?i)^(?:linux|windows)(?:/(?:amd64|arm64))?$")

CMAKE_ARCH_NAME_RE = re.compile(r"\bCMAKE_CUDA_ARCHITECTURES\b", re.IGNORECASE)
TORCH_ARCH_NAME_RE = re.compile(r"\bTORCH_CUDA_ARCH_LIST\b", re.IGNORECASE)
ARCH_TOKEN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:sm_|compute_)?"
    r"(?:\d{1,2}\.\d|\d{2,3})(?:(?:-(?:real|virtual))|(?:\+ptx))?"
    r"(?![A-Za-z0-9_])"
)
NVCC_ARCH_RE = re.compile(
    r"(?i)(?:--gpu-architecture|-arch)\s*(?:=|\s)\s*"
    r"(?P<arch>(?:sm_|compute_)?\d{2,3})"
)
NVCC_CODE_VALUE_RE = re.compile(r"(?i)\bcode\s*=\s*(?P<value>\[[^\]]*\]|[^\s]+)")
NVCC_KIND_ARCH_RE = re.compile(r"(?i)\b(?P<kind>sm|compute)_(?P<arch>\d{2,3})\b")
ARCHITECTURE_EVIDENCE_SUFFIXES = {
    ".bash",
    ".bazel",
    ".bzl",
    ".cmake",
    ".make",
    ".mk",
    ".py",
    ".sh",
    ".yaml",
    ".yml",
    ".zsh",
}


@dataclass(frozen=True)
class _Target:
    name: str
    driver: str | None
    driver_branch: int | None
    compute_capability: str | None
    normalized_compute_capability: str | None
    platform: str | None
    line: int
    driver_line: int | None
    compute_capability_line: int | None
    platform_line: int | None
    end_line: int


@dataclass(frozen=True)
class _Profile:
    path: Path
    targets: tuple[_Target, ...]


@dataclass(frozen=True)
class _ProfileLoad:
    profile: _Profile | None
    path: Path | None
    error: str | None = None
    line: int = 1


@dataclass(frozen=True)
class _EvidenceFile:
    path: Path
    text: str
    lines: tuple[str, ...]


@dataclass(frozen=True)
class _CudaImage:
    file: _EvidenceFile
    line: int
    version: str
    major: int


@dataclass(frozen=True)
class _ArchitectureEvidence:
    file: _EvidenceFile
    line: int
    real_architectures: tuple[str, ...]
    virtual_architectures: tuple[str, ...]


@dataclass(frozen=True)
class _LineEvidence:
    file: _EvidenceFile
    line: int


@dataclass(frozen=True)
class _TensorRTBuilder:
    file: _EvidenceFile
    line: int
    artifacts: tuple[str, ...]
    has_ampere_plus: bool


@dataclass(frozen=True)
class _TensorRTPackage:
    file: _EvidenceFile
    line: int
    artifacts: tuple[str, ...]


@dataclass(frozen=True)
class _DockerStage:
    from_line: int
    from_body: str
    base: str
    alias: str | None
    parent_index: int | None
    instructions: tuple[tuple[int, str, str], ...]


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
    )


def _looks_like_evidence_path(path: Path) -> bool:
    return (
        _is_dockerfile(path)
        or path.name.lower() in EVIDENCE_NAMES
        or path.suffix.lower() in EVIDENCE_SUFFIXES
    )


def _is_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _yaml_graph_is_safe(value: Any) -> bool:
    active: set[int] = set()
    visited: set[int] = set()
    node_count = [0]
    return _yaml_node_is_safe(value, 0, active, visited, node_count)


def _yaml_node_is_safe(
    value: Any,
    depth: int,
    active: set[int],
    visited: set[int],
    node_count: list[int],
) -> bool:
    if depth > MAX_YAML_GRAPH_DEPTH:
        return False
    node_count[0] += 1
    if node_count[0] > MAX_YAML_GRAPH_NODES:
        return False

    children: tuple[Any, ...] | None = None
    if isinstance(value, dict):
        children = tuple(value.keys()) + tuple(value.values())
    elif isinstance(value, list):
        children = tuple(value)
    if children is None:
        return isinstance(value, (str, int, float, bool, type(None)))

    value_id = id(value)
    if value_id in active:
        return False
    if value_id in visited:
        return True
    active.add(value_id)
    safe = all(
        _yaml_node_is_safe(child, depth + 1, active, visited, node_count)
        for child in children
    )
    active.remove(value_id)
    visited.add(value_id)
    return safe


def _normalize_compute_capability(value: str) -> str | None:
    normalized = value.strip().lower()
    if normalized.startswith("sm_"):
        normalized = normalized[3:]
    elif normalized.startswith("compute_"):
        normalized = normalized[8:]
    if normalized.endswith(("-real", "-virtual")):
        normalized = normalized.rsplit("-", 1)[0]
    if normalized.endswith("+ptx"):
        normalized = normalized[:-4]

    dotted = re.fullmatch(r"(?P<major>\d{1,2})\.(?P<minor>\d)", normalized)
    if dotted is not None:
        return f"{int(dotted.group('major'))}{dotted.group('minor')}"
    if re.fullmatch(r"\d{2,3}", normalized) is not None:
        return str(int(normalized))
    return None


def _driver_branch(value: str) -> int | None:
    match = re.fullmatch(
        r"\s*[rR]?(?P<branch>\d{3,4})(?:\.\d+){0,2}\s*",
        value,
    )
    if match is None:
        return None
    return int(match.group("branch"))


def _target_lines(
    lines: list[str], name: str, *, start: int
) -> tuple[int, int, dict[str, int]]:
    name_re = re.compile(r"^\s*-?\s*name\s*:\s*(?P<name>.*?)\s*(?:#.*)?$")
    field_re = re.compile(
        r"^\s+(?P<field>driver|compute_capability|platform)\s*:",
        re.IGNORECASE,
    )
    for index in range(max(0, start - 1), len(lines)):
        match = name_re.match(lines[index])
        if match is None:
            continue
        value = match.group("name").strip().strip("\"'")
        if value == name:
            end_index = len(lines)
            for candidate in range(index + 1, len(lines)):
                if name_re.match(lines[candidate]) is not None:
                    end_index = candidate
                    break
            fields: dict[str, int] = {}
            for candidate in range(index + 1, end_index):
                field_match = field_re.match(lines[candidate])
                if field_match is not None:
                    fields[field_match.group("field").lower()] = candidate + 1
            return index + 1, max(index + 1, end_index), fields
    return 1, 1, {}


def _parse_targets(  # skylos: ignore[SKY-Q301,SKY-Q306] strict contract parser
    raw: Any, lines: list[str]
) -> tuple[_Target, ...] | None:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_TARGETS:
        return None
    targets: list[_Target] = []
    names: set[str] = set()
    line_cursor = 1
    for item in raw:
        if not isinstance(item, dict):
            return None
        if set(item) - {
            "name",
            "vendor",
            "driver",
            "compute_capability",
            "platform",
        }:
            return None
        name = item.get("name")
        vendor = item.get("vendor")
        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 256
            or not isinstance(vendor, str)
            or vendor.strip().lower() != "nvidia"
            or name.strip() in names
        ):
            return None
        name = name.strip()

        driver = item.get("driver")
        compute_capability = item.get("compute_capability")
        platform = item.get("platform")
        if driver is not None and (not isinstance(driver, str) or len(driver) > 128):
            return None
        if compute_capability is not None and not isinstance(compute_capability, str):
            return None
        if platform is not None:
            if (
                not isinstance(platform, str)
                or len(platform) > 128
                or SUPPORTED_PLATFORM_RE.fullmatch(platform.strip()) is None
            ):
                return None
            platform = platform.strip().lower()
        if driver is None and compute_capability is None:
            return None
        if driver is not None and _driver_branch(driver) is None:
            return None

        normalized_capability = None
        if compute_capability is not None:
            normalized_capability = _normalize_compute_capability(compute_capability)
            if normalized_capability is None:
                return None

        line, end_line, field_lines = _target_lines(lines, name, start=line_cursor)
        line_cursor = max(line_cursor, line + 1)
        names.add(name)
        targets.append(
            _Target(
                name=name,
                driver=driver,
                driver_branch=_driver_branch(driver) if driver is not None else None,
                compute_capability=compute_capability,
                normalized_compute_capability=normalized_capability,
                platform=platform,
                line=line,
                driver_line=field_lines.get("driver"),
                compute_capability_line=field_lines.get("compute_capability"),
                platform_line=field_lines.get("platform"),
                end_line=end_line,
            )
        )
    return tuple(targets)


def _load_profile(root: Path) -> _ProfileLoad:
    if yaml is None:
        return _ProfileLoad(None, None, "PyYAML is unavailable")
    for profile_name in PROFILE_NAMES:
        path = root / ".skylos" / profile_name
        try:
            present = path.exists() or path.is_symlink()
        except OSError:
            return _ProfileLoad(None, path, "GPU target contract is unreadable")
        if not present:
            continue
        source = read_project_text_no_symlink(
            root,
            path,
            max_bytes=MAX_PROFILE_BYTES,
            encoding="utf-8",
            errors="replace",
        )
        if source is None:
            return _ProfileLoad(
                None,
                path,
                "GPU target contract must be a bounded regular file, not a symlink",
            )
        try:
            loader = _UniqueKeySafeLoader(source)
            try:
                raw = loader.get_single_data()
            finally:
                loader.dispose()
        except Exception as exc:
            logger.debug("Unable to parse GPU target profile: %s", path, exc_info=True)
            problem_mark = getattr(exc, "problem_mark", None)
            line = int(getattr(problem_mark, "line", 0)) + 1
            return _ProfileLoad(None, path, "GPU target contract YAML is invalid", line)
        if (
            not isinstance(raw, dict)
            or not _yaml_graph_is_safe(raw)
            or set(raw) - {"version", "targets"}
        ):
            return _ProfileLoad(None, path, "GPU target contract schema is invalid")
        if type(raw.get("version")) is not int or raw["version"] != 1:
            return _ProfileLoad(
                None, path, "GPU target contract version must be exactly 1"
            )
        lines = source.splitlines()
        targets = _parse_targets(raw.get("targets"), lines)
        if targets is None:
            return _ProfileLoad(
                None,
                path,
                "GPU target contract targets are empty, ambiguous, or invalid",
            )
        return _ProfileLoad(_Profile(path=path, targets=targets), path)
    return _ProfileLoad(None, None)


def _normalize_changed_paths(root: Path, changed_files: set[str]) -> set[Path]:
    normalized: set[Path] = set()
    for raw_path in changed_files:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            if candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=False)
        except OSError:
            continue
        if _is_under_root(resolved, root):
            normalized.add(resolved)
    return normalized


def _contract_was_touched(
    root: Path,
    profile: _Profile,
    changed_files: set[str],
) -> tuple[bool, set[Path]]:
    changed_paths = _normalize_changed_paths(root, changed_files)
    for path in changed_paths:
        if path == profile.path or _looks_like_evidence_path(path):
            return True, changed_paths
    return False, changed_paths


def _discover_evidence_files(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded filesystem walk
    root: Path, profile: _Profile
) -> tuple[list[_EvidenceFile], str | None]:
    paths: list[Path] = []
    walked_directories = 0
    incomplete_reason: str | None = None
    for current_root, dirnames, filenames in os.walk(root, followlinks=False):
        walked_directories += 1
        if walked_directories > MAX_WALKED_DIRECTORIES:
            incomplete_reason = (
                f"GPU evidence exceeded {MAX_WALKED_DIRECTORIES} directories"
            )
            break
        base = Path(current_root)
        safe_dirs: list[str] = []
        for dirname in sorted(dirnames):
            directory = base / dirname
            try:
                if dirname not in SKIP_DIR_NAMES and not directory.is_symlink():
                    safe_dirs.append(dirname)
            except OSError:
                continue
        dirnames[:] = safe_dirs

        for filename in sorted(filenames):
            path = base / filename
            if path == profile.path or not _looks_like_evidence_path(path):
                continue
            try:
                file_stat = path.stat(follow_symlinks=False)
            except OSError:
                continue
            if path.is_symlink() or not stat.S_ISREG(file_stat.st_mode):
                continue
            if file_stat.st_size > MAX_EVIDENCE_BYTES:
                incomplete_reason = (
                    f"GPU evidence file exceeds {MAX_EVIDENCE_BYTES} bytes: {path}"
                )
                break
            if len(paths) >= MAX_CANDIDATE_FILES:
                incomplete_reason = (
                    f"GPU evidence exceeded {MAX_CANDIDATE_FILES} candidate files"
                )
                break
            paths.append(path)
        if incomplete_reason is not None:
            break

    evidence: list[_EvidenceFile] = []
    total_bytes = 0
    for path in sorted(paths):
        try:
            file_size = path.stat(follow_symlinks=False).st_size
        except OSError:
            continue
        if file_size > MAX_EVIDENCE_BYTES:
            continue
        if total_bytes + file_size > MAX_TOTAL_EVIDENCE_BYTES:
            incomplete_reason = (
                f"GPU evidence exceeded {MAX_TOTAL_EVIDENCE_BYTES} total bytes"
            )
            break
        source = read_project_text_no_symlink(
            root,
            path,
            max_bytes=MAX_EVIDENCE_BYTES,
            encoding="utf-8",
            errors="replace",
        )
        if source is None:
            incomplete_reason = f"GPU evidence changed or became unreadable: {path}"
            break
        total_bytes += file_size
        evidence.append(
            _EvidenceFile(path=path, text=source, lines=tuple(source.splitlines()))
        )
    return evidence, incomplete_reason


def _is_inline_ignored(lines: tuple[str, ...], line: int, rule_id: str) -> bool:
    needle = f"skylos: ignore[{rule_id}]"
    for index in (line - 2, line - 1):
        if 0 <= index < len(lines) and needle in _line_comment_text(lines[index]):
            return True
    return False


def _line_comment_text(line: str) -> str:
    comments: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        next_char = line[index + 1] if index + 1 < len(line) else ""
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
            index += 1
            continue
        if char == "#" or (char == "/" and next_char == "/"):
            comments.append(line[index + (2 if char == "/" else 1) :])
            break
        if char == "/" and next_char == "*":
            end = line.find("*/", index + 2)
            if end < 0:
                comments.append(line[index + 2 :])
                break
            comments.append(line[index + 2 : end])
            index = end + 2
            continue
        index += 1
    return " ".join(comments)


def _is_comment_only_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//", "/*", "*"))


def _docker_instructions(file: _EvidenceFile) -> list[tuple[int, str, str]]:
    instructions: list[tuple[int, str, str]] = []
    index = 0
    while index < len(file.lines):
        line = file.lines[index]
        match = DOCKER_INSTRUCTION_RE.match(line)
        if match is None:
            index += 1
            continue
        instruction = match.group("instruction").upper()
        body = match.group("body") or ""
        start_line = index + 1
        while line.rstrip().endswith("\\") and index + 1 < len(file.lines):
            body = body.rstrip().removesuffix("\\").rstrip()
            index += 1
            line = file.lines[index]
            body = f"{body} {line.strip()}".strip()
        instructions.append((start_line, instruction, body))
        heredoc_matches = list(
            re.finditer(
                r"<<(?P<strip>-)?\s*(?P<quote>['\"]?)(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)",
                body,
            )
        )
        for heredoc_match in heredoc_matches:
            delimiter = heredoc_match.group("delimiter")
            strip_tabs = heredoc_match.group("strip") is not None
            while index + 1 < len(file.lines):
                index += 1
                candidate = file.lines[index]
                if strip_tabs:
                    candidate = candidate.lstrip("\t")
                if candidate.strip() == delimiter:
                    break
        index += 1
    return instructions


def _final_docker_stage_instructions(
    file: _EvidenceFile,
) -> list[tuple[int, str, str]]:
    stages = _docker_stages(file)
    if not stages:
        return []
    final_stage = stages[-1]
    return [
        (final_stage.from_line, "FROM", final_stage.from_body),
        *final_stage.instructions,
    ]


def _docker_stages(  # skylos: ignore[SKY-Q301] stateful Dockerfile grammar
    file: _EvidenceFile,
) -> list[_DockerStage]:
    global_args: dict[str, str] = {}
    aliases: dict[str, int] = {}
    mutable_stages: list[dict[str, Any]] = []
    current_stage: dict[str, Any] | None = None

    for line_number, instruction, body in _docker_instructions(file):
        if instruction == "ARG" and current_stage is None:
            arg_match = DOCKER_ARG_BODY_RE.match(body.split("#", 1)[0].strip())
            if arg_match is not None:
                global_args[arg_match.group("name")] = arg_match.group("value").strip(
                    "\"'"
                )
            continue
        if instruction != "FROM":
            if current_stage is not None:
                current_stage["instructions"].append((line_number, instruction, body))
            continue

        tokens = _docker_tokens(body)
        index = 0
        while index < len(tokens) and tokens[index].startswith("--"):
            option = tokens[index].split("=", 1)[0].lower()
            if "=" not in tokens[index] and option == "--platform":
                index += 2
            else:
                index += 1
        if index >= len(tokens):
            current_stage = None
            continue
        base = _substitute_build_args(tokens[index], global_args)
        remaining = tokens[index + 1 :]
        alias = None
        if len(remaining) >= 2 and remaining[0].lower() == "as":
            alias = remaining[1]
        stage_index = len(mutable_stages)
        current_stage = {
            "from_line": line_number,
            "from_body": body,
            "base": base,
            "alias": alias,
            "parent_index": aliases.get(base.lower()),
            "instructions": [],
        }
        mutable_stages.append(current_stage)
        if alias is not None:
            aliases[alias.lower()] = stage_index

    return [
        _DockerStage(
            from_line=stage["from_line"],
            from_body=stage["from_body"],
            base=stage["base"],
            alias=stage["alias"],
            parent_index=stage["parent_index"],
            instructions=tuple(stage["instructions"]),
        )
        for stage in mutable_stages
    ]


def _effective_final_docker_instructions(
    file: _EvidenceFile,
) -> list[tuple[int, str, str]]:
    stages = _docker_stages(file)
    if not stages:
        return []
    stage_indexes: list[int] = []
    stage_index: int | None = len(stages) - 1
    while stage_index is not None:
        stage_indexes.append(stage_index)
        stage_index = stages[stage_index].parent_index
    return [
        instruction
        for index in reversed(stage_indexes)
        for instruction in stages[index].instructions
    ]


def _docker_tokens(body: str) -> list[str]:
    stripped = body.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            raw = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
            return raw
        return []
    try:
        return shlex.split(stripped, comments=False, posix=True)
    except ValueError:
        return stripped.split()


def _serialized_artifact_path(path: str, *, allow_glob: bool) -> str | None:
    normalized = path.replace("\\", "/").strip().removeprefix("./").rstrip("/")
    if (
        not normalized
        or normalized.startswith("/")
        or ".." in normalized.split("/")
        or not re.search(r"\.(?:engine|plan)$", normalized, re.IGNORECASE)
    ):
        return None
    dynamic_markers = "{}$%"
    if any(marker in normalized for marker in dynamic_markers):
        return None
    if not allow_glob and any(marker in normalized for marker in "*?[]"):
        return None
    return normalized


def _docker_copy_artifacts(body: str) -> tuple[str, ...]:
    tokens = _docker_tokens(body)
    index = 0
    options_with_values = {"--chown", "--chmod", "--exclude", "--from"}
    from_stage: str | None = None
    while index < len(tokens) and tokens[index].startswith("--"):
        option = tokens[index].split("=", 1)[0]
        if option == "--from":
            if "=" in tokens[index]:
                from_stage = tokens[index].split("=", 1)[1]
            elif index + 1 < len(tokens):
                from_stage = tokens[index + 1]
        if "=" not in tokens[index] and option in options_with_values:
            index += 2
        else:
            index += 1
    payload = tokens[index:]
    if len(payload) < 2:
        return ()
    artifacts: set[str] = set()
    for source in payload[:-1]:
        artifact = _serialized_artifact_path(source, allow_glob=True)
        if artifact is not None:
            artifacts.add(artifact)
            continue
        # A cross-stage COPY addresses the source stage's filesystem, so an
        # absolute path is normal. Preserve a precise filename correlation
        # without allowing absolute host paths for ordinary build-context COPY.
        normalized = source.replace("\\", "/").strip().rstrip("/")
        if from_stage is None or not normalized.startswith("/"):
            continue
        basename = normalized.rsplit("/", 1)[-1]
        artifact = _serialized_artifact_path(basename, allow_glob=True)
        if artifact is not None:
            artifacts.add(artifact)
    return tuple(sorted(artifacts))


def _is_architecture_evidence_file(path: Path) -> bool:
    return (
        _is_dockerfile(path)
        or path.name.lower() in EVIDENCE_NAMES
        or path.suffix.lower() in ARCHITECTURE_EVIDENCE_SUFFIXES
    )


def _substitute_build_args(value: str, args: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("plain")
        return args.get(name, match.group(0))

    return BUILD_ARG_REFERENCE_RE.sub(replace, value)


def _cuda_images(files: list[_EvidenceFile]) -> list[_CudaImage]:
    images: list[_CudaImage] = []
    for file in files:
        if not _is_dockerfile(file.path):
            continue
        stages = _docker_stages(file)
        if not stages:
            continue
        stage_index = len(stages) - 1
        while stages[stage_index].parent_index is not None:
            stage_index = stages[stage_index].parent_index  # type: ignore[assignment]
        runtime_base = stages[stage_index]
        cuda_match = CUDA_IMAGE_RE.search(runtime_base.base)
        if cuda_match is None or _is_inline_ignored(
            file.lines, runtime_base.from_line, "SKY-GPU001"
        ):
            continue
        major = int(cuda_match.group("major"))
        minor = cuda_match.group("minor")
        version = f"{major}.{minor}" if minor is not None else str(major)
        images.append(
            _CudaImage(
                file=file,
                line=runtime_base.from_line,
                version=version,
                major=major,
            )
        )
    return images


def _extract_architecture_kinds(
    value: str, *, syntax: str
) -> tuple[set[str], set[str]]:
    real: set[str] = set()
    virtual: set[str] = set()
    for match in ARCH_TOKEN_RE.finditer(value):
        token = match.group(0)
        normalized = _normalize_compute_capability(token)
        if normalized is not None:
            lowered = token.lower()
            if syntax == "cmake":
                if lowered.endswith("-real"):
                    real.add(normalized)
                elif lowered.endswith("-virtual"):
                    virtual.add(normalized)
                else:
                    # CMake deliberately emits both SASS and PTX when a CUDA
                    # architecture has no -real/-virtual suffix.
                    real.add(normalized)
                    virtual.add(normalized)
            elif syntax == "torch":
                real.add(normalized)
                if lowered.endswith("+ptx"):
                    virtual.add(normalized)
            elif syntax == "virtual":
                virtual.add(normalized)
            else:
                real.add(normalized)
    return real, virtual


def _python_architecture_assignments(  # skylos: ignore[SKY-Q301] conservative AST proof
    file: _EvidenceFile,
) -> tuple[list[tuple[int, str, str]], bool]:
    if (
        "CMAKE_CUDA_ARCHITECTURES" not in file.text
        and "TORCH_CUDA_ARCH_LIST" not in file.text
    ):
        return [], False
    try:
        tree = ast.parse(file.text, filename=str(file.path))
        compile(tree, str(file.path), "exec")
    except (SyntaxError, ValueError, TypeError):
        return [], True

    assignments: list[tuple[int, str, str]] = []
    ambiguous = False
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value_node = node.value
        for target in targets:
            name: str | None = None
            if isinstance(target, ast.Name) and target.id in {
                "CMAKE_CUDA_ARCHITECTURES",
                "TORCH_CUDA_ARCH_LIST",
            }:
                name = target.id
            elif (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and isinstance(target.value.value, ast.Name)
                and target.value.value.id == "os"
                and target.value.attr == "environ"
                and isinstance(target.slice, ast.Constant)
                and target.slice.value
                in {"CMAKE_CUDA_ARCHITECTURES", "TORCH_CUDA_ARCH_LIST"}
            ):
                name = str(target.slice.value)
            if name is None:
                continue
            if not isinstance(value_node, ast.Constant) or not isinstance(
                value_node.value, str
            ):
                ambiguous = True
                continue
            assignments.append((int(node.lineno), name, value_node.value))
    return assignments, ambiguous


def _cmake_architecture_assignment(
    file: _EvidenceFile,
) -> tuple[list[tuple[int, str, str]], bool]:
    assignment_re = re.compile(
        r"^\s*set\s*\(\s*CMAKE_CUDA_ARCHITECTURES\s+(?P<value>[^)]*)\)\s*$",
        re.IGNORECASE,
    )
    block_start_re = re.compile(
        r"^\s*(?:if|foreach|while|function|macro)\s*\(", re.IGNORECASE
    )
    block_end_re = re.compile(
        r"^\s*end(?:if|foreach|while|function|macro)\s*\(", re.IGNORECASE
    )
    depth = 0
    assignments: list[tuple[int, str, str]] = []
    ambiguous = False
    for line_number, raw_line in enumerate(file.lines, 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if block_end_re.match(line):
            depth = max(0, depth - 1)
        match = assignment_re.match(line)
        if match is not None:
            if depth:
                ambiguous = True
            assignments.append(
                (line_number, "CMAKE_CUDA_ARCHITECTURES", match.group("value"))
            )
        elif CMAKE_ARCH_NAME_RE.search(line) is not None or re.search(
            r"\bCUDA_ARCHITECTURES\b", line, re.IGNORECASE
        ):
            # Target properties and generated/indirect assignments can override
            # the global variable. Without the target graph, abstain.
            ambiguous = True
        if block_start_re.match(line):
            depth += 1
    if len(assignments) != 1:
        ambiguous = ambiguous or bool(assignments)
    return assignments, ambiguous


def _shell_architecture_assignments(
    file: _EvidenceFile,
) -> tuple[list[tuple[int, str, str]], bool]:
    assignment_re = re.compile(
        r"^\s*(?:export\s+)?(?P<name>CMAKE_CUDA_ARCHITECTURES|"
        r"TORCH_CUDA_ARCH_LIST)\s*(?::?=|\?=)\s*(?P<value>.*?)\s*$",
        re.IGNORECASE,
    )
    assignments: list[tuple[int, str, str]] = []
    ambiguous = False
    for line_number, raw_line in enumerate(file.lines, 1):
        if _is_comment_only_line(raw_line):
            continue
        line = raw_line.split("#", 1)[0]
        match = assignment_re.match(line)
        if match is None:
            continue
        value = match.group("value").strip().strip("\"'")
        if "$" in value:
            ambiguous = True
            continue
        assignments.append((line_number, match.group("name").upper(), value))
    return assignments, ambiguous


def _nvcc_command_text(  # skylos: ignore[SKY-Q301] shell token state machine
    line: str,
) -> str | None:
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return None

    segments: list[list[str]] = [[]]
    for token in tokens:
        if token and all(character in ";&|" for character in token):
            segments.append([])
        else:
            segments[-1].append(token)

    wrappers = {"ccache", "command", "exec", "sccache"}
    for segment in segments:
        if not segment:
            continue
        segment[0] = segment[0].lstrip("@-+")
        index = 0
        if segment[index].upper() == "RUN":
            index += 1
        while index < len(segment) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*", segment[index]
        ):
            index += 1
        if index < len(segment) and Path(segment[index]).name == "env":
            index += 1
            while index < len(segment) and (
                segment[index].startswith("-")
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", segment[index])
            ):
                index += 1
        while index < len(segment) and Path(segment[index]).name in wrappers:
            index += 1
        if index < len(segment) and Path(segment[index]).name == "nvcc":
            return " ".join(segment[index:])
    return None


def _nvcc_flag_configuration_lines(file: _EvidenceFile) -> set[int]:
    lines: set[int] = set()
    cmake_active = False
    cmake_depth = 0
    shell_continuation = False
    cmake_start_re = re.compile(
        r"^\s*set\s*\(\s*(?:CMAKE_)?CUDA_NVCC_FLAGS\b",
        re.IGNORECASE,
    )
    shell_start_re = re.compile(
        r"^\s*(?:export\s+)?(?:CUDA_NVCC_FLAGS|NVCCFLAGS)\s*[:?+]?=",
        re.IGNORECASE,
    )
    for line_number, raw_line in enumerate(file.lines, 1):
        if not cmake_active and cmake_start_re.match(raw_line):
            cmake_active = True
            cmake_depth = 0
        if cmake_active:
            lines.add(line_number)
            cmake_depth += raw_line.count("(") - raw_line.count(")")
            if cmake_depth <= 0:
                cmake_active = False
            continue
        if shell_continuation or shell_start_re.match(raw_line):
            lines.add(line_number)
            shell_continuation = raw_line.rstrip().endswith("\\")
        else:
            shell_continuation = False
    return lines


def _architecture_evidence(  # skylos: ignore[SKY-C304,SKY-Q301,SKY-Q302,SKY-Q306] bounded evidence correlation
    files: list[_EvidenceFile],
) -> tuple[list[_ArchitectureEvidence], bool]:
    records: list[_ArchitectureEvidence] = []
    evidence_files: set[Path] = set()
    ambiguous = False
    for file in files:
        if not _is_architecture_evidence_file(file.path):
            continue
        suffix = file.path.suffix.lower()
        if suffix == ".py":
            assignments, file_ambiguous = _python_architecture_assignments(file)
        elif file.path.name.lower() == "cmakelists.txt" or suffix == ".cmake":
            assignments, file_ambiguous = _cmake_architecture_assignment(file)
        else:
            assignments, file_ambiguous = _shell_architecture_assignments(file)
        ambiguous = ambiguous or file_ambiguous

        file_records: list[_ArchitectureEvidence] = []
        for line_number, name, value in assignments:
            lowered = value.lower()
            if re.search(r"\b(?:native|all(?:-major)?)\b", lowered) or "$" in value:
                ambiguous = True
                continue
            syntax = "cmake" if name == "CMAKE_CUDA_ARCHITECTURES" else "torch"
            real, virtual = _extract_architecture_kinds(value, syntax=syntax)
            if not real and not virtual:
                ambiguous = True
                continue
            if _is_inline_ignored(file.lines, line_number, "SKY-GPU002"):
                continue
            file_records.append(
                _ArchitectureEvidence(
                    file=file,
                    line=line_number,
                    real_architectures=tuple(sorted(real, key=int)),
                    virtual_architectures=tuple(sorted(virtual, key=int)),
                )
            )

        # Explicit nvcc commands are accepted only from command/build files,
        # never from arbitrary C/C++/Python string literals.
        if suffix != ".py" and suffix not in {
            ".c",
            ".cc",
            ".cpp",
            ".cu",
            ".cuh",
            ".cxx",
            ".h",
            ".hpp",
        }:
            nvcc_flag_lines = _nvcc_flag_configuration_lines(file)
            for line_number, raw_line in enumerate(file.lines, 1):
                if _is_comment_only_line(raw_line):
                    continue
                code_line = raw_line.split("#", 1)[0]
                command_text = _nvcc_command_text(code_line)
                evidence_text = (
                    command_text
                    if command_text is not None
                    else code_line
                    if line_number in nvcc_flag_lines
                    else None
                )
                if evidence_text is None:
                    continue
                real: set[str] = set()
                virtual: set[str] = set()
                nvcc_match = NVCC_ARCH_RE.search(evidence_text)
                if nvcc_match is not None:
                    arch = nvcc_match.group("arch")
                    normalized = _normalize_compute_capability(arch)
                    if normalized is not None:
                        if "compute_" in arch.lower():
                            virtual.add(normalized)
                        else:
                            real.add(normalized)
                            # nvcc's real-architecture shorthand expands to a
                            # matching cubin plus forward-compatible PTX.
                            virtual.add(normalized)
                if "-gencode" in evidence_text or "--generate-code" in evidence_text:
                    if "$" in evidence_text:
                        ambiguous = True
                        continue
                    for value_match in NVCC_CODE_VALUE_RE.finditer(evidence_text):
                        for code_match in NVCC_KIND_ARCH_RE.finditer(
                            value_match.group("value")
                        ):
                            normalized = _normalize_compute_capability(
                                code_match.group("arch")
                            )
                            if normalized is None:
                                continue
                            if code_match.group("kind").lower() == "compute":
                                virtual.add(normalized)
                            else:
                                real.add(normalized)
                if (real or virtual) and not _is_inline_ignored(
                    file.lines, line_number, "SKY-GPU002"
                ):
                    file_records.append(
                        _ArchitectureEvidence(
                            file=file,
                            line=line_number,
                            real_architectures=tuple(sorted(real, key=int)),
                            virtual_architectures=tuple(sorted(virtual, key=int)),
                        )
                    )

        if file_records:
            evidence_files.add(file.path)
            records.extend(file_records)

    # A root-wide union across independent build systems can make stale release
    # output look covered. Require one authoritative architecture evidence file.
    if len(evidence_files) > 1:
        ambiguous = True
    return records, ambiguous


def _attribute_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _assigned_paths(statement: ast.stmt) -> set[str]:
    targets: list[ast.AST] = []
    if isinstance(statement, ast.Assign):
        targets.extend(statement.targets)
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        targets.append(statement.target)
    elif isinstance(statement, (ast.For, ast.AsyncFor)):
        targets.append(statement.target)
    elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {statement.name}
    elif isinstance(statement, ast.Delete):
        targets.extend(statement.targets)

    paths: set[str] = set()

    def add_target(target: ast.AST) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                add_target(item)
            return
        path = _attribute_name(target)
        if path is not None:
            paths.add(path)

    for target in targets:
        add_target(target)
    return paths


def _statement_rebinds_name(statement: ast.stmt, name: str) -> bool:
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id == name
        for node in ast.walk(statement)
    )


def _is_result_write(statement: ast.stmt, output_name: str, result_name: str) -> bool:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    call = statement.value
    return (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == output_name
        and call.func.attr == "write"
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == result_name
    )


def _python_open_artifact(  # skylos: ignore[SKY-Q301] conservative artifact proof
    statement: ast.stmt, result_name: str
) -> str | None:
    if not isinstance(statement, ast.With) or len(statement.items) != 1:
        return None
    item = statement.items[0]
    if (
        not isinstance(item.context_expr, ast.Call)
        or not isinstance(item.context_expr.func, ast.Name)
        or item.context_expr.func.id != "open"
        or not item.context_expr.args
        or not isinstance(item.context_expr.args[0], ast.Constant)
        or not isinstance(item.context_expr.args[0].value, str)
        or not isinstance(item.optional_vars, ast.Name)
    ):
        return None
    mode = "r"
    if len(item.context_expr.args) >= 2 and isinstance(
        item.context_expr.args[1], ast.Constant
    ):
        mode = str(item.context_expr.args[1].value)
    for keyword in item.context_expr.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            mode = str(keyword.value.value)
    if "w" not in mode or "b" not in mode:
        return None

    output_name = item.optional_vars.id
    for child in statement.body:
        if _is_result_write(child, output_name, result_name):
            return _serialized_artifact_path(
                item.context_expr.args[0].value,
                allow_glob=False,
            )
        if _statement_rebinds_name(child, result_name):
            return None
    return None


def _python_tensorrt_builders(  # skylos: ignore[SKY-C304,SKY-Q306] bounded TensorRT AST proof
    file: _EvidenceFile,
) -> list[_TensorRTBuilder]:
    try:
        tree = ast.parse(file.text, filename=str(file.path))
        compile(tree, str(file.path), "exec")
    except (SyntaxError, ValueError, TypeError):
        return []
    has_tensorrt_import = any(
        (
            isinstance(node, ast.Import)
            and any(alias.name == "tensorrt" for alias in node.names)
        )
        or (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "tensorrt"
        )
        for node in ast.walk(tree)
    )
    if not has_tensorrt_import:
        return []

    builders: list[_TensorRTBuilder] = []

    def visit_body(  # skylos: ignore[SKY-Q301,SKY-Q306] stateful scope traversal
        body: list[ast.stmt],
    ) -> None:
        ampere_configs: set[str] = set()
        for index, statement in enumerate(body):
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                visit_body(statement.body)

            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "hardware_compatibility_level"
                    ):
                        config_name = _attribute_name(target.value)
                        value_name = _attribute_name(statement.value)
                        if (
                            config_name is not None
                            and value_name is not None
                            and value_name.endswith(
                                "HardwareCompatibilityLevel.AMPERE_PLUS"
                            )
                        ):
                            ampere_configs.add(config_name)
                        elif config_name is not None:
                            ampere_configs.discard(config_name)

            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                for assigned_path in _assigned_paths(statement):
                    ampere_configs = {
                        config
                        for config in ampere_configs
                        if config != assigned_path
                        and not config.startswith(f"{assigned_path}.")
                    }
                continue
            value = statement.value
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            if (
                not isinstance(value, ast.Call)
                or not isinstance(value.func, ast.Attribute)
                or value.func.attr != "build_serialized_network"
                or len(value.args) != 2
                or value.keywords
                or len(targets) != 1
                or not isinstance(targets[0], ast.Name)
            ):
                for assigned_path in _assigned_paths(statement):
                    ampere_configs = {
                        config
                        for config in ampere_configs
                        if config != assigned_path
                        and not config.startswith(f"{assigned_path}.")
                    }
                continue
            config_name = _attribute_name(value.args[1])
            if config_name is None:
                continue
            result_name = targets[0].id
            artifacts: set[str] = set()
            for later in body[index + 1 :]:
                artifact = _python_open_artifact(later, result_name)
                if artifact is not None:
                    artifacts.add(artifact)
                if _statement_rebinds_name(later, result_name):
                    break
            if not artifacts or _is_inline_ignored(
                file.lines, int(statement.lineno), "SKY-GPU003"
            ):
                continue
            builders.append(
                _TensorRTBuilder(
                    file=file,
                    line=int(statement.lineno),
                    artifacts=tuple(sorted(artifacts)),
                    has_ampere_plus=config_name in ampere_configs,
                )
            )
            for assigned_path in _assigned_paths(statement):
                ampere_configs = {
                    config
                    for config in ampere_configs
                    if config != assigned_path
                    and not config.startswith(f"{assigned_path}.")
                }

    visit_body(tree.body)
    return builders


def _cpp_without_comments(  # skylos: ignore[SKY-Q301,SKY-Q306] lexical state machine
    source: str,
) -> str:
    output: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if quote is not None:
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            while index < len(source) and source[index] != "\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            output.extend((" ", " "))
            index += 2
            while index < len(source):
                if (
                    source[index] == "*"
                    and index + 1 < len(source)
                    and source[index + 1] == "/"
                ):
                    output.extend((" ", " "))
                    index += 2
                    break
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _cpp_tensorrt_builders(file: _EvidenceFile) -> list[_TensorRTBuilder]:
    source = _cpp_without_comments(file.text)
    if not re.search(r"#\s*include\s*[<\"]NvInfer\.h[>\"]", source):
        return []
    build_re = re.compile(
        r"(?:auto|nvinfer1::IHostMemory\s*\*?)\s+(?P<result>[A-Za-z_]\w*)\s*=\s*"
        r"[A-Za-z_]\w*(?:->|\.)buildSerializedNetwork\s*\(\s*[^,]+,\s*"
        r"\*?(?P<config>[A-Za-z_]\w*)\s*\)",
        re.DOTALL,
    )
    setter_re = re.compile(
        r"(?P<config>[A-Za-z_]\w*)(?:->|\.)setHardwareCompatibilityLevel\s*\(\s*"
        r"(?:[A-Za-z_]\w*\s*(?:::|\.))*k?AMPERE_PLUS\s*\)",
        re.DOTALL,
    )
    stream_re = re.compile(
        r"std::ofstream\s+(?P<stream>[A-Za-z_]\w*)\s*\(\s*"
        r"(?P<quote>[\"'])(?P<path>[^\"'\r\n]+\.(?:engine|plan))(?P=quote)",
        re.IGNORECASE,
    )
    builders: list[_TensorRTBuilder] = []
    setters = [
        (match.start(), match.group("config")) for match in setter_re.finditer(source)
    ]
    for match in build_re.finditer(source):
        result_name = match.group("result")
        config_name = match.group("config")
        artifacts: set[str] = set()
        for stream_match in stream_re.finditer(source, match.end()):
            tail = source[stream_match.end() :]
            write_re = re.compile(
                rf"\b{re.escape(stream_match.group('stream'))}\s*\.\s*write\s*\(\s*"
                rf"{re.escape(result_name)}\s*(?:->|\.)"
            )
            if write_re.search(tail) is None:
                continue
            artifact = _serialized_artifact_path(
                stream_match.group("path"), allow_glob=False
            )
            if artifact is not None:
                artifacts.add(artifact)
        line_number = source.count("\n", 0, match.start()) + 1
        if not artifacts or _is_inline_ignored(file.lines, line_number, "SKY-GPU003"):
            continue
        builders.append(
            _TensorRTBuilder(
                file=file,
                line=line_number,
                artifacts=tuple(sorted(artifacts)),
                has_ampere_plus=any(
                    position < match.start() and setter_config == config_name
                    for position, setter_config in setters
                ),
            )
        )
    return builders


def _tensorrt_evidence(
    files: list[_EvidenceFile],
) -> tuple[list[_TensorRTBuilder], list[_TensorRTPackage]]:
    builders: list[_TensorRTBuilder] = []
    packages: list[_TensorRTPackage] = []
    for file in files:
        suffix = file.path.suffix.lower()
        if suffix == ".py":
            builders.extend(_python_tensorrt_builders(file))
        elif suffix in {".cc", ".cpp", ".cxx"}:
            builders.extend(_cpp_tensorrt_builders(file))
        if not _is_dockerfile(file.path):
            continue
        for line_number, instruction, body in _effective_final_docker_instructions(
            file
        ):
            if instruction not in {"ADD", "COPY"} or _is_inline_ignored(
                file.lines, line_number, "SKY-GPU003"
            ):
                continue
            package_artifacts = _docker_copy_artifacts(body)
            if package_artifacts:
                packages.append(
                    _TensorRTPackage(
                        file=file,
                        line=line_number,
                        artifacts=package_artifacts,
                    )
                )
    return builders, packages


def _matching_tensorrt_artifact(
    builders: list[_TensorRTBuilder],
    packages: list[_TensorRTPackage],
    *,
    changed_paths: set[Path] | None = None,
) -> tuple[_TensorRTBuilder, _TensorRTPackage, str] | None:
    for builder in builders:
        for package in packages:
            if (
                changed_paths
                and builder.file.path not in changed_paths
                and package.file.path not in changed_paths
            ):
                continue
            for artifact in builder.artifacts:
                if any(
                    fnmatch.fnmatchcase(artifact, package_pattern)
                    for package_pattern in package.artifacts
                ):
                    return builder, package, artifact
    return None


def _anchor(
    profile: _Profile,
    profile_line: int,
    contributors: list[_LineEvidence],
    changed_paths: set[Path],
) -> tuple[Path, int]:
    if profile.path in changed_paths:
        return profile.path, profile_line
    for contributor in contributors:
        if contributor.file.path in changed_paths:
            return contributor.file.path, contributor.line
    if contributors:
        return contributors[0].file.path, contributors[0].line
    return profile.path, profile_line


def _finding(
    *,
    rule_id: str,
    name: str,
    message: str,
    file: Path,
    line: int,
    value: str,
    metadata: dict[str, Any],
    related_locations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    finding = config_finding(
        rule_id=rule_id,
        domain="gpu",
        provider="nvidia",
        name=name,
        message=message,
        file=file,
        line=line,
        severity="HIGH",
        value=value,
        finding_type="gpu_compatibility",
        category="RELIABILITY",
    )
    finding["metadata"] = metadata
    if related_locations:
        finding["related_locations"] = related_locations
    return finding


def _related_line(path: Path, line: int) -> dict[str, Any]:
    return {
        "file": str(path),
        "start_line": line,
        "end_line": line,
    }


def _related_span(path: Path, start_line: int, end_line: int) -> dict[str, Any]:
    return {
        "file": str(path),
        "start_line": max(1, start_line),
        "end_line": max(max(1, start_line), end_line),
    }


def _target_related_line(
    profile: _Profile, target: _Target, *, field: str
) -> dict[str, Any]:
    field_line = {
        "driver": target.driver_line,
        "compute_capability": target.compute_capability_line,
        "platform": target.platform_line,
    }.get(field)
    return _related_line(profile.path, field_line or target.line)


def _contract_finding(
    path: Path,
    message: str,
    *,
    line: int = 1,
    related_locations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    profile_end_line = max(1, line)
    profile_root = path.parent.parent if path.parent.name == ".skylos" else path.parent
    source = read_project_text_no_symlink(
        profile_root,
        path,
        max_bytes=MAX_PROFILE_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if source is not None:
        profile_end_line = max(profile_end_line, len(source.splitlines()))
    locations = [
        _related_span(path, 1, profile_end_line),
        *(related_locations or []),
    ]
    return _finding(
        rule_id="SKY-GPU000",
        name="GPU release contract is invalid or incomplete",
        message=(
            f"{message}. Skylos cannot prove GPU release compatibility until the "
            "contract/evidence is complete."
        ),
        file=path,
        line=max(1, line),
        value="GPU compatibility proof incomplete",
        metadata={
            "profile": str(path),
            "contract_error": message,
            "evidence_files": [str(path)],
        },
        related_locations=locations,
    )


def _driver_finding(  # skylos: ignore[SKY-Q301] fail-closed contract correlation
    profile: _Profile,
    images: list[_CudaImage],
    changed_paths: set[Path],
) -> dict[str, Any] | None:
    for image in images:
        if (
            changed_paths
            and profile.path not in changed_paths
            and image.file.path not in changed_paths
        ):
            continue
        incompatible: list[tuple[_Target, int]] = []
        for target in profile.targets:
            platform = (target.platform or "linux").strip().lower()
            if platform.startswith("windows"):
                platform_family = "windows"
            elif platform.startswith("linux"):
                platform_family = "linux"
            else:
                continue
            minimum = CUDA_MINIMUM_DRIVER_BRANCH[platform_family][image.major]
            if (
                target.driver is not None
                and target.driver_branch is not None
                and target.driver_branch < minimum
            ):
                incompatible.append((target, minimum))
        if not incompatible:
            continue
        first, first_minimum_branch = incompatible[0]
        anchor_file, anchor_line = _anchor(
            profile,
            first.driver_line or first.line,
            [_LineEvidence(file=image.file, line=image.line)],
            changed_paths,
        )
        targets = ", ".join(
            f"{target.name} (driver {target.driver}, needs branch {minimum})"
            for target, minimum in incompatible
        )
        target_label = "target" if len(incompatible) == 1 else "targets"
        verb = "is" if len(incompatible) == 1 else "are"
        return _finding(
            rule_id="SKY-GPU001",
            name="CUDA image requires newer NVIDIA driver",
            message=(
                f"CUDA {image.version} image requires NVIDIA driver branch "
                f"{first_minimum_branch} or newer for the first incompatible "
                f"platform, but {target_label} {targets} {verb} below the applicable "
                "minimum. Upgrade the target driver, use cuda-compat deliberately, "
                "or build on an older compatible CUDA image."
            ),
            file=anchor_file,
            line=anchor_line,
            value=f"CUDA {image.version} requires driver {first_minimum_branch}",
            metadata={
                "profile": str(profile.path),
                "cuda_version": image.version,
                "minimum_driver_branch": first_minimum_branch,
                "incompatible_targets": [
                    {
                        "name": target.name,
                        "driver": target.driver,
                        "driver_branch": target.driver_branch,
                        "minimum_driver_branch": minimum,
                        "platform": target.platform or "linux (default)",
                    }
                    for target, minimum in incompatible
                ],
                "evidence_files": [str(image.file.path), str(profile.path)],
            },
            related_locations=[
                *(
                    _target_related_line(profile, target, field="driver")
                    for target, _ in incompatible
                ),
                _related_line(image.file.path, image.line),
            ],
        )
    return None


def _architecture_finding(  # skylos: ignore[SKY-C304,SKY-Q301] fail-closed contract correlation
    profile: _Profile,
    records: list[_ArchitectureEvidence],
    ambiguous_evidence: bool,
    changed_paths: set[Path],
) -> dict[str, Any] | None:
    if not records or ambiguous_evidence:
        return None
    if (
        changed_paths
        and profile.path not in changed_paths
        and not any(record.file.path in changed_paths for record in records)
    ):
        return None
    real_architectures = {
        architecture for record in records for architecture in record.real_architectures
    }
    virtual_architectures = {
        architecture
        for record in records
        for architecture in record.virtual_architectures
    }

    def target_is_covered(target_architecture: str) -> bool:
        target_value = int(target_architecture)
        target_major = target_value // 10
        sass_covered = any(
            int(architecture) // 10 == target_major
            and int(architecture) <= target_value
            for architecture in real_architectures
        )
        ptx_covered = any(
            int(architecture) <= target_value for architecture in virtual_architectures
        )
        return sass_covered or ptx_covered

    missing = [
        target
        for target in profile.targets
        if target.normalized_compute_capability is not None
        and not target_is_covered(target.normalized_compute_capability)
    ]
    if not missing:
        return None

    first = missing[0]
    contributors = [
        _LineEvidence(file=record.file, line=record.line) for record in records
    ]
    anchor_file, anchor_line = _anchor(
        profile,
        first.compute_capability_line or first.line,
        contributors,
        changed_paths,
    )
    sass_display = (
        ", ".join(f"sm_{arch}" for arch in sorted(real_architectures, key=int))
        or "none"
    )
    ptx_display = (
        ", ".join(f"compute_{arch}" for arch in sorted(virtual_architectures, key=int))
        or "none"
    )
    missing_display = ", ".join(
        f"{target.name}={target.compute_capability} "
        f"(sm_{target.normalized_compute_capability})"
        for target in missing
    )
    target_label = "target" if len(missing) == 1 else "targets"
    verb = "is" if len(missing) == 1 else "are"
    evidence_files = list(dict.fromkeys(str(record.file.path) for record in records))
    return _finding(
        rule_id="SKY-GPU002",
        name="CUDA target architecture missing from build",
        message=(
            f"CUDA build embeds SASS for {sass_display} and PTX for {ptx_display}, "
            "but declared "
            f"{target_label} {missing_display} {verb} not covered. Add the missing "
            "architecture or "
            "an intentional PTX fallback to the release build."
        ),
        file=anchor_file,
        line=anchor_line,
        value="missing "
        + ", ".join(f"sm_{target.normalized_compute_capability}" for target in missing),
        metadata={
            "profile": str(profile.path),
            "compiled_architectures": sorted(real_architectures, key=int),
            "ptx_architectures": sorted(virtual_architectures, key=int),
            "missing_targets": [
                {
                    "name": target.name,
                    "compute_capability": target.compute_capability,
                    "normalized_compute_capability": (
                        target.normalized_compute_capability
                    ),
                }
                for target in missing
            ],
            "evidence_files": evidence_files + [str(profile.path)],
        },
        related_locations=[
            *(
                _target_related_line(profile, target, field="compute_capability")
                for target in missing
            ),
            *(_related_line(record.file.path, record.line) for record in records),
        ],
    )


def _tensorrt_finding(  # skylos: ignore[SKY-C304,SKY-Q301] fail-closed contract correlation
    profile: _Profile,
    builders: list[_TensorRTBuilder],
    packages: list[_TensorRTPackage],
    changed_paths: set[Path],
) -> dict[str, Any] | None:
    target_capabilities = {
        target.name: target.normalized_compute_capability
        for target in profile.targets
        if target.normalized_compute_capability is not None
    }
    target_platforms = {
        target.name: target.platform.strip().lower()
        for target in profile.targets
        if target.platform is not None and target.platform.strip()
    }
    artifact_match = _matching_tensorrt_artifact(
        builders,
        packages,
        changed_paths=(None if profile.path in changed_paths else changed_paths),
    )
    heterogeneous_hardware = len(set(target_capabilities.values())) >= 2
    heterogeneous_platforms = len(set(target_platforms.values())) >= 2
    if (
        not heterogeneous_hardware
        and not heterogeneous_platforms
        or artifact_match is None
    ):
        return None
    builder, package, artifact = artifact_match
    if (
        not heterogeneous_platforms
        and builder.has_ampere_plus
        and target_capabilities
        and all(int(capability) >= 80 for capability in target_capabilities.values())
    ):
        return None

    target_by_name = {target.name: target for target in profile.targets}
    first_target = next(
        (
            target
            for target in profile.targets
            if target.name in target_capabilities or target.name in target_platforms
        ),
        profile.targets[0],
    )
    contributors = [
        _LineEvidence(file=builder.file, line=builder.line),
        _LineEvidence(file=package.file, line=package.line),
    ]
    anchor_file, anchor_line = _anchor(
        profile,
        (
            first_target.platform_line
            if heterogeneous_platforms and first_target.platform_line is not None
            else first_target.compute_capability_line or first_target.line
        ),
        contributors,
        changed_paths,
    )
    target_display = ", ".join(
        f"{target.name}="
        f"{target.compute_capability or target.platform or 'declared target'}"
        for target in profile.targets
        if target.name in target_capabilities or target.name in target_platforms
    )
    if heterogeneous_platforms:
        platform_display = ", ".join(
            f"{name}={platform}" for name, platform in target_platforms.items()
        )
        compatibility_message = (
            f"The same plan is packaged for different runtime platforms "
            f"({platform_display}); hardware compatibility does not make one "
            "engine portable across operating-system/CPU targets."
        )
    elif builder.has_ampere_plus:
        pre_ampere = ", ".join(
            f"{name}={target_by_name[name].compute_capability}"
            for name, capability in target_capabilities.items()
            if int(capability) < 80
        )
        compatibility_message = (
            f"The builder sets AMPERE_PLUS, but {pre_ampere} is below compute "
            "capability 8.0 and is not covered."
        )
    else:
        compatibility_message = (
            "The builder does not set AMPERE_PLUS hardware compatibility."
        )
    return _finding(
        rule_id="SKY-GPU003",
        name="TensorRT engine is not portable across target GPUs",
        message=(
            f"Serialized TensorRT engine {artifact} is packaged for heterogeneous "
            f"GPU targets ({target_display}). {compatibility_message} "
            "Build one engine per target or set a supported compatibility level "
            "before serialization."
        ),
        file=anchor_file,
        line=anchor_line,
        value="TensorRT engine lacks hardware compatibility",
        metadata={
            "profile": str(profile.path),
            "target_compute_capabilities": target_capabilities,
            "target_platforms": target_platforms,
            "artifact": artifact,
            "builder_file": str(builder.file.path),
            "package_file": str(package.file.path),
            "evidence_files": [
                str(builder.file.path),
                str(package.file.path),
                str(profile.path),
            ],
        },
        related_locations=[
            *(
                _target_related_line(
                    profile,
                    target,
                    field=(
                        "platform"
                        if heterogeneous_platforms and target.platform is not None
                        else "compute_capability"
                    ),
                )
                for target in profile.targets
                if target.name in target_capabilities or target.name in target_platforms
            ),
            _related_line(builder.file.path, builder.line),
            _related_line(package.file.path, package.line),
        ],
    )


def scan_gpu_compatibility(  # skylos: ignore[SKY-C304,SKY-Q301,SKY-Q306] bounded proof orchestrator
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
    require_contract: bool = False,
) -> list[dict[str, Any]]:
    """Check a declared NVIDIA target fleet against static release evidence."""

    try:
        root_path = Path(root).expanduser().resolve(strict=True)
    except OSError:
        return []
    if not root_path.is_dir():
        return []

    ignored = ignore or set()

    # The profile is the user's explicit compatibility contract. Without one,
    # broad GPU source patterns are intentionally not interpreted as findings.
    profile_load = _load_profile(root_path)
    if profile_load.profile is None:
        if profile_load.path is not None and profile_load.error is not None:
            if "SKY-GPU000" in ignored:
                return []
            return [
                _contract_finding(
                    profile_load.path,
                    profile_load.error,
                    line=profile_load.line,
                )
            ]
        if changed_files is not None:
            changed_paths_without_profile = _normalize_changed_paths(
                root_path, changed_files
            )
            deleted_profile = next(
                (
                    root_path / ".skylos" / profile_name
                    for profile_name in PROFILE_NAMES
                    if root_path / ".skylos" / profile_name
                    in changed_paths_without_profile
                ),
                None,
            )
            if deleted_profile is not None and "SKY-GPU000" not in ignored:
                return [
                    _contract_finding(
                        deleted_profile,
                        "GPU target contract was deleted from this change",
                    )
                ]
        if require_contract and "SKY-GPU000" not in ignored:
            return [
                _contract_finding(
                    root_path / ".skylos" / PROFILE_NAMES[0],
                    "GPU target contract is required for the selected GPU release rules",
                )
            ]
        return []
    profile = profile_load.profile

    changed_paths: set[Path] = set()
    if changed_files is not None:
        touched, changed_paths = _contract_was_touched(
            root_path, profile, changed_files
        )
        if not touched:
            return []

    files, incomplete_reason = _discover_evidence_files(root_path, profile)
    if incomplete_reason is not None:
        if "SKY-GPU000" in ignored:
            return []
        return [
            _contract_finding(
                profile.path,
                incomplete_reason,
                related_locations=[
                    _related_line(path, 1) for path in sorted(changed_paths)
                ],
            )
        ]
    findings: list[dict[str, Any]] = []
    architecture_surface_files = [
        file
        for file in files
        if CMAKE_ARCH_NAME_RE.search(file.text) is not None
        or TORCH_ARCH_NAME_RE.search(file.text) is not None
        or NVCC_ARCH_RE.search(file.text) is not None
        or "-gencode" in file.text
        or "--generate-code" in file.text
    ]

    if "SKY-GPU001" not in ignored:
        cuda_images = _cuda_images(files)
        driver_contract_present = any(
            target.driver is not None for target in profile.targets
        )
        driver_surface_changed = (
            changed_files is None
            or profile.path in changed_paths
            or any(_is_dockerfile(path) for path in changed_paths)
        )
        if driver_contract_present and not cuda_images and driver_surface_changed:
            if "SKY-GPU000" not in ignored:
                findings.append(
                    _contract_finding(
                        profile.path,
                        "Declared target drivers have no final-stage NVIDIA CUDA image evidence",
                        related_locations=[
                            *(
                                _related_span(file.path, 1, max(1, len(file.lines)))
                                for file in files
                                if _is_dockerfile(file.path)
                            ),
                            *(
                                _related_line(path, 1)
                                for path in sorted(changed_paths)
                                if _is_dockerfile(path) and not path.exists()
                            ),
                        ],
                    )
                )
        else:
            finding = _driver_finding(profile, cuda_images, changed_paths)
            if finding is not None:
                findings.append(finding)

    if "SKY-GPU002" not in ignored:
        architecture_records, ambiguous_architecture_evidence = _architecture_evidence(
            files
        )
        architecture_contract_present = any(
            target.compute_capability is not None for target in profile.targets
        )
        architecture_surface_changed = (
            changed_files is None
            or profile.path in changed_paths
            or any(file.path in changed_paths for file in architecture_surface_files)
            or any(
                path.name.lower() in EVIDENCE_NAMES
                or path.name.lower() == "cmakelists.txt"
                or path.suffix.lower()
                in {".cmake", ".make", ".mk", ".sh", ".bash", ".zsh"}
                for path in changed_paths
                if not path.exists()
            )
        )
        if (
            architecture_contract_present
            and not architecture_records
            and not ambiguous_architecture_evidence
            and architecture_surface_changed
        ):
            if "SKY-GPU000" not in ignored:
                findings.append(
                    _contract_finding(
                        profile.path,
                        "Declared compute capabilities have no authoritative CUDA architecture evidence",
                        related_locations=[
                            *(
                                _related_span(file.path, 1, max(1, len(file.lines)))
                                for file in architecture_surface_files
                            ),
                            *(
                                _related_line(path, 1)
                                for path in sorted(changed_paths)
                                if not path.exists()
                                and (
                                    path.name.lower() in EVIDENCE_NAMES
                                    or path.name.lower() == "cmakelists.txt"
                                    or path.suffix.lower()
                                    in {
                                        ".cmake",
                                        ".make",
                                        ".mk",
                                        ".sh",
                                        ".bash",
                                        ".zsh",
                                    }
                                )
                            ),
                        ],
                    )
                )
        elif ambiguous_architecture_evidence:
            if "SKY-GPU000" not in ignored:
                findings.append(
                    _contract_finding(
                        profile.path,
                        "CUDA architecture evidence is dynamic or has multiple authoritative sources",
                        related_locations=[
                            _related_span(file.path, 1, max(1, len(file.lines)))
                            for file in architecture_surface_files
                        ],
                    )
                )
        else:
            finding = _architecture_finding(
                profile,
                architecture_records,
                False,
                changed_paths,
            )
            if finding is not None:
                findings.append(finding)

    if "SKY-GPU003" not in ignored:
        builders, packages = _tensorrt_evidence(files)
        finding = _tensorrt_finding(
            profile,
            builders,
            packages,
            changed_paths,
        )
        if finding is not None:
            findings.append(finding)

    return findings
