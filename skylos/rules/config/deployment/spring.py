"""Review Spring Boot Actuator exposure declarations without starting the app."""

import re
from pathlib import Path

from skylos.core.file_discovery import discover_source_files
from skylos.core.inline_directives import directive_ignores
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.config.cicd.yaml_source import load_yaml_documents_with_locations
from skylos.rules.config.findings import config_finding

_RULE = "SKY-D432"
_PREFIX = ("management", "endpoints", "web", "exposure")
_PROPERTY = re.compile(
    r"^\s*management\.endpoints\.web\.exposure\.(include|exclude)"
    r"(?:\s*[=:]\s*|\s+)(.*)$"
)
_EXTENSIONS = {".yaml", ".yml", ".properties"}


def _wildcard(value):
    if isinstance(value, str):
        return "*" in {part.strip() for part in value.split(",")}
    if isinstance(value, list):
        return any(isinstance(part, str) and part.strip() == "*" for part in value)
    return False


def _key_paths(mapping, target, prefix=()):
    if not isinstance(mapping, dict):
        return
    for key, value in mapping.items():
        if not isinstance(key, str):
            continue
        pieces = tuple(key.split("."))
        if pieces == target:
            yield (*prefix, key), value
        elif len(pieces) < len(target) and target[: len(pieces)] == pieces:
            yield from _key_paths(value, target[len(pieces) :], (*prefix, key))


def _yaml_exposures(text):
    lines = text.count("\n") + 1
    for data, source in load_yaml_documents_with_locations(text):
        include = list(_key_paths(data, (*_PREFIX, "include")))
        exclude = list(_key_paths(data, (*_PREFIX, "exclude")))
        if len(include) != 1 or any(_wildcard(value) for _, value in exclude):
            continue
        key, value = include[0]
        if not _wildcard(value):
            continue
        line = source.line_for_path(key) or 1
        comments = ((i, source.comment_on_line(i)) for i in range(1, lines + 1))
        yield line, ((i, c) for i, c in comments if c is not None)


def _property_exposures(text):
    values = {}
    comments = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", "!")):
            comments.append((number, line.lstrip().replace("!", "#", 1)))
        found = _PROPERTY.fullmatch(line)
        if found:
            values[found[1]] = (number, found[2])
    include = values.get("include")
    if (
        include
        and _wildcard(include[1])
        and not _wildcard(values.get("exclude", (0, ""))[1])
    ):
        yield include[0], comments


def scan_spring_actuator(
    root, *, changed_files=None, ignore=None, scan_paths=None, exclude_folders=None
):
    if _RULE in (ignore or ()):
        return []
    target = Path(root)
    project = target.parent if target.is_file() else target
    project = project.resolve()

    def resolved(path):
        path = Path(path)
        return (path if path.is_absolute() else project / path).resolve()

    changed = (
        {resolved(path) for path in changed_files}
        if changed_files is not None
        else None
    )
    selected_files = set()
    selected_dirs = set()
    for entry in scan_paths or ():
        candidate = Path(entry).expanduser()
        if candidate.is_symlink():
            continue
        try:
            candidate = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if candidate.is_dir():
            selected_dirs.add(candidate)
        elif candidate.is_file():
            selected_files.add(candidate)
    findings = []
    for path in discover_source_files(target, _EXTENSIONS, exclude_folders):
        if path.stem != "application" and not path.stem.startswith("application-"):
            continue
        if changed is not None and path not in changed:
            continue
        if (
            scan_paths is not None
            and path not in selected_files
            and not any(path.is_relative_to(directory) for directory in selected_dirs)
        ):
            continue
        text = read_project_text_no_symlink(
            project, path, max_bytes=256 * 1024, encoding="utf-8"
        )
        if text is None:
            continue
        exposures = (
            _property_exposures
            if path.suffix.lower() == ".properties"
            else _yaml_exposures
        )
        for line, comments in exposures(text):
            blanket, by_line = directive_ignores(comments, text.count("\n") + 1)
            if line in blanket or _RULE in by_line.get(line, ()):
                continue
            findings.append(
                config_finding(
                    rule_id=_RULE,
                    domain="web_framework",
                    provider="spring_boot",
                    name="Spring Boot Actuator web exposure",
                    message="This file allows all enabled Actuator endpoints to be exposed over HTTP when its settings apply. Review the active configuration and authentication.",
                    file=path,
                    line=line,
                    severity="MEDIUM",
                    value="*",
                    finding_type="review",
                )
            )
    return findings
