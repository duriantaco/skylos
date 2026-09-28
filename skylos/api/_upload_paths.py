"""File paths in an upload, per the contract's ``finding.file_path`` rules.

``normalize_contract_file_path`` is what the server does to a path it
receives; ``resolve_upload_location`` is what the CLI sends: a path inside
the project, never an absolute machine path, a ``..`` path or a placeholder.
"""

from __future__ import annotations

import os
import posixpath
import re
from typing import Any
from urllib.parse import unquote_to_bytes

from skylos.api._upload_contract import field_max_length, placeholder_paths

__all__ = [
    "ASCII_WHITESPACE",
    "REASON_CONTROL_CHARACTER",
    "REASON_DOT_SEGMENT",
    "REASON_EMPTY",
    "REASON_EMPTY_SEGMENT",
    "REASON_MISSING",
    "REASON_NOT_STRING",
    "REASON_PLACEHOLDER",
    "REASON_TOO_LONG",
    "encode_upload_path",
    "file_path_problem",
    "normalize_contract_file_path",
    "resolve_upload_location",
    "upload_location_uri",
]

# Machine reasons for a path the server stores without a location. They match
# the server's ``finding_warnings`` reasons (skylos-cloud src/lib/repo-subpath.ts
# and src/lib/upload-contract.ts) and the shared fixtures.
REASON_MISSING = "missing"
REASON_NOT_STRING = "not_a_string"
REASON_EMPTY = "empty"
REASON_CONTROL_CHARACTER = "control_character"
REASON_DOT_SEGMENT = "dot_segment"
REASON_EMPTY_SEGMENT = "empty_segment"
REASON_TOO_LONG = "too_long"
# CLI-side name for a placeholder such as "unknown" (the contract treats it
# like any other invalid path). The CLI never sends one; see apply_upload_contract.
REASON_PLACEHOLDER = "placeholder"

# The contract trims surrounding ASCII whitespace only (space, tab, CR, LF,
# vertical tab, form feed); Python's str.strip() would also remove
# U+001C-U+001F, U+0085 and Unicode spaces.
ASCII_WHITESPACE = " \t\r\n\x0b\x0c"

_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE_RE = re.compile(r"^[A-Za-z]:/")
_ABSOLUTE_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_FILE_SCHEME_RE = re.compile(r"^file:/*", re.IGNORECASE)
_REPEATED_SLASH_RE = re.compile(r"/{2,}")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_CI_WORKSPACE_PREFIXES = (
    re.compile(r"^home/runner/work/[^/]+/[^/]+/"),
    re.compile(r"^__w/[^/]+/[^/]+/"),
    re.compile(r"^github/workspace/"),
)


def _percent_decode_once(text: str) -> str:
    """``decodeURIComponent`` semantics: unchanged when not valid encoding."""
    if "%" not in text or _BAD_PERCENT_RE.search(text):
        return text
    try:
        return unquote_to_bytes(text).decode("utf-8")
    except UnicodeDecodeError:
        return text


def normalize_contract_file_path(value: Any) -> str | None:
    """Apply the contract's ``file_path.normalize`` steps, in order.

    This is what the server does to a path it receives. Returns ``None`` when
    the value is not a string.
    """
    if not isinstance(value, str):
        return None
    text = value.strip(ASCII_WHITESPACE)
    text = _percent_decode_once(text)
    text = text.replace("\\", "/")
    text = _FILE_SCHEME_RE.sub("", text)
    text = _DRIVE_RE.sub("", text)
    text = text.lstrip("/")
    for prefix in _CI_WORKSPACE_PREFIXES:
        stripped = prefix.sub("", text, count=1)
        if stripped != text:
            text = stripped
            break
    return _REPEATED_SLASH_RE.sub("/", text)


def encode_upload_path(path: str) -> str:
    """Escape ``%`` so the server's single percent-decode gives ``path`` back."""
    return path.replace("%", "%25")


def file_path_problem(value: Any) -> str | None:
    """Why the server would store this path without a location, or None."""
    if value is None or value == "":
        return REASON_MISSING
    return _normalized_path_problem(
        normalize_contract_file_path(value), field_max_length("file_path", 500)
    )


def _normalized_path_problem(normalized: str | None, max_length: int) -> str | None:
    if normalized is None:
        return REASON_NOT_STRING
    if not normalized:
        return REASON_EMPTY
    if normalized.lower() in placeholder_paths():
        return REASON_PLACEHOLDER
    if _CONTROL_CHARACTER_RE.search(normalized):
        return REASON_CONTROL_CHARACTER
    segments = normalized.split("/")
    if "." in segments or ".." in segments:
        return REASON_DOT_SEGMENT
    if "" in segments:
        return REASON_EMPTY_SEGMENT
    if len(normalized) > max_length:
        return REASON_TOO_LONG
    return None


def _looks_absolute(text: str) -> bool:
    return (
        text.startswith(("/", "\\"))
        or bool(_ABSOLUTE_DRIVE_RE.match(text))
        or text[:5].lower() == "file:"
    )


def _local_path(text: str) -> str:
    if text[:5].lower() == "file:":
        rest = _percent_decode_once(text[5:]).lstrip("/")
        return rest if _ABSOLUTE_DRIVE_RE.match(rest) else "/" + rest
    return text


def _relative_inside(path: str, base_dir: str) -> str | None:
    """``path`` relative to ``base_dir``, or None when it is outside it."""
    try:
        rel = os.path.relpath(path, base_dir)
    except ValueError:  # another drive on Windows
        return None
    rel = rel.replace("\\", "/")
    if rel == ".." or rel.startswith("../") or os.path.isabs(rel):
        return None
    return rel


def _inside_base(local: str, base_dir: str | None) -> str | None:
    if not base_dir:
        return None
    rel = _relative_inside(local, base_dir)
    if rel is None:
        # A symlinked temp or home folder (/var vs /private/var) can make the
        # same file look outside the repository; compare real paths too.
        try:
            rel = _relative_inside(os.path.realpath(local), os.path.realpath(base_dir))
        except (OSError, ValueError):
            rel = None
    return rel


def _is_directory(
    base_dir: str | None, path: str, cache: dict[str, bool] | None
) -> bool:
    if not base_dir:
        return False
    if cache is not None and path in cache:
        return cache[path]
    try:
        result = os.path.isdir(os.path.join(base_dir, path))
    except (OSError, ValueError):
        result = False
    if cache is not None:
        cache[path] = result
    return result


def resolve_upload_location(
    finding: dict[str, Any],
    base_dir: str | None,
    root: str | None,
    *,
    allow_directory: bool = False,
    isdir_cache: dict[str, bool] | None = None,
) -> str | None:
    """The project-relative path to send, or None for "no location".

    Never an absolute machine path and never a path that climbs out of the
    repository with ``..``.
    """
    raw = finding.get("file_path")
    if not isinstance(raw, str):
        return None
    text = raw.strip(ASCII_WHITESPACE)
    if not text or text.lower() in placeholder_paths():
        return None
    if _looks_absolute(text):
        text = _inside_base(_local_path(text), base_dir) or ""
    elif text.startswith(".."):
        # Relative to the repository but outside it; the analyzer's absolute
        # path can still place it (for example a symlinked checkout).
        absolute = finding.get("file")
        if isinstance(absolute, str) and os.path.isabs(absolute):
            text = _inside_base(absolute, base_dir) or ""
    text = text.replace("\\", "/")
    if not text:
        return None
    path = posixpath.normpath(text)
    if path in (".", "..") or path.startswith("../") or path.startswith("/"):
        return None
    if _normalized_path_problem(
        normalize_contract_file_path(encode_upload_path(path)),
        field_max_length("file_path", 500),
    ):
        return None
    if root not in (None, ".") and path == root:
        return None  # a project folder is not a file
    if not allow_directory and _is_directory(base_dir, path, isdir_cache):
        return None  # nor is any other folder
    return path


def upload_location_uri(raw: Any, base_dir: str | os.PathLike | None) -> str | None:
    """Path for a secondary location (related location, flow step) in an upload.

    Same rules as a finding's own path; None means drop the location.
    """
    if not isinstance(raw, str):
        return None
    base = os.fspath(base_dir) if base_dir is not None else None
    location = resolve_upload_location({"file_path": raw, "file": raw}, base, None)
    return encode_upload_path(location) if location else None
