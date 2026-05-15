from __future__ import annotations

from pathlib import Path


def normalize_repo_subpath(value) -> str | None:
    if value is None:
        return ""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or raw in {".", "./"}:
        return ""

    normalized = raw.replace("\\", "/").strip("/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    if not normalized:
        return ""
    if len(normalized) > 300:
        return None

    segments = normalized.split("/")
    for segment in segments:
        if not segment or segment in {".", ".."}:
            return None
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in segment):
            return None
    return "/".join(segments)


def repo_subpath_for_project(project_path, git_root=None) -> str:
    if not project_path:
        return ""

    root = Path(git_root).resolve() if git_root else None
    target = Path(project_path).resolve()
    if target.is_file():
        target = target.parent

    if not root:
        return ""

    try:
        rel = target.relative_to(root)
    except ValueError:
        return ""

    normalized = normalize_repo_subpath(rel.as_posix())
    return normalized or ""


def project_context_for_upload(project_path, git_root=None) -> dict[str, str]:
    return {"project_root": repo_subpath_for_project(project_path, git_root)}
