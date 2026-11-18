from __future__ import annotations

import re
import subprocess
from pathlib import Path

from skylos.cloud.shadow_upload import _cloud_repository_identity
from skylos.core.git_safety import read_only_git_command, read_only_git_environment


def cloud_origin_identity(repo: str | Path = ".") -> str | None:
    """Read only the provider and repository path that Cloud can safely bind."""
    result = subprocess.run(
        read_only_git_command(["-C", str(repo), "remote", "get-url", "origin"]),
        capture_output=True, text=True, errors="replace", timeout=5,
        env=read_only_git_environment(), check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        identity = _cloud_repository_identity(result.stdout)
    except ValueError:
        identity = ""
    # Match only Cloud-supported paths. In particular, an scp-style path
    # with a query, local filesystem path or unsupported host never goes into
    # the browser query, terminal text, or server request logs.
    path_segment = r"[a-zA-Z0-9_.-]+"
    if re.fullmatch(rf"github\.com/{path_segment}/{path_segment}", identity):
        return identity
    if re.fullmatch(rf"gitlab\.com/(?:{path_segment}/)+{path_segment}", identity):
        return identity
    raise ValueError("Cloud repository linking supports GitHub and GitLab.com origins.")


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
