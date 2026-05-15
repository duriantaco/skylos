from pathlib import Path

from skylos.constants import SNIPPET_CONTEXT_LINES


__all__ = ["_resolve_snippet_path", "extract_snippet"]


def _resolve_snippet_path(file_abs, repo_root=None) -> Path | None:
    if not file_abs:
        return None
    try:
        candidate = Path(file_abs).resolve()
        if repo_root:
            root = Path(repo_root).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                return None
        if not candidate.is_file():
            return None
        return candidate
    except OSError:
        return None


def extract_snippet(
    file_abs,
    line_number,
    context=SNIPPET_CONTEXT_LINES,
    repo_root=None,
) -> str | None:
    safe_path = _resolve_snippet_path(file_abs, repo_root)
    if safe_path is None:
        return None
    try:
        lines = safe_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])
    except (OSError, UnicodeDecodeError):
        return None
