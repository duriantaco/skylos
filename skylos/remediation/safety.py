from __future__ import annotations

from pathlib import Path

PYTHON_SOURCE_SUFFIXES = (".py", ".pyi", ".pyw")


def python_rewrite_blocker(
    file_path: str | Path, *, root_path: str | Path | None = None
) -> str | None:
    """Why the Python dead-code rewriter cannot edit this file, or None."""
    if Path(file_path).suffix.lower() not in PYTHON_SOURCE_SUFFIXES:
        return "not a Python file; only Python files are edited"
    try:
        path = resolve_remediation_path(file_path, root_path=root_path)
        source = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        return str(exc)

    import libcst as cst

    try:
        cst.parse_module(source)
    except cst.ParserSyntaxError as exc:
        summary = str(exc).strip().splitlines()
        if summary:
            return f"the Python rewriter cannot parse it ({summary[0]})"
        return "the Python rewriter cannot parse it"
    return None


def resolve_remediation_path(
    file_path: str | Path, *, root_path: str | Path | None = None
) -> Path:
    path = Path(file_path)

    if root_path is None:
        if path.is_symlink():
            raise ValueError(f"Refusing to modify symlinked path: {path}")
        return path

    root = Path(root_path).resolve(strict=True)
    if root.is_file():
        root = root.parent

    candidate = path if path.is_absolute() else root / path
    if candidate.is_symlink():
        raise ValueError(f"Refusing to modify symlinked path: {candidate}")

    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"Refusing to modify non-file path: {candidate}")

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Refusing to modify path outside scan root: {candidate}"
        ) from exc

    return resolved
