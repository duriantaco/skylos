from __future__ import annotations

from pathlib import Path


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
