"""Select the database dialect for each SQL file without connecting to a database."""

from __future__ import annotations

from pathlib import Path

import tomllib

from skylos.core.safe_cache_io import read_project_text_no_symlink, strip_utf8_bom

POSTGRES_DUMP_BYTE_LIMIT = 16_000_000

_ALIASES = {"postgres": "postgresql", "sqlserver": "tsql", "mssql": "tsql"}


def _dialect(value):
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    name = value.strip().lower()
    return _ALIASES.get(name, name)


def _migration_dialect(path: Path, root: Path):
    for directory in path.parents:
        if not directory.is_relative_to(root):
            break
        if directory.name != "migrations":
            continue
        lock = directory / "migration_lock.toml"
        if lock.is_symlink():
            return "unknown"
        if not lock.exists():
            continue
        source = read_project_text_no_symlink(root, lock, max_bytes=64_000)
        if source is None:
            return "unknown"
        try:
            return _dialect(tomllib.loads(source).get("provider"))
        except ValueError:
            return "unknown"
    return None


def analyze_sql_file(file, cfg, project_root):
    path = Path(file).absolute()
    root = Path(project_root).absolute() if project_root else path.parent
    if root.is_file():
        root = root.parent
    section = cfg.get("sql", {})
    configured = (
        _dialect(section["dialect"])
        if isinstance(section, dict) and "dialect" in section
        else None
    )
    provider = _migration_dialect(path, root)
    dialect = configured or provider or "unknown"
    coverage = {"file": str(file), "dialect": dialect}
    if configured and provider and configured != provider:
        return [], {**coverage, "status": "conflicting_dialect"}
    if dialect == "unknown":
        return [], {**coverage, "status": "unknown_dialect"}
    if dialect != "postgresql":
        return [], {**coverage, "status": "unsupported_dialect"}

    source = read_project_text_no_symlink(
        root, path, max_bytes=POSTGRES_DUMP_BYTE_LIMIT, encoding="utf-8", newline=""
    )
    if source is None:
        return [], {
            **coverage,
            "status": "unparsed",
            "reason": "Unreadable UTF-8 SQL or file exceeds the 16 MB input limit.",
        }
    from skylos.visitors.languages.postgresql import scan_postgresql

    rows, error = scan_postgresql(strip_utf8_bom(source), str(file))
    if error:
        return [], {**coverage, "status": "unparsed", "reason": error}
    return rows, {**coverage, "status": "checked"}
