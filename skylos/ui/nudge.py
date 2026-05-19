import os
from pathlib import Path
import stat

NUDGE_PYPROJECT_MAX_BYTES = 512 * 1024


def _is_ci():
    return any(
        os.getenv(v)
        for v in (
            "CI",
            "GITHUB_ACTIONS",
            "JENKINS_URL",
            "BUILD_NUMBER",
            "CIRCLECI",
            "GITLAB_CI",
            "TRAVIS",
            "TF_BUILD",
        )
    )


def _nudges_enabled(project_root=None):
    if project_root is None:
        project_root = Path.cwd()

    try:
        toml_path = _safe_pyproject_path(project_root)
        if toml_path is None:
            return True

        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return True

        data = tomllib.loads(_read_pyproject_text(toml_path))

        return data.get("tool", {}).get("skylos", {}).get("nudges", True)
    except Exception:
        return True


def _safe_pyproject_path(project_root=None) -> Path | None:
    root = Path(project_root or Path.cwd()).resolve()
    toml_path = root / "pyproject.toml"
    try:
        path_stat = toml_path.lstat()
    except FileNotFoundError:
        return None

    if stat.S_ISLNK(path_stat.st_mode):
        raise ValueError(f"{toml_path}: pyproject.toml must not be a symlink")
    if not stat.S_ISREG(path_stat.st_mode):
        raise ValueError(f"{toml_path}: pyproject.toml must be a regular file")

    resolved = toml_path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"{toml_path}: pyproject.toml must stay inside project root"
        ) from exc

    return toml_path


def _read_pyproject_text(toml_path: Path) -> str:
    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow

    fd = os.open(  # skylos: ignore[SKY-D215] validated nudge config path with no-follow checks
        toml_path, flags
    )
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{toml_path}: pyproject.toml must be a regular file")
        if file_stat.st_size > NUDGE_PYPROJECT_MAX_BYTES:
            raise ValueError(f"{toml_path}: pyproject.toml is too large")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(NUDGE_PYPROJECT_MAX_BYTES + 1)
        if len(data) > NUDGE_PYPROJECT_MAX_BYTES:
            raise ValueError(f"{toml_path}: pyproject.toml is too large")
    finally:
        if fd >= 0:
            os.close(fd)

    return data.decode("utf-8")


def pick_nudge(result, args, project_root=None):
    if getattr(args, "json", False):
        return None
    if getattr(args, "quiet", False):
        return None
    if _is_ci():
        return None
    if not _nudges_enabled(project_root):
        return None

    dead_code_count = sum(
        len(result.get(k, []) or [])
        for k in (
            "unused_functions",
            "unused_imports",
            "unused_variables",
            "unused_classes",
            "unused_parameters",
        )
    )
    danger_count = len(result.get("danger", []) or [])
    quality_count = len(result.get("quality", []) or [])
    secrets_count = len(result.get("secrets", []) or [])
    total = dead_code_count + danger_count + quality_count + secrets_count

    ran_all = getattr(args, "all_checks", False)
    ran_danger = getattr(args, "danger", False)
    ran_secrets = getattr(args, "secrets", False)
    ran_quality = getattr(args, "quality", False)

    if dead_code_count > 5:
        return "[dim]Verify with LLM:[/dim] [bold]skylos agent verify .[/bold]"

    if danger_count > 0 or secrets_count > 0:
        return "[dim]Check LLM defenses:[/dim] [bold]skylos defend .[/bold]"

    if not ran_all and not (ran_danger and ran_secrets and ran_quality):
        extras = []
        if not ran_danger:
            extras.append("security")
        if not ran_secrets:
            extras.append("secrets")
        if not ran_quality:
            extras.append("quality")
        return f"[dim]Add {' + '.join(extras)} scanning:[/dim] [bold]skylos . -a[/bold]"

    if quality_count > 10:
        return "[dim]Auto-remediate:[/dim] [bold]skylos agent remediate .[/bold]"

    if total == 0:
        return "[dim]Clean codebase! Share it:[/dim] [bold]skylos badge[/bold]"

    return None
