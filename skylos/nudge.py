import os
from pathlib import Path


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

    toml_path = Path(project_root) / "pyproject.toml"
    if not toml_path.exists():
        return True

    try:
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return True

        with open(toml_path, "rb") as f:
            data = tomllib.load(f)

        return data.get("tool", {}).get("skylos", {}).get("nudges", True)
    except Exception:
        return True


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
