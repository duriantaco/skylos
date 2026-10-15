from __future__ import annotations

import logging
import pathlib
import shlex
import subprocess
from contextlib import contextmanager
from pathlib import Path
from skylos.core.ci_env import github_or_ci_base_ref
from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
    worktree_safe_git_command,
)

_SAFE_ADDOPTS_FLAGS = frozenset(
    {
        "--json",
        "--github",
        "--summary",
        "--tree",
        "--verbose",
        "-v",
        "--strict",
        "--no-default-excludes",
        "--include-generated",
        "--secrets",
        "--danger",
        "--quality",
        "--expand-advice",
        "--ai-defects",
        "--sca",
        "--all",
        "-a",
        "--no-grep-verify",
        "--baseline",
        "--provenance",
        "--no-provenance",
    }
)

_SAFE_ADDOPTS_VALUE_OPTIONS = frozenset(
    {
        "--format",
        "--confidence",
        "-c",
        "--exclude",
        "--exclude-folder",
        "--include-folder",
        "--diff-base",
        "--diff",
        "--severity",
        "--category",
        "--select",
        "--file-filter",
        "--limit",
        "--provenance-base",
    }
)

_SAFE_ADDOPTS_CHOICES = {
    "--format": {"rich", "pretty", "json", "llm", "github", "gitlab", "concise"},
    "--severity": {"critical", "high", "medium", "low"},
}


@contextmanager
def quiet_analyzer_logs():
    """Hide the analyzer's INFO progress lines ("Analyzing 7 files...").

    They go through the root logger with timestamps; commands that print a
    report of their own keep only warnings and errors.
    """
    analyzer_logger = logging.getLogger("Skylos")
    previous_level = analyzer_logger.level
    analyzer_logger.setLevel(logging.WARNING)
    try:
        yield
    finally:
        analyzer_logger.setLevel(previous_level)


def _coerce_addopts(addopts) -> list[str]:
    if isinstance(addopts, str):
        return shlex.split(addopts)
    if isinstance(addopts, list):
        return [str(item) for item in addopts]
    return []


def _is_safe_addopt_value(option: str, value: str) -> bool:
    if value == "--":
        return False

    choices = _SAFE_ADDOPTS_CHOICES.get(option)
    if choices is not None and value not in choices:
        return False

    if option in {"--confidence", "-c"}:
        try:
            confidence = int(value)
        except ValueError:
            return False
        return 0 <= confidence <= 100

    if option == "--limit":
        try:
            limit = int(value)
        except ValueError:
            return False
        return limit >= 0

    return True


def sanitize_addopts(addopts) -> list[str]:
    """Return pyproject addopts that cannot select paths or execution sinks."""

    tokens = _coerce_addopts(addopts)
    sanitized: list[str] = []
    index = 0

    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            break

        if token in _SAFE_ADDOPTS_FLAGS:
            sanitized.append(token)
            index += 1
            continue

        if token in _SAFE_ADDOPTS_VALUE_OPTIONS:
            if index + 1 >= len(tokens):
                index += 1
                continue
            value = tokens[index + 1]
            if _is_safe_addopt_value(token, value):
                sanitized.extend([token, value])
            index += 2
            continue

        if token.startswith("--") and "=" in token:
            option, value = token.split("=", 1)
            if option in _SAFE_ADDOPTS_VALUE_OPTIONS and _is_safe_addopt_value(
                option, value
            ):
                sanitized.append(token)
            index += 1
            continue

        index += 1

    return sanitized


def get_git_changed_files(
    root_path,
    base_ref=None,
    *,
    strict_base=False,
    include_deleted=False,
):
    supported_exts = {
        ".py",
        ".pyi",
        ".pyw",
        ".go",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".java",
        ".cpp",
        ".cc",
        ".cxx",
        ".hpp",
        ".hh",
        ".hxx",
        ".cs",
        ".kt",
        ".kts",
        ".php",
        ".rs",
        ".dart",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
    }

    def _collect_supported(output, repo_root):
        files = []
        seen = set()
        for line in output.splitlines():
            full_path = pathlib.Path(repo_root) / line
            if (
                pathlib.Path(line).name != ".env"
                and not pathlib.Path(line).name.startswith(".env.")
                and pathlib.Path(line).suffix.lower() not in supported_exts
            ):
                continue
            if (full_path.exists() or include_deleted) and full_path not in seen:
                files.append(full_path)
                seen.add(full_path)
        return files

    def _safe_diff(args, root, timeout):
        # Worktree diffs run the repository's clean filters; neutralize every
        # configured filter/diff driver or refuse (a refusal raises so the
        # strict-base path surfaces it).
        cmd = worktree_safe_git_command(args, root)
        if cmd is None:
            raise ValueError(
                "the repository configures Git content filters that could "
                "not be inspected safely"
            )
        return subprocess.check_output(
            cmd,
            cwd=root,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=read_only_git_environment(),
        ).decode("utf-8")

    try:
        repo_root = pathlib.Path(
            subprocess.check_output(
                read_only_git_command(["rev-parse", "--show-toplevel"]),
                cwd=root_path,
                stderr=subprocess.DEVNULL,
                timeout=10,
                env=read_only_git_environment(),
            )
            .decode("utf-8")
            .strip()
        )
        if base_ref:
            try:
                output = _safe_diff(
                    ["diff", "--name-only", f"{base_ref}...HEAD"], repo_root, 30
                )
                return _collect_supported(output, repo_root)
            except Exception as exc:
                if strict_base:
                    message = f"Unable to diff against base ref {base_ref}"
                    raise ValueError(message) from exc
                return []

        output = _safe_diff(["diff", "--name-only", "HEAD"], repo_root, 30)
        try:
            untracked_output = subprocess.check_output(
                read_only_git_command(["ls-files", "--others", "--exclude-standard"]),
                cwd=repo_root,
                stderr=subprocess.DEVNULL,
                timeout=30,
                env=read_only_git_environment(),
            ).decode("utf-8")
        except Exception:
            untracked_output = ""

        base_ref = github_or_ci_base_ref()
        if base_ref:
            diff_args = ["diff", "--name-only", f"origin/{base_ref}...HEAD"]
        else:
            diff_args = ["diff", "--name-only", "origin/main...HEAD"]
        try:
            branch_output = _safe_diff(diff_args, repo_root, 30)
        except Exception:
            branch_output = ""
        return _collect_supported(
            f"{output}\n{untracked_output}\n{branch_output}",
            repo_root,
        )
    except Exception as exc:
        if strict_base:
            raise ValueError("Unable to discover git changed files") from exc
        return []


def estimate_cost(files):
    total_chars = 0
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            total_chars += len(content)
        except Exception:
            pass
    est_tokens = total_chars / 4
    est_cost_usd = (est_tokens / 1_000_000) * 2.50
    return est_tokens, est_cost_usd


def load_addopts(start_path: Path | None = None):
    """``addopts`` from the nearest config file that sets it (same discovery
    as ``load_config``: .skylos.toml, skylos.toml, pyproject.toml)."""
    from skylos.config import _find_config_layers, _load_toml_user_config

    current = (start_path or Path.cwd()).resolve()
    try:
        layers, _ = _find_config_layers(current)
    except (OSError, ValueError):
        return []
    for config_path in layers:
        try:
            user_cfg = _load_toml_user_config(config_path)
        except (OSError, ValueError):  # unreadable or invalid TOML
            continue
        if "addopts" in user_cfg:
            return sanitize_addopts(user_cfg.get("addopts", []))
    return []
