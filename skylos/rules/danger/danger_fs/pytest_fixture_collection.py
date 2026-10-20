"""Literal source-owned pytest collection commands; no shell execution."""

import re
import shlex

from skylos.core.safe_cache_io import read_project_text_no_symlink


def _pytest_commands(root):
    """Only direct shell-step pytest invocations from the repository root."""
    import yaml

    selected = set()
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return selected
    paths = sorted(workflow_dir.iterdir())
    if len(paths) > 128:
        return None
    for path in paths:
        if path.suffix not in {".yml", ".yaml"}:
            continue
        text = read_project_text_no_symlink(root, path, max_bytes=1_000_000)
        if text is None:
            return None
        document = yaml.safe_load(text)
        if not isinstance(document, dict):
            continue
        defaults = document.get("defaults", {}).get("run", {})
        jobs = document.get("jobs", {})
        if not isinstance(defaults, dict) or not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            job_defaults = job.get("defaults", {}).get("run", defaults)
            steps = job.get("steps", [])
            if (
                not isinstance(job_defaults, dict)
                or not isinstance(steps, list)
                or len(steps) > 2048
            ):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                command = step.get("run")
                workdir = step.get(
                    "working-directory", job_defaults.get("working-directory")
                )
                if not isinstance(command, str):
                    # CodSpeedHQ/action action.yml defines run as the command
                    # and working-directory as its cwd. Other action inputs
                    # have no such inferred execution contract.
                    action = step.get("uses", "")
                    if not isinstance(action, str) or not re.fullmatch(
                        r"CodSpeedHQ/action@[0-9a-fA-F]{40}", action
                    ):
                        continue
                    inputs = step.get("with", {})
                    if not isinstance(inputs, dict):
                        continue
                    command = inputs.get("run")
                    workdir = inputs.get("working-directory", ".")
                    if not isinstance(command, str):
                        continue
                if workdir is not None and workdir not in (".", "./"):
                    continue
                selected.update(_shell_pytest_files(root, command))
    return selected


def _shell_pytest_files(root, script):
    selected = set()
    lines = script.replace("\\\n", " ").splitlines()
    for line in lines:
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            words = list(lexer)
        except ValueError:
            return set()
        if not words:
            continue
        if any(
            word in {"cd", "pushd", "popd", ";", "&&", "||", "|", "&"} for word in words
        ):
            return set()
        if len(words) > 2 and words[:2] in (
            ["uv", "run"],
            ["poetry", "run"],
            ["pdm", "run"],
        ):
            words = words[2:]
        if (
            len(words) >= 3
            and re.fullmatch(r"python(?:3(?:\.\d+)?)?", words[0])
            and words[1:3] == ["-m", "pytest"]
        ):
            words = ["pytest", *words[3:]]
        if words[0] not in {"pytest", "py.test"}:
            continue
        for word in words[1:]:
            if word.startswith("-"):
                if word not in {
                    "-q",
                    "--quiet",
                    "-v",
                    "--verbose",
                    "-x",
                    "--exitfirst",
                    "-s",
                    "--codspeed",
                }:
                    return set()
                continue
            filename = word.split("::", 1)[0]
            candidate = root / filename
            if filename.endswith(".py") and candidate.is_file():
                selected.add(candidate.absolute())
    return selected
