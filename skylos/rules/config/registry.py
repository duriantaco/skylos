from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from skylos.core.git_context import GitContext
from skylos.rules.config.cicd.github_actions import (
    scan_github_actions,
    scan_github_actions_file,
)
from skylos.rules.config.cicd.gitlab_ci import scan_gitlab_ci, scan_gitlab_ci_file
from skylos.rules.config.container.dockerfile import scan_dockerfiles
from skylos.rules.config.deployment.exposure import scan_deployment_exposure
from skylos.rules.config.edge.docker_compose import scan_docker_compose
from skylos.rules.config.edge.systemd import scan_systemd
from skylos.rules.config.gpu.compatibility import scan_gpu_compatibility


def _repository_ci_findings(
    root: str | Path,
    *,
    changed_files: set[str] | None,
    ignore: set[str] | None,
    analysis_errors: list[dict[str, Any]] | None = None,
    scan_paths: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Active worktree CI contracts also apply to a source-directory scan."""
    requested = Path(root)
    if requested.is_symlink() or not requested.is_dir():
        return []
    scope = requested.resolve()
    try:
        context = GitContext.from_path(scope)
        proof = context.run("rev-parse", "--show-toplevel")
    except (OSError, subprocess.SubprocessError):
        # Git proof is optional. Selected-directory checks must still run.
        return []
    if proof.returncode != 0 or not proof.stdout.strip():
        return []
    repository = Path(proof.stdout.strip()).resolve()
    if repository != context.root.resolve() or not scope.is_relative_to(repository):
        return []
    if scope == repository:
        return []  # The selected-root scanners already cover these files.
    # A common configuration directory does not prove that separate list
    # targets belong to its worktree (for example, nested repositories).
    if scan_paths is not None:
        for target in scan_paths:
            try:
                owner = GitContext.from_path(target)
                owner_proof = owner.run("rev-parse", "--show-toplevel")
            except (OSError, subprocess.SubprocessError):
                return []
            if (
                owner_proof.returncode != 0
                or not owner_proof.stdout.strip()
                or Path(owner_proof.stdout.strip()).resolve() != repository
                or owner.root.resolve() != repository
            ):
                return []
    selected = (
        None
        if changed_files is None
        else {Path(os.path.abspath(repository / path)) for path in changed_files}
    )
    candidates: list[tuple[Path, Any]] = []
    github = repository / ".github"
    workflows = github / "workflows"
    if not github.is_symlink() and not workflows.is_symlink() and workflows.is_dir():
        candidates.extend(
            (path, scan_github_actions_file)
            for path in sorted(workflows.iterdir())
            if path.suffix.lower() in {".yml", ".yaml"}
            and path.is_file()
            and not path.is_symlink()
        )
    gitlab = repository / ".gitlab-ci.yml"
    if gitlab.is_file() and not gitlab.is_symlink():
        candidates.append((gitlab, scan_gitlab_ci_file))

    findings: list[dict[str, Any]] = []
    for path, scanner in candidates:
        if path.is_relative_to(scope) or (selected is not None and path not in selected):
            continue
        if scanner is scan_github_actions_file:
            findings.extend(
                scanner(
                    path, root=repository, ignore=ignore,
                    analysis_errors=analysis_errors,
                )
            )
        else:
            findings.extend(scanner(path, root=repository, ignore=ignore))
    return findings


def scan_config_files(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
    analysis_errors: list[dict[str, Any]] | None = None,
    required_rules: str | list[str] | tuple[str, ...] | set[str] | None = None,
    scan_paths: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(
        scan_github_actions(
            root, changed_files=changed_files, ignore=ignore,
            analysis_errors=analysis_errors,
        )
    )
    findings.extend(scan_gitlab_ci(root, changed_files=changed_files, ignore=ignore))
    findings.extend(
        _repository_ci_findings(
            root, changed_files=changed_files, ignore=ignore,
            analysis_errors=analysis_errors, scan_paths=scan_paths,
        )
    )
    findings.extend(scan_dockerfiles(root, changed_files=changed_files, ignore=ignore))
    findings.extend(
        scan_docker_compose(root, changed_files=changed_files, ignore=ignore)
    )
    findings.extend(scan_systemd(root, changed_files=changed_files, ignore=ignore))
    findings.extend(
        scan_deployment_exposure(root, changed_files=changed_files, ignore=ignore)
    )
    selection_values = (
        [required_rules] if isinstance(required_rules, str) else required_rules or ()
    )
    normalized_selection = {
        str(rule_id).strip().upper() for rule_id in selection_values
    }
    findings.extend(
        scan_gpu_compatibility(
            root,
            changed_files=changed_files,
            ignore=ignore,
            require_contract=bool(
                normalized_selection
                & {"SKY-GPU000", "SKY-GPU001", "SKY-GPU002", "SKY-GPU003"}
            ),
        )
    )
    return findings
