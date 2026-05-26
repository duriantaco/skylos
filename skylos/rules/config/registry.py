from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.rules.config.cicd.github_actions import scan_github_actions
from skylos.rules.config.cicd.gitlab_ci import scan_gitlab_ci
from skylos.rules.config.edge.docker_compose import scan_docker_compose
from skylos.rules.config.edge.systemd import scan_systemd


def scan_config_files(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(
        scan_github_actions(root, changed_files=changed_files, ignore=ignore)
    )
    findings.extend(scan_gitlab_ci(root, changed_files=changed_files, ignore=ignore))
    findings.extend(
        scan_docker_compose(root, changed_files=changed_files, ignore=ignore)
    )
    findings.extend(scan_systemd(root, changed_files=changed_files, ignore=ignore))
    return findings
