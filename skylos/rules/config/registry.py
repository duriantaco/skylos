from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.rules.config.cicd.github_actions import scan_github_actions
from skylos.rules.config.cicd.gitlab_ci import scan_gitlab_ci
from skylos.rules.config.container.dockerfile import scan_dockerfiles
from skylos.rules.config.deployment.exposure import scan_deployment_exposure
from skylos.rules.config.edge.docker_compose import scan_docker_compose
from skylos.rules.config.edge.systemd import scan_systemd
from skylos.rules.config.gpu.compatibility import scan_gpu_compatibility


def scan_config_files(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
    required_rules: str | list[str] | tuple[str, ...] | set[str] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(
        scan_github_actions(root, changed_files=changed_files, ignore=ignore)
    )
    findings.extend(scan_gitlab_ci(root, changed_files=changed_files, ignore=ignore))
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
