import json

from skylos.analyzer import analyze
from skylos.rules.config import scan_config_files
from skylos.rules.config.edge.docker_compose import scan_docker_compose


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _write_risky_compose(path):
    path.write_text(
        """
services:
  camera:
    image: nvcr.io/nvidia/l4t-base:r35.4.1
    privileged: true
    runtime: nvidia
    network_mode: host
    devices:
      - /dev/video0:/dev/video0
    volumes:
      - /run/udev:/run/udev:ro
      - /var/run/docker.sock:/var/run/docker.sock
""".lstrip(),
        encoding="utf-8",
    )


def test_edge_compose_scanner_detects_privileged_device_runtime(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    _write_risky_compose(compose)

    findings = scan_docker_compose(tmp_path)

    assert {"SKY-D330", "SKY-D331", "SKY-D332"}.issubset(_rule_ids(findings))
    assert {
        "kind": "config",
        "domain": "edge",
        "provider": "docker_compose",
        "type": "container",
    }.items() <= findings[0].items()


def test_edge_compose_scanner_accepts_minimal_service(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text(
        """
services:
  api:
    image: ghcr.io/example/api@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
    ports:
      - "8080:8080"
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_docker_compose(tmp_path) == []


def test_edge_compose_changed_files_stay_under_scan_root(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    outside_compose = outside / "docker-compose.yml"
    _write_risky_compose(outside_compose)

    findings = scan_config_files(
        repo,
        changed_files={str(outside_compose), "../outside/docker-compose.yml"},
    )

    assert findings == []


def test_config_scanner_routes_single_edge_compose_file(tmp_path):
    compose = tmp_path / "compose.edge.yaml"
    _write_risky_compose(compose)

    findings = scan_config_files(compose)

    assert {"SKY-D330", "SKY-D331", "SKY-D332"}.issubset(_rule_ids(findings))


def test_edge_compose_ignore_suppresses_rule(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    _write_risky_compose(compose)

    findings = scan_config_files(compose, ignore={"SKY-D330"})

    assert "SKY-D330" not in _rule_ids(findings)
    assert {"SKY-D331", "SKY-D332"}.issubset(_rule_ids(findings))


def test_analyzer_reports_edge_compose_dangers_without_source_files(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    _write_risky_compose(compose)

    result = json.loads(analyze(str(tmp_path), enable_danger=True))

    assert "danger" in result
    assert {"SKY-D330", "SKY-D331", "SKY-D332"}.issubset(
        _rule_ids(result["danger"])
    )
    assert result["analysis_summary"]["danger_count"] == len(result["danger"])
