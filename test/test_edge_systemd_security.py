import json

from skylos.analyzer import analyze
from skylos.rules.config import scan_config_files
from skylos.rules.config.edge.systemd import scan_systemd


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _write_risky_service(path):
    path.write_text(
        """
[Unit]
Description=Jetson camera service

[Service]
ExecStart=/home/jetson/camera/start.sh --device /dev/video0
User=root
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN
DeviceAllow=/dev/*
Restart=always

[Install]
WantedBy=multi-user.target
""".lstrip(),
        encoding="utf-8",
    )


def test_edge_systemd_scanner_detects_root_service_risks(tmp_path):
    service = tmp_path / "jetson-camera.service"
    _write_risky_service(service)

    findings = scan_systemd(tmp_path)

    assert {"SKY-D333", "SKY-D334", "SKY-D335", "SKY-D336"}.issubset(
        _rule_ids(findings)
    )
    assert {
        "kind": "config",
        "domain": "edge",
        "provider": "systemd",
        "type": "service",
    }.items() <= findings[0].items()


def test_edge_systemd_scanner_accepts_hardened_non_root_service(tmp_path):
    service = tmp_path / "camera.service"
    service.write_text(
        """
[Unit]
Description=Jetson camera service

[Service]
ExecStart=/usr/local/bin/camera-agent --device /dev/video0
User=camera
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_systemd(tmp_path) == []


def test_edge_systemd_scanner_accepts_restrictive_capability_bounding_set(tmp_path):
    service = tmp_path / "jetson-camera.service"
    service.write_text(
        """
[Unit]
Description=Jetson camera service

[Service]
ExecStart=/usr/local/bin/camera-agent --device /dev/video0
User=camera
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_systemd(tmp_path) == []


def test_edge_systemd_scanner_ignores_non_edge_service(tmp_path):
    service = tmp_path / "api.service"
    service.write_text(
        """
[Unit]
Description=API service

[Service]
ExecStart=/home/app/start.sh
User=root
""".lstrip(),
        encoding="utf-8",
    )

    assert scan_systemd(tmp_path) == []


def test_edge_systemd_changed_files_stay_under_scan_root(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    outside_service = outside / "jetson-camera.service"
    _write_risky_service(outside_service)

    findings = scan_config_files(
        repo,
        changed_files={str(outside_service), "../outside/jetson-camera.service"},
    )

    assert findings == []


def test_config_scanner_routes_single_edge_systemd_file(tmp_path):
    service = tmp_path / "jetson-camera.service"
    _write_risky_service(service)

    findings = scan_config_files(service)

    assert {"SKY-D333", "SKY-D334", "SKY-D335", "SKY-D336"}.issubset(
        _rule_ids(findings)
    )


def test_edge_systemd_ignore_suppresses_rule(tmp_path):
    service = tmp_path / "jetson-camera.service"
    _write_risky_service(service)

    findings = scan_config_files(service, ignore={"SKY-D333"})

    assert "SKY-D333" not in _rule_ids(findings)
    assert {"SKY-D334", "SKY-D335", "SKY-D336"}.issubset(_rule_ids(findings))


def test_analyzer_reports_edge_systemd_dangers_without_source_files(tmp_path):
    service = tmp_path / "jetson-camera.service"
    _write_risky_service(service)

    result = json.loads(analyze(str(tmp_path), enable_danger=True))

    assert "danger" in result
    assert {"SKY-D333", "SKY-D334", "SKY-D335", "SKY-D336"}.issubset(
        _rule_ids(result["danger"])
    )
    assert result["analysis_summary"]["danger_count"] == len(result["danger"])
