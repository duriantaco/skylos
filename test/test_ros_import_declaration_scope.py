import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep

AMENT_PACKAGE = (
    '<package format="3"><name>robot_driver</name>'
    "<buildtool_depend>ament_cmake</buildtool_depend>"
    "<exec_depend>rclpy</exec_depend></package>"
)
LAUNCH_FILE = (
    "from launch import LaunchDescription\n\n\n"
    "def generate_launch_description():\n"
    "    return LaunchDescription([])\n"
)
PYPROJECT = '[project]\nname = "robot-tools"\ndependencies = []\n'


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        text, encoding="utf-8"
    )
    return path


def _stub_registry(monkeypatch, statuses):
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: set())
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})
    monkeypatch.setattr(
        dep,
        "_check_pypi_status",
        lambda name, _cache: statuses.get(name, "missing"),
    )


def _scan(repo, files, added):
    full = dep.scan_python_dependency_hallucinations(repo, files)
    diff, _ = dep.scan_diff_added_imports(repo, added)
    return (
        sorted((f["rule_id"], f["symbol"], f["file"].rsplit("/", 1)[-1]) for f in full),
        sorted((f["rule_id"], f["symbol"], f["file"].rsplit("/", 1)[-1]) for f in diff),
    )


def test_ros_imports_without_any_ros_package_are_not_undeclared(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    names = (
        "rclpy",
        "nav_msgs",
        "sensor_msgs_py",
        "ament_index_python",
        "requests",
        "fabricated_robot_package",
    )
    source = _write(
        repo / "tools" / "probe.py", "".join(f"import {name}\n" for name in names)
    )
    _stub_registry(monkeypatch, {"requests": "exists"})

    full, diff = _scan(
        repo,
        [source],
        [("tools/probe.py", line, name) for line, name in enumerate(names, start=1)],
    )

    expected = [
        (dep.RULE_ID_HALLUCINATION, "fabricated_robot_package", "probe.py"),
        (dep.RULE_ID_UNDECLARED, "requests", "probe.py"),
    ]
    assert full == expected
    assert diff == expected


@pytest.mark.parametrize(
    ("manifest", "content", "scan_root"),
    [
        ("ws/hardware/drivers/lidar/package.xml", AMENT_PACKAGE, "ws"),
        (
            "ws/legacy/package.xml",
            '<package format="2"><name>legacy</name>'
            "<buildtool_depend>catkin</buildtool_depend></package>",
            "ws",
        ),
        (
            "ws/php/package.xml",
            '<package version="2.0" xmlns="http://pear.php.net/dtd/package-2.0">'
            "<name>tool</name></package>",
            "ws",
        ),
        ("ws/package.xml", AMENT_PACKAGE, "ws/tools_repo"),
    ],
    ids=["unrelated-ament-package", "ros1-package", "other-xml", "scan-root-parent"],
)
def test_any_package_manifest_keeps_ros_imports_reportable(
    monkeypatch, tmp_path, manifest, content, scan_root
):
    _write(tmp_path / manifest, content)
    repo = tmp_path / scan_root
    _write(repo / "pyproject.toml", PYPROJECT)
    source = _write(repo / "tools" / "probe.py", "import rclpy\n")
    _stub_registry(monkeypatch, {})

    full, diff = _scan(repo, [source], [("tools/probe.py", 1, "rclpy")])

    expected = [(dep.RULE_ID_UNDECLARED, "rclpy", "probe.py")]
    assert full == expected
    assert diff == expected


@pytest.mark.parametrize("unseen", ["entry-bound", "symlinked-directory"])
def test_unseen_repository_content_keeps_ros_imports_reportable(
    monkeypatch, tmp_path, unseen
):
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    source = _write(repo / "tools" / "probe.py", "import rclpy\n")
    if unseen == "entry-bound":
        for index in range(4):
            _write(repo / f"data{index}" / "sample.txt", "")
        monkeypatch.setattr(dep, "MAX_ROS_ABSENCE_ENTRIES", 3, raising=False)
    else:
        outside = tmp_path / "outside"
        _write(outside / "robot_driver" / "package.xml", AMENT_PACKAGE)
        try:
            (repo / "src").symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are unavailable")
    _stub_registry(monkeypatch, {})

    full, diff = _scan(repo, [source], [("tools/probe.py", 1, "rclpy")])

    expected = [(dep.RULE_ID_UNDECLARED, "rclpy", "probe.py")]
    assert full == expected
    assert diff == expected


def test_launch_entrypoint_identifies_the_ros_launch_package(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    launch_file = _write(repo / "bringup.launch.py", LAUNCH_FILE)
    without_entrypoint = _write(
        repo / "tool.launch.py", "from launch import LaunchDescription\n"
    )
    ordinary_file = _write(repo / "probe.py", LAUNCH_FILE)
    with_parameter = _write(
        repo / "param.launch.py",
        LAUNCH_FILE.replace(
            "generate_launch_description()", "generate_launch_description(context)"
        ),
    )
    _stub_registry(monkeypatch, {"launch": "exists"})
    files = [launch_file, without_entrypoint, ordinary_file, with_parameter]
    added = [(path.name, 1, "launch") for path in files]

    full, diff = _scan(repo, files, added)

    expected = [
        (dep.RULE_ID_UNDECLARED, "launch", "param.launch.py"),
        (dep.RULE_ID_UNDECLARED, "launch", "probe.py"),
        (dep.RULE_ID_UNDECLARED, "launch", "tool.launch.py"),
    ]
    assert full == expected
    assert diff == expected

    _write(repo / "ros2" / "robot_driver" / "package.xml", AMENT_PACKAGE)
    findings = dep.scan_python_dependency_hallucinations(repo, [launch_file])
    assert [(f["rule_id"], f["symbol"]) for f in findings] == [
        (dep.RULE_ID_UNDECLARED, "launch")
    ]
    assert "Undeclared ROS import 'launch'" in findings[0]["message"]
