"""ROS launch loader roots need file-role and import/return evidence."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze


def _unused(tmp_path, source, *, name="bringup.launch.py", extra_files=None):
    (tmp_path / name).write_text(textwrap.dedent(source))
    for relative, contents in (extra_files or {}).items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    result = json.loads(analyze(str(tmp_path), conf=60, grep_cache=False, grep_verify=False, enable_dependency_hallucinations=False))
    assert not result.get("analysis_errors")
    return {item["name"] for item in result.get("unused_functions", [])}


@pytest.mark.parametrize("import_line, constructor", [
    ("from launch import LaunchDescription", "LaunchDescription"),
    ("from launch import LaunchDescription as Description", "Description"),
    ("import launch as ros", "ros.LaunchDescription"),
])
def test_ros_loader_is_root_but_stale_neighbor_stays_unused(tmp_path, import_line, constructor):
    unused = _unused(tmp_path, f"""
        {import_line}
        def live_helper():
            return []
        def generate_launch_description():
            return {constructor}(live_helper())
        def stale_neighbor():
            return []
    """)
    assert "generate_launch_description" not in unused
    assert "live_helper" not in unused
    assert "stale_neighbor" in unused


@pytest.mark.parametrize("source", [
    """
    def generate_launch_description():
        return []
    """,
    """
    from launch import LaunchDescription
    LaunchDescription = tuple
    def generate_launch_description():
        return LaunchDescription([])
    """,
    """
    import launch
    launch.LaunchDescription = tuple
    def generate_launch_description():
        return launch.LaunchDescription([])
    """,
    """
    from launch import LaunchDescription
    import importlib
    importlib.import_module("launch").LaunchDescription = tuple
    def generate_launch_description():
        return LaunchDescription([])
    """,
    """
    from launch import LaunchDescription
    mutate(LaunchDescription)
    def generate_launch_description():
        return LaunchDescription([])
    """,
    """
    from launch import LaunchDescription
    @unknown_decorator
    def generate_launch_description():
        return LaunchDescription([])
    """,
])
def test_names_and_replaced_contracts_are_not_ros_roots(tmp_path, source):
    assert "generate_launch_description" in _unused(tmp_path, source)


def test_same_name_in_ordinary_python_file_is_not_a_loader(tmp_path):
    assert "generate_launch_description" in _unused(tmp_path, """
        from launch import LaunchDescription
        def generate_launch_description():
            return LaunchDescription([])
    """, name="ordinary.py")


def test_local_launch_package_is_not_the_ros_framework(tmp_path):
    assert "generate_launch_description" in _unused(tmp_path, """
        from launch import LaunchDescription
        def generate_launch_description():
            return LaunchDescription([])
    """, extra_files={"launch.py": "LaunchDescription = list\n"})
