"""
PoC test: Verify that _pip_install_to_temp does NOT blindly run `pip3 install`
with arbitrary package names derived from analyzed project imports.

The vulnerability allows a malicious repository to cause Skylos to install
arbitrary pip packages (including typosquats with malicious setup.py) during
dead code verification. The package name comes from the analyzed project's
import statements and dependency declarations.

This test mocks subprocess.run to verify:
1. Before fix: _pip_install_to_temp would call pip3 install with any name
2. After fix: _pip_install_to_temp is removed/disabled, or validates names
"""

import re
import sys
import os
from unittest.mock import patch, MagicMock, call

import pytest


# Clear any cached state between tests
@pytest.fixture(autouse=True)
def clear_pip_cache():
    from skylos.llm import verify_orchestrator as vo
    vo._pip_install_cache.clear()
    vo._pip_temp_dirs.clear()
    yield
    vo._pip_install_cache.clear()
    vo._pip_temp_dirs.clear()


def test_pip_install_to_temp_rejects_arbitrary_packages():
    """_pip_install_to_temp should NOT execute pip install for arbitrary names."""
    from skylos.llm.verify_orchestrator import _pip_install_to_temp

    # Simulate a malicious package name that could come from a scanned project
    malicious_names = [
        "evil-package",
        "typosquat-requests",
        "rqeuests",  # common typosquat
        "flask",  # even legitimate-looking names shouldn't be pip-installed
        "my--evil; echo pwned",  # injection attempt
    ]

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        for name in malicious_names:
            result = _pip_install_to_temp(name)
            # After fix: function should return None without calling pip
            assert result is None, (
                f"_pip_install_to_temp({name!r}) should return None "
                f"(pip install should be disabled)"
            )

    # Verify pip3 was never invoked
    assert not mock_run.called, (
        "subprocess.run should never be called by _pip_install_to_temp — "
        "arbitrary pip installs from analyzed project data are unsafe"
    )


def test_find_parent_class_info_no_pip_install():
    """
    _find_parent_class_info should NOT trigger pip install for packages
    referenced in the analyzed project's imports/dependencies.
    """
    from skylos.llm.verify_orchestrator import _find_parent_class_info
    import tempfile, os

    # Create a fake project with a malicious dependency
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a pyproject.toml referencing a typosquat package
        pyproject = os.path.join(tmpdir, "pyproject.toml")
        with open(pyproject, "w") as f:
            f.write("""
[project]
name = "evil-project"
dependencies = ["rqeuests>=2.0"]
""")

        # Write a source file that imports from the typosquat
        src_file = os.path.join(tmpdir, "app.py")
        with open(src_file, "w") as f:
            f.write("""
from rqeuests.sessions import Session

class MySession(Session):
    def get(self, url):
        return super().get(url)
""")

        source_cache = {src_file: open(src_file).read()}
        finding = {
            "name": "get",
            "full_name": "app.MySession.get",
            "simple_name": "get",
            "type": "method",
            "file": src_file,
            "line": 5,
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="not found"
            )
            _find_parent_class_info(finding, source_cache, project_root=tmpdir)

            # Check that no pip install was executed
            for c in mock_run.call_args_list:
                args = c[0][0] if c[0] else c[1].get("args", [])
                if isinstance(args, list) and "pip3" in args and "install" in args:
                    pytest.fail(
                        f"pip3 install was called with args {args} — "
                        f"this is the vulnerability: arbitrary pip install "
                        f"from analyzed project data"
                    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
