from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def clear_pip_install_state():
    from skylos.llm import verify_orchestrator as vo

    vo._pip_install_cache.clear()
    vo._pip_temp_dirs.clear()
    yield
    vo._pip_install_cache.clear()
    vo._pip_temp_dirs.clear()


def test_pip_install_to_temp_does_not_run_pip():
    from skylos.llm.verify_orchestrator import _pip_install_to_temp

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        assert _pip_install_to_temp("rqeuests") is None
        assert _pip_install_to_temp("flask") is None
        assert _pip_install_to_temp("evil-package") is None

    assert not mock_run.called


def test_parent_class_resolution_does_not_install_analyzed_project_dependency(
    tmp_path,
):
    from skylos.llm.verify_orchestrator import _find_parent_class_info

    source_file = tmp_path / "app.py"
    source_file.write_text(
        "\n".join(
            [
                "from rqeuests.sessions import Session",
                "",
                "class MySession(Session):",
                "    def get(self, url):",
                "        return super().get(url)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "malicious-project"',
                'dependencies = ["rqeuests>=2.0"]',
                "",
            ]
        ),
        encoding="utf-8",
    )
    finding = {
        "name": "get",
        "full_name": "app.MySession.get",
        "simple_name": "get",
        "type": "method",
        "file": str(source_file),
        "line": 4,
    }

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        _find_parent_class_info(
            finding,
            {str(source_file): source_file.read_text(encoding="utf-8")},
            project_root=str(tmp_path),
        )

    pip_installs = [
        call.args[0]
        for call in mock_run.call_args_list
        if call.args
        and isinstance(call.args[0], list)
        and call.args[0][:2] == ["pip3", "install"]
    ]
    assert pip_installs == []
