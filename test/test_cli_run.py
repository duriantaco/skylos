import os
import sys
import types
from unittest.mock import patch

import pytest
from rich.console import Console


class TestRunCommand:
    @patch("skylos.cli.load_config", return_value={})
    @patch("skylos.cli.parse_exclude_folders", return_value=("custom_folder",))
    def test_run_port_flag_overrides_env(
        self, mock_parse_exclude_folders, mock_load_config
    ):
        from skylos.cli import main

        seen = {}

        def capture_start_server(**kwargs):
            seen["port"] = os.environ.get("SKYLOS_PORT")
            seen["kwargs"] = kwargs

        fake_server = types.ModuleType("skylos.web.server")
        fake_server.start_server = capture_start_server

        with patch.dict(os.environ, {"SKYLOS_PORT": "6123"}, clear=False):
            with patch.dict(sys.modules, {"skylos.web.server": fake_server}):
                with patch.object(sys, "argv", ["skylos", "run", "--port", "5111"]):
                    main()

            assert os.environ["SKYLOS_PORT"] == "6123"

        assert seen["port"] == "5111"
        assert seen["kwargs"] == {"exclude_folders": ["custom_folder"]}
        mock_parse_exclude_folders.assert_called_once()
        mock_load_config.assert_called_once()

    def test_run_port_flag_requires_integer(self):
        from skylos.cli import main

        with patch.object(sys, "argv", ["skylos", "run", "--port", "abc"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1

    def test_run_port_flag_requires_value(self):
        from skylos.cli import main

        with patch.object(sys, "argv", ["skylos", "run", "--port"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1

    def test_run_command_warns_that_web_dashboard_is_deprecated(self):
        from skylos.commands.run_cmd import run_run_command

        seen = {}
        console = Console(record=True, width=200)

        def capture_start_server(**kwargs):
            seen["kwargs"] = kwargs

        run_run_command(
            [],
            console_factory=lambda: console,
            load_config_func=lambda _path: {},
            parse_exclude_folders_func=lambda **_kwargs: ("custom_folder",),
            start_server_loader=lambda: capture_start_server,
        )

        rendered = console.export_text()
        assert "`skylos run` is deprecated" in rendered
        assert "next major release" in rendered
        assert "skylos . -a" in rendered
        assert "skylos suite ." in rendered
        assert seen["kwargs"] == {"exclude_folders": ["custom_folder"]}
