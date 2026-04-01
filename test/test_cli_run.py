import os
import sys
import types
from unittest.mock import patch

import pytest


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

        fake_server = types.ModuleType("skylos.server")
        fake_server.start_server = capture_start_server

        with patch.dict(os.environ, {"SKYLOS_PORT": "6123"}, clear=False):
            with patch.dict(sys.modules, {"skylos.server": fake_server}):
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
