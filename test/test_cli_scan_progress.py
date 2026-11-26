import json
import sys
from io import StringIO
from pathlib import Path
from threading import Event

import pytest
from rich.console import Console

from skylos import cli
from skylos.ui import scan_progress_output as output


def test_redirected_human_report_keeps_updating_during_a_quiet_phase(monkeypatch):
    emitted = Event()

    class Log(StringIO):
        def flush(self):
            super().flush()
            if "Resolving references" in self.getvalue():
                emitted.set()

    stream = Log()
    monkeypatch.setattr(output, "_HEARTBEAT_SECONDS", 0.02)
    console = Console(file=StringIO(), force_terminal=False)
    with output.scan_progress_output(
        console, mode="auto", human=True, stream=stream
    ) as progress:
        progress.update(4, 11, Path("PHASE: mark refs"))
        assert emitted.wait(3)
    assert "4/11 refs" in stream.getvalue()
    assert "\x1b" not in stream.getvalue()


@pytest.mark.parametrize("mode", ["auto", "plain", "off"])
def test_json_progress_is_opt_in_and_only_on_stderr(
    tmp_path, monkeypatch, capsys, mode
):
    (tmp_path / "demo.py").write_text("print('demo')\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SKYLOS_NO_TELEMETRY", "1")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", ".", "--format", "json", "--no-provenance", "--progress", mode],
    )
    cli.main()
    stdout, stderr = capsys.readouterr()
    assert json.loads(stdout)["analysis_summary"]["total_files"] == 1
    assert ("stages done" in stderr) == (mode == "plain")
    assert "stages done" not in stdout
