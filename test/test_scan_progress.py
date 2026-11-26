from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from skylos.ui.scan_progress import ScanProgress


@pytest.mark.parametrize("width", [80, 120])
def test_terminal_scan_shows_two_rows_with_literal_file_name(width):
    output = StringIO()
    console = Console(file=output, width=width)
    progress = ScanProgress(console)
    progress.update(320, 500, Path("src/[red]a\n.py"))
    console.print(progress._render())

    stage, files = output.getvalue().splitlines()
    assert "Analyze files" in stage and "1/4 stages done" in stage
    assert "320/500 files" in files and "Completed src/[red]a?.py" in files


def test_single_file_total_and_phase_start_use_distinct_displays(monkeypatch):
    now = 100
    monkeypatch.setattr("skylos.ui.scan_progress.monotonic", lambda: now)
    progress = ScanProgress(Console(file=StringIO()))
    progress.update(0, 1, Path("PHASE: file analysis"))
    assert "0/1 files" in progress.status_text()
    progress.update(1, 1, Path("foo\x1b\r\u202efile.py"))
    assert "Completed foo???file.py" in progress.status_text()
    assert "1/4 stages done" in progress.status_text()
    progress.update(0, 1, Path("PHASE: mark refs"))
    assert "0/1 refs" in progress.status_text()
    progress.update(0, 1, Path("PHASE: dead-code liveness"))
    now += 32
    assert "2/4 stages done" in progress.status_text()
    assert "32s in phase · ETA unknown" in progress.status_text()
    assert "0/1" not in progress.status_text()
    progress.update(0, 1, Path("PHASE: building report"))
    assert "3/4 stages done" in progress.status_text()
    progress.reporting("Rendering findings")
    assert "Rendering findings" in progress.status_text()


def test_in_flight_files_and_last_completed_are_distinguishable(tmp_path):
    progress = ScanProgress(Console(file=StringIO()), tmp_path)
    progress(0, 20, Path("PHASE: file analysis"))
    a, b = (tmp_path / "src" / name for name in ("a.py", "b.py"))
    progress.file_started(a)
    assert "Analyzing src/a.py" in progress.status_text()
    progress.file_finished(a)
    progress(1, 20, a)
    assert "Completed src/a.py" in progress.status_text()

    running = [a, b]
    progress.parallel_activity(lambda: tuple(running))
    assert "Analyzing (2 active) src/a.py" in progress.status_text()
    running.remove(a)
    assert "Analyzing src/b.py" in progress.status_text()
    progress.parallel_activity(None)
    assert "Completed src/a.py" in progress.status_text()
    progress(0, 8, Path("PHASE: Reading Python modules"))
    progress.file_started(b)
    assert "Reading src/b.py" in progress.status_text()
    assert "0/8 modules" in progress.status_text()


def test_phase_eta_needs_sustained_progress_and_expires(monkeypatch):
    now = 100
    monkeypatch.setattr("skylos.ui.scan_progress.monotonic", lambda: now)
    progress = ScanProgress(Console(file=StringIO(), width=80))
    marker = Path("PHASE: framework callbacks")
    progress(0, 10, marker)
    for count, now in [(1, 102), (2, 103)]:
        progress(count, 10, marker)
        assert "ETA" not in progress.status_text()
    now = 106
    progress(3, 10, marker)
    assert "phase ETA ~0:14" in progress.status_text()
    progress.file_started(Path("many/long/directory/names/before/a/real/views.py"))
    with progress.console.capture() as capture:
        progress.console.print(progress._render())
    detail = capture.get().splitlines()[1]
    assert "Checking callbacks" in detail and "views.py" in detail
    assert "3/10 modules" in detail and "phase ETA" in detail
    now += 15
    assert "ETA" not in progress.status_text()
    assert "count unchanged for 15s" in progress.status_text()
    progress(0, 10, marker)
    assert "ETA" not in progress.status_text() and "15s" not in progress.status_text()
    progress(0, 1, Path("PHASE: framework entry points"))
    with progress.console.capture() as capture:
        progress.console.print(progress._render())
    assert capture.get().splitlines()[1].strip() == "Finding framework entry points"


def test_live_progress_cleans_up_when_scan_fails(monkeypatch):
    monkeypatch.setenv("TERM", "xterm-256color")
    output = StringIO()
    console = Console(file=output, width=80, force_terminal=True, force_interactive=True)
    with (
        pytest.raises(RuntimeError, match="scan failed"),
        ScanProgress(console) as progress,
    ):
        progress.update(1, 2, Path("mod.py"))
        raise RuntimeError("scan failed")
    console.print("Recovered")
    display = output.getvalue()
    assert "Discover files" in display
    assert "4/4 stages done" not in display
    assert "\x1b[?25h" in display
    assert display.endswith("Recovered\n")
