import json
import subprocess
import sys
import textwrap
from io import StringIO

import pytest
from rich.console import Console

from skylos.commands import doctor_cmd
from skylos.core import fast


@pytest.mark.parametrize(
    "installed,expected",
    [("absent", False), ("legacy", False), ("incomplete", False), ("complete", True)],
)
def test_doctor_checks_usable_native_apis(installed, expected):
    # Isolate native imports from whichever extension the test environment has.
    script = textwrap.dedent(
        """
        import json
        import sys
        import types

        installed = sys.argv[1]
        sys.modules['skylos_fast'] = None
        sys.modules['skylos_rust'] = None
        if installed == 'legacy':
            sys.modules['skylos_rust'] = types.ModuleType('skylos_rust')
        elif installed in ('incomplete', 'complete'):
            native = types.ModuleType('skylos_fast')
            if installed == 'complete':
                for name in ('discover_files', 'detect_clone_pairs',
                             'compute_similarity', 'analyze_coupling', 'find_cycles'):
                    setattr(native, name, lambda *args: None)
            sys.modules['skylos_fast'] = native

        from skylos.commands.doctor_cmd import _rust_available
        print(json.dumps({'available': _rust_available()}))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script, installed],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == {"available": expected}


@pytest.fixture
def doctor_runtime(monkeypatch):
    monkeypatch.setattr(doctor_cmd, "_llm_available", lambda: False)
    monkeypatch.setattr(doctor_cmd, "_dart_available", lambda: True)
    monkeypatch.setattr(doctor_cmd, "_interactive_available", lambda: False)
    monkeypatch.setattr(doctor_cmd, "_ripgrep_available", lambda: True)
    monkeypatch.setattr(
        doctor_cmd, "_go_engine_status", lambda: {"status": "available"}
    )
    monkeypatch.setattr(doctor_cmd.platform, "python_version", lambda: "3.14.0")


@pytest.mark.parametrize("available", [False, True])
def test_doctor_json_reports_optional_native_backend(
    doctor_runtime, monkeypatch, capsys, available
):
    monkeypatch.setattr(fast, "FAST_AVAILABLE", available)

    assert doctor_cmd.run_doctor_command(["--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "ok"
    assert report["checks"]["rust_acceleration"] == {
        "status": "available" if available else "unavailable",
        "module": "skylos_fast",
        "optional": True,
        "build_url": doctor_cmd.RUST_ACCELERATION_BUILD_URL,
    }
    assert "skylos[fast]" not in json.dumps(report)


@pytest.mark.parametrize("available", [False, True])
def test_doctor_text_replaces_nonexistent_extra_hint(
    doctor_runtime, monkeypatch, available
):
    monkeypatch.setattr(fast, "FAST_AVAILABLE", available)
    output = StringIO()
    console = Console(file=output, width=240, color_system=None)
    monkeypatch.setattr(doctor_cmd, "Console", lambda: console)
    monkeypatch.setattr(doctor_cmd, "_print_cloud_status", lambda console: None)
    monkeypatch.setattr(doctor_cmd, "_print_local_status", lambda console: None)

    assert doctor_cmd.run_doctor_command() == 0
    printed = output.getvalue()

    assert "skylos[fast]" not in printed
    if available:
        assert "skylos_fast available (optional Rust acceleration)" in printed
        assert "Rust acceleration unavailable" not in printed
    else:
        assert (
            "Rust acceleration unavailable (optional; using Python fallbacks)"
            in printed
        )
        assert "Build from source:" in printed
        assert doctor_cmd.RUST_ACCELERATION_BUILD_URL in printed
