"""Execute the advisory workflow's diagnostics and exit-status contract offline."""

import json
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest
import yaml

from test.fixture_paths import write_fixture


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/skylos.yaml"


def _steps():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["scan"]


def _step(name):
    return next(item for item in _steps()["steps"] if item.get("name") == name)


@pytest.fixture(scope="module")
def installed_scanner(tmp_path_factory):
    """A real isolated interpreter with a controlled installed CLI provider."""
    root = tmp_path_factory.mktemp("trusted-self-scan")
    environment = root / "environment"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    python = environment / "bin/python"
    purelib = Path(
        subprocess.check_output(
            [
                str(python),
                "-I",
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            text=True,
        ).strip()
    )
    write_fixture(purelib, "skylos/__init__.py", "")
    write_fixture(purelib, "skylos/entry.py", """import faulthandler
import json
import os
import sys
from pathlib import Path

def main():
    from diagnostics_probe import dump_completed
    if not dump_completed.wait(timeout=5):
        raise RuntimeError("Python diagnostics thread did not dump its stack")
    Path(os.environ["SCAN_INVOCATION"]).write_text(json.dumps({
        "args": sys.argv[1:], "isolated": sys.flags.isolated, "provider": __file__,
    }))
    if os.environ["SCAN_WRITE_REPORT"] == "1":
        Path(os.environ["REPORT"]).write_text(json.dumps({"danger": [], "secrets": []}))
    raise SystemExit(int(os.environ["SCAN_STUB_STATUS"]))
""")
    # Observe the actual inline bootstrap's diagnostics, while keeping the real
    # faulthandler and threading calls rather than substituting dummy results.
    write_fixture(purelib, "watchdog_probe.py", """import faulthandler
import json
import os
import threading
from pathlib import Path

original_later = faulthandler.dump_traceback_later
def observed_later(delay, repeat=False, **kwargs):
    if os.environ.get("SCAN_TIMER_INVOCATION"):
        Path(os.environ["SCAN_TIMER_INVOCATION"]).write_text(json.dumps({"delay": delay, "repeat": repeat}))
    return original_later(delay, repeat=repeat, **kwargs)
faulthandler.dump_traceback_later = observed_later

original_start = threading.Thread.start
def observed_start(self):
    if os.environ.get("SCAN_PROGRESS_INVOCATION"):
        target = getattr(self, "_target", None)
        Path(os.environ["SCAN_PROGRESS_INVOCATION"]).write_text(json.dumps({
            "target": getattr(target, "__name__", None),
            "daemon": self.daemon,
            "faulthandler": faulthandler.is_enabled(),
        }))
    return original_start(self)
threading.Thread.start = observed_start
""")
    write_fixture(purelib, "diagnostics_probe.pth", "import diagnostics_probe\n")
    help_script = write_fixture(environment, "bin/skylos", """#!/bin/sh
if [ "$1" = "--help" ]; then
  if [ "$SCAN_AI_SUPPORTED" = "1" ]; then echo "--ai-defects"; else echo "--quality"; fi
  exit 0
fi
exit 99
""")
    help_script.chmod(0o755)
    timeout = write_fixture(
        root,
        "timeout",
        f"#!{sys.executable}\n"
        + """import json
import os
import subprocess
import sys
from pathlib import Path

Path(os.environ["SCAN_TIMEOUT_INVOCATION"]).write_text(json.dumps(sys.argv[1:]))
# This fault injector replaces only the external GNU timeout utility. It runs
# the workflow's actual isolated Python command, then models its exit status.
result = subprocess.run(sys.argv[4:], check=False)
override = os.environ.get("SCAN_TIMEOUT_STATUS")
raise SystemExit(int(override) if override else result.returncode)
"""
    )
    timeout.chmod(0o755)
    return root, environment, purelib


def _run_scan(tmp_path, installed_scanner, *, status=0, report=True, diff="", ai=True):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("workflow execution requires bash")
    root, environment, _purelib = installed_scanner
    (tmp_path / ".venv").symlink_to(environment, target_is_directory=True)
    write_fixture(tmp_path, "skylos/__init__.py", """import os
from pathlib import Path
Path(os.environ["SCAN_HOSTILE_IMPORT"]).write_text("checkout code imported")
raise RuntimeError("untrusted checkout import")
""")
    env = dict(os.environ)
    env.update(
        {
            "PATH": str(root) + os.pathsep + os.defpath,
            "PYTHONPATH": str(tmp_path),
            "REPORT": "scan report.json",
            "DIFF_BASE": diff,
            "GITHUB_OUTPUT": str(tmp_path / "outputs"),
            "SCAN_INVOCATION": str(tmp_path / "invocation.json"),
            "SCAN_TIMER_INVOCATION": str(tmp_path / "timer.json"),
            "SCAN_PROGRESS_INVOCATION": str(tmp_path / "progress.json"),
            "SCAN_TIMEOUT_INVOCATION": str(tmp_path / "timeout.json"),
            "SCAN_HOSTILE_IMPORT": str(tmp_path / "hostile-imported"),
            "SCAN_WRITE_REPORT": str(int(report)),
            "SCAN_AI_SUPPORTED": str(int(ai)),
            "SCAN_STUB_STATUS": str(status if status not in {124, 137} else 0),
            "SCAN_TIMEOUT_STATUS": str(status) if status in {124, 137} else "",
        }
    )
    result = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-eo",
            "pipefail",
            "-c",
            _step("Run Skylos")["run"],
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    return result, env


@pytest.mark.parametrize("status", [0, 1, 2, 124, 137, 139])
@pytest.mark.parametrize("report", [False, True])
def test_scan_and_final_status_survive_reports_and_watchdog_failures(
    tmp_path, installed_scanner, status, report
):
    result, env = _run_scan(tmp_path, installed_scanner, status=status, report=report)
    outputs = dict(
        line.split("=", 1) for line in (tmp_path / "outputs").read_text().splitlines()
    )
    assert outputs == {"REPORT": "scan report.json", "status": str(status)}
    assert result.returncode == (status if status and not report else 0), result.stderr
    assert (tmp_path / "scan report.json").is_file() is report
    final = subprocess.run(
        [
            shutil.which("bash"),
            "-eo",
            "pipefail",
            "-c",
            # Model the workflow's status != '0' step condition, then execute
            # its actual body. A successful scan never enters this step.
            'if [ "$SCAN_STATUS" != "0" ]; then\n'
            + _step("Preserve Skylos scan exit code")["run"]
            + "\nfi",
        ],
        env={**env, "SCAN_STATUS": outputs["status"]},
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert final.returncode == status
    if status == 0 and not report:
        # Success without JSON is still rejected by the actual report gate.
        script = (
            _step("Block high-risk security findings")["run"]
            .split("<<'PY'\n", 1)[1]
            .rsplit("\nPY", 1)[0]
        )
        gate = subprocess.run(
            [sys.executable, "-", env["REPORT"]],
            input=script,
            cwd=tmp_path,
            env=env,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        assert gate.returncode != 0


@pytest.mark.parametrize("diff", ["", "a" * 40])
@pytest.mark.parametrize("ai", [False, True])
def test_actual_isolated_entry_preserves_security_flags_and_diff_scope(
    tmp_path, installed_scanner, diff, ai
):
    result, _env = _run_scan(tmp_path, installed_scanner, diff=diff, ai=ai)
    assert result.returncode == 0, result.stderr
    invocation = json.loads((tmp_path / "invocation.json").read_text())
    expected = [".", "--quality", "--danger", "--secrets"]
    if ai:
        expected.append("--ai-defects")
    if diff:
        expected.extend(["--diff-base", diff, "--diff", diff])
    expected.extend(["--json", "-o", "scan report.json"])
    assert invocation["args"] == expected
    assert invocation["isolated"] == 1
    assert Path(invocation["provider"]).samefile(
        installed_scanner[2] / "skylos" / "entry.py"
    )
    assert not (tmp_path / "hostile-imported").exists()
    # faulthandler's watchdog reads other threads' frames without the GIL and
    # crashed CI scans with SIGSEGV; progress stacks come from a Python thread.
    assert not (tmp_path / "timer.json").exists()
    assert json.loads((tmp_path / "progress.json").read_text()) == {
        "target": "report_progress",
        "daemon": True,
        "faulthandler": True,
    }
    assert "Current thread" in result.stderr
    assert "diagnostics_probe.py" in result.stderr
    watchdog = json.loads((tmp_path / "timeout.json").read_text())
    assert watchdog[:6] == [
        "--signal=INT",
        "--kill-after=30s",
        "35m",
        ".venv/bin/python",
        "-I",
        "-c",
    ]
    assert "--preserve-status" not in watchdog


def test_isolation_control_rejects_the_same_checkout_import_without_I(
    tmp_path, installed_scanner
):
    result, env = _run_scan(tmp_path, installed_scanner)
    assert result.returncode == 0, result.stderr
    control = subprocess.run(
        [
            str(tmp_path / ".venv/bin/python"),
            "-c",
            "from skylos.entry import main; main()",
        ],
        env=env,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert control.returncode != 0
    assert (tmp_path / "hostile-imported").read_text() == "checkout code imported"


def test_workflow_reserves_time_for_report_processing_without_weakening_security():
    job = _steps()
    assert job["timeout-minutes"] == 45
    assert _step("Run Skylos")["timeout-minutes"] == 40
    assert _step("Run Skylos")["env"]["SKYLOS_GREP_BUDGET"] == "120"
    steps = job["steps"]
    preserve = _step("Preserve Skylos scan exit code")
    assert preserve["if"] == "always() && steps.scan.outputs.status != '0'"
    assert steps.index(_step("Upload report artifact")) < steps.index(preserve)
