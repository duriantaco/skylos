"""Optional imports in a source snapshot cannot abort command detection."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


@pytest.mark.parametrize(
    "handler", ["except ImportError:", "except:", "except ImportError as error:"]
)
@pytest.mark.parametrize("companion", [False, True], ids=["same-file", "companion"])
@pytest.mark.parametrize("sink", ["os.system", "subprocess.run"])
def test_snapshot_exception_handlers_preserve_native_command_findings(
    tmp_path, monkeypatch, capsys, handler, companion, sink
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    optional = f"try:\n    import optional_module\n{handler}\n    pass\n"
    source = f"import {sink.split('.')[0]}\n"
    if companion:
        write_fixture(root, "optional_support.py", optional)
    else:
        source += optional
    source += "def run(user):\n"
    line = len(source.splitlines()) + 1
    keywords = ", shell=True" if sink == "subprocess.run" else ""
    source += f'    {sink}("echo " + user{keywords})\n'
    path = write_fixture(root, "app.py", source)

    raw = [row for row in scan_ctx(root, [path]) if row["rule_id"] == "SKY-D212"]
    raw_stderr = capsys.readouterr().err
    report = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    native_stderr = capsys.readouterr().err

    assert not raw_stderr
    assert not native_stderr
    assert not report.get("analysis_errors")
    assert report.get("analysis_summary", {}).get("analysis_error_count", 0) == 0
    listed = [row for row in report.get("danger", []) if row["rule_id"] == "SKY-D212"]
    for findings in (raw, listed):
        assert [(row["line"], row["severity"]) for row in findings] == [
            (line, "CRITICAL")
        ]
        assert all(row["file"] == str(path) for row in findings)
    assert all(
        row["listing"]["listed"] and row["metadata"]["security_trace"] for row in listed
    )
    assert (
        check_gate(
            report,
            {"gate": {"max_critical": 0, "max_high": 1000, "max_security": 1000}},
        )[0]
        is False
    )
