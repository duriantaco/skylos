"""Project-aware operator finalization never certifies a partial file scan."""

import pytest

from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


@pytest.mark.parametrize("complete", [False, True])
def test_operator_api_requires_complete_project_context(tmp_path, complete):
    if complete:
        write_fixture(tmp_path, "pyproject.toml", '[project]\nname="operators"\n')
    file = write_fixture(
        tmp_path, "worker.py", "import sys\nopen(sys.argv[1]).read()\n"
    )
    rows = [row for row in scan_ctx(tmp_path, [file]) if row["rule_id"] == "SKY-D215"]
    assert bool(rows) is not complete
    if rows:
        assert all(
            row["metadata"]["path_provenance"]["status"] == "unknown" for row in rows
        )


def test_operator_api_checks_callers_outside_selected_files(tmp_path):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="operators"\n')
    file = write_fixture(
        tmp_path, "worker.py", "import sys\nopen(sys.argv[1]).read()\n"
    )
    write_fixture(
        tmp_path,
        "routes.py",
        "import subprocess, sys\nfrom fastapi import FastAPI\napp=FastAPI()\n"
        "@app.post('/read')\ndef route(path: str):\n"
        "    subprocess.run([sys.executable, 'worker.py', path])\n",
    )
    rows = [row for row in scan_ctx(tmp_path, [file]) if row["rule_id"] == "SKY-D215"]
    assert rows
    assert all(
        row["metadata"]["path_provenance"]["status"] == "untrusted" for row in rows
    )
