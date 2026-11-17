"""A recognized filter body is evidence of a check, not proof of safety."""

import ast

from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.rules.danger.danger_fs.path_provenance import resolve_helper_parameter_findings


FILTER = """def prepare(raw):
    cleaned = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
    return cleaned or 'flight'
"""
OPAQUE = """def background():
    pass
foreign.register(background)
"""


def _scan(tmp_path, *, helper=FILTER, opaque=OPAQUE, expression="prepare(payload.flightId)", extra=""):
    app = (
        "from pathlib import Path\nfrom fastapi import FastAPI\n"
        "from pydantic import BaseModel\nfrom storage import load, other\n"
        "app = FastAPI()\n"
        "class FlightRequest(BaseModel):\n    flightId: str\n"
        + helper + opaque
        + "@app.post('/read')\ndef view(payload: FlightRequest):\n"
        + "    return load(Path('/srv') / " + expression + " / 'manifest.json')\n"
        + extra
    )
    storage = (
        "def load(path):\n    return open(path).read()\n"
        "def other(path):\n    return open(path).read()\n"
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nname="uncertainty"\n')
    findings = []
    for name, text in {"app.py": app, "storage.py": storage}.items():
        path = tmp_path / name
        path.write_text(text)
        scan(ast.parse(text), path, findings)
    suppressed = []
    kept = resolve_helper_parameter_findings(
        findings, scan_path=tmp_path, project_root=tmp_path, suppressed=suppressed
    )
    return [row for row in kept if row["rule_id"] == "SKY-D215"], suppressed


def _assert_unverified_check(row):
    assert row["severity"] == "HIGH"
    metadata = row["metadata"]
    assert metadata["path_source"] == "resolved_caller"
    assert metadata["path_provenance"]["status"] == "untrusted"
    assert metadata["path_provenance"]["validation_uncertainty"]["status"] == "unverified"
    assert metadata["security_evidence"]["source"]
    assert metadata["security_evidence"]["guards_seen"]
    assert "native-string/runtime assumptions" in row["message"]
    assert "no containment check" not in row["message"]


def test_unverified_request_model_keeps_warning_and_acknowledges_filter(tmp_path):
    rows, _ = _scan(tmp_path)

    assert len(rows) == 1
    _assert_unverified_check(rows[0])


def test_reject_on_change_check_is_not_reported_as_absent(tmp_path):
    helper = FILTER + """def checked(raw):
    safe = prepare(raw)
    if safe != raw:
        raise ValueError('invalid')
    return raw
"""
    rows, _ = _scan(tmp_path, helper=helper, expression="checked(payload.flightId)")

    assert len(rows) == 1
    _assert_unverified_check(rows[0])


def test_missing_filter_has_no_validation_uncertainty_note(tmp_path):
    rows, _ = _scan(tmp_path, helper="def prepare(raw):\n    return raw.strip()\n")

    assert len(rows) == 1
    assert "validation_uncertainty" not in rows[0]["metadata"]["path_provenance"]
    assert not rows[0]["metadata"]["security_evidence"]["guards_seen"]


def test_known_unsafe_custom_string_caller_is_still_reported(tmp_path):
    extra = """class Raw(str):
    def __iter__(self):
        yield Raw('/')
    def isalnum(self):
        return True
view(FlightRequest.model_construct(flightId=Raw('input')))
"""
    rows, _ = _scan(tmp_path, opaque="", extra=extra)

    assert len(rows) == 1
    _assert_unverified_check(rows[0])


def test_proven_native_filter_remains_withheld(tmp_path):
    rows, suppressed = _scan(tmp_path, opaque="")

    assert not rows
    assert any(row["rule_id"] == "SKY-D215" for row in suppressed)


def test_unrelated_later_sink_does_not_inherit_the_note(tmp_path):
    extra = """@app.get('/unsafe/{raw}')
def unsafe(raw: str):
    return other(Path('/srv') / raw)
"""
    rows, _ = _scan(tmp_path, extra=extra)

    by_symbol = {row["symbol"]: row for row in rows}
    _assert_unverified_check(by_symbol["load"])
    assert "validation_uncertainty" not in by_symbol["other"]["metadata"]["path_provenance"]
    assert "filename check body is present" not in by_symbol["other"]["message"]
