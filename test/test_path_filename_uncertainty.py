"""A recognized filter body is evidence of a check, not proof of safety."""

import ast

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.rules.danger.danger_fs.path_provenance import (
    resolve_helper_parameter_findings,
)
from test.fixture_paths import write_fixture

FILTER = """def prepare(raw):
    cleaned = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
    return cleaned or 'flight'
"""
# Opaque code may call ``background`` with any object, and ``background``
# hands that object to more opaque code, so no model write is ruled out.
OPAQUE = """def background(item):
    foreign.consume(item)
foreign.register(background)
"""


def _scan(
    tmp_path,
    *,
    helper=FILTER,
    opaque=OPAQUE,
    expression="prepare(payload.flightId)",
    extra="",
    model_fields="",
):
    app = (
        "from pathlib import Path\nfrom fastapi import FastAPI\n"
        "from pydantic import BaseModel, Field\nfrom storage import load, other\n"
        "DEFAULT_INTERVAL = 2.0\nRECORD = True\n"
        "app = FastAPI()\n"
        "class FlightRequest(BaseModel):\n    flightId: str\n"
        + model_fields
        + helper
        + opaque
        + "@app.post('/read')\ndef view(payload: FlightRequest):\n"
        + "    return load(Path('/srv') / "
        + expression
        + " / 'manifest.json')\n"
        + extra
    )
    storage = (
        "def load(path):\n    return open(path).read()\n"
        "def other(path):\n    return open(path).read()\n"
    )
    write_fixture(
        tmp_path,
        (tmp_path / "pyproject.toml").relative_to(tmp_path),
        '[project]\nname="uncertainty"\n',
        overwrite=True,
    )
    findings = []
    for name, text in {"app.py": app, "storage.py": storage}.items():
        path = tmp_path / name
        write_fixture(tmp_path, (path).relative_to(tmp_path), text, overwrite=True)
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
    assert (
        metadata["path_provenance"]["validation_uncertainty"]["status"] == "unverified"
    )
    assert metadata["security_evidence"]["source"]
    assert metadata["security_evidence"]["guards_seen"]
    assert "native-string/runtime assumptions" in row["message"]
    assert "no containment check" not in row["message"]


def test_unverified_request_model_keeps_warning_and_acknowledges_filter(tmp_path):
    rows, _ = _scan(tmp_path)

    assert len(rows) == 1
    _assert_unverified_check(rows[0])


def test_reject_on_change_check_is_not_reported_as_absent(tmp_path):
    helper = (
        FILTER
        + """def checked(raw):
    safe = prepare(raw)
    if safe != raw:
        raise ValueError('invalid')
    return raw
"""
    )
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


@pytest.mark.parametrize(
    "opaque",
    [
        # A sort key and a zero-argument callback cannot receive or rewrite a
        # model, so they no longer withhold the filter proof.
        "def ordered(items):\n    return sorted(items, key=lambda item: item.score)\n",
        "def background():\n    pass\nforeign.register(background)\n",
        "import threading\nclass Worker:\n    def loop(self, stop):\n        stop.wait()\n"
        "    def start(self):\n        stop = threading.Event()\n"
        "        threading.Thread(target=self.loop, args=(stop,)).start()\n",
    ],
)
def test_inert_escaping_functions_keep_the_filter_proof(tmp_path, opaque):
    rows, suppressed = _scan(tmp_path, opaque=opaque)

    assert not rows
    assert any(row["rule_id"] == "SKY-D215" for row in suppressed)


def test_unrelated_model_cycle_and_copy_keep_the_filter_proof(tmp_path):
    # A self-referencing local and ``model_copy`` of a different model used
    # to mark every model in the process as possibly rewritten.
    opaque = (
        "class Status(BaseModel):\n    state: str = 'idle'\n"
        "def walk(node):\n    while node:\n        node = node.parent\n    return node\n"
        "def status():\n    return Status().model_copy(update={'state': walk(None)})\n"
    )
    rows, suppressed = _scan(tmp_path, opaque=opaque)

    assert not rows
    assert any(row["rule_id"] == "SKY-D215" for row in suppressed)


def test_non_literal_default_of_another_field_keeps_the_filter_proof(tmp_path):
    rows, suppressed = _scan(
        tmp_path,
        opaque="",
        model_fields="    interval: float = Field(default=DEFAULT_INTERVAL, ge=0.5)\n"
        "    record: bool = RECORD\n",
    )

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
    assert (
        "validation_uncertainty"
        not in by_symbol["other"]["metadata"]["path_provenance"]
    )
    assert "filename check body is present" not in by_symbol["other"]["message"]


def test_dropping_filter_form_is_a_filename_proof(tmp_path):
    helper = """def prepare(raw):
    return ''.join(c for c in raw if c.isalnum() or c in '-_')
"""
    rows, suppressed = _scan(tmp_path, helper=helper, opaque="")

    assert not rows
    assert any(row["rule_id"] == "SKY-D215" for row in suppressed)


@pytest.mark.parametrize(
    "helper",
    [
        # Two conditions, a different element, or a dot in the allowed set
        # are not the proven form.
        "def prepare(raw):\n    return ''.join(c for c in raw if c.isalnum() if c)\n",
        "def prepare(raw):\n    return ''.join(c.upper() for c in raw if c.isalnum())\n",
        "def prepare(raw):\n    return ''.join(c for c in raw if c.isalnum() or c in '-_.')\n",
    ],
    ids=["two-conditions", "transformed-element", "dot-allowed"],
)
def test_dropping_filter_variants_outside_the_proof_stay_reported(tmp_path, helper):
    rows, _ = _scan(tmp_path, helper=helper, opaque="")

    assert len(rows) == 1
