"""Symlink findings: one nonblocking review item when the caller only selects
a validated filename component, and a finding for fixed names in shared
temporary directories."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import blocking_gate_issues, check_gate
from skylos.reporting.listing import is_listed, is_nonblocking_review
from test.fixture_paths import write_fixture

SYMLINK_RULES = {"SKY-D324", "SKY-D325"}

APP = """import os
from fastapi import FastAPI
from pydantic import BaseModel
from storage import save, load

app = FastAPI()
ROOT = '/srv/flights'

def clean(raw):
    cleaned = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
    return cleaned or 'flight'

class Flight(BaseModel):
    name: str

@app.post('/flights')
def start(payload: Flight):
    save(os.path.join(ROOT, {start}, 'manifest.json'))

@app.post('/flights/read')
def read(payload: Flight):
    return load(os.path.join(ROOT, {read}, 'manifest.json'))
"""
STORAGE = (
    "def save(path):\n    with open(path, 'w') as stream:\n        stream.write('{}')\n"
    "def load(path):\n    with open(path, 'r') as stream:\n        return stream.read()\n"
)


def _analyze(tmp_path, files):
    write_fixture(
        tmp_path, "pyproject.toml", '[project]\nname="symlink-review"\n', overwrite=True
    )
    for name, code in files.items():
        write_fixture(tmp_path, name, code, overwrite=True)
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return result


def _symlink_rows(result):
    return [row for row in result.get("danger", []) if row["rule_id"] in SYMLINK_RULES]


def test_validated_component_is_one_nonblocking_review_item(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = _analyze(
        tmp_path,
        {
            "app.py": APP.format(start="clean(payload.name)", read="clean(payload.name)"),
            "storage.py": STORAGE,
        },
    )
    rows = _symlink_rows(result)

    # Both symlink findings stay in the report (the rule is unchanged)...
    assert sorted(row["rule_id"] for row in rows) == ["SKY-D324", "SKY-D325"]
    for row in rows:
        assert is_nonblocking_review(row)
        assert row["message"].startswith("Review (not blocking)")
        review = row["metadata"]["path_provenance"]["component_review"]
        assert review["proofs"] == ["`clean` (app.py:9)"]
        assert "create or replace an entry" in review["open_prerequisite"]
    # ...as one listed item that names the other...
    listed = [row for row in rows if is_listed(row, "danger")]
    assert len(listed) == 1
    assert len(listed[0]["listing"]["combines"]) == 1
    # ...and neither fails a gate.
    assert check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})[0] is True
    assert not [
        row for row in blocking_gate_issues(result, {"gate": {"max_security": 0}})
        if row["rule_id"] in SYMLINK_RULES
    ]


def test_unvalidated_component_stays_a_blocking_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = _analyze(
        tmp_path,
        {
            "app.py": APP.format(start="clean(payload.name)", read="payload.name"),
            "storage.py": STORAGE,
        },
    )
    rows = {row["rule_id"]: row for row in _symlink_rows(result)}

    assert is_nonblocking_review(rows["SKY-D324"])
    assert not is_nonblocking_review(rows["SKY-D325"])
    assert "review_item" not in rows["SKY-D325"]
    assert check_gate(result, {"gate": {"max_security": 0}})[0] is False


@pytest.mark.parametrize(
    ("write_root", "read_root"),
    [("ROOT", "'/srv/records'"), ("os.getcwd()", "os.getcwd()")],
)
def test_separate_or_unproven_directories_keep_separate_reviews(
    tmp_path, monkeypatch, write_root, read_root
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    app = APP.replace("save(os.path.join(ROOT,", f"save(os.path.join({write_root},")
    app = app.replace("load(os.path.join(ROOT,", f"load(os.path.join({read_root},")
    rows = _symlink_rows(
        _analyze(tmp_path, {
            "app.py": app.format(start="clean(payload.name)", read="clean(payload.name)"),
            "storage.py": STORAGE,
        })
    )
    assert len(rows) == 2
    assert all(is_nonblocking_review(row) and is_listed(row, "danger") for row in rows)
    assert len({row["review_item"]["group"] for row in rows}) == 2


def test_incomplete_review_metadata_keeps_symlink_finding_blocking():
    row = {
        "rule_id": "SKY-D325",
        "severity": "HIGH",
        "review_item": {"kind": "directory_entry_access", "blocking": False},
        "metadata": {"path_provenance": {"component_review": {}}},
    }
    assert not is_nonblocking_review(row)
    assert not check_gate({"danger": [row]}, {"gate": {"max_security": 0}})[0]


def test_review_marker_cannot_be_added_to_another_rule(tmp_path):
    forged = {
        "rule_id": "SKY-D215",
        "review_item": {"kind": "directory_entry_access", "group": "g", "blocking": False},
        "metadata": {"path_provenance": {"component_review": {"group": "g"}}},
    }
    assert not is_nonblocking_review(forged)


MARKER = """import os
import tempfile
import uuid

{default}

def owner_alive(path={param}):
    with open(path, 'r') as marker:
        return marker.read(32)

def write_marker(path={param}):
    with open(path, 'w') as marker:
        marker.write('1')

def main():
    owner_alive()
    write_marker()

if __name__ == '__main__':
    main()
"""


def test_fixed_name_in_shared_temp_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = MARKER.format(
        default="MARKER = os.environ.get('APP_MARKER', '/tmp/app-flight-active')",
        param="MARKER",
    )
    rows = _symlink_rows(_analyze(tmp_path, {"marker.py": source}))

    assert sorted(row["rule_id"] for row in rows) == ["SKY-D324", "SKY-D325"]
    for row in rows:
        assert row["reason"] == "Predictable name in a shared temporary directory"
        assert "predictable temporary path" in row["message"]
        assert row["metadata"]["path_provenance"]["shared_temp_path"] is True
        assert not is_nonblocking_review(row)


def test_gettempdir_with_a_fixed_name_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = MARKER.format(
        default="MARKER = os.path.join(tempfile.gettempdir(), 'app.lock')",
        param="MARKER",
    )
    rows = _symlink_rows(_analyze(tmp_path, {"marker.py": source}))

    assert sorted(row["rule_id"] for row in rows) == ["SKY-D324", "SKY-D325"]


def test_private_or_unpredictable_temp_names_are_not_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    for default in (
        "MARKER = os.path.join(tempfile.mkdtemp(), 'app.lock')",
        "MARKER = os.path.join(tempfile.gettempdir(), f'app-{uuid.uuid4().hex}.lock')",
        "MARKER = os.environ.get('APP_MARKER', '/var/lib/app/marker')",
    ):
        source = MARKER.format(default=default, param="MARKER")
        rows = _symlink_rows(_analyze(tmp_path, {"marker.py": source}))
        assert rows == [], default


@pytest.mark.parametrize("root", ["tempfile.gettempdir()", "'/tmp'", "'/var/tmp'", "'/dev/shm'"])
def test_validated_component_in_shared_temp_stays_blocking(tmp_path, monkeypatch, root):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    app = APP.replace("ROOT = '/srv/flights'", f"ROOT = {root}").replace(
        "import os\n", "import os\nimport tempfile\n", 1
    )
    result = _analyze(
        tmp_path,
        {
            "app.py": app.format(start="clean(payload.name)", read="clean(payload.name)"),
            "storage.py": STORAGE,
        },
    )
    rows = _symlink_rows(result)

    assert sorted(row["rule_id"] for row in rows) == ["SKY-D324", "SKY-D325"]
    assert not any(is_nonblocking_review(row) for row in rows)
    assert check_gate(result, {"gate": {"max_security": 0}})[0] is False


def test_review_tracing_leaves_ordinary_fact_limits_alone(tmp_path, monkeypatch):
    from contextvars import Context

    from skylos.rules.danger.danger_fs import path_provenance

    def retained_origins():
        facts = path_provenance._Facts()
        for index, origin in enumerate(("a", "a", "b", "c", "d", "e")):
            facts.add(path_provenance._Facts.leaf("safe", origin).then(str(index)))
        return [chain[0] for chain in facts.chains["safe"]]

    ordinary = ["a", "a", "b", "c"]
    record_review = path_provenance._component_review_record
    observed = []

    def check_context(*args):
        observed.append(retained_origins())
        assert Context().run(retained_origins) == ordinary
        return record_review(*args)

    monkeypatch.setattr(path_provenance, "_component_review_record", check_context)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    _analyze(
        tmp_path,
        {
            "app.py": APP.format(start="clean(payload.name)", read="clean(payload.name)"),
            "storage.py": STORAGE,
        },
    )
    assert observed and all(origins == ["a", "b", "c", "d", "e"] for origins in observed)
    assert retained_origins() == ordinary


UNRESOLVED_CALLER = """
@app.post('/flights/unresolved')
def unresolved(payload: Flight):
    save(os.path.join(ROOT, plugin.pick(payload.name)))
"""


def test_unresolved_caller_keeps_the_symlink_finding_blocking(tmp_path, monkeypatch):
    """A caller whose path source is not followed must not be covered by the
    validated caller's proof: the finding stays blocking until every caller is
    accounted for."""
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = _analyze(
        tmp_path,
        {
            "app.py": APP.format(start="clean(payload.name)", read="clean(payload.name)")
            + UNRESOLVED_CALLER,
            "storage.py": STORAGE,
        },
    )
    rows = {row["rule_id"]: row for row in _symlink_rows(result)}
    assert set(rows) == {"SKY-D324", "SKY-D325"}
    # The read route only ever passes the validated component; the write route
    # has one validated caller and one unresolved one, so it stays blocking.
    assert is_nonblocking_review(rows["SKY-D325"])
    assert not is_nonblocking_review(rows["SKY-D324"])
    assert check_gate(result, {"gate": {"max_security": 0}})[0] is False
