"""Conditional HTTP evidence must preserve risk from ordinary Python callers."""

import pytest

from skylos.rules.danger.danger_fs.path_provenance import FILENAME_HTTP_GUARD
from test.test_path_filename_proof import FILTER, _project_scan


def _marked(rows):
    return [
        any(
            FILENAME_HTTP_GUARD in step
            for key, chains in row["metadata"]["path_provenance"].items()
            if key in {"untrusted", "guarded", "unknown", "guarded_http"}
            for chain in chains
            for step in chain
        )
        for row in rows
    ]


@pytest.fixture(autouse=True)
def ordinary_decoding_only(monkeypatch):
    """A missing global attestation must keep these findings available."""
    monkeypatch.setattr(
        "skylos.security.framework_contracts.native_http_pipeline_is_intact",
        lambda *_args, **_kwargs: False,
    )


@pytest.mark.parametrize(
    ("helper", "expression", "suffix", "expected"),
    [
        (FILTER, "normalize(raw)", "", True),
        (FILTER, "normalize(raw)", "view(get_untyped_value())\n", False),
        (
            FILTER + "def check(raw):\n"
            "    filtered = normalize(raw)\n"
            "    if filtered != raw:\n"
            "        raise ValueError\n"
            "    return raw\n",
            "check(raw)",
            "",
            True,
        ),
        (
            FILTER + "def check(raw):\n"
            "    filtered = normalize('other')\n"
            "    if filtered != raw:\n"
            "        raise ValueError\n"
            "    return raw\n",
            "check(raw)",
            "",
            False,
        ),
        (
            FILTER + "def check(raw):\n"
            "    filtered = normalize(raw)\n"
            "    if filtered != raw:\n"
            "        raise ValueError\n"
            "    raw = get_untyped_value()\n"
            "    return raw\n",
            "check(raw)",
            "",
            False,
        ),
    ],
)
def test_http_string_guard_follows_its_actual_input(
    tmp_path, helper, expression, suffix, expected
):
    rows, _ = _project_scan(tmp_path, helper, expression=expression, suffix=suffix)
    assert len(rows) == 2
    assert all(marked is expected for marked in _marked(rows))


@pytest.mark.parametrize("other_value", [False, True])
def test_guarded_model_field_round_trips_through_helper(tmp_path, other_value):
    from test.test_path_filename_proof_routes import STORAGE, _resolve

    source = """from fastapi import Body, FastAPI
from pydantic import BaseModel
from storage import load, save

app = FastAPI()
class Document(BaseModel):
    name: str | None = None
"""
    source += FILTER
    source += """
def persist(value):
    path = '/srv/files/' + normalize((value.name or '').strip())
    save(path)
    return load(path)

@app.post('/open')
def endpoint(payload: Document | None = Body(default=None)):
    return persist(payload or Document())
"""
    if other_value:
        source += "\npersist(make_untyped_record())\n"
    kept, _ = _resolve(tmp_path, {"app.py": source, "storage.py": STORAGE}, tmp_path)
    rows = [row for row in kept if row["rule_id"] == "SKY-D215"]
    assert len(rows) == 2
    assert _marked(rows) == [not other_value, not other_value]
