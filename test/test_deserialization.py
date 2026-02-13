"""Tests for extended insecure deserialization rules (SKY-D233 / DANGEROUS_CALLS)."""
from pathlib import Path
from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def test_marshal_loads_flags(tmp_path):
    code = "import marshal\ndata = marshal.loads(b'\\x00')\n"
    out = _scan_one(tmp_path, "deser_marshal.py", code)
    assert any("marshal" in f.get("message", "").lower() for f in out)


def test_shelve_open_flags(tmp_path):
    code = "import shelve\ndb = shelve.open('test.db')\n"
    out = _scan_one(tmp_path, "deser_shelve.py", code)
    assert any("shelve" in f.get("message", "").lower() for f in out)


def test_dill_loads_flags(tmp_path):
    code = "import dill\nobj = dill.loads(b'\\x00')\n"
    out = _scan_one(tmp_path, "deser_dill.py", code)
    assert any("dill" in f.get("message", "").lower() or "deseri" in f.get("message", "").lower() for f in out)


def test_pickle_loads_still_flags(tmp_path):
    """Existing rule — make sure it didn't break."""
    code = "import pickle\nobj = pickle.loads(b'\\x00')\n"
    out = _scan_one(tmp_path, "deser_pickle.py", code)
    assert any("pickle" in f.get("message", "").lower() for f in out)
