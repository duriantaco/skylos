from pathlib import Path
from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


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
    assert any(
        "dill" in f.get("message", "").lower()
        or "deseri" in f.get("message", "").lower()
        for f in out
    )


def test_pickle_loads_still_flags(tmp_path):
    code = "import pickle\nobj = pickle.loads(b'\\x00')\n"
    out = _scan_one(tmp_path, "deser_pickle.py", code)
    assert any("pickle" in f.get("message", "").lower() for f in out)


def test_torch_load_without_weights_only_flags_d265(tmp_path):
    code = """
import torch

model = torch.load("model.pt")
"""
    out = _scan_one(tmp_path, "model_torch_load.py", code)
    assert "SKY-D265" in _rule_ids(out)


def test_torch_load_weights_only_true_is_not_d265(tmp_path):
    code = """
import torch

model = torch.load("model.pt", weights_only=True)
"""
    out = _scan_one(tmp_path, "model_torch_weights_only.py", code)
    assert "SKY-D265" not in _rule_ids(out)


def test_huggingface_downloaded_checkpoint_load_is_critical_d265(tmp_path):
    code = """
import torch
from huggingface_hub import hf_hub_download

path = hf_hub_download(repo_id="owner/model", filename="model.pt")
model = torch.load(path)
"""
    out = _scan_one(tmp_path, "model_remote_torch_load.py", code)
    findings = [finding for finding in out if finding["rule_id"] == "SKY-D265"]
    assert findings
    assert findings[0]["severity"] == "CRITICAL"


def test_numpy_allow_pickle_flags_d265(tmp_path):
    code = """
import numpy as np

weights = np.load("weights.npy", allow_pickle=True)
"""
    out = _scan_one(tmp_path, "model_numpy_pickle.py", code)
    assert "SKY-D265" in _rule_ids(out)


def test_joblib_model_load_flags_d265(tmp_path):
    code = """
import joblib

model = joblib.load("classifier.joblib")
"""
    out = _scan_one(tmp_path, "model_joblib_load.py", code)
    assert "SKY-D265" in _rule_ids(out)
