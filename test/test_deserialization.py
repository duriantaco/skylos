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


def test_huggingface_download_without_revision_flags_d345(tmp_path):
    code = """
from huggingface_hub import hf_hub_download

path = hf_hub_download(repo_id="owner/model", filename="model.pt")
"""
    out = _scan_one(tmp_path, "model_hf_unpinned.py", code)
    assert "SKY-D345" in _rule_ids(out)


def test_huggingface_download_mutable_revision_flags_d345(tmp_path):
    code = """
from huggingface_hub import snapshot_download

path = snapshot_download(repo_id="owner/model", revision="main")
"""
    out = _scan_one(tmp_path, "model_hf_main.py", code)
    assert "SKY-D345" in _rule_ids(out)


def test_huggingface_download_commit_revision_is_not_d345(tmp_path):
    code = """
from huggingface_hub import hf_hub_download

path = hf_hub_download(
    repo_id="owner/model",
    filename="model.pt",
    revision="0123456789abcdef0123456789abcdef01234567",
)
"""
    out = _scan_one(tmp_path, "model_hf_pinned.py", code)
    assert "SKY-D345" not in _rule_ids(out)


def test_transformers_from_pretrained_without_revision_flags_d345(tmp_path):
    code = """
from transformers import AutoModel

model = AutoModel.from_pretrained("owner/model")
"""
    out = _scan_one(tmp_path, "model_transformers_unpinned.py", code)
    assert "SKY-D345" in _rule_ids(out)


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


def test_load_dataset_packaged_builder_with_local_files_is_not_d345(tmp_path):
    # agent-pr-bench real-10: the json builder parses a local corpus file.
    code = """
import datasets

corpus = datasets.load_dataset("json", data_files=corpus_path, split="train")
local = datasets.load_dataset("./data/my_dataset")
"""
    out = _scan_one(tmp_path, "dataset_local.py", code)
    assert "SKY-D345" not in _rule_ids(out)


def test_load_dataset_hub_repo_or_remote_files_flags_d345(tmp_path):
    code = """
from datasets import load_dataset

hub = load_dataset("owner/dataset")
remote = load_dataset("json", data_files="https://example.com/train.jsonl")
"""
    out = _scan_one(tmp_path, "dataset_hub.py", code)
    lines = sorted(f["line"] for f in out if f["rule_id"] == "SKY-D345")
    assert lines == [4, 5]


def _findings_by_line(findings, rule_id):
    return {f["line"]: f["severity"] for f in findings if f["rule_id"] == rule_id}


def test_yaml_unsafe_and_full_loaders_flag_d206(tmp_path):
    code = (
        "import yaml\n"
        "def a(s):\n    return yaml.unsafe_load(s)\n"
        "def b(s):\n    return yaml.full_load(s)\n"
        "def c(s):\n    return list(yaml.unsafe_load_all(s))\n"
        "def d(s):\n    return yaml.load(s, Loader=yaml.FullLoader)\n"
    )
    out = _scan_one(tmp_path, "yaml_unsafe.py", code)
    assert sorted(_findings_by_line(out, "SKY-D206")) == [3, 5, 7, 9]


def test_yaml_data_only_loaders_are_not_d206(tmp_path):
    code = (
        "import yaml\n"
        "FAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\n"
        "def a(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n"
        "def b(s):\n    return yaml.load(s, Loader=yaml.BaseLoader)\n"
        "def c(s):\n    return yaml.load(s, Loader=FAST)\n"
        "def d(s):\n    return yaml.safe_load(s)\n"
    )
    out = _scan_one(tmp_path, "yaml_safe.py", code)
    assert "SKY-D206" not in _rule_ids(out)


def test_yaml_loader_named_safe_but_bound_to_unsafe_still_flags(tmp_path):
    code = (
        "import yaml\n"
        "SafeLoader = yaml.UnsafeLoader\n"
        "def a(s):\n    return yaml.load(s, Loader=SafeLoader)\n"
        "def b(s):\n"
        "    safe = yaml.SafeLoader\n"
        "    return yaml.load(s, Loader=yaml.Loader)\n"
    )
    out = _scan_one(tmp_path, "yaml_shadow.py", code)
    assert sorted(_findings_by_line(out, "SKY-D206")) == [4, 7]


def test_ruamel_unsafe_type_flags_and_safe_type_does_not(tmp_path):
    code = (
        "from ruamel.yaml import YAML\n"
        "unsafe = YAML(typ='unsafe')\n"
        "safe = YAML(typ='safe')\n"
        "round_trip = YAML()\n"
    )
    out = _scan_one(tmp_path, "ruamel_types.py", code)
    assert sorted(_findings_by_line(out, "SKY-D206")) == [2]


def test_pickle_family_loaders_flag(tmp_path):
    code = (
        "import io, marshal, pickle\n"
        "import cloudpickle\n"
        "import jsonpickle\n"
        "import pandas as pd\n"
        "def a(p):\n    return pd.read_pickle(p)\n"
        "def b(f):\n    return pickle.Unpickler(f).load()\n"
        "def c(f):\n    u = pickle.Unpickler(f)\n    return u.load()\n"
        "def d(b):\n    return cloudpickle.loads(b)\n"
        "def e(f):\n    return marshal.load(f)\n"
        "def g(t):\n    return jsonpickle.decode(t)\n"
    )
    out = _scan_one(tmp_path, "pickle_family.py", code)
    assert sorted(_findings_by_line(out, "SKY-D204")) == [6, 8, 11]
    assert sorted(_findings_by_line(out, "SKY-D205")) == [13]
    assert sorted(_findings_by_line(out, "SKY-D233")) == [15, 17]


def test_unpickler_subclass_needs_find_class_to_be_quiet(tmp_path):
    code = (
        "import io, pickle\n"
        "class Restricted(pickle.Unpickler):\n"
        "    def find_class(self, module, name):\n"
        "        raise pickle.UnpicklingError(name)\n"
        "class PassThrough(pickle.Unpickler):\n"
        "    pass\n"
        "def a(b):\n    return Restricted(io.BytesIO(b)).load()\n"
        "def c(b):\n    return PassThrough(io.BytesIO(b)).load()\n"
    )
    out = _scan_one(tmp_path, "unpickler_subclass.py", code)
    assert sorted(_findings_by_line(out, "SKY-D204")) == [10]


def test_trust_remote_code_true_flags_d213(tmp_path):
    code = (
        "from transformers import AutoModel, pipeline\n"
        "from langchain_huggingface import HuggingFaceEmbeddings\n"
        "a = AutoModel.from_pretrained('org/m', trust_remote_code=True)\n"
        "b = pipeline('text-generation', model='org/m', trust_remote_code=True)\n"
        "c = HuggingFaceEmbeddings(model_name='org/m', model_kwargs={'trust_remote_code': True})\n"
        "d = AutoModel.from_pretrained('org/m', revision='0123456789abcdef0123456789abcdef01234567', trust_remote_code=True)\n"
    )
    out = _scan_one(tmp_path, "hf_remote_code.py", code)
    assert _findings_by_line(out, "SKY-D213") == {
        3: "HIGH",
        4: "HIGH",
        5: "HIGH",
        6: "MEDIUM",
    }


def test_trust_remote_code_off_or_caller_chosen_is_not_d213(tmp_path):
    code = (
        "from transformers import AutoModel\n"
        "a = AutoModel.from_pretrained('org/m', trust_remote_code=False)\n"
        "def load(name, flag):\n"
        "    return AutoModel.from_pretrained(name, trust_remote_code=flag)\n"
    )
    out = _scan_one(tmp_path, "hf_remote_code_off.py", code)
    assert "SKY-D213" not in _rule_ids(out)
