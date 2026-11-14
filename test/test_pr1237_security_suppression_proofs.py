"""A suppression needs proof that survives binding and value changes."""

import ast
import json
from pathlib import Path

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan as scan_paths
from skylos.rules.danger.danger_logging import scan as scan_logging
from skylos.rules.danger.danger_ml.model_deserialization import (
    _ModelDeserializationChecker,
)
from skylos.rules.danger.danger_net.ssrf_flow import scan as scan_ssrf
from skylos.visitors.languages.typescript import scan_typescript_file


@pytest.mark.parametrize("binding", ["helper", "regex", "wildcard"])
def test_import_rebinding_cannot_prove_a_filename_is_safe(tmp_path, binding):
    code = '''import os
import re
from fastapi import APIRouter
router = APIRouter()
NAME_RE = re.compile(r"[a-zA-Z0-9_-]+")
def validate_name(name: str):
    if not NAME_RE.fullmatch(name):
        raise ValueError("invalid")
    return name
'''
    if binding == "regex":
        code += '''from helper import NAME_RE
@router.get("/read/{name:path}")
def read(name: str):
    if not NAME_RE.fullmatch(name):
        raise ValueError("invalid")
    return open(os.path.join("state", name)).read()
'''
    else:
        code += (
            "from helper import validate_name\n"
            if binding == "helper"
            else "from helper import *\n"
        )
        code += '''@router.get("/read/{name:path}")
def read(name: str):
    return open(os.path.join("state", validate_name(name))).read()
'''
    findings = []
    scan_paths(ast.parse(code), tmp_path / "app.py", findings)
    sink = len(code.splitlines())
    assert {(f["rule_id"], f["line"]) for f in findings} >= {
        ("SKY-D215", sink),
        ("SKY-D325", sink),
    }


@pytest.mark.parametrize("descriptor", ["property", "getattribute", "external_base"])
def test_mapping_assignment_does_not_prove_attribute_reads_are_mappings(
    tmp_path, descriptor
):
    bases = "(UnknownBase)" if descriptor == "external_base" else ""
    code = f'''import httpx
from flask import Flask, request
from plugin import UnknownBase
app = Flask(__name__)
class Relay{bases}:
    def __init__(self):
        self._client = {{}}
'''
    if descriptor == "property":
        code += '''    @property
    def _client(self):
        return httpx.Client()
    @_client.setter
    def _client(self, value):
        pass
'''
    elif descriptor == "getattribute":
        code += '''    def __getattribute__(self, name):
        if name == "_client":
            return httpx.Client()
        return object.__getattribute__(self, name)
'''
    code += '''    def relay(self):
        return self._client.get(request.args["target"])
'''
    findings = []
    scan_ssrf(ast.parse(code), tmp_path / "app.py", findings)
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        ("SKY-D216", len(code.splitlines()))
    ]


def test_mapping_proof_cache_keeps_class_owners_separate(tmp_path):
    code = '''import httpx
from flask import request
class Cache:
    def __init__(self):
        self._client = {}
    def read(self):
        return self._client.get(request.args["target"])
class Relay:
    def __init__(self):
        self._client = {}
    @property
    def _client(self):
        return httpx.Client()
    @_client.setter
    def _client(self, value):
        pass
    def read(self):
        return self._client.get(request.args["target"])
'''
    findings = []
    scan_ssrf(ast.parse(code), tmp_path / "app.py", findings)
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D216", 18)]


@pytest.mark.parametrize(
    "expression",
    [
        "key[:8]",
        "key[:8] + key[8:16] + key[16:24] + key[24:32]",
        "f'{key[:8]}{key[8:16]}{key[16:24]}{key[24:32]}'",
        "mask(key) + key",
    ],
)
def test_credential_fragments_remain_sensitive_when_logged(tmp_path, expression):
    code = f'''import os
def mask(key):
    return key[:6] + "..." + key[-4:]
key = os.environ["PASSWORD"]
print({expression})
'''
    findings = scan_logging(ast.parse(code), {"filename": str(tmp_path / "app.py")})
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D251", 5)]


@pytest.mark.parametrize(
    "expression",
    ["key[:6] + '...' + key[-4:]", "key[:6] + ('...' + key[-4:])"],
)
def test_explicit_prefix_ellipsis_suffix_mask_stays_redacted(tmp_path, expression):
    code = f'''import os
def mask(key):
    return {expression}
print(mask(os.environ["API_TOKEN"]))
'''
    assert scan_logging(ast.parse(code), {"filename": str(tmp_path / "app.py")}) == []


@pytest.mark.parametrize(
    "reference",
    [
        'os.path.join("google-bert", "bert-base-uncased")',
        'str(Path("google-bert/bert-base-uncased"))',
        'os.path.normpath("google-bert/bert-base-uncased")',
        'os.path.expanduser("google-bert/bert-base-uncased")',
        'str(Path("./google-bert/bert-base-uncased"))',
    ],
)
def test_path_spelling_can_still_name_a_mutable_hub_model(tmp_path, reference):
    code = f'''import os
from pathlib import Path
from transformers import AutoModel
AutoModel.from_pretrained({reference})
'''
    tree = ast.parse(code)
    findings = []
    _ModelDeserializationChecker(tmp_path / "app.py", findings, tree=tree).visit(tree)
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D345", 4)]


@pytest.mark.parametrize("reference", ['"/srv/models/model"', '"./models/model"'])
def test_explicit_local_model_paths_stay_quiet(tmp_path, reference):
    code = f'''from transformers import AutoModel
AutoModel.from_pretrained({reference})
'''
    tree = ast.parse(code)
    findings = []
    _ModelDeserializationChecker(tmp_path / "app.py", findings, tree=tree).visit(tree)
    assert findings == []


def test_explicit_offline_model_load_stays_quiet(tmp_path):
    code = '''from pathlib import Path
from transformers import AutoModel
def load(path: Path):
    return AutoModel.from_pretrained(str(path), local_files_only=True)
'''
    tree = ast.parse(code)
    findings = []
    _ModelDeserializationChecker(tmp_path / "app.py", findings, tree=tree).visit(tree)
    assert findings == []


def test_checkpoint_benchmark_keeps_ambiguous_and_proven_local_controls():
    path = (
        Path(__file__).resolve().parents[1]
        / "benchmarks/security/fixtures/noise_python_hf_local_checkpoint_path/load.py"
    )
    tree = ast.parse(path.read_text())
    findings = []
    _ModelDeserializationChecker(path, findings, tree=tree).visit(tree)
    # The original ambiguous fixture is preserved at line 7. The added
    # offline-only and absolute-path loaders must remain quiet.
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D345", 7)]


@pytest.mark.parametrize("shadow", ["Path = custom_path", "str = custom_string"])
def test_shadowed_path_provider_cannot_prove_a_local_load(tmp_path, shadow):
    code = f'''from pathlib import Path
from transformers import AutoModel
{shadow}
AutoModel.from_pretrained(str(Path("/srv/models/model")))
'''
    tree = ast.parse(code)
    findings = []
    _ModelDeserializationChecker(tmp_path / "app.py", findings, tree=tree).visit(tree)
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-D345", 4)]


@pytest.mark.parametrize("side_effect", [False, True])
def test_client_directive_cannot_override_explicit_node_server_execution(
    tmp_path, side_effect
):
    code = '''"use client";
import http from "node:http";
async function relay(target: string) { return fetch(target); }
http.createServer(async (req, res) => {
 const target = new URL(req.url!, "http://localhost").searchParams.get("target");
 const response = await relay(target!);
 res.end(await response.text());
}).listen(3000);
'''
    if side_effect:
        code = code.replace(
            'import http from "node:http";',
            'import "node:http"; const http = globalThis.http;',
        )
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {}}))
    path = tmp_path / "server.ts"
    path.write_text(code)
    findings = scan_typescript_file(str(path))[7]
    assert [(f["rule_id"], f["line"]) for f in findings if f["rule_id"] == "SKY-D216"] == [
        ("SKY-D216", 3)
    ]
