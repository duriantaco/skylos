"""Security exemptions require the concrete API and serialized-value origin."""

import ast

import pytest

from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


def _scan(tmp_path, source, engine="scan"):
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")
    if engine == "scan":
        return scan_ctx(tmp_path, [path])
    rule = DangerousCallsRule()
    return [
        finding
        for node in ast.walk(ast.parse(source))
        for finding in (rule.visit_node(node, {"filename": str(path)}) or [])
    ]


@pytest.mark.parametrize(
    "source",
    [
        "from opentelemetry import propagate\ndef trace(headers):\n    return propagate.extract(headers)\n",
        "import opentelemetry.propagate as p\ndef trace(headers):\n    return p.extract(headers)\n",
        "try:\n    from opentelemetry import propagate\nexcept ImportError:\n    raise\ndef trace(headers):\n    return propagate.extract(headers)\n",
    ],
)
def test_tracing_context_is_not_archive_extraction(tmp_path, source):
    assert not [f for f in _scan(tmp_path, source) if f["rule_id"] == "SKY-D326"]


@pytest.mark.parametrize(
    "source",
    [
        "from opentelemetry import propagate\ndef trace(propagate, member):\n    return propagate.extract(member)\n",
        "from opentelemetry import propagate\npropagate = archive\npropagate.extract(member)\n",
        "from opentelemetry import propagate\npropagate.extract = archive.extract\npropagate.extract(member)\n",
        "from opentelemetry import propagate\nsetattr(propagate, 'extract', archive.extract)\npropagate.extract(member)\n",
        "from opentelemetry import propagate\nother = propagate\nother.extract = archive.extract\npropagate.extract(member)\n",
        "from opentelemetry import propagate\nglobals()['propagate'] = archive\npropagate.extract(member)\n",
        "from opentelemetry import propagate\ndef trace(member):\n    for propagate in archives:\n        propagate.extract(member)\n",
        "from opentelemetry import propagate\npropagate.extractall()\n",
        "import tarfile\ndef unpack(path, member):\n    archive = tarfile.open(path)\n    archive.extract(member)\n",
    ],
)
def test_unproven_or_changed_tracing_receiver_keeps_archive_warning(tmp_path, source):
    assert [f for f in _scan(tmp_path, source) if f["rule_id"] == "SKY-D326"]


@pytest.mark.parametrize("engine", ["scan", "rule"])
@pytest.mark.parametrize(
    "source",
    [
        "import pickle\nresult = pickle.loads(pickle.dumps({'name': 'value', 'n': [1, 2]}))\n",
        "from pickle import dumps as encode, loads as decode\ndef roundtrip():\n    packed = encode({'name': 'value'})\n    alias = packed\n    return decode(alias)\n",
        "import pickle\ndef roundtrip(flag):\n    if flag:\n        packed = pickle.dumps([1])\n    else:\n        packed = pickle.dumps([2])\n    return pickle.loads(packed)\n",
    ],
)
def test_proven_data_roundtrip_has_no_untrusted_deserialization_warning(
    tmp_path, engine, source
):
    assert not [
        f for f in _scan(tmp_path, source, engine) if f["rule_id"] == "SKY-D205"
    ]


@pytest.mark.parametrize("engine", ["scan", "rule"])
@pytest.mark.parametrize(
    "source",
    [
        "import pickle\ndef decode(payload):\n    return pickle.loads(payload)\n",
        "import pickle\ndef roundtrip(value):\n    return pickle.loads(pickle.dumps(value))\n",
        "import pickle\ndef decode(payload):\n    packed = pickle.dumps({'x': 1})\n    packed = payload\n    return pickle.loads(packed)\n",
        "import pickle\ndef decode(payload, flag):\n    packed = payload\n    if flag:\n        packed = pickle.dumps({'x': 1})\n    return pickle.loads(packed)\n",
        "import pickle\ndef decode(payload):\n    packed = pickle.dumps({'x': 1})\n    for packed in payload:\n        pass\n    return pickle.loads(packed)\n",
        "import pickle\npickle.dumps = encode_external\npickle.loads(pickle.dumps({'x': 1}))\n",
        "from pickle import dumps, loads\ndef decode(dumps):\n    return loads(dumps({'x': 1}))\n",
        "from pickle import dumps, loads\nclass Style:\n    def __init__(self, meta):\n        self._meta = dumps(meta)\n    def meta(self):\n        return loads(self._meta)\n",
        "import pickle\npickle.loads(b'raw pickle bytecode')\n",
    ],
)
def test_unknown_pickle_sources_and_lookalikes_remain_auditable(
    tmp_path, engine, source
):
    out = [f for f in _scan(tmp_path, source, engine) if f["rule_id"] == "SKY-D205"]
    assert out
    assert all(
        "only deserialize bytes from trusted sources" in f["message"] for f in out
    )


@pytest.mark.parametrize("engine", ["scan", "rule"])
@pytest.mark.parametrize(
    "source",
    [
        "import pickle\ndef decode(payload):\n    packed = pickle.dumps({'x': 1})\n    print(packed := payload)\n    return pickle.loads(packed)\n",
        "import pickle\ndef decode(payload):\n    data = ([],)\n    data[0].append(payload)\n    return pickle.loads(pickle.dumps(data))\n",
        "import pickle\ndef decode(payload):\n    try:\n        packed = payload\n    except Exception:\n        packed = pickle.dumps({'x': 1})\n    else:\n        return pickle.loads(packed)\n",
        "import pickle\ndef decode(payload):\n    packed = pickle.dumps({'x': 1})\n    for item in range(2):\n        pickle.loads(packed)\n        packed = payload\n",
        "import pickle\ndef decode(payload):\n    try:\n        packed = payload\n        fail()\n        packed = pickle.dumps({'x': 1})\n    except Exception:\n        return pickle.loads(packed)\n",
        "import pickle\nclass Decoder:\n    pickle = unknown\n    value = pickle.loads(pickle.dumps({'x': 1}))\n",
    ],
)
def test_pickle_proof_rejects_incomplete_flow(tmp_path, engine, source):
    assert [f for f in _scan(tmp_path, source, engine) if f["rule_id"] == "SKY-D205"]


@pytest.mark.parametrize(
    "source",
    [
        "from opentelemetry import propagate\nclass X:\n    propagate = archive\n    result = propagate.extract(member)\n",
        "from opentelemetry import propagate\nclass X:\n    propagate = archive\n    def unpack(self, member=propagate.extract(item)):\n        pass\n",
        "from opentelemetry import propagate\nresult = [propagate.extract(item) for propagate in archives]\n",
    ],
)
def test_tracing_proof_does_not_cross_python_scope_boundaries(tmp_path, source):
    assert [f for f in _scan(tmp_path, source) if f["rule_id"] == "SKY-D326"]


@pytest.mark.parametrize("engine", ["scan", "rule"])
@pytest.mark.parametrize(
    "mutation",
    [
        "[(packed := payload) for _ in items]",
        "def nested(value=(packed := payload)): pass",
    ],
)
def test_pickle_proof_rejects_expression_rebinding(tmp_path, engine, mutation):
    source = (
        "import pickle\ndef decode(payload, items):\n    packed = pickle.dumps([1])\n    "
        + mutation
        + "\n    return pickle.loads(packed)\n"
    )
    assert [f for f in _scan(tmp_path, source, engine) if f["rule_id"] == "SKY-D205"]


@pytest.mark.parametrize(
    "patch_import, patch_call",
    [
        ("from unittest.mock import patch as replace", "replace"),
        ("import unittest.mock as mocking", "mocking.patch"),
        ("from unittest import mock", "mock.patch"),
        ("from unittest.mock import patch\nreplace = patch", "replace"),
    ],
)
def test_mock_patch_cannot_establish_a_known_tracing_api(
    tmp_path, patch_import, patch_call
):
    source = (
        "from opentelemetry import propagate\n"
        + patch_import
        + "\nwith "
        + patch_call
        + "('opentelemetry.propagate.extract', archive.extract):\n    propagate.extract(member)\n"
    )
    assert [f for f in _scan(tmp_path, source) if f["rule_id"] == "SKY-D326"]


@pytest.mark.parametrize("engine", ["scan", "rule"])
def test_mock_patch_cannot_establish_a_pickle_roundtrip(tmp_path, engine):
    source = "import pickle\nfrom unittest.mock import patch as replace\nwith replace('pickle.dumps', malicious_encoder):\n    pickle.loads(pickle.dumps([1]))\n"
    assert [f for f in _scan(tmp_path, source, engine) if f["rule_id"] == "SKY-D205"]
