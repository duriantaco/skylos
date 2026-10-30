"""Narrow filename proofs must not erase independent filesystem risks."""

import ast
from pathlib import Path

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.rules.danger.danger_fs.path_provenance import resolve_helper_parameter_findings


FILTER = """def normalize(raw):
    clean = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
    return clean or 'flight'
"""
STORAGE = """def load(path):
    with open(path, 'r') as stream:
        return stream.read()
def save(path):
    with open(path, 'w') as stream:
        stream.write('record')
"""


def _project_scan(tmp_path, helper, *, expression="normalize(raw)", annotation=": str", prelude="", suffix="", complete=True):
    source = (
        "from pathlib import Path\nfrom fastapi import FastAPI\n"
        "from storage import load, save\napp = FastAPI()\n"
        + prelude + helper
        + "@app.get('/files/{raw}')\ndef view(raw" + annotation + "):\n"
        + "    path = Path('/srv/flights') / " + expression + " / 'manifest.json'\n"
        + "    save(path)\n    return load(path)\n" + suffix
    )
    (tmp_path / 'pyproject.toml').write_text('[project]\nname="filename-proof"\n')
    findings = []
    for filename, text in [('app.py', source), ('storage.py', STORAGE)]:
        path = tmp_path / filename
        path.write_text(text)
        scan(ast.parse(text), path, findings)
    suppressed = []
    kept = resolve_helper_parameter_findings(
        findings, scan_path=tmp_path, project_root=tmp_path if complete else None, suppressed=suppressed,
    )
    # Traversal safety must never change the write/read candidates themselves.
    assert {
        (f['rule_id'], Path(f['file']).name, f['line'], f['symbol'])
        for f in kept if f['rule_id'] in {'SKY-D324', 'SKY-D325'}
    } == {
        ('SKY-D324', 'storage.py', 5, 'save'),
        ('SKY-D325', 'storage.py', 2, 'load'),
    }
    return [f for f in kept if f['rule_id'] == 'SKY-D215'], suppressed


def test_resolved_character_filter_has_rule_specific_proof(tmp_path):
    kept, suppressed = _project_scan(tmp_path, FILTER)
    assert not kept
    candidates = [f for f in suppressed if f['rule_id'] == 'SKY-D215']
    assert len(candidates) == 2
    assert all(f['metadata']['path_provenance']['status'] == 'safe' for f in candidates)


def test_partial_project_keeps_unknown_external_callers(tmp_path):
    kept, _ = _project_scan(tmp_path, FILTER, complete=False)
    assert len(kept) == 2


@pytest.mark.parametrize('helper', [
    FILTER.replace("('-', '_')", "('-', '_', '/')"),
    FILTER.replace("('-', '_')", "('-', '_', '.')"),
    FILTER.replace("or 'flight'", 'or raw'),
    "def normalize(raw):\n    return raw.strip()\n",
    '@decorate\n' + FILTER,
    FILTER + "def passthrough(raw):\n    return raw\nnormalize.__code__ = passthrough.__code__\n",
])
def test_unsafe_filter_lookalikes_remain_reported(tmp_path, helper):
    kept, _ = _project_scan(tmp_path, helper)
    assert len(kept) == 2


def test_arbitrary_helper_annotation_is_not_native_string_proof(tmp_path):
    kept, _ = _project_scan(tmp_path, FILTER.replace('normalize(raw)', 'normalize(raw: str)'), annotation='')
    assert len(kept) == 2


@pytest.mark.parametrize('reject', ["raise ValueError('invalid')", 'pass', 'return raw'])
def test_only_terminating_rejection_proves_surviving_value(tmp_path, reject):
    helper = FILTER + "def checked(raw):\n    if normalize(raw) != raw:\n        " + reject + "\n    return raw\n"
    kept, _ = _project_scan(tmp_path, helper, expression='checked(raw)')
    assert bool(kept) == (reject != "raise ValueError('invalid')")


def test_checked_input_reassignment_keeps_traversal(tmp_path):
    helper = FILTER + """def checked(raw):
    if normalize(raw) != raw:
        raise ValueError('invalid')
    raw = raw + '/../../escape'
    return raw
"""
    kept, _ = _project_scan(tmp_path, helper, expression='checked(raw)')
    assert len(kept) == 2


@pytest.mark.parametrize('check', ['type(raw) is not str', 'not isinstance(raw, str)'])
def test_native_type_guard_rejects_custom_string_iteration(tmp_path, check):
    helper = FILTER + "def exact(raw):\n    if " + check + ":\n        raise TypeError('native string')\n    return normalize(raw)\n"
    kept, _ = _project_scan(tmp_path, helper, expression='exact(raw)', annotation='')
    assert bool(kept) == (check != 'type(raw) is not str')


@pytest.mark.parametrize('prelude', [
    'app.get = custom_decorator\n',
    'app.router.route_class = CustomRoute\n',
    'app.add_middleware(CustomMiddleware)\n',
])
def test_custom_framework_setup_does_not_prove_native_string(tmp_path, prelude):
    kept, _ = _project_scan(tmp_path, FILTER, prelude=prelude)
    assert len(kept) == 2


def test_direct_call_can_bypass_framework_string_conversion(tmp_path):
    suffix = """class Custom(str):
    def __iter__(self):
        yield Custom('/')
    def isalnum(self):
        return True
view(Custom('input'))
"""
    kept, _ = _project_scan(tmp_path, FILTER, suffix=suffix)
    assert len(kept) == 2
