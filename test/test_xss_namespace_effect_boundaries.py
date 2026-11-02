"""Literal-key proofs must preserve provider and callback uncertainty."""

import pytest

from skylos.core.gatekeeper import check_gate
from test.test_namespace_write_boundaries import RENDER, _scan


COPY = """
def clone(run_args, values):
    merged = argparse.Namespace(**{**vars(run_args), **values})
    for key, value in values.items():
        setattr(merged, key, value)
    return merged
"""


@pytest.mark.parametrize(
    "source,expected",
    [
        pytest.param(
            "key = '_phase'\nother = key\n"
            "def stamp(error, value):\n    setattr(error, other, value)\n",
            0,
            id="lowercase-literal-alias",
        ),
        pytest.param(
            "key = '_phase'\ndef stamp(error):\n    delattr(error, key)\n",
            0,
            id="literal-deletion",
        ),
        pytest.param(
            "def stamp(error, value):\n    key = '_phase'; setattr(error, key, value)\n",
            0,
            id="same-line-literal-before-write",
        ),
        pytest.param(
            "import builtins\nfrom plugin import replacement\n"
            "key = 'vars'\nsetattr(builtins, key, replacement)\n" + COPY,
            1,
            id="builtin-vars-replaced",
        ),
        pytest.param(
            "import importlib\nfrom plugin import replacement\n"
            "key = 'import_module'\nsetattr(importlib, key, replacement)\n" + COPY,
            1,
            id="importer-replaced",
        ),
        pytest.param(
            COPY + "values = {'mode': 'fast'}\nother = values\n"
            "configure(other)\nclone({}, values)\n",
            1,
            id="input-mapping-alias-escapes",
        ),
        pytest.param(
            "def identity(value, quote=True):\n    return value\n"
            "key = 'escape'\nclass Values:\n"
            "    def __iter__(self):\n"
            "        setattr(html, key, identity)\n"
            "        return iter(())\n"
            "    def items(self):\n        return self\n"
            + COPY
            + "clone({}, Values())\n",
            1,
            id="iteration-replaces-escape",
        ),
    ],
)
def test_namespace_effect_proofs_preserve_api_boundaries(
    tmp_path, monkeypatch, source, expected
):
    raw, listed, result = _scan(tmp_path, monkeypatch, RENDER + source)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([("SKY-D228", "fragment_link", 5, "HIGH")] if expected else [])
    if listed:
        assert listed[0]["finding_type"] == "review"
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is (not expected), reasons
