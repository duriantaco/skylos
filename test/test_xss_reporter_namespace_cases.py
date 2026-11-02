"""Replay the six shapes reported for escaped fragment links in #1143."""

import pytest

from skylos.core.gatekeeper import check_gate
from test.test_namespace_write_boundaries import _scan


RENDER = """# app.py
import argparse
import html


def fragment_link(name: str) -> str:
    return (
        f"<a href=\\"#{html.escape(name, quote=True)}\\">"
        f"<code>{html.escape(name, quote=True)}</code></a>"
    )
"""


@pytest.mark.parametrize("escaped", [True, False], ids=["escaped", "raw"])
@pytest.mark.parametrize(
    "extra",
    [
        pytest.param("", id="no-write"),
        pytest.param(
            "def merge(values):\n"
            "    merged = argparse.Namespace()\n"
            "    for key, value in values.items():\n"
            "        setattr(merged, key, value)\n"
            "    return merged\n",
            id="empty-namespace",
        ),
        pytest.param(
            "def tag(error: BaseException, value: str) -> BaseException:\n"
            "    setattr(error, '_phase', value)\n"
            "    return error\n",
            id="literal-key",
        ),
        pytest.param(
            "_ATTR = '_phase'\n"
            "def tag(error: BaseException, value: str) -> BaseException:\n"
            "    setattr(error, _ATTR, value)\n"
            "    return error\n",
            id="constant-key",
        ),
        pytest.param(
            "def merge(run_args, values):\n"
            "    merged = argparse.Namespace(**vars(run_args))\n"
            "    for key, value in values.items():\n"
            "        setattr(merged, key, value)\n"
            "    return merged\n",
            id="vars-copy-loop",
        ),
        pytest.param(
            "def merge(run_args, values):\n"
            "    return argparse.Namespace(**{**vars(run_args), **values})\n",
            id="direct-return-merge",
        ),
    ],
)
def test_reported_namespace_shapes_preserve_real_escaping(
    tmp_path, monkeypatch, extra, escaped
):
    render = (
        RENDER if escaped else RENDER.replace("html.escape(name, quote=True)", "name")
    )
    raw, listed, result = _scan(tmp_path, monkeypatch, render + "\n" + extra)
    expected = [] if escaped else [("SKY-D228", "fragment_link", 7, "HIGH")]
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == expected
    if listed:
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is escaped, reasons
