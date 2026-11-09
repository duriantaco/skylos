"""Fresh Namespace objects do not establish an inert attribute-write protocol."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


RENDER = """import argparse
import html

def fragment_link(name):
    return (
        f'<a href="#{html.escape(name, quote=True)}">'
        f'<code>{html.escape(name, quote=True)}</code></a>'
    )
"""
MERGE = """
def merge_options(values):
    merged = argparse.Namespace()
    for key, value in values.items():
        setattr(merged, key, value)
    return merged
"""
SWITCHING_CLASS = """import argparse
import html

class SwitchingNamespace(argparse.Namespace):
    def __setattr__(self, key, value):
        setattr(html, key, value)
"""
IDENTITY = "def identity(value, quote=True):\n    return value\n"


def _scan(tmp_path, monkeypatch, source, providers=()):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    path = write_fixture(tmp_path, "app.py", source)
    for filename, content in providers:
        write_fixture(tmp_path, filename, content)
    raw = [row for row in scan_ctx(tmp_path, [path]) if row["rule_id"] == "SKY-D228"]
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not result.get("analysis_errors")
    assert result.get("analysis_summary", {}).get("analysis_error_count", 0) == 0
    listed = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D228"]
    return raw, listed, result


@pytest.mark.parametrize("escaped", [True, False])
def test_escaping_without_a_mutator_keeps_its_original_html_context(
    tmp_path, monkeypatch, escaped
):
    source = RENDER
    if not escaped:
        source = source.replace("html.escape(name, quote=True)", "name")
    raw, listed, result = _scan(tmp_path, monkeypatch, source)
    assert len(raw) == len(listed) == (0 if escaped else 1)
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_security": 10}})
    assert passed is escaped, reasons


@pytest.mark.parametrize(
    "mutator,providers",
    [
        pytest.param(
            "def change(key, value):\n    setattr(html, key, value)\n",
            (),
            id="actual-module-receiver",
        ),
        pytest.param(
            "def change(flag, key, value):\n    receiver = argparse.Namespace() if flag else html\n    setattr(receiver, key, value)\n",
            (),
            id="conditional-module-receiver",
        ),
        pytest.param(
            "from plugin import SwitchingNamespace\n"
            + IDENTITY
            + "receiver = argparse.Namespace()\nsetattr(receiver, '__class__', SwitchingNamespace)\nsetattr(receiver, 'escape', identity)\n",
            (("plugin.py", SWITCHING_CLASS),),
            id="class-switch-before-next-literal-write",
        ),
        pytest.param(
            "from plugin import SwitchingNamespace\n"
            + IDENTITY
            + MERGE
            + "merge_options({'__class__': SwitchingNamespace, 'escape': identity})\n",
            (("plugin.py", SWITCHING_CLASS),),
            id="class-switch-in-original-loop",
        ),
        pytest.param(
            IDENTITY
            + "receiver = argparse.Namespace()\nsetattr(receiver, '__dict__', html.__dict__)\nsetattr(receiver, 'escape', identity)\n",
            (),
            id="instance-dictionary-becomes-module-dictionary",
        ),
        pytest.param(
            IDENTITY
            + "class Key(str):\n    def __hash__(self):\n        html.escape = identity\n        return super().__hash__()\nreceiver = argparse.Namespace()\nsetattr(receiver, Key('field'), None)\n",
            (),
            id="string-key-hash-protocol-with-literal-value",
        ),
        pytest.param(
            IDENTITY
            + "class Key(str):\n    __hash__ = str.__hash__\n    def __eq__(self, other):\n        html.escape = identity\n        return str.__eq__(self, other)\nreceiver = argparse.Namespace()\nsetattr(receiver, 'field', 1)\nsetattr(receiver, Key('field'), None)\n",
            (),
            id="string-key-equality-protocol-with-literal-value",
        ),
        pytest.param(
            IDENTITY
            + "def changed(self, key, value):\n    html.escape = identity\nargparse.Namespace.__setattr__ = changed\nreceiver = argparse.Namespace()\nsetattr(receiver, 'field', None)\n",
            (),
            id="native-class-setter-replaced",
        ),
        pytest.param(
            IDENTITY
            + "receiver = argparse.Namespace()\nsetattr(receiver, 'escape', identity)\n",
            (("argparse.py", "import html\ndef Namespace():\n    return html\n"),),
            id="local-provider-returns-module",
        ),
        pytest.param(
            IDENTITY
            + "def setattr(receiver, key, value):\n    html.escape = identity\nreceiver = argparse.Namespace()\nsetattr(receiver, 'field', None)\n",
            (),
            id="setter-spelling-is-not-builtin-identity",
        ),
    ],
)
def test_namespace_writes_retain_raw_listed_high_review_and_gate_failure(
    tmp_path, monkeypatch, mutator, providers
):
    raw, listed, result = _scan(
        tmp_path, monkeypatch, RENDER + "\n" + mutator, providers
    )
    for rows in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in rows
        ] == [("SKY-D228", "fragment_link", 5, "HIGH")]
    assert listed[0]["finding_type"] == "review"
    assert listed[0]["listing"]["listed"] is True
    assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_security": 10}})
    assert passed is False
    assert any("high" in str(reason).lower() for reason in reasons)


def test_unrestricted_namespace_loop_without_visible_effects_preserves_escape(
    tmp_path, monkeypatch
):
    raw, listed, result = _scan(tmp_path, monkeypatch, RENDER + MERGE)
    assert raw == listed == []
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_security": 10}})
    assert passed is True, reasons
