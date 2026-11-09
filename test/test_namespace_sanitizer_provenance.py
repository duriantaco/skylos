"""Source-proven instance writes do not invalidate unrelated HTML escaping."""

import pytest

from skylos.core.gatekeeper import check_gate
from test.test_namespace_write_boundaries import MERGE, RENDER, SWITCHING_CLASS, _scan
from test.fixture_paths import write_fixture
from skylos.rules.danger.danger import scan_ctx


def _assert_result(tmp_path, monkeypatch, source, expected, providers=()):
    raw, listed, result = _scan(tmp_path, monkeypatch, source, providers)
    assert len(raw) == len(listed) == int(expected)
    if expected:
        assert listed[0]["rule_id"] == "SKY-D228"
        assert listed[0]["severity"] == "HIGH"
        assert listed[0]["finding_type"] == "review"
        assert listed[0]["listing"]["listed"] is True
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_security": 10}})
    assert passed is (not expected), reasons


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(RENDER + MERGE, id="unannotated-original"),
        pytest.param(
            RENDER
            + MERGE.replace(
                "values):", "values: dict[str, object]) -> argparse.Namespace:"
            ),
            id="annotated-original",
        ),
        pytest.param(
            RENDER
            + "import argparse as ap\n"
            + MERGE.replace("argparse.Namespace()", "ap.Namespace()"),
            id="module-import-alias",
        ),
        pytest.param(
            RENDER
            + "from argparse import Namespace as NS\n"
            + MERGE.replace("argparse.Namespace()", "NS()"),
            id="class-import-alias",
        ),
        pytest.param(
            RENDER + MERGE + "merge_options({'alpha': 1})\n", id="literal-data-caller"
        ),
        pytest.param(
            RENDER + MERGE + "options = {'alpha': 1}\nmerge_options(options)\n",
            id="literal-data-alias",
        ),
        pytest.param(
            RENDER + MERGE + "def unrelated(argparse):\n    return argparse\n",
            id="lexically-shadowed-other-scope",
        ),
    ],
)
def test_isolated_namespace_writes_preserve_actual_escape_proof(
    tmp_path, monkeypatch, source
):
    _assert_result(tmp_path, monkeypatch, source, False)


@pytest.mark.parametrize(
    "extra,providers",
    [
        pytest.param(
            "from plugin import SwitchingNamespace\ndef forward(data):\n    return merge_options(data)\nforward({'__class__': SwitchingNamespace, 'escape': str})\n",
            (("plugin.py", SWITCHING_CLASS),),
            id="class-payload-through-forwarder",
        ),
        pytest.param(
            "from plugin import SwitchingNamespace\npayload = {}\npayload.update({'__class__': SwitchingNamespace, 'escape': str})\nmerge_options(payload)\n",
            (("plugin.py", SWITCHING_CLASS),),
            id="mutated-native-container",
        ),
        pytest.param("register(merge_options)\n", (), id="helper-as-callback"),
        pytest.param(
            "from opaque import install\ndef unrelated():\n    return 0\ninstall(unrelated)\n",
            (),
            id="source-function-globals-capability",
        ),
        pytest.param(
            "from helper import unrelated as callback\nfrom opaque import install\ninstall(callback)\n",
            (("helper.py", "import html\ndef unrelated():\n    return 0\n"),),
            id="imported-source-function-globals-capability",
        ),
        pytest.param(
            "from opaque import install\ninstall(lambda: 0)\n",
            (),
            id="lambda-globals-capability",
        ),
        pytest.param(
            "payload = {}\ndef mutate(merge_options):\n    merge_options(payload)\nfrom opaque import install\nmutate(install)\nmerge_options(payload)\n",
            (),
            id="callee-spelling-does-not-prove-data-map-use",
        ),
        pytest.param(
            "from importlib import import_module as load\nload(input())\n",
            (),
            id="dynamic-loader-alias",
        ),
        pytest.param(
            "import inspect\ninspect.currentframe().f_globals\n",
            (),
            id="reflective-namespace",
        ),
        pytest.param(
            "import argparse\nconfigure(argparse.Namespace)\n",
            (),
            id="native-class-escape",
        ),
        pytest.param(
            "import argparse\nFactory = argparse.Namespace\nconfigure(Factory)\n",
            (),
            id="native-class-alias-escape",
        ),
        pytest.param(
            "from plugin import configure\nconfigure(html)\n",
            (
                (
                    "plugin.py",
                    "def configure(module):\n    module.escape = lambda value, quote=True: value\n",
                ),
            ),
            id="sanitizer-module-escape",
        ),
        pytest.param(
            "",
            (("html.py", "def escape(value, quote=True):\n    return value\n"),),
            id="local-sanitizer-provider",
        ),
        pytest.param(
            "from external import payload\nclass Holder:\n    payload = {'field': None}\n    def apply(self):\n        merge_options(payload)\n",
            (),
            id="method-lookup-skips-class-namespace",
        ),
        pytest.param(
            "",
            (("argparse.pyc", "untrusted compiled-provider placeholder"),),
            id="non-source-local-provider",
        ),
        pytest.param(
            "from plugin import configure\ndef marker(value: configure(argparse.Namespace)):\n    pass\nmarker.__annotations__\n",
            (
                (
                    "plugin.py",
                    "def configure(cls):\n    cls.__setattr__ = lambda self, key, value: None\n",
                ),
            ),
            id="executable-annotation-capability",
        ),
        pytest.param(
            "import sys\nsys.path.insert(0, 'vendor')\n",
            (
                (
                    "vendor/argparse.py",
                    "import html\ndef Namespace():\n    return html\n",
                ),
            ),
            id="import-search-path-provider",
        ),
    ],
)
def test_visible_effects_prevent_namespace_isolation(
    tmp_path, monkeypatch, extra, providers
):
    _assert_result(tmp_path, monkeypatch, RENDER + MERGE + extra, True, providers)


@pytest.mark.parametrize(
    "merge",
    [
        MERGE.replace(
            "    for key, value", "    configure(merged)\n    for key, value"
        ),
        MERGE.replace(
            "    for key, value", "    values = build_payload()\n    for key, value"
        ),
        MERGE.replace(
            "argparse.Namespace()", "argparse.Namespace() if choose else html"
        ),
        MERGE.replace(
            "    for key, value", "    import html as merged\n    for key, value"
        ),
        MERGE.replace(
            "    for key, value",
            "    match html:\n        case merged:\n            pass\n    for key, value",
        ),
        MERGE.replace("    merged =", "    global merged\n    merged ="),
        MERGE.replace("values):", "values=build_payload()):"),
        MERGE.replace(
            "    for key, value", "    configure(values)\n    for key, value"
        ),
        MERGE.replace(
            "    for key, value", "    values.update(load_values())\n    for key, value"
        ),
    ],
)
def test_receiver_and_mapping_provenance_must_remain_stable(
    tmp_path, monkeypatch, merge
):
    _assert_result(tmp_path, monkeypatch, RENDER + merge, True)


def test_unrelated_plain_class_does_not_invent_namespace_mutation(
    tmp_path, monkeypatch
):
    source = (
        RENDER
        + MERGE
        + "class Plain:\n    def __init__(self, value):\n        self.value = value\n"
    )
    _assert_result(tmp_path, monkeypatch, source, False)


@pytest.mark.parametrize(
    "context",
    [
        "class Sneaky(str):\n    def replace(self, old, new, count=-1):\n        return self\nSneaky('value')\n",
        "from opaque import install\ndef frames():\n    yield 0\ninstall(frames())\n",
        "from opaque import install\ninstall(value for value in ())\n",
        "from opaque import install\nasync def suspended():\n    return None\ninstall(suspended())\n",
        "from external import replace\nSneaky = type('Sneaky', (str,), {'replace': replace})\n",
        "from types import new_class as create\nfrom external import configure\nSneaky = create('Sneaky', (str,), exec_body=configure)\n",
        "from external import create\nSneaky = create()\nchoose = False\nif choose:\n    Sneaky = str\n",
    ],
)
def test_source_defined_execution_objects_are_not_native_data_contexts(
    tmp_path, monkeypatch, context
):
    source = RENDER + MERGE + context
    if "Sneaky" in context:
        source = source.replace(
            "html.escape(name, quote=True)", "html.escape(Sneaky(name), quote=True)"
        )
    _assert_result(tmp_path, monkeypatch, source, True)


def test_legacy_malformed_context_keeps_later_unescaped_sink(tmp_path):
    source = RENDER + MERGE + "def later(name):\n    return f'<b>{name}</b>'\n"
    path = write_fixture(tmp_path, "app.py", source)
    rows = [row for row in scan_ctx(object(), [path]) if row["rule_id"] == "SKY-D228"]
    assert {row["symbol"] for row in rows} == {"fragment_link", "later"}
