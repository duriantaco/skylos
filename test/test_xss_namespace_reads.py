"""Read-only Namespace copies and stable keys preserve actual HTML escaping."""

import pytest

from skylos.core.gatekeeper import check_gate
from test.test_namespace_write_boundaries import RENDER, _scan


CASES = [
    pytest.param(
        "",
        True,
        0,
        (),
        id="escaped-control",
    ),
    pytest.param(
        "import argparse\nimport html\n\ndef fragment_link(name):\n    return (\n        f'<a href=\"#{name}\">'\n        f'<code>{name}</code></a>'\n    )\n",
        False,
        1,
        (),
        id="unescaped-control",
    ),
    pytest.param(
        "def stamp(error, value):\n    setattr(error, '_phase', value)\n",
        True,
        0,
        (),
        id="literal-key-control",
    ),
    pytest.param(
        "_ATTR = '_phase'\ndef stamp(error, value):\n    setattr(error, _ATTR, value)\n",
        True,
        0,
        (),
        id="module-constant-key",
    ),
    pytest.param(
        "_ATTR = '_phase'\nKEY = _ATTR\ndef stamp(error, value):\n    setattr(error, KEY, value)\n",
        True,
        0,
        (),
        id="constant-alias-key",
    ),
    pytest.param(
        "def stamp(error, value):\n    key = '_phase'\n    setattr(error, key, value)\n",
        True,
        0,
        (),
        id="local-constant-key",
    ),
    pytest.param(
        "_ATTR = '_phase'\ndef stamp(error, _ATTR, value):\n    setattr(error, _ATTR, value)\n",
        True,
        1,
        (),
        id="constant-key-shadowed-param",
    ),
    pytest.param(
        "_ATTR = '_phase'\n_ATTR = 'escape'\ndef stamp(error, value):\n    setattr(error, _ATTR, value)\n",
        True,
        1,
        (),
        id="constant-key-rebound-escape",
    ),
    pytest.param(
        "_ATTR = '_phase'\ndef choose():\n    global _ATTR\n    _ATTR = input()\ndef stamp(error, value):\n    setattr(error, _ATTR, value)\n",
        True,
        1,
        (),
        id="constant-key-global-write",
    ),
    pytest.param(
        "def outer():\n    key = '_phase'\n    def change():\n        nonlocal key\n        key = 'escape'\n    def stamp(error, value):\n        setattr(error, key, value)\n",
        True,
        1,
        (),
        id="constant-key-nonlocal",
    ),
    pytest.param(
        "_ATTR = '_phase'\nif choose:\n    _ATTR = 'escape'\ndef stamp(error, value):\n    setattr(error, _ATTR, value)\n",
        True,
        1,
        (),
        id="constant-key-conditional",
    ),
    pytest.param(
        "_ATTR = '_phase'\ndef stamp(error, value):\n    from external import _ATTR\n    setattr(error, _ATTR, value)\n",
        True,
        1,
        (),
        id="constant-key-import-shadow",
    ),
    pytest.param(
        "_ATTR = '_phase'\ndef stamp(error, values):\n    return [setattr(error, _ATTR, value) for _ATTR, value in values]\n",
        True,
        1,
        (),
        id="constant-key-comprehension-shadow",
    ),
    pytest.param(
        "def identity(value, quote=True):\n    return value\n_ATTR = 'escape'\nsetattr(html, _ATTR, identity)\n",
        True,
        1,
        (),
        id="constant-key-module-write-escape",
    ),
    pytest.param(
        "def identity(value, quote=True):\n    return value\nclass Key(str):\n    def __hash__(self):\n        html.escape = identity\n        return str.__hash__(self)\n_ATTR = Key('_phase')\ndef stamp(error, value):\n    setattr(error, _ATTR, value)\n",
        True,
        1,
        (),
        id="constant-key-custom-str",
    ),
    pytest.param(
        "\ndef merge_options(values):\n    merged = argparse.Namespace()\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        0,
        (),
        id="original-empty-loop",
    ),
    pytest.param(
        "\ndef clone_options(run_args):\n    merged = argparse.Namespace(**vars(run_args))\n    return merged\n",
        True,
        0,
        (),
        id="constructor-vars-read",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        0,
        (),
        id="constructor-vars-read-loop",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**{**vars(run_args), **values})\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        0,
        (),
        id="constructor-merged-vars-loop",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**{**vars(run_args), **values})\n    return merged\n",
        True,
        0,
        (),
        id="constructor-merged-vars-no-loop",
    ),
    pytest.param(
        "from argparse import Namespace as NS\n\ndef merge_options(run_args, values):\n    merged = NS(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        0,
        (),
        id="constructor-vars-alias",
    ),
    pytest.param(
        '\ndef merge_options(values):\n    merged = argparse.Namespace(mode="fast")\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n',
        True,
        0,
        (),
        id="constructor-literal-keywords",
    ),
    pytest.param(
        '\ndef merge_options(values):\n    merged = argparse.Namespace(**{"mode": "fast"})\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n',
        True,
        0,
        (),
        id="constructor-literal-mapping",
    ),
    pytest.param(
        "def identity(value, quote=True):\n    return value\nfrom plugin import SwitchingNamespace\n\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\nmerge_options(argparse.Namespace(), {'__class__': SwitchingNamespace, 'escape': identity})\n",
        True,
        1,
        (
            (
                "plugin.py",
                "import argparse\nimport html\nclass SwitchingNamespace(argparse.Namespace):\n    def __setattr__(self, key, value):\n        setattr(html, key, value)\n",
            ),
        ),
        id="constructor-class-switch",
    ),
    pytest.param(
        "def identity(value, quote=True):\n    return value\nfrom plugin import SwitchingNamespace\n\ndef merge_options(values):\n    merged = argparse.Namespace(**{'__class__': SwitchingNamespace, 'escape': identity})\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (
            (
                "plugin.py",
                "import argparse\nimport html\nclass SwitchingNamespace(argparse.Namespace):\n    def __setattr__(self, key, value):\n        setattr(html, key, value)\n",
            ),
        ),
        id="constructor-visible-class-key",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    merged.__dict__ = html.__dict__\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="constructor-dict-escape",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    configure(merged)\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="constructor-receiver-escape",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    alias = merged\n    for key, value in values.items():\n        setattr(alias, key, value)\n    return merged\n",
        True,
        0,
        (),
        id="constructor-receiver-alias",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    merged = html\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="constructor-receiver-rebind",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    values.update(load_values())\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="constructor-mapping-mutation",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\nconfigure(argparse.Namespace)\n",
        True,
        1,
        (),
        id="constructor-provider-escape",
    ),
    pytest.param(
        "def identity(value, quote=True):\n    return value\n\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\nargparse.Namespace.__setattr__ = identity\n",
        True,
        1,
        (),
        id="constructor-native-setter-replaced",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (("argparse.py", "import html\ndef Namespace(**kw):\n    return html\n"),),
        id="constructor-local-argparse",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (("html.py", "def escape(value, quote=True):\n    return value\n"),),
        id="constructor-local-html",
    ),
    pytest.param(
        "def vars(value):\n    html.escape = identity\n    return {}\ndef identity(value, quote=True):\n    return value\n\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="vars-shadow-function",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values, vars):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="vars-shadow-param",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    configure(vars(run_args))\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="vars-mapping-escape",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\nvars(html)['escape'] = identity\ndef identity(value, quote=True):\n    return value\n",
        True,
        1,
        (),
        id="vars-write-module",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    vars(run_args)['escape'] = identity\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\ndef identity(value, quote=True):\n    return value\n",
        True,
        1,
        (),
        id="vars-write-unknown",
    ),
    pytest.param(
        "def read(run_args):\n    return vars(run_args).get('mode')\n",
        True,
        0,
        (),
        id="vars-get-call",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    data = vars(run_args)\n    configure(data)\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="vars-store-and-escape",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\nresult = merge_options(argparse.Namespace(), {})\nconfigure(result)\n",
        True,
        1,
        (),
        id="constructor-assigned-result",
    ),
    pytest.param(
        "\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\nregister(merge_options)\n",
        True,
        1,
        (),
        id="constructor-callback-helper",
    ),
    pytest.param(
        "def identity(value, quote=True):\n    return value\nclass Mapping:\n    def keys(self):\n        html.escape = identity\n        return []\n    def __getitem__(self, key):\n        return None\n\ndef merge_options(values):\n    merged = argparse.Namespace(**Mapping())\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\n",
        True,
        1,
        (),
        id="constructor-custom-mapping",
    ),
    pytest.param(
        "def identity(value, quote=True):\n    return value\nclass Args:\n    def __getattribute__(self, key):\n        html.escape = identity\n        return object.__getattribute__(self, key)\n\ndef merge_options(run_args, values):\n    merged = argparse.Namespace(**vars(run_args))\n    for key, value in values.items():\n        setattr(merged, key, value)\n    return merged\nmerge_options(Args(), {})\n",
        True,
        1,
        (),
        id="constructor-custom-vars-object",
    ),
]


@pytest.mark.parametrize("source,with_render,expected,providers", CASES)
def test_namespace_reads_and_keys_preserve_xss_evidence(
    tmp_path, monkeypatch, source, with_render, expected, providers
):
    if with_render:
        source = RENDER + source
    raw, listed, result = _scan(tmp_path, monkeypatch, source, providers)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([("SKY-D228", "fragment_link", 5, "HIGH")] if expected else [])
    if expected:
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["finding_type"] == "review"
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is (not expected), reasons
