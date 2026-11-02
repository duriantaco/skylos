"""Unsafe import identity must remain a reason to reject an XSS proof."""

import pytest

from skylos.core.gatekeeper import check_gate
from test.test_namespace_write_boundaries import MERGE, RENDER, _scan
from test.test_xss_namespace_effect_boundaries import COPY


@pytest.mark.parametrize(
    "prefix,expected,copy",
    [
        pytest.param(
            "import importlib as loader\nimport importlib as loader\n"
            "from plugin import replacement\nkey = 'import_module'\n"
            "setattr(loader, key, replacement)\n",
            1,
            COPY,
            id="repeated-import",
        ),
        pytest.param(
            "import decimal as loader\nimport importlib as loader\n"
            "from plugin import replacement\nkey = 'import_module'\n"
            "setattr(loader, key, replacement)\n",
            1,
            COPY,
            id="conflicting-imports",
        ),
        pytest.param(
            "import importlib as loader\nfrom plugin import replacement\n"
            "def install():\n    global loader\n"
            "    key = 'import_module'\n    setattr(loader, key, replacement)\n",
            1,
            COPY,
            id="global-import-owner",
        ),
        pytest.param(
            "from plugin import replacement\ndef outer():\n"
            "    import importlib as loader\n    def install():\n"
            "        nonlocal loader\n        key = 'import_module'\n"
            "        setattr(loader, key, replacement)\n",
            1,
            COPY,
            id="nonlocal-import-owner",
        ),
        pytest.param(
            "import importlib as loader\nfrom plugin import replacement\n"
            "def install(loader=loader):\n    key = 'import_module'\n"
            "    setattr(loader, key, replacement)\ninstall()\n",
            1,
            COPY,
            id="outer-import-captured-by-default",
        ),
        pytest.param(
            "import importlib as loader\nfrom plugin import replacement\n"
            "def install(*, loader=loader):\n    key = 'import_module'\n"
            "    setattr(loader, key, replacement)\ninstall()\n",
            1,
            COPY,
            id="outer-import-captured-by-keyword-default",
        ),
        *[
            pytest.param(
                f"import sys\nsys.{attribute} = {{}}\n",
                1,
                COPY,
                id=f"system-{attribute}-replaced",
            )
            for attribute in ("path", "meta_path", "modules")
        ],
        *[
            pytest.param(
                f"from {module} import {name} as factory\n"
                "from plugin import replacement\nkey = '_phase'\n"
                "setattr(factory, key, replacement)\n",
                1,
                COPY,
                id=f"masked-{module}-{name}",
            )
            for module, name in (
                ("operator", "attrgetter"),
                ("operator", "methodcaller"),
                ("types", "new_class"),
            )
        ],
        pytest.param(
            "setattr(html, '_phase', 'ready')\nconfigure(html)\n",
            1,
            COPY,
            id="mutated-sanitizer-module-escapes",
        ),
        pytest.param(
            "import importlib as loader\ndef stamp(loader):\n"
            "    setattr(loader, '_phase', 'ready')\n",
            0,
            MERGE,
            id="parameter-shadows-import",
        ),
        pytest.param(
            "import importlib as loader\nloader = 'plain'\nprint(loader)\n",
            0,
            MERGE,
            id="literal-rebinding-before-read",
        ),
        pytest.param(
            "import importlib as loader\nloader = 'plain'; print(loader)\n",
            0,
            MERGE,
            id="same-line-literal-rebinding-before-read",
        ),
        pytest.param(
            "import importlib as loader; loader = 'plain'; print(loader)\n",
            0,
            MERGE,
            id="same-line-import-and-literal-rebinding-before-read",
        ),
        pytest.param(
            "setattr(html, '_phase', 'ready')\n",
            0,
            MERGE,
            id="unrelated-literal-module-metadata",
        ),
        pytest.param(
            "html._phase = 'ready'\n",
            0,
            MERGE,
            id="unrelated-direct-module-metadata",
        ),
        *[
            pytest.param(
                "import importlib as loader\nmarkers = " + expression + "\n",
                0,
                MERGE,
                id=f"{kind}-comprehension-shadows-import",
            )
            for kind, expression in (
                ("list", "[loader for loader in ('plain',)]"),
                ("set", "{loader for loader in ('plain',)}"),
                ("dict", "{loader: loader for loader in ('plain',)}"),
            )
        ],
        pytest.param(
            "def install():\n    import importlib as loader\n"
            "    markers = [loader for loader in configure(loader)]\n",
            1,
            COPY,
            id="first-iterable-uses-outer-import",
        ),
    ],
)
def test_import_hazards_do_not_become_sanitizer_proofs(
    tmp_path, monkeypatch, prefix, expected, copy
):
    # Keep the renderer's binding independent of module metadata writes.
    render = RENDER.replace(
        "import html\n", "import html\nfrom html import escape as esc\n"
    ).replace("html.escape(", "esc(")
    raw, listed, result = _scan(tmp_path, monkeypatch, render + prefix + copy)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([("SKY-D228", "fragment_link", 6, "HIGH")] if expected else [])
    if listed:
        assert listed[0]["finding_type"] == "review"
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is (not expected), reasons


@pytest.mark.parametrize(
    "signature",
    [
        "marker=setattr(html, key, replacement)",
        "*, marker=setattr(html, key, replacement)",
        "marker: setattr(html, key, replacement)",
    ],
    ids=["default", "keyword-default", "annotation"],
)
@pytest.mark.parametrize(
    "outer,inner,expected",
    [("escape", "_phase", 1), ("_phase", "escape", 0)],
    ids=["replaces-escape", "unrelated-metadata"],
)
def test_literal_keys_in_headers_use_the_enclosing_scope(
    tmp_path, monkeypatch, signature, outer, inner, expected
):
    source = (
        "import argparse\nimport html\nfrom plugin import replacement\n"
        f"key = {outer!r}\ndef tag({signature}):\n    key = {inner!r}\n"
        "from html import escape\n\n"
        "def fragment_link(name):\n    return (\n"
        "        f'<a href=\"#{escape(name, quote=True)}\">'\n"
        "        f'<code>{escape(name, quote=True)}</code></a>'\n    )\n"
    ) + COPY
    raw, listed, result = _scan(tmp_path, monkeypatch, source)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([("SKY-D228", "fragment_link", 10, "HIGH")] if expected else [])
    if listed:
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is (not expected), reasons


@pytest.mark.parametrize(
    "depth,native,escape,expected",
    [
        (17, False, False, 0),
        (40, False, False, 0),
        (17, True, False, 0),
        (17, True, True, 1),
    ],
    ids=["scalar-17", "scalar-40", "native-metadata-17", "native-escape-17"],
)
def test_long_alias_chains_keep_data_and_native_capabilities_distinct(
    tmp_path, monkeypatch, depth, native, escape, expected
):
    prefix = "a0 = html\n" if native else "a0 = 'plain'\n"
    prefix += "".join(f"a{i} = a{i - 1}\n" for i in range(1, depth + 1))
    if escape:
        prefix += f"configure(a{depth})\n"
    elif native:
        prefix += f"setattr(a{depth}, '_phase', 'ready')\n"
    else:
        prefix += f"print(a{depth})\n"
    render = RENDER.replace(
        "import html\n", "import html\nfrom html import escape as esc\n"
    ).replace("html.escape(", "esc(")
    raw, listed, result = _scan(
        tmp_path, monkeypatch, render + prefix + (COPY if escape else MERGE)
    )
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([("SKY-D228", "fragment_link", 6, "HIGH")] if expected else [])
    if listed:
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is (not expected), reasons


@pytest.mark.parametrize("attribute_write", [False, True], ids=["setter", "attribute"])
def test_module_namespace_rebinding_invalidates_native_metadata_proof(
    tmp_path, monkeypatch, attribute_write
):
    prefix = (
        "import app as current\nimport html as holder\nfrom plugin import replacement\n"
    )
    prefix += (
        "current.holder = replacement\n"
        if attribute_write
        else "setattr(current, 'holder', replacement)\n"
    )
    prefix += "setattr(holder, '_phase', 'ready')\n"
    render = RENDER.replace(
        "import html\n", "import html\nfrom html import escape as esc\n"
    ).replace("html.escape(", "esc(")
    raw, listed, result = _scan(tmp_path, monkeypatch, render + prefix + COPY)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == [("SKY-D228", "fragment_link", 6, "HIGH")]
    assert listed[0]["listing"]["listed"] is True
    assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is False, reasons


@pytest.mark.parametrize(
    "capture_first", [True, False], ids=["before-rebind", "after-rebind"]
)
def test_native_alias_capture_keeps_the_identity_at_its_assignment(
    tmp_path, monkeypatch, capture_first
):
    prefix = (
        "import app as current\nimport html as holder\nfrom plugin import replacement\n"
    )
    if capture_first:
        prefix += "saved = holder\n"
    prefix += "setattr(current, 'holder', replacement)\n"
    if not capture_first:
        prefix += "saved = holder\n"
    prefix += "setattr(saved, '_phase', 'ready')\n"
    render = RENDER.replace(
        "import html\n", "import html\nfrom html import escape as esc\n"
    ).replace("html.escape(", "esc(")
    raw, listed, result = _scan(
        tmp_path, monkeypatch, render + prefix + (MERGE if capture_first else COPY)
    )
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([] if capture_first else [("SKY-D228", "fragment_link", 6, "HIGH")])
    if listed:
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is capture_first, reasons


def test_an_opaque_setter_cannot_be_treated_as_a_literal_module_write(
    tmp_path, monkeypatch
):
    prefix = (
        "import app as current\nfrom plugin import setattr, replacement\n"
        "setattr(current, 'marker', replacement)\n"
    )
    clone = "def clone(run_args):\n    return argparse.Namespace(**vars(run_args))\n"
    render = RENDER.replace(
        "import html\n", "import html\nfrom html import escape as esc\n"
    ).replace("html.escape(", "esc(")
    raw, listed, result = _scan(tmp_path, monkeypatch, render + prefix + clone)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == [("SKY-D228", "fragment_link", 6, "HIGH")]
    assert listed[0]["listing"]["listed"] is True
    assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is False, reasons


@pytest.mark.parametrize(
    "prefix",
    [
        "import app as current\nimport html as holder\ncurrent.holder: object\nsetattr(holder, '_phase', 'ready')\n",
        "import html as holder\nholder: object\nsetattr(holder, '_phase', 'ready')\n",
        "def stamp():\n    import html as holder\n    holder: object\n    setattr(holder, '_phase', 'ready')\n",
        "def stamp():\n    holder: object\n    configure(holder)\n",
    ],
    ids=[
        "attribute-declaration",
        "module-declaration",
        "existing-local-import",
        "unbound-local-shadow",
    ],
)
def test_annotations_without_values_do_not_replace_native_bindings(
    tmp_path, monkeypatch, prefix
):
    render = RENDER.replace(
        "import html\n", "import html\nfrom html import escape as esc\n"
    ).replace("html.escape(", "esc(")
    raw, listed, result = _scan(tmp_path, monkeypatch, render + prefix + MERGE)
    assert raw == listed == []
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is True, reasons


@pytest.mark.parametrize(
    "prefix,expected,copy",
    [
        pytest.param(
            "import app as current\nprint(current)\n", 0, MERGE, id="builtin-reader"
        ),
        pytest.param(
            "import app as current\ndef print(module):\n    pass\nprint(current)\n",
            0,
            MERGE,
            id="owned-inert-reader",
        ),
        pytest.param(
            "import app as current\nfrom plugin import print\nprint(current)\n",
            1,
            "def clone(run_args):\n    return argparse.Namespace(**vars(run_args))\n",
            id="opaque-reader",
        ),
        pytest.param(
            "import app as current\nfrom plugin import print\ndef log(current):\n    print(current)\n",
            0,
            MERGE,
            id="ordinary-parameter-shadow",
        ),
        pytest.param(
            "import app as current\nfrom plugin import print\ndef log(current):\n    print(current)\nlog(current)\n",
            1,
            COPY,
            id="visible-module-caller",
        ),
        pytest.param(
            "import app as current\nisinstance(current, object)\n",
            0,
            MERGE,
            id="builtin-type-spec",
        ),
        pytest.param(
            "import app as current\nimport types\nisinstance(current, types.ModuleType)\n",
            0,
            MERGE,
            id="native-module-type-spec",
        ),
        pytest.param(
            "import app as current\nfrom types import ModuleType as MT\nisinstance(current, MT)\n",
            0,
            MERGE,
            id="native-module-type-alias",
        ),
        pytest.param(
            "import app as current\nfrom plugin import Checker\nisinstance(current, Checker)\n",
            1,
            COPY,
            id="opaque-instance-check",
        ),
        pytest.param(
            "import app as current\nfrom plugin import replacement\n__dir__ = replacement\ndir(current)\n",
            1,
            COPY,
            id="opaque-dir-hook",
        ),
        pytest.param(
            "import app as current\n__dir__ = None\ndir(current)\n",
            0,
            MERGE,
            id="inert-dir-field",
        ),
        pytest.param(
            "import app as current\ndef __dir__():\n    return []\ndir(current)\n",
            0,
            MERGE,
            id="owned-inert-dir-hook",
        ),
        pytest.param(
            "import app as current\nfrom plugin import replacement\n__spec__ = replacement\nprint(current)\n",
            1,
            COPY,
            id="opaque-module-spec",
        ),
        pytest.param(
            "import app as current\n__spec__ = None\nprint(current)\n",
            0,
            MERGE,
            id="inert-module-spec",
        ),
        pytest.param(
            "import app as current\nfrom plugin import replacement\n"
            "def print(module):\n    pass\n"
            "def stamp(error):\n    setattr(error, 'print', replacement)\n"
            "print(current)\n",
            0,
            MERGE,
            id="unrelated-object-metadata-keeps-inert-reader",
        ),
        pytest.param(
            "import app as current\nfrom plugin import replacement\n"
            "def print(module):\n    pass\n"
            "def stamp(error):\n    setattr(current, 'print', replacement)\n"
            "print(current)\n",
            1,
            COPY,
            id="module-rebinding-invalidates-inert-reader",
        ),
        *[
            pytest.param(
                "import app as current\nfrom plugin import payload\n"
                "def inspect(choose):\n    spec = current.__spec__\n"
                "    if choose:\n        spec = None\n"
                "    spec.origin = None\n"
                f"    spec.loader = {loader}\n    print(current)\n",
                expected,
                copy,
                id=f"ambiguous-metadata-{loader}",
            )
            for loader, expected, copy in (("payload", 1, COPY), ("None", 0, MERGE))
        ],
        *[
            pytest.param(
                "import app as current\nfrom plugin import payload\n"
                "def inspect(choose):\n"
                "    spec = current.__spec__ if choose else None\n"
                "    spec.origin = None\n"
                f"    spec.loader = {loader}\n    print(current)\n",
                expected,
                COPY,
                id=f"conditional-metadata-{loader}",
            )
            for loader, expected in (("payload", 1), ("None", 0))
        ],
        *[
            pytest.param(
                "import app as current\nfrom plugin import payload\n"
                "def inspect(choose):\n"
                "    if (spec := current.__spec__):\n        pass\n"
                "    spec.origin = None\n"
                f"    spec.loader = {loader}\n    print(current)\n",
                expected,
                COPY if expected else MERGE,
                id=f"walrus-metadata-{loader}",
            )
            for loader, expected in (("payload", 1), ("None", 0))
        ],
    ],
)
def test_module_read_calls_need_actual_read_only_behavior(
    tmp_path, monkeypatch, prefix, expected, copy
):
    render = RENDER.replace(
        "import html\n", "import html\nfrom html import escape as esc\n"
    ).replace("html.escape(", "esc(")
    raw, listed, result = _scan(tmp_path, monkeypatch, render + prefix + copy)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([("SKY-D228", "fragment_link", 6, "HIGH")] if expected else [])
    if listed:
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is (not expected), reasons


@pytest.mark.parametrize(
    "definition",
    [
        "def tag(marker=(key := 'escape')):\n    pass\n",
        "class Tag((key := 'escape') and object):\n    pass\n",
    ],
    ids=["function-default", "class-base"],
)
def test_header_walrus_writes_invalidate_the_enclosing_literal_key(
    tmp_path, monkeypatch, definition
):
    source = (
        "import argparse\nimport html\nfrom plugin import replacement\n"
        "key = '_phase'\n"
        + definition
        + "setattr(html, key, replacement)\nfrom html import escape\n\n"
        "def fragment_link(name):\n    return (\n"
        "        f'<a href=\"#{escape(name, quote=True)}\">'\n"
        "        f'<code>{escape(name, quote=True)}</code></a>'\n    )\n"
    ) + COPY
    raw, listed, result = _scan(tmp_path, monkeypatch, source)
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == [("SKY-D228", "fragment_link", 11, "HIGH")]
    assert listed[0]["listing"]["listed"] is True
    assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is False, reasons


@pytest.mark.parametrize(
    "exports,peer,expected",
    [
        ("", "from plugin import mutate\nmutate(app)\n", 1),
        ("cfg = html\n", "from plugin import mutate\nmutate(app.cfg)\n", 1),
        ("VERSION = 'plain'\n", "print(app.VERSION)\n", 0),
        ("cfg = html\n", "print(app.cfg)\n", 0),
        (
            "cfg = html\n",
            "from plugin import mutate\ndef forward(choose):\n"
            "    alias = app.cfg\n    if choose:\n        alias = None\n"
            "    mutate(alias)\n",
            1,
        ),
        (
            "cfg = html\n",
            "from plugin import mutate\ndef forward(choose):\n"
            "    alias = app.cfg\n    mutate(alias)\n",
            1,
        ),
    ],
    ids=[
        "opaque-module",
        "opaque-export",
        "plain-data",
        "builtin-module-reader",
        "ambiguous-export-alias",
        "stable-export-alias",
    ],
)
def test_peer_module_capabilities_keep_opaque_calls_separate_from_data_reads(
    tmp_path, monkeypatch, exports, peer, expected
):
    raw, listed, result = _scan(
        tmp_path,
        monkeypatch,
        RENDER + exports + MERGE,
        providers=(("peer.py", "import app\n" + peer),),
    )
    for findings in (raw, listed):
        assert [
            (row["rule_id"], row["symbol"], row["line"], row["severity"])
            for row in findings
        ] == ([("SKY-D228", "fragment_link", 5, "HIGH")] if expected else [])
    if listed:
        assert listed[0]["listing"]["listed"] is True
        assert listed[0]["metadata"]["security_trace"]
    passed, reasons = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is (not expected), reasons
