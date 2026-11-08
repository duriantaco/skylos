"""Positive API-shape reads propagate through resolved re-export bindings."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


def _write(root, name, source):
    target = root / name
    target.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324]


def _scan(root):
    result = json.loads(
        analyze(
            str(root),
            conf=0,
            grep_verify=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return result


def _unused(result, filename="library.ts"):
    return {
        item["name"]
        for category in ("unused_functions", "unused_exports", "unused_variables")
        for item in result.get(category, [])
        if Path(item["file"]).name == filename
    }


@pytest.mark.parametrize("hops", [1, 3, 25])
@pytest.mark.parametrize("read", ["dynamic", "namespace"])
def test_enumerated_namespace_keeps_forwarded_aliases_and_unused_sibling(
    tmp_path, hops, read
):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"main":"./generated.js","scripts":{"start":"node index.ts"}}',
    )
    body = (
        'Object.keys(await import("./barrel")).sort();'
        if read == "dynamic"
        else 'import * as api from "./barrel"; Object.keys(api).sort();'
    )
    _write(tmp_path, "index.ts", body)
    _write(tmp_path, "barrel.ts", 'export * from "./hop0";')
    for index in range(hops):
        source = f"./hop{index + 1}" if index < hops - 1 else "./library"
        _write(tmp_path, f"hop{index}.ts", f'export * from "{source}";')
    _write(
        tmp_path,
        "library.ts",
        "export function create() {}\nexport const firstAlias = create;\nexport const secondAlias = create;\nfunction spare() {}\n",
    )
    assert _unused(_scan(tmp_path)) == {"spare"}


def test_positive_read_propagates_through_star_cycle(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"main":"./generated.js","scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path, "index.ts", 'Object.keys(await import("./barrel"));')
    _write(tmp_path, "barrel.ts", 'export * from "./library";')
    _write(
        tmp_path,
        "library.ts",
        'export * from "./barrel"; export function create() {}\nexport const chosen = create;',
    )
    assert _unused(_scan(tmp_path)) == set()


@pytest.mark.parametrize("named", [False, True])
def test_positive_star_read_excludes_default_unless_explicitly_renamed(tmp_path, named):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"main":"./generated.js","scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path, "index.ts", 'Object.keys(await import("./barrel"));')
    _write(tmp_path, "barrel.ts", 'export * from "./bridge";')
    _write(
        tmp_path,
        "bridge.ts",
        'export {default as chosen} from "./library";'
        if named
        else 'export * from "./library";',
    )
    _write(tmp_path, "library.ts", "export default function launch() {}\n")
    assert _unused(_scan(tmp_path)) == (set() if named else {"launch"})


def test_ambiguous_star_names_do_not_gain_references_from_key_enumeration(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"main":"./generated.js","scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path, "index.ts", 'Object.keys(await import("./barrel"));')
    _write(tmp_path, "barrel.ts", 'export * from "./one"; export * from "./two";')
    _write(tmp_path, "one.ts", "export function collided() {}")
    _write(tmp_path, "two.ts", "export function collided() {}")
    result = _scan(tmp_path)
    assert _unused(result, "one.ts") == {"collided"}
    assert _unused(result, "two.ts") == {"collided"}


def test_explicit_export_shadows_a_same_named_star_export(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"main":"./generated.js","scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path, "index.ts", 'Object.keys(await import("./barrel"));')
    _write(
        tmp_path, "barrel.ts", 'export {selected} from "./one"; export * from "./two";'
    )
    _write(tmp_path, "one.ts", "export function selected() {}")
    _write(tmp_path, "two.ts", "export function selected() {}")
    result = _scan(tmp_path)
    assert _unused(result, "one.ts") == set()
    assert _unused(result, "two.ts") == {"selected"}


def test_unknown_star_provider_does_not_invent_positive_binding_evidence():
    from skylos.visitors.base import Definition
    from skylos.visitors.languages.typescript.reexport_demand import (
        add_enumerated_reexport_reads,
    )

    definition = Definition("chosen", "function", "/source/library.ts", 1)
    definition.is_exported = True
    imports = {
        "/source/barrel.ts": [
            {"source": "./library", "names": ["*"], "is_reexport": True},
            {"source": "./missing", "names": ["*"], "is_reexport": True},
        ]
    }
    from collections import defaultdict

    add_enumerated_reexport_reads(
        imports,
        {"chosen": definition},
        lambda source, importer: (
            "/source/library.ts" if source == "./library" else None
        ),
        {"/source/barrel.ts"},
        defaultdict(set),
    )
    # The unknown provider might conflict with chosen. Declining this additional
    # positive proof does not assert that the actual binding is unused.
    assert definition.references == 0


def test_exhausted_positive_binding_budget_preserves_prior_reference_state(monkeypatch):
    from collections import defaultdict
    from skylos.visitors.base import Definition
    from skylos.visitors.languages.typescript import reexport_demand

    definition = Definition("chosen", "function", "/source/library.ts", 1)
    definition.is_exported = True
    definition.references = 3
    monkeypatch.setattr(reexport_demand, "_MAX_EXPORT_DEMAND_ITEMS", 0)
    reexport_demand.add_enumerated_reexport_reads(
        {
            "/source/barrel.ts": [
                {"source": "./library", "names": ["*"], "is_reexport": True}
            ]
        },
        {"chosen": definition},
        lambda source, importer: "/source/library.ts",
        {"/source/barrel.ts"},
        defaultdict(set),
    )
    assert definition.references == 3


@pytest.mark.parametrize("signal", ["type-only declaration", "ambient declaration"])
def test_key_enumeration_does_not_read_erased_type_declarations(signal):
    from collections import defaultdict
    from skylos.visitors.base import Definition
    from skylos.visitors.languages.typescript.reexport_demand import (
        add_enumerated_reexport_reads,
    )

    definition = Definition("Contract", "class", "/source/library.ts", 1)
    definition.is_exported = True
    definition.framework_signals.append(signal)
    add_enumerated_reexport_reads(
        {
            "/source/barrel.ts": [
                {"source": "./library", "names": ["*"], "is_reexport": True}
            ]
        },
        {"Contract": definition},
        lambda source, importer: "/source/library.ts",
        {"/source/barrel.ts"},
        defaultdict(set),
    )
    assert definition.references == 0


def test_local_export_shadows_star_binding_during_key_enumeration(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"type":"module","main":"./generated.mjs","scripts":{"start":"node index.mjs"}}',
    )
    _write(tmp_path, "index.mjs", 'Object.keys(await import("./barrel.mjs"));')
    _write(
        tmp_path,
        "barrel.mjs",
        'function chosen() {}\nexport {chosen};\nexport * from "./library.mjs";',
    )
    _write(
        tmp_path,
        "library.mjs",
        "export function chosen() {}\nexport function spare() {}",
    )
    assert _unused(_scan(tmp_path), "library.mjs") == {"chosen", "spare"}
