"""Static regression coverage for imports re-exported by local clauses."""

from pathlib import Path

import pytest

from skylos.core import js_api_surface_exports
from skylos.core.js_api_surface import inspect_js_file_api_surface
from skylos.rules.ai_defect.js_api_hallucination import (
    JS_SOURCE_SUFFIXES,
    scan_js_local_api_hallucinations,
)
from skylos.visitors.languages.typescript.core import TypeScriptCore
from skylos.visitors.languages.typescript.resolve import MonorepoResolver


def _create_sources(repo: Path, sources: dict[str, str]):
    for filename, source in sources.items():
        path = repo / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write(source)


def _scan(repo: Path):
    files = sorted(
        path for path in repo.rglob("*") if path.suffix in JS_SOURCE_SUFFIXES
    )
    raw_imports = {}
    for path in files:
        core = TypeScriptCore(str(path), path.read_bytes())
        core.scan()
        if core.raw_imports:
            raw_imports[path] = core.raw_imports
    return scan_js_local_api_hallucinations(
        repo,
        files,
        raw_imports,
        monorepo_resolver=MonorepoResolver(str(repo)),
    )


@pytest.mark.parametrize("suffix", [".ts", ".js"])
def test_import_then_local_export_has_complete_surface(tmp_path, suffix):
    _create_sources(
        tmp_path,
        {
            f"mod{suffix}": "export function foo() { return 'label'; }\n",
            f"index{suffix}": 'import { foo } from "./mod";\nexport { foo };\n',
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, f"index{suffix}")

    assert surface is not None
    assert surface["metadata"]["complete"] is True
    assert surface["exports"] == ["foo"]
    assert surface["members"]["foo"]["kind"] == "function"


@pytest.mark.parametrize("suffix", [".ts", ".js"])
def test_downstream_import_from_local_barrel_is_not_phantom(tmp_path, suffix):
    _create_sources(
        tmp_path,
        {
            f"mod{suffix}": "export function foo() { return 'label'; }\n",
            f"index{suffix}": 'import { foo } from "./mod";\nexport { foo };\n',
            f"app{suffix}": 'import { foo } from "./index";\nfoo();\n',
        },
    )

    findings, coverage = _scan(tmp_path)

    assert findings == []
    assert coverage["status"] == "completed"
    assert coverage["outcome"] == "pass"
    assert coverage["finding_count"] == 0
    assert coverage["verified_references"] == 2
    assert coverage["skipped_references"] == 0


@pytest.mark.parametrize(
    ("suffix", "barrel", "kinds"),
    [
        pytest.param(
            ".ts",
            'import {\n  foo as first,\n  foo as second,\n} from "./mod";\n'
            "export {\n  first as published,\n  second as alternate,\n};\n",
            {"alternate": "function", "published": "function"},
            id="ts-multiline-import-and-export-aliases",
        ),
        pytest.param(
            ".js",
            'import {\n  foo as first,\n  foo as second,\n} from "./mod";\n'
            "export {\n  first as published,\n  second as alternate,\n};\n",
            {"alternate": "function", "published": "function"},
            id="js-multiline-import-and-export-aliases",
        ),
        pytest.param(
            ".ts",
            'export { foo };\nimport { foo } from "./mod";\n',
            {"foo": "function"},
            id="export-before-import",
        ),
        pytest.param(
            ".ts",
            'import { "foo" as local } from "./mod";\nexport { local as foo };\n',
            {"foo": "function"},
            id="quoted-imported-name",
        ),
        pytest.param(
            ".ts",
            'import makeLabel from "./mod";\nexport { makeLabel as labelFactory };\n',
            {"labelFactory": "function"},
            id="default-import-renamed-named-export",
        ),
        pytest.param(
            ".ts",
            'import { default as makeLabel } from "./mod";\n'
            "export { makeLabel as default };\n",
            {"default": "function"},
            id="named-default-import-exported-as-default",
        ),
        pytest.param(
            ".js",
            'import * as localLabels from "./mod";\n'
            "export { localLabels as labels };\n",
            {"labels": "namespace"},
            id="namespace-import-not-flattened",
        ),
        pytest.param(
            ".ts",
            'import type { Widget } from "./mod";\n'
            'import { Label } from "./mod";\n'
            "export { Widget, Label };\n",
            {"Label": "type", "Widget": "type"},
            id="type-only-import-and-upstream-interface",
        ),
        pytest.param(
            ".ts",
            'import { type Widget, foo } from "./mod";\nexport { Widget, foo };\n',
            {"Widget": "type", "foo": "function"},
            id="inline-type-import-does-not-affect-runtime-sibling",
        ),
        pytest.param(
            ".ts",
            'import { Widget, foo } from "./mod";\n'
            "export type { Widget };\nexport { type foo as FactoryType };\n",
            {"FactoryType": "type", "Widget": "type"},
            id="statement-and-specifier-type-only-exports",
        ),
        pytest.param(
            ".ts",
            'import type { Label } from "./mod";\n'
            "const Label = 'label';\nexport { Label };\n",
            {"Label": "variable"},
            id="imported-type-does-not-overwrite-local-runtime-value",
        ),
        pytest.param(
            ".ts",
            'import { Widget } from "./mod";\n'
            "type Widget = string;\nexport { Widget };\n",
            {"Widget": "class"},
            id="imported-runtime-value-supersedes-local-type-alias",
        ),
    ],
)
def test_imported_export_surface_preserves_names_and_kinds(
    tmp_path, suffix, barrel, kinds
):
    module = (
        "export function foo() { return 'label'; }\n"
        "export default function makeLabel() { return 'label'; }\n"
        "export class Widget {}\n"
    )
    if suffix == ".ts":
        module += "export interface Label { text: string }\n"
    _create_sources(tmp_path, {f"mod{suffix}": module, f"index{suffix}": barrel})

    surface = inspect_js_file_api_surface(tmp_path, f"index{suffix}")

    assert surface is not None
    assert surface["exports"] == sorted(kinds)
    assert {
        name: member["kind"] for name, member in surface["members"].items()
    } == kinds
    assert surface["metadata"]["complete"] is True
    assert surface["metadata"]["incomplete_reasons"] == []


def test_unexported_imports_stay_private_without_degrading_surface(tmp_path):
    _create_sources(
        tmp_path,
        {
            "mod.ts": "export function foo() { return 'label'; }\n",
            "index.ts": 'import { unused } from "optional-labels";\n'
            'import { foo } from "./mod";\nexport const published = "label";\n',
            "app.ts": 'import { foo } from "./index";\nfoo();\n',
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")
    findings, coverage = _scan(tmp_path)

    assert surface is not None
    assert surface["exports"] == ["published"]
    assert surface["metadata"]["complete"] is True
    assert [
        (finding["rule_id"], finding["file"], finding["line"], finding["simple_name"])
        for finding in findings
    ] == [("SKY-L012", str(tmp_path / "app.ts"), 1, "foo")]
    assert coverage["finding_count"] == 1


@pytest.mark.parametrize(
    "barrel",
    [
        pytest.param(
            'import { missing as absent } from "./mod";\nexport { absent };\n',
            id="imported-symbol-not-present-in-source",
        ),
        pytest.param("export { absent };\n", id="unknown-local-binding"),
    ],
)
def test_barrel_does_not_invent_nonexistent_bindings(tmp_path, barrel):
    _create_sources(
        tmp_path,
        {
            "mod.ts": "export function foo() { return 'label'; }\n",
            "index.ts": barrel,
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")

    assert surface is not None
    assert surface["exports"] == []
    assert surface["members"] == {}


@pytest.mark.parametrize("source", ["optional-labels", "./missing"])
def test_unresolved_exported_import_makes_surface_incomplete(tmp_path, source):
    _create_sources(
        tmp_path,
        {
            "index.ts": f'import {{ foo }} from "{source}";\nexport {{ foo }};\n',
            "app.ts": 'import { foo } from "./index";\nfoo();\n',
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")
    findings, coverage = _scan(tmp_path)

    assert surface is not None
    assert surface["exports"] == []
    assert surface["metadata"]["complete"] is False
    assert surface["metadata"]["incomplete_reasons"]
    assert findings == []
    assert coverage["finding_count"] == 0
    assert coverage["outcome"] == "incomplete"


def test_chained_import_then_export_barrels_remain_resolvable(tmp_path):
    _create_sources(
        tmp_path,
        {
            "mod.ts": "export function foo() { return 'label'; }\n",
            "middle.ts": 'import { foo as local } from "./mod";\n'
            "export { local as shared };\n",
            "index.ts": 'import { shared as local } from "./middle";\n'
            "export { local as foo };\n",
            "app.ts": 'import { foo } from "./index";\nfoo();\n',
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")
    findings, coverage = _scan(tmp_path)

    assert surface is not None
    assert surface["exports"] == ["foo"]
    assert surface["members"]["foo"]["kind"] == "function"
    assert surface["metadata"]["complete"] is True
    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 3
    assert coverage["skipped_references"] == 0


def test_cyclic_imported_barrels_do_not_claim_complete_absence(tmp_path):
    _create_sources(
        tmp_path,
        {
            "index.ts": 'import { foo } from "./other";\nexport { foo };\n',
            "other.ts": 'import { foo } from "./index";\nexport { foo };\n',
            "app.ts": 'import { foo } from "./index";\nfoo();\n',
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")
    findings, coverage = _scan(tmp_path)

    assert surface is not None
    assert surface["exports"] == []
    assert surface["metadata"]["complete"] is False
    assert surface["metadata"]["incomplete_reasons"]
    assert findings == []
    assert coverage["finding_count"] == 0
    assert coverage["outcome"] == "incomplete"


@pytest.mark.parametrize(
    ("barrel", "kinds"),
    [
        pytest.param(
            'import { type as local } from "./mod";\nexport { local };\n',
            {"local": "variable"},
            id="exported-value-named-type-is-not-a-modifier",
        ),
        pytest.param(
            'import /* label types */ type\n{ Widget } from "./mod";\n'
            "export { Widget };\n",
            {"Widget": "type"},
            id="statement-type-modifier-with-comment-and-newline",
        ),
        pytest.param(
            'import { type/* label type */\n Widget } from "./mod";\n'
            "export { Widget };\n",
            {"Widget": "type"},
            id="specifier-type-modifier-with-comment-and-newline",
        ),
        pytest.param(
            'import Label, { foo as local } from "./mod";\n'
            "export { Label as PublishedLabel, local as published };\n",
            {"PublishedLabel": "class", "published": "function"},
            id="mixed-default-and-named-import-clause",
        ),
        pytest.param(
            'import type * as Labels from "./mod";\nexport { Labels };\n',
            {"Labels": "type"},
            id="type-only-namespace-import",
        ),
        pytest.param(
            'import type Label from "./mod";\nexport { Label };\n',
            {"Label": "type"},
            id="type-only-default-import",
        ),
    ],
)
def test_barrel_type_modifiers_follow_syntax_not_identifier_text(
    tmp_path, barrel, kinds
):
    _create_sources(
        tmp_path,
        {
            "mod.ts": "export const type = 'label';\n"
            "export function foo() { return 'label'; }\n"
            "export class Widget {}\nexport default class Label {}\n",
            "index.ts": barrel,
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")

    assert surface is not None
    assert surface["exports"] == sorted(kinds)
    assert {
        name: member["kind"] for name, member in surface["members"].items()
    } == kinds
    assert surface["metadata"]["complete"] is True
    assert surface["metadata"]["incomplete_reasons"] == []


def test_many_local_exports_read_their_shared_source_only_once(tmp_path, monkeypatch):
    names = [f"label{index}" for index in range(30)]
    clause = ", ".join(names)
    _create_sources(
        tmp_path,
        {
            "mod.ts": "".join(
                f"export function {name}() {{ return 'label'; }}\n" for name in names
            ),
            "index.ts": f'import {{ {clause} }} from "./mod";\n'
            f"export {{ {clause} }};\n",
        },
    )
    original_read = js_api_surface_exports.read_text_no_symlink
    source_path = (tmp_path / "mod.ts").resolve()
    source_reads = 0

    def counted_read(path, *args, **kwargs):
        nonlocal source_reads
        if Path(path) == source_path:
            source_reads += 1
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(js_api_surface_exports, "read_text_no_symlink", counted_read)

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")

    assert surface is not None
    assert surface["exports"] == sorted(names)
    assert all(member["kind"] == "function" for member in surface["members"].values())
    assert surface["metadata"]["complete"] is True
    assert source_reads == 1


def test_unsupported_local_export_named_type_does_not_prove_absence(tmp_path):
    # The current parser produces an ERROR for this contextual-keyword export.
    # Keep its surface incomplete instead of inventing a complete empty API.
    _create_sources(
        tmp_path,
        {
            "mod.ts": "export function foo() { return 'label'; }\n",
            "index.ts": 'import { foo as type } from "./mod";\nexport { type };\n',
            "app.ts": 'import { type as readLabel } from "./index";\nreadLabel();\n',
        },
    )

    surface = inspect_js_file_api_surface(tmp_path, "index.ts")
    findings, coverage = _scan(tmp_path)

    assert surface is not None
    assert surface["exports"] == []
    assert surface["metadata"]["complete"] is False
    assert "parse_error" in surface["metadata"]["incomplete_reasons"]
    assert findings == []
    assert coverage["finding_count"] == 0
    assert coverage["outcome"] == "incomplete"


@pytest.mark.parametrize(
    ("module_path", "package_files"),
    [
        pytest.param("mod.cjs", {}, id="cjs-extension"),
        pytest.param("mod.cts", {}, id="cts-extension"),
        pytest.param(
            "mod.js",
            {"package.json": '{"type":"commonjs"}\n'},
            id="root-commonjs-package",
        ),
        pytest.param(
            "nested/mod.js",
            {
                "package.json": '{"type":"module"}\n',
                "nested/package.json": '{"type":"commonjs"}\n',
            },
            id="nested-commonjs-package-overrides-root",
        ),
    ],
)
def test_commonjs_implicit_default_survives_local_barrel_export(
    tmp_path, module_path, package_files
):
    _create_sources(
        tmp_path,
        {
            **package_files,
            module_path: "const label = 1;\n",
            "index.ts": f'import labels from "./{module_path}";\nexport {{ labels }};\n',
            "app.ts": 'import { labels } from "./index";\n',
        },
    )

    source_surface = inspect_js_file_api_surface(tmp_path, module_path)
    barrel_surface = inspect_js_file_api_surface(tmp_path, "index.ts")
    findings, coverage = _scan(tmp_path)

    assert source_surface is not None
    assert source_surface["exports"] == ["default"]
    assert source_surface["members"]["default"]["kind"] == "commonjs"
    assert source_surface["metadata"]["complete"] is True
    assert barrel_surface is not None
    assert barrel_surface["exports"] == ["labels"]
    assert barrel_surface["members"]["labels"]["kind"] == "commonjs"
    assert barrel_surface["metadata"]["complete"] is True
    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 2
    assert coverage["skipped_references"] == 0


@pytest.mark.parametrize(
    ("module_path", "package_type"),
    [
        pytest.param("mod.mjs", "commonjs", id="mjs-overrides-commonjs-package"),
        pytest.param("mod.js", "module", id="js-in-module-package"),
    ],
)
def test_esm_source_does_not_invent_implicit_default(
    tmp_path, module_path, package_type
):
    _create_sources(
        tmp_path,
        {
            "package.json": f'{{"type":"{package_type}"}}\n',
            module_path: "const label = 1;\n",
            "index.ts": f'import labels from "./{module_path}";\nexport {{ labels }};\n',
        },
    )

    source_surface = inspect_js_file_api_surface(tmp_path, module_path)
    barrel_surface = inspect_js_file_api_surface(tmp_path, "index.ts")

    assert source_surface is not None
    assert source_surface["exports"] == []
    assert source_surface["metadata"]["complete"] is True
    assert barrel_surface is not None
    assert barrel_surface["exports"] == []
    assert barrel_surface["members"] == {}


def test_many_barrel_consumers_keep_only_genuine_missing_name_finding(tmp_path):
    names = [f"label{index}" for index in range(30)]
    clause = ", ".join(names)
    sources = {
        "mod.ts": "".join(
            f"export function {name}() {{ return 'label'; }}\n" for name in names
        ),
        "index.ts": f'import {{ {clause} }} from "./mod";\nexport {{ {clause} }};\n',
    }
    for index in range(4):
        imported_names = clause if index < 3 else f"{clause}, missingLabel"
        sources[f"consumer{index}.ts"] = (
            f'import {{ {imported_names} }} from "./index";\n'
        )
    _create_sources(tmp_path, sources)

    findings, coverage = _scan(tmp_path)

    assert [
        (finding["rule_id"], finding["file"], finding["line"], finding["simple_name"])
        for finding in findings
    ] == [("SKY-L012", str(tmp_path / "consumer3.ts"), 1, "missingLabel")]
    assert coverage["status"] == "completed"
    assert coverage["outcome"] == "fail"
    assert coverage["finding_count"] == 1
    assert coverage["references"] == 151
    assert coverage["verified_references"] == 150
    assert coverage["skipped_references"] == 0
