"""A narrow local type-provider proof is required before proposing TS edits."""

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from skylos.cleanup_typescript import (
    MAX_PROOF_BYTES,
    plan_typescript_unused_import,
    revalidate_typescript_dependencies,
    typescript_import_anchor_present,
)


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"strict":true,"module":"ESNext"}}'
    )
    (tmp_path / "types.ts").write_text(
        "export interface Shape { value: string; count?: number }\n"
    )
    source = b"import type { Shape } from './types';\nexport {};\nconst count = 3;\n"
    return tmp_path, source


def task(root, source, *, name="Shape", line=1, file="consumer.ts"):
    (root / file).parent.mkdir(parents=True, exist_ok=True)
    (root / file).write_bytes(source)
    return {
        "id": "a" * 64,
        "rule_id": "SKY-U002",
        "category": "dead_code",
        "file": file,
        "line": line,
        "name": name,
        "source_sha256": sha256(source).hexdigest(),
        "finding": {"name": name, "file": str(root / file), "line": line},
    }


def plan(workspace, **kwargs):
    root, source = workspace
    return plan_typescript_unused_import(task(root, source, **kwargs), root, source)


def test_unused_local_structural_type_produces_patch_and_dependency_hashes(workspace):
    root, source = workspace
    finding = task(root, source)
    original = deepcopy(finding)
    result = plan_typescript_unused_import(finding, root, source)
    assert result["replacement"] == "export {};\nconst count = 3;\n"
    assert result["binding"] == {
        "imported": "Shape",
        "local": "Shape",
        "module": "./types",
        "line": 1,
    }
    assert result["provider_hashes"] == {
        "types.ts": sha256((root / "types.ts").read_bytes()).hexdigest()
    }
    assert result["resolution_hashes"]["types.d.ts"] is None
    assert result["resolution_hashes"]["tsconfig.json"]
    assert json.loads(result["target_anchor"])["kind"] == "typescript_import_type"
    assert "no compiler" in result["limitations"][0]
    assert (root / "consumer.ts").read_bytes() == source and finding == original
    revalidate_typescript_dependencies(root, result)


@pytest.mark.parametrize(
    "file,source,line,name",
    [
        (
            "consumer.ts",
            b"import type { Shape as Local } from './types.ts';\nexport {};\n",
            1,
            "Local",
        ),
        (
            "consumer.ts",
            b"import type {\n Shape\n} from './types';\nexport {};\n",
            2,
            "Shape",
        ),
        (
            "consumer.tsx",
            b"import type { Shape } from './types';\nexport const view = <div />;\n",
            1,
            "Shape",
        ),
        (
            "consumer.ts",
            b"// ordinary context\r\nimport type {Shape} from './types';\r\nexport {};\r\n",
            2,
            "Shape",
        ),
    ],
)
def test_alias_multiline_tsx_and_crlf_preserve_unrelated_source(
    workspace, file, source, line, name
):
    root, _ = workspace
    result = plan_typescript_unused_import(
        task(root, source, file=file, line=line, name=name), root, source
    )
    assert "import type" not in result["replacement"]
    assert "export " in result["replacement"]
    if b"\r\n" in source:
        assert result["replacement"] == "// ordinary context\r\nexport {};\r\n"


@pytest.mark.parametrize(
    "provider",
    [
        "export type Shape = string | null;",
        "export type Shape = {readonly value: string; count?: number[]};",
        "export interface Shape {value: string;}\nexport type Another = number;",
    ],
)
def test_direct_predefined_and_structural_type_providers_are_supported(
    workspace, provider
):
    root, _ = workspace
    (root / "types.ts").write_text(provider)
    assert plan(workspace)["provider_hashes"]["types.ts"]


@pytest.mark.parametrize(
    "provider",
    [
        "export type Shape = Other;",
        "export type Other = string; export type Shape = Other;",
        "export interface Shape extends Other {}",
        "export interface Shape {value: Date}",
        "export interface Shape<T> {value:T}",
        "export type Shape = typeof globalThis;",
        "export type Shape = import('./augment').Shape;",
        "import './augment'; export interface Shape {}",
        "import type {Other} from './other'; export interface Shape {}",
        "declare global {interface Window {extra:number}} export interface Shape {}",
        "declare module 'external' {interface Extra {}} export interface Shape {}",
        "export namespace Shape {export type Value = string}",
        "export {Shape} from './other';",
        "export default interface Shape {}",
        "/// <reference path='./ambient.d.ts' />\nexport interface Shape {}",
        "/* provider note */ export interface Shape {}",
        "export interface Different {}",
        "export interface Shape {} export interface Shape {}",
        "console.log('side effect'); export interface Shape {}",
        "export interface Shape {value:",
    ],
)
def test_provider_dependencies_augmentation_reexports_and_ambiguity_are_refused(
    workspace, provider
):
    root, _ = workspace
    (root / "types.ts").write_text(provider)
    with pytest.raises(ValueError):
        plan(workspace)


@pytest.mark.parametrize(
    "tail",
    [
        "type Used = Shape;",
        "let used:Shape;",
        "export type {Shape};",
        "const view = <Shape />;",
        "function shadow(Shape:number) {return Shape;}",
        "const property = {Shape: 3};",
        r"let value: \u0053hape;",
        "/** @type {Shape} */ const value = 3;",
    ],
)
def test_binding_reads_and_ambiguous_name_occurrences_are_refused(workspace, tail):
    root, source = workspace
    source += tail.encode()
    with pytest.raises(ValueError):
        plan_typescript_unused_import(
            task(root, source, file="consumer.tsx"), root, source
        )


@pytest.mark.parametrize(
    "source",
    [
        "import {Shape} from './types';\nexport {};",
        "import {type Shape} from './types';\nexport {};",
        "import type Shape from './types';\nexport {};",
        "import type * as Shape from './types';\nexport {};",
        "import type {Shape, Other} from './types';\nexport {};",
        "import type { /* note */ Shape } from './types';\nexport {};",
        "import type {Shape} from './types';\nconst value = 3;",
        "// @ts-ignore\nimport type {Shape} from './types';\nexport {};",
        "// eslint-disable-next-line\nimport type {Shape} from './types';\nexport {};",
        "import type {Shape} from 'package';\nexport {};",
        "import type {Shape} from '../types';\nexport {};",
        "import type {Shape} from './types';\nexport {",
        "import type {Shape} from './types' with {type:'json'};\nexport {};",
    ],
)
def test_non_explicit_imports_directives_missing_marker_and_bad_syntax_are_refused(
    workspace, source
):
    root, _ = workspace
    encoded = source.encode()
    line = 2 if source.startswith("//") else 1
    with pytest.raises(ValueError):
        plan_typescript_unused_import(task(root, encoded, line=line), root, encoded)


@pytest.mark.parametrize(
    "configuration",
    [
        '{"extends":"./base.json"}',
        '{"extends":[]}',
        '{"references":[{"path":"../other"}]}',
        '{"compilerOptions":{"moduleSuffixes":[".native",""]}}',
        '{"compilerOptions":{"moduleSuffixes":[]}}',
        '{"compilerOptions":{"rootDirs":["src","generated"]}}',
        '{"compilerOptions":{"paths":{"*": ["generated/*"]}}}',
        '{"compilerOptions":{"plugins":[{"name":"custom"}]}}',
        '{"compilerOptions":{"noResolve":true}}',
        '{"compilerOptions":{"module":"NodeNext"}}',
        '{"compilerOptions":{"moduleResolution":"node16"}}',
        '{"compilerOptions":[]}',
        '{"extends":"unsafe","extends":null}',
        "{",
    ],
)
def test_unresolved_or_custom_configuration_is_refused(workspace, configuration):
    root, _ = workspace
    (root / "tsconfig.json").write_text(configuration)
    with pytest.raises(ValueError):
        plan(workspace)


def test_jsonc_configuration_is_read_as_data_without_execution(workspace):
    root, _ = workspace
    (root / "tsconfig.json").write_text(
        '// config comment\n{"compilerOptions":{"strict":true,},}'
    )
    assert plan(workspace)["resolution_hashes"]["tsconfig.json"]


@pytest.mark.parametrize(
    "alternative", ["types.tsx", "types.d.ts", "types.js", "types/index.ts"]
)
def test_multiple_local_module_candidates_are_refused(workspace, alternative):
    root, _ = workspace
    (root / alternative).parent.mkdir(parents=True, exist_ok=True)
    (root / alternative).write_text("export interface Shape {}")
    with pytest.raises(ValueError, match="ambiguous"):
        plan(workspace)


def test_provider_and_configuration_changes_or_new_alternatives_invalidate_preview(
    workspace,
):
    root, _ = workspace
    result = plan(workspace)
    original = (root / "types.ts").read_text()
    (root / "types.ts").write_text("export interface Shape {count: number}")
    with pytest.raises(ValueError, match="changed"):
        revalidate_typescript_dependencies(root, result)
    (root / "types.ts").write_text(original)
    (root / "types.d.ts").write_text("export interface Shape {}")
    with pytest.raises(ValueError, match="changed"):
        revalidate_typescript_dependencies(root, result)
    (root / "types.d.ts").unlink()
    (root / "tsconfig.json").write_text('{"compilerOptions":{"strict":false}}')
    with pytest.raises(ValueError, match="changed"):
        revalidate_typescript_dependencies(root, result)


def test_provider_symlinks_hardlinks_and_large_sources_are_refused(workspace):
    root, _ = workspace
    original = (root / "types.ts").read_text()
    (root / "types.ts").unlink()
    (root / "other.ts").write_text(original)
    (root / "types.ts").symlink_to(root / "other.ts")
    with pytest.raises(ValueError, match="symlink"):
        plan(workspace)
    (root / "types.ts").unlink()
    import os

    os.link(root / "other.ts", root / "types.ts")
    with pytest.raises(ValueError, match="singly linked"):
        plan(workspace)
    (root / "types.ts").unlink()
    (root / "types.ts").write_text(" " * (MAX_PROOF_BYTES + 1))
    with pytest.raises(ValueError, match="budget"):
        plan(workspace)


def test_stale_task_wrong_binding_line_rule_and_declaration_files_are_refused(
    workspace,
):
    root, source = workspace
    for changed in [
        {"source_sha256": "0" * 64},
        {"name": "Wrong"},
        {"rule_id": "SKY-U001"},
        {"category": "quality"},
    ]:
        finding = task(root, source)
        finding.update(changed)
        with pytest.raises(ValueError):
            plan_typescript_unused_import(finding, root, source)
    finding = task(root, source)
    finding["finding"]["line"] = 2
    with pytest.raises(ValueError):
        plan_typescript_unused_import(finding, root, source)
    with pytest.raises(ValueError, match="ordinary"):
        plan_typescript_unused_import(
            task(root, source, file="consumer.d.ts"), root, source
        )


def test_missing_configuration_and_malformed_dependency_proof_are_refused(workspace):
    root, _ = workspace
    (root / "tsconfig.json").unlink()
    with pytest.raises(ValueError, match="local tsconfig"):
        plan(workspace)
    for proof in [
        {},
        {
            "provider_hashes": {"../outside": "a" * 64},
            "resolution_hashes": {"tsconfig.json": None},
        },
        {
            "provider_hashes": {"types.ts": None},
            "resolution_hashes": {"tsconfig.json": None},
        },
    ]:
        with pytest.raises(ValueError):
            revalidate_typescript_dependencies(root, proof)


def test_unavailable_parser_refuses_the_adapter(workspace, monkeypatch):
    import tree_sitter_typescript

    def unavailable():
        raise RuntimeError("parser unavailable")

    monkeypatch.setattr(tree_sitter_typescript, "language_typescript", unavailable)
    with pytest.raises(ValueError, match="unavailable"):
        plan(workspace)


@pytest.mark.parametrize("folder", ["", "src/"])
def test_real_native_unused_import_finding_identifies_the_supported_binding(
    tmp_path, folder
):
    from skylos.analyzer import analyze

    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"strict":true,"module":"ESNext"}}'
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"private": True, "type": "module", "main": folder + "consumer.ts"})
    )
    (tmp_path / folder).mkdir(exist_ok=True)
    (tmp_path / folder / "types.ts").write_text(
        "export interface Shape {value:string}\n"
    )
    source = b"import type {Shape} from './types';\nexport {};\nconsole.log('entry');\n"
    selected = task(tmp_path, source, file=folder + "consumer.ts")
    report = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            trace_file=False,
        )
    )
    assert not report.get("analysis_errors")
    imports = [
        row
        for row in report.get("unused_imports", [])
        if row.get("simple_name", row.get("name")) == "Shape"
    ]
    assert len(imports) == 1
    selected["finding"] = imports[0]
    selected["name"] = imports[0]["name"]
    selected["line"] = imports[0]["line"]
    result = plan_typescript_unused_import(selected, tmp_path, source)
    assert result["binding"]["local"] == "Shape"


def test_original_anchor_survives_line_shifts_and_requires_actual_binding(workspace):
    root, source = workspace
    result = plan(workspace)
    anchor = result["target_anchor"]
    assert typescript_import_anchor_present(
        b"\n\n" + source, anchor, file_path="consumer.ts"
    )
    assert not typescript_import_anchor_present(
        result["replacement"], anchor, file_path="consumer.ts"
    )
    assert not typescript_import_anchor_present(
        b"import type {Shape as Other} from './types';\nexport {};",
        anchor,
        file_path="consumer.ts",
    )
    assert not typescript_import_anchor_present(
        b"import type {Shape} from './other';\nexport {};",
        anchor,
        file_path="consumer.ts",
    )
    with pytest.raises(ValueError, match="syntax"):
        typescript_import_anchor_present(
            b"import type {Shape", anchor, file_path="consumer.ts"
        )
    with pytest.raises(ValueError, match="anchor"):
        typescript_import_anchor_present(source, "{}", file_path="consumer.ts")
