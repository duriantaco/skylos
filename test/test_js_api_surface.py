from __future__ import annotations

import json

import pytest

from skylos.core.api_symbol_truth import (
    SURFACE_KIND_JS_MODULE,
    cached_api_symbol_surface,
)
from skylos.core.js_api_surface import build_js_api_surfaces, cache_js_api_surfaces


def test_js_api_surface_extracts_package_exports_and_reexports(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "@acme/ui",
                "version": "1.2.3",
                "exports": {
                    ".": {
                        "types": "./dist/index.d.ts",
                        "import": "./dist/index.js",
                    },
                    "./button": "./src/button.ts",
                },
            }
        ),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
export function makeUser(name: string) { return { name }; }
export class Client {}
export const version = "1.2.3";
export { helper as makeHelper } from "./helper";
export * from "./types";
export default function createClient() { return new Client(); }
""",
        encoding="utf-8",
    )
    (src / "helper.ts").write_text(
        "export function helper() { return true; }\n",
        encoding="utf-8",
    )
    (src / "types.ts").write_text(
        "export interface User { id: string }\n",
        encoding="utf-8",
    )
    (src / "button.ts").write_text(
        "export class Button {}\n",
        encoding="utf-8",
    )

    surfaces = cache_js_api_surfaces(repo)

    assert {surface["name"] for surface in surfaces} == {"@acme/ui", "@acme/ui/button"}
    shared = cached_api_symbol_surface(repo, SURFACE_KIND_JS_MODULE, "@acme/ui")
    assert shared["version"] == "1.2.3"
    assert shared["origin"] == "package.json"
    assert shared["metadata"]["entrypoint"] == "src/index.ts"
    assert shared["exports"] == [
        "Client",
        "User",
        "default",
        "makeHelper",
        "makeUser",
        "version",
    ]
    assert shared["members"]["makeUser"]["kind"] == "function"
    assert shared["members"]["Client"]["kind"] == "class"
    assert shared["members"]["version"]["kind"] == "variable"
    assert shared["members"]["default"]["kind"] == "function"
    assert shared["members"]["makeHelper"]["target"] == "./helper"
    assert shared["members"]["User"]["kind"] == "type"
    assert shared["members"]["User"]["source_path"] == "src/types.ts"

    button = cached_api_symbol_surface(repo, SURFACE_KIND_JS_MODULE, "@acme/ui/button")
    assert button["exports"] == ["Button"]
    assert button["members"]["Button"]["kind"] == "class"


def test_js_api_surface_extracts_commonjs_exports(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "legacy-lib", "main": "./index.cjs"}),
        encoding="utf-8",
    )
    (repo / "index.cjs").write_text(
        """
const legacy = () => true;
exports.before = () => false;
module.exports = { legacy, named: function named() {} };
exports.extra = class Extra {};
module.exports.more = () => true;
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface["name"] == "legacy-lib"
    assert surface["exports"] == ["legacy", "more", "named"]
    assert surface["members"]["legacy"]["kind"] == "value"
    assert surface["members"]["named"]["kind"] == "function"
    assert surface["members"]["more"]["kind"] == "function"


def test_js_api_surface_star_export_semantics(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "star-lib", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
export * from "./plain";
export * as utils from "./utils";
""",
        encoding="utf-8",
    )
    (src / "plain.ts").write_text(
        """
export default function hidden() { return false; }
export function visible() { return true; }
""",
        encoding="utf-8",
    )
    (src / "utils.ts").write_text(
        "export function helper() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface["exports"] == ["utils", "visible"]
    assert surface["members"]["visible"]["kind"] == "function"
    assert surface["members"]["utils"]["kind"] == "namespace"


def test_js_api_surface_skips_entrypoint_through_symlinked_parent(tmp_path):
    repo = tmp_path / "repo"
    real_dir = repo / "real"
    real_dir.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "linked-lib", "main": "./linked/index.js"}),
        encoding="utf-8",
    )
    (real_dir / "index.js").write_text(
        "export function leaked() { return true; }\n",
        encoding="utf-8",
    )
    try:
        (repo / "linked").symlink_to(real_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    assert build_js_api_surfaces(repo) == []


def test_js_api_surface_ignores_commonjs_assignments_inside_functions(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "installer-lib", "main": "./index.cjs"}),
        encoding="utf-8",
    )
    (repo / "index.cjs").write_text(
        """
exports.visible = () => true;
function install() {
  exports.hidden = () => false;
  module.exports.alsoHidden = () => false;
}
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["visible"]


def test_js_api_surface_local_named_exports_require_existing_binding(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "local-export-lib", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
const real = 1;
export { real as alias, missing };
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["alias"]
    assert surfaces[0]["members"]["alias"]["kind"] == "variable"


def test_js_api_surface_local_named_exports_ignore_nested_bindings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "nested-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        """
function wrapper() {
  function hidden() { return false; }
}
export { hidden };
""",
        encoding="utf-8",
    )

    assert build_js_api_surfaces(repo) == []


def test_js_api_surface_export_map_falls_back_to_existing_condition(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "conditional-lib",
                "exports": {
                    ".": {
                        "types": "./types/missing.d.ts",
                        "import": "./src/index.ts",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        "export function realEntry() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["realEntry"]


def test_js_api_surface_export_map_uses_one_condition_target_per_key(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    types = repo / "types"
    src.mkdir(parents=True)
    types.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "single-condition-lib",
                "exports": {
                    ".": {
                        "types": "./types/index.d.ts",
                        "import": "./src/index.ts",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (types / "index.d.ts").write_text(
        "export interface TypeOnly { id: string }\n",
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        "export function runtimeEntry() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["runtimeEntry"]


def test_js_api_surface_star_reexport_precedence_and_ambiguity(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "precedence-lib", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
export * from "./types";
export * from "./other";
export { Foo } from "./runtime";
""",
        encoding="utf-8",
    )
    (src / "types.ts").write_text(
        """
export type Foo = string;
export function Ambiguous() { return "types"; }
""",
        encoding="utf-8",
    )
    (src / "other.ts").write_text(
        """
export function Ambiguous() { return "other"; }
export function OtherOnly() { return true; }
""",
        encoding="utf-8",
    )
    (src / "runtime.ts").write_text(
        "export function Foo() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface["exports"] == ["Foo", "OtherOnly"]
    assert surface["members"]["Foo"]["kind"] == "function"
    assert surface["members"]["Foo"]["source"] == "named_reexport"
    assert surface["members"]["OtherOnly"]["source"] == "star_reexport"


def test_js_api_surface_direct_export_overrides_star_reexport(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "direct-over-star-lib", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
export * from "./a";
export function Foo() { return "local"; }
""",
        encoding="utf-8",
    )
    (src / "a.ts").write_text(
        "export type Foo = string;\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["Foo"]
    assert surfaces[0]["members"]["Foo"]["kind"] == "function"
    assert surfaces[0]["members"]["Foo"]["source"] == "static_export"


def test_js_api_surface_namespace_reexport_overrides_star_member(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "namespace-lib", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
export * from "./a";
export * as utils from "./b";
""",
        encoding="utf-8",
    )
    (src / "a.ts").write_text(
        "export function utils() { return false; }\n",
        encoding="utf-8",
    )
    (src / "b.ts").write_text(
        "export function helper() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["utils"]
    assert surfaces[0]["members"]["utils"]["kind"] == "namespace"
    assert surfaces[0]["members"]["utils"]["source"] == "namespace_reexport"


def test_js_api_surface_local_named_export_accepts_module_scope_var(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "var-lib", "main": "./index.js"}),
        encoding="utf-8",
    )
    (repo / "index.js").write_text(
        """
var real = 1;
export { real };
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["real"]
    assert surfaces[0]["members"]["real"]["kind"] == "variable"


def test_js_api_surface_default_interface_is_type_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "default-type-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        "export default interface User { id: string }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["default"]
    assert surfaces[0]["members"]["default"]["kind"] == "type"


def test_js_api_surface_export_namespace_records_namespace_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "namespace-decl-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        """
export namespace NS {
  export function hidden() { return false; }
  export const value = 1;
}
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["NS"]
    assert surfaces[0]["members"]["NS"]["kind"] == "namespace"


def test_js_api_surface_export_declare_namespace_records_namespace_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "declare-namespace-lib", "types": "./index.d.ts"}),
        encoding="utf-8",
    )
    (repo / "index.d.ts").write_text(
        """
export declare namespace NS {
  export function hidden(): void;
}
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["NS"]
    assert surfaces[0]["members"]["NS"]["kind"] == "namespace"


def test_js_api_surface_plain_namespace_named_export(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "plain-namespace-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        """
namespace NS {
  export function hidden() { return false; }
}
export { NS };
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["NS"]
    assert surfaces[0]["members"]["NS"]["kind"] == "namespace"


def test_js_api_surface_same_line_namespace_does_not_hide_top_level_export(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "same-line-namespace-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        "export namespace NS {} export function visible() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["NS", "visible"]
    assert surfaces[0]["members"]["NS"]["kind"] == "namespace"
    assert surfaces[0]["members"]["visible"]["kind"] == "function"


def test_js_api_surface_same_line_namespace_member_same_name_does_not_hide_export(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "same-name-namespace-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        "export namespace NS { export function visible() {} } "
        "export function visible() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["NS", "visible"]
    assert surfaces[0]["members"]["NS"]["kind"] == "namespace"
    assert surfaces[0]["members"]["visible"]["kind"] == "function"


def test_js_api_surface_destructured_exports_use_bound_names(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "destructure-lib", "main": "./index.js"}),
        encoding="utf-8",
    )
    (repo / "index.js").write_text(
        """
export const { foo, bar: baz, nested: { deep } } = obj;
export const [first, second] = arr;
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["baz", "deep", "first", "foo", "second"]


def test_js_api_surface_destructured_export_defaults_use_bound_names(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "destructure-default-lib", "main": "./index.js"}),
        encoding="utf-8",
    )
    (repo / "index.js").write_text(
        """
export const { foo = 1 } = obj;
export const [first = fallback] = arr;
export const { bar: baz = other } = obj;
const { local = fallback } = obj;
export { local };
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["baz", "first", "foo", "local"]


def test_js_api_surface_abstract_class_and_ambient_enum_exports(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "abstract-lib", "types": "./index.d.ts"}),
        encoding="utf-8",
    )
    (repo / "index.d.ts").write_text(
        """
export abstract class Base {}
export declare abstract class DeclBase {}
export declare enum Mode { Read, Write }
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["Base", "DeclBase", "Mode"]
    assert surfaces[0]["members"]["Base"]["kind"] == "class"
    assert surfaces[0]["members"]["DeclBase"]["kind"] == "class"
    assert surfaces[0]["members"]["Mode"]["kind"] == "class"


def test_js_api_surface_default_abstract_class_is_class(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "default-abstract-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        "export default abstract class Base {}\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["default"]
    assert surfaces[0]["members"]["default"]["kind"] == "class"


def test_js_api_surface_export_type_clauses_are_type_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "type-clause-lib", "main": "./index.ts"}),
        encoding="utf-8",
    )
    (repo / "index.ts").write_text(
        """
class RuntimeClass {}
export type { RuntimeClass as RuntimeType };
export { type RuntimeClass as InlineRuntimeType };
export type { makeUser as UserFactory } from "./runtime";
export { type makeUser as InlineUserFactory } from "./runtime";
""",
        encoding="utf-8",
    )
    (repo / "runtime.ts").write_text(
        "export function makeUser() { return {}; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == [
        "InlineRuntimeType",
        "InlineUserFactory",
        "RuntimeType",
        "UserFactory",
    ]
    assert surfaces[0]["members"]["InlineRuntimeType"]["kind"] == "type"
    assert surfaces[0]["members"]["InlineUserFactory"]["kind"] == "type"
    assert surfaces[0]["members"]["RuntimeType"]["kind"] == "type"
    assert surfaces[0]["members"]["UserFactory"]["kind"] == "type"


def test_js_api_surface_export_type_star_forms_are_type_only(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "type-star-lib", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
export type * from "./types";
export type * as typeNS from "./types";
""",
        encoding="utf-8",
    )
    (src / "types.ts").write_text(
        """
export class Widget {}
export default interface HiddenDefault {}
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["Widget", "typeNS"]
    assert surfaces[0]["members"]["Widget"]["kind"] == "type"
    assert surfaces[0]["members"]["typeNS"]["kind"] == "type"


def test_js_api_surface_declaration_file_function_signatures(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "declaration-lib", "types": "./index.d.ts"}),
        encoding="utf-8",
    )
    (repo / "index.d.ts").write_text(
        """
export function makeUser(name: string): User;
export declare function makeOrg(id: string): Org;
export declare const directVersion: string;
declare function hidden(): void;
declare const version: string;
export { version };
""",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == [
        "directVersion",
        "makeOrg",
        "makeUser",
        "version",
    ]
    assert surfaces[0]["members"]["makeUser"]["kind"] == "function"
    assert surfaces[0]["members"]["makeOrg"]["kind"] == "function"
    assert surfaces[0]["members"]["directVersion"]["kind"] == "variable"
    assert surfaces[0]["members"]["version"]["kind"] == "variable"


def test_js_api_surface_skips_minified_entrypoints(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "minified-lib", "main": "./index.min.js"}),
        encoding="utf-8",
    )
    (repo / "index.min.js").write_text(
        "export const noisy = 1;" + ("x" * 6000),
        encoding="utf-8",
    )

    assert build_js_api_surfaces(repo) == []
    assert cache_js_api_surfaces(repo) == []


def test_js_api_surface_skips_excluded_package_dirs(tmp_path):
    repo = tmp_path / "repo"
    for excluded_dir, package_name in (
        ("node_modules", "dep"),
        ("generated", "generated-lib"),
        ("vendor", "vendored"),
    ):
        package_dir = repo / excluded_dir / package_name
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text(
            json.dumps({"name": package_name, "main": "./index.js"}),
            encoding="utf-8",
        )
        (package_dir / "index.js").write_text(
            "export function leaked() {}\n",
            encoding="utf-8",
        )

    assert build_js_api_surfaces(repo) == []


def test_js_api_surface_skips_external_and_missing_named_reexports(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "reexport-lib", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        """
export { map } from "lodash";
export { Missing } from "./missing";
export { existing as localExisting } from "./local";
""",
        encoding="utf-8",
    )
    (src / "local.ts").write_text(
        "export function existing() { return true; }\n",
        encoding="utf-8",
    )

    surfaces = build_js_api_surfaces(repo)

    assert len(surfaces) == 1
    assert surfaces[0]["exports"] == ["localExisting"]
    assert surfaces[0]["members"]["localExisting"]["kind"] == "function"
    assert surfaces[0]["members"]["localExisting"]["target"] == "./local"


def test_js_api_surface_does_not_fallback_when_exports_map_is_unsupported(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "wildcard-lib",
                "exports": {"./feature/*": "./src/feature/*.js"},
                "main": "./src/index.ts",
            }
        ),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        "export function shouldNotFallback() { return true; }\n",
        encoding="utf-8",
    )

    assert build_js_api_surfaces(repo) == []
