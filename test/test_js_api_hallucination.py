from __future__ import annotations

import json
from pathlib import Path

from skylos.rules.ai_defect.js_api_hallucination import (
    scan_js_local_api_hallucinations,
)
from skylos.visitors.languages.typescript.core import TypeScriptCore
from skylos.visitors.languages.typescript.resolve import MonorepoResolver


def _scan(repo: Path):
    files = sorted(
        path
        for path in repo.rglob("*")
        if path.is_file()
        and path.name.endswith(
            (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
        )
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


def test_js_api_hallucination_finds_missing_named_default_type_and_namespace_exports(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "security.ts").write_text(
        """
export default function defaultGuard() { return true; }
export function verifyToken() { return true; }
export type User = { id: string };
""",
        encoding="utf-8",
    )
    (repo / "app.ts").write_text(
        """
import defaultGuard, {
  verifyToken,
  verifyAdmin,
  type User,
  type MissingType,
} from "./security";
import * as security from "./security";

defaultGuard();
verifyToken();
security.verifyToken();
security.verifyTenant();
""",
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert {finding["simple_name"] for finding in findings} == {
        "MissingType",
        "verifyAdmin",
        "verifyTenant",
    }
    assert {finding["metadata"]["reference_kind"] for finding in findings} == {
        "named_import",
        "namespace_member",
    }
    assert all(finding["metadata"]["proof_state"] == "verified" for finding in findings)
    assert coverage["status"] == "completed"
    assert coverage["outcome"] == "fail"
    assert coverage["finding_count"] == 3
    assert coverage["skipped_references"] == 0


def test_js_api_hallucination_marks_external_and_computed_references_incomplete(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "local.ts").write_text(
        "export function known() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "app.ts").write_text(
        """
import { useState } from "react";
import * as local from "./local";

local[window.location.hash]();
useState();
""",
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["references"] == 2
    assert coverage["skipped_references"] == 2
    assert {reason["code"] for reason in coverage["reasons"]} == {
        "computed_namespace_member",
        "external_or_unresolved_module",
    }


def test_js_api_hallucination_handles_workspace_reexports_and_commonjs(tmp_path):
    repo = tmp_path / "repo"
    app = repo / "apps" / "web"
    api = repo / "packages" / "api"
    legacy = repo / "packages" / "legacy"
    app.mkdir(parents=True)
    (api / "src").mkdir(parents=True)
    legacy.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "workspace-root", "workspaces": ["apps/*", "packages/*"]}),
        encoding="utf-8",
    )
    (app / "package.json").write_text(
        json.dumps({"name": "web", "private": True}),
        encoding="utf-8",
    )
    (api / "package.json").write_text(
        json.dumps(
            {
                "name": "@acme/api",
                "exports": {".": "./src/index.ts"},
            }
        ),
        encoding="utf-8",
    )
    (api / "src" / "index.ts").write_text(
        """
export { verifyToken } from "./security";
export type { User } from "./types";
export default function createClient() { return {}; }
""",
        encoding="utf-8",
    )
    (api / "src" / "security.ts").write_text(
        "export function verifyToken() { return true; }\n",
        encoding="utf-8",
    )
    (api / "src" / "types.ts").write_text(
        "export interface User { id: string }\n",
        encoding="utf-8",
    )
    (legacy / "package.json").write_text(
        json.dumps({"name": "legacy-auth", "main": "./index.cjs"}),
        encoding="utf-8",
    )
    (legacy / "index.cjs").write_text(
        "module.exports = { validate: () => true };\n",
        encoding="utf-8",
    )
    (app / "app.ts").write_text(
        """
import createClient, { verifyToken, type User } from "@acme/api";
import * as api from "@acme/api";
const { validate } = require("legacy-auth");
const legacy = require("legacy-auth");

createClient();
verifyToken();
api.verifyToken();
validate();
legacy.validate();
const user: User = { id: "1" };
""",
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 8
    assert coverage["skipped_references"] == 0


def test_js_api_hallucination_does_not_claim_absence_on_external_reexport(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "@acme/api", "main": "./src/index.ts"}),
        encoding="utf-8",
    )
    (src / "index.ts").write_text(
        'export * from "third-party";\n',
        encoding="utf-8",
    )
    (src / "app.ts").write_text(
        'import { maybeExternal } from "@acme/api";\nmaybeExternal();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["reasons"] == [{"code": "surface_external_reexport", "count": 1}]


def test_js_api_hallucination_ignores_shadowed_namespace_binding(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "security.ts").write_text(
        "export function verifyToken() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "app.ts").write_text(
        """
import * as security from "./security";

function run(security: { invented(): void }) {
  security.invented();
}

security.verifyToken();
""",
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 1


def test_js_api_hallucination_marks_literal_dynamic_import_incomplete(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.ts").write_text(
        "export function known() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "app.ts").write_text(
        """
async function run() {
  const api = await import("./api");
  api.invented();
}
""",
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["references"] == 1
    assert coverage["skipped_references"] == 1
    assert coverage["reasons"] == [{"code": "unsupported_dynamic_import", "count": 1}]


def test_js_api_hallucination_marks_typescript_import_equals_incomplete(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.cjs").write_text(
        "module.exports = { known: () => true };\n",
        encoding="utf-8",
    )
    (repo / "app.ts").write_text(
        """
import api = require("./api.cjs");
api.invented();
""",
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["references"] == 1
    assert coverage["skipped_references"] == 1
    assert coverage["reasons"] == [
        {"code": "unsupported_typescript_import_equals", "count": 1}
    ]


def test_js_api_hallucination_accepts_commonjs_default_facade(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "legacy.cjs").write_text(
        "module.exports = { known: () => true };\n",
        encoding="utf-8",
    )
    (repo / "app.mjs").write_text(
        'import legacy from "./legacy.cjs";\nlegacy.known();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 1


def test_js_api_hallucination_uses_require_package_condition(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "dual-package",
                "exports": {
                    ".": {
                        "import": "./index.mjs",
                        "require": "./index.cjs",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (repo / "index.mjs").write_text(
        "export function esmOnly() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "index.cjs").write_text(
        "module.exports = { cjsOnly: () => true };\n",
        encoding="utf-8",
    )
    (repo / "app.cjs").write_text(
        'const { cjsOnly } = require("dual-package");\ncjsOnly();\n',
        encoding="utf-8",
    )
    (repo / "app.mjs").write_text(
        'import { esmOnly } from "dual-package";\nesmOnly();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 2


def test_js_api_hallucination_uses_types_package_condition(tmp_path):
    repo = tmp_path / "repo"
    types = repo / "types"
    repo.mkdir()
    types.mkdir()
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "typed-package",
                "exports": {
                    ".": {
                        "types": "./types/index.d.ts",
                        "import": "./index.js",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (types / "index.d.ts").write_text(
        "export interface Options { enabled: boolean }\n",
        encoding="utf-8",
    )
    (repo / "index.js").write_text(
        "export function runtimeOnly() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "app.ts").write_text(
        'import type { Options } from "typed-package";\n'
        "const options: Options = { enabled: true };\n",
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 1


def test_js_api_hallucination_marks_conditional_commonjs_exports_incomplete(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.cjs").write_text(
        """
if (process.env.ENABLE_API) {
  module.exports.real = () => true;
}
""",
        encoding="utf-8",
    )
    (repo / "app.cjs").write_text(
        'const { real } = require("./api.cjs");\nreal();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["reasons"] == [
        {"code": "surface_conditional_commonjs_export", "count": 1}
    ]


def test_js_api_hallucination_accepts_commonjs_package_default_for_plain_js(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "legacy-package", "type": "commonjs"}),
        encoding="utf-8",
    )
    (repo / "legacy.js").write_text(
        'console.log("loaded");\n',
        encoding="utf-8",
    )
    (repo / "app.mjs").write_text(
        'import legacy from "./legacy.js";\nconsole.log(legacy);\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 1


def test_js_api_hallucination_respects_package_condition_declaration_order(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "ordered-package",
                "exports": {
                    ".": {
                        "node": "./node.js",
                        "import": "./import.js",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (repo / "node.js").write_text(
        "export function nodeOnly() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "import.js").write_text(
        "export function importOnly() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "app.mjs").write_text(
        'import { nodeOnly } from "ordered-package";\nnodeOnly();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "pass"
    assert coverage["verified_references"] == 1


def test_js_api_hallucination_marks_nested_commonjs_mutation_calls_incomplete(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.cjs").write_text(
        """
if (process.env.ENABLE_API) {
  Object.defineProperty(module.exports, "real", { value: () => true });
  Object.assign(exports, { other: () => true });
}
""",
        encoding="utf-8",
    )
    (repo / "app.cjs").write_text(
        'const { real, other } = require("./api.cjs");\nreal();\nother();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["reasons"] == [
        {"code": "surface_conditional_commonjs_export", "count": 2}
    ]


def test_js_api_hallucination_does_not_fall_through_uncertain_nested_condition(
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "nested-package",
                "exports": {
                    ".": {
                        "import": {
                            "custom": "./custom.js",
                            "default": "./actual.js",
                        },
                        "default": "./fallback.js",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (repo / "custom.js").write_text(
        "export function customOnly() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "actual.js").write_text(
        "export function real() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "fallback.js").write_text(
        "export function fallbackOnly() { return true; }\n",
        encoding="utf-8",
    )
    (repo / "app.mjs").write_text(
        'import { real } from "nested-package";\nreal();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["reasons"] == [
        {"code": "unsupported_import_package_condition", "count": 1}
    ]


def test_js_api_hallucination_does_not_verify_incomplete_surface_member(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "api.cjs").write_text(
        """
module.exports = { real: () => true };
if (process.env.DISABLE_API) {
  module.exports = {};
}
""",
        encoding="utf-8",
    )
    (repo / "app.cjs").write_text(
        'const { real } = require("./api.cjs");\nreal();\n',
        encoding="utf-8",
    )

    findings, coverage = _scan(repo)

    assert findings == []
    assert coverage["outcome"] == "incomplete"
    assert coverage["verified_references"] == 0
    assert coverage["reasons"] == [
        {"code": "surface_conditional_commonjs_export", "count": 1}
    ]
