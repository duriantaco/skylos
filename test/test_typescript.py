import pickle

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file

TS_CODE = """
// 1. DEAD CODE
function unusedLegacyFunction() {
    return "delete me";
}

// 2. DANGER
function runUnsafe(input: string) {
    eval(input);
}

// 3. QUALITY (Complexity ~3)
function simpleFunction(x: number) {
    if (x > 10) { return true; } else { return false; }
}

runUnsafe("test");
"""

JS_CODE = """
// 1. DEAD CODE
function unusedLegacyFunction() {
    return "delete me";
}

// 2. DANGER
function runUnsafe(input) {
    eval(input);
}

// 3. QUALITY (Complexity ~3)
function simpleFunction(x) {
    if (x > 10) { return true; } else { return false; }
}

runUnsafe("test");
"""


@pytest.mark.parametrize(
    ("filename", "code"),
    [("app.ts", TS_CODE), ("app.js", JS_CODE)],
)
def test_typescript_scanner_defaults(tmp_path, filename, code):
    d = tmp_path / "src"
    d.mkdir()
    p = d / filename
    p.write_text(code, encoding="utf-8")

    results = scan_typescript_file(str(p))
    defs, refs, _, _, _, _, quality, danger, _, _, _, _, _ = results

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert "unusedLegacyFunction" in def_names
    assert "unusedLegacyFunction" not in ref_names
    assert "runUnsafe" in ref_names

    eval_findings = [f for f in danger if f["rule_id"] == "SKY-D201"]
    assert len(eval_findings) == 1

    assert len(quality) == 0


def test_typescript_config_override(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    p = d / "app.ts"
    p.write_text(TS_CODE, encoding="utf-8")

    strict_config = {"languages": {"typescript": {"complexity": 1}}}

    results = scan_typescript_file(str(p), config=strict_config)
    _, _, _, _, _, _, quality, _, _, _, _, _, _ = results

    assert len(quality) > 0
    assert quality[0]["rule_id"] == "SKY-Q301"


def test_jsx_scanner_parses_component_file(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    p = d / "widget.jsx"
    p.write_text(
        'export default function Widget() { return <div className="card">hi</div>; }\n',
        encoding="utf-8",
    )

    defs, refs, _, _, _, _, quality, danger, _, _, _, _, _ = scan_typescript_file(
        str(p)
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert "Widget" in def_names
    assert "div" not in ref_names
    assert quality == []
    assert danger == []


def test_typescript_scan_result_is_parallel_worker_picklable(tmp_path):
    p = tmp_path / "app.ts"
    p.write_text("export function run(input: string) { return eval(input); }\n")

    result = scan_typescript_file(str(p), {}, enable_quality_rules=False)

    pickle.dumps(result)


def test_minified_js_scan_result_keeps_tuple_shape(tmp_path):
    p = tmp_path / "app.min.js"
    p.write_text("function run(){return 1}\n", encoding="utf-8")

    result = scan_typescript_file(str(p))

    assert len(result) == 13
    assert result[0] == []
    assert result[12] == []


def test_react_error_boundary_lifecycle_methods_are_not_dead_defs(tmp_path):
    p = tmp_path / "Boundary.tsx"
    p.write_text(
        """
import { Component } from "react";

class Boundary extends Component {
  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error(error);
  }

  render() {
    return null;
  }
}
""",
        encoding="utf-8",
    )

    defs, *_ = scan_typescript_file(str(p))
    def_names = {d.name for d in defs}

    assert "Boundary.getDerivedStateFromError" not in def_names
    assert "Boundary.componentDidCatch" not in def_names


def test_declaration_file_defs_are_treated_as_public_ambient_api(tmp_path):
    p = tmp_path / "types.d.ts"
    p.write_text(
        """
declare global {
  interface Window {
    __APP_API__?: unknown;
  }
}

declare module "external-lib" {
  export class MultiPoint {}
}
""",
        encoding="utf-8",
    )

    defs, *_ = scan_typescript_file(str(p))
    exported = {d.name for d in defs if d.is_exported}

    assert {"Window", "MultiPoint"} <= exported


def test_regular_ts_ambient_declaration_defs_are_public_api(tmp_path):
    p = tmp_path / "host.ts"
    p.write_text(
        """
export function registerHost() {}

declare global {
  interface Window {
    __APP_API__?: unknown;
  }
}
""",
        encoding="utf-8",
    )

    defs, *_ = scan_typescript_file(str(p))
    exported = {d.name for d in defs if d.is_exported}

    assert "Window" in exported


def test_object_literal_methods_are_not_reported_as_standalone_defs(tmp_path):
    p = tmp_path / "dragState.ts"
    p.write_text(
        """
let table: string | null = null;

export const dragState = {
  get table() { return table; },
  start(name: string) { table = name; },
  clear() { table = null; },
};

dragState.clear();
""",
        encoding="utf-8",
    )

    defs, refs, *_ = scan_typescript_file(str(p))

    assert "clear" not in {d.name for d in defs}
    assert "clear" in {r[0] for r in refs}


def test_default_parameter_and_update_expression_identifiers_are_refs(tmp_path):
    p = tmp_path / "helpers.ts"
    p.write_text(
        """
const MAX_HISTORY_SIZE = 10;
let idCounter = 0;

export function addHistoryEntry(maxSize = MAX_HISTORY_SIZE) {
  return maxSize;
}

export function generateId() {
  return `custom-${idCounter++}`;
}
""",
        encoding="utf-8",
    )

    _, refs, *_ = scan_typescript_file(str(p))
    ref_names = {r[0] for r in refs}

    assert {"MAX_HISTORY_SIZE", "idCounter"} <= ref_names


def test_aliased_named_import_defs_use_local_binding(tmp_path):
    p = tmp_path / "icons.tsx"
    p.write_text(
        """
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { Image as ImageIcon } from "lucide-react";

export function pick() {
  openFileDialog();
  return <ImageIcon />;
}
""",
        encoding="utf-8",
    )

    defs, refs, *_ = scan_typescript_file(str(p))
    import_names = {d.name for d in defs if d.type == "import"}
    ref_names = {r[0] for r in refs}

    assert {"openFileDialog", "ImageIcon"} <= import_names
    assert "open" not in import_names
    assert "Image" not in import_names
    assert {"openFileDialog", "ImageIcon"} <= ref_names


def test_awaited_generic_call_identifier_is_ref_in_tsx(tmp_path):
    p = tmp_path / "CellNameAiButton.tsx"
    p.write_text(
        """
import { invoke } from "@tauri-apps/api/core";

export function Button() {
  async function handleGenerate() {
    const name = await invoke<string>("generate_cell_name");
    return name.trim();
  }
  return <button onClick={handleGenerate} />;
}
""",
        encoding="utf-8",
    )

    defs, refs, *_ = scan_typescript_file(str(p))
    import_names = {d.name for d in defs if d.type == "import"}
    ref_names = {r[0] for r in refs}

    assert "invoke" in import_names
    assert "invoke" in ref_names
