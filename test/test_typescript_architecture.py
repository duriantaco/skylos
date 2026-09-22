from pathlib import Path

from skylos.analysis.typescript_architecture import build_ts_architecture_inputs


def test_ts_graph_includes_all_discovered_modules_and_only_scanned_edges(tmp_path):
    app = tmp_path / "src" / "app.ts"
    api = tmp_path / "src" / "api.ts"
    idle = tmp_path / "src" / "idle.jsx"
    excluded = tmp_path / "excluded.ts"
    external = tmp_path.parent / "external.ts"
    app.parent.mkdir()
    app.write_text('import { API } from "./api";\nAPI();\n')
    api.write_text("export function API() {}\n")
    idle.write_text("export const idle = 1;\n")
    excluded.write_text("export const excluded = 1;\n")
    external.write_text("export const external = 1;\n")

    graph, files, abstractness, loc = build_ts_architecture_inputs(
        [app, api, idle],
        tmp_path,
        {api: {str(app)}, excluded: {str(app)}, external: {str(app)}},
    )

    assert graph == {
        "src.app": {"src.api"},
        "src.api": set(),
        "src.idle": set(),
    }
    assert files == {
        "src.app": str(app),
        "src.api": str(api),
        "src.idle": str(idle),
    }
    assert loc == {"src.app": 2, "src.api": 1, "src.idle": 1}
    assert abstractness["src.api"]["total_functions"] == 1


def test_module_names_are_stable_when_extensions_or_path_shapes_collide(tmp_path):
    paths = [tmp_path / name for name in ("a.ts", "a.js", "a__ts.ts", "x.y.ts")]
    nested = tmp_path / "x" / "y.ts"
    nested.parent.mkdir()
    paths.append(nested)
    for path in paths:
        path.write_text("export const value = 1;\n")

    first = build_ts_architecture_inputs(paths, tmp_path, {})[1]
    second = build_ts_architecture_inputs(reversed(paths), tmp_path, {})[1]

    assert first == second
    assert len(first) == len(paths)
    assert set(first.values()) == {str(path) for path in paths}
    assert "a__ts" in first  # Existing base is reserved, so use a unique variant.


def test_typescript_abstractness_counts_interfaces_and_abstract_classes(tmp_path):
    source = tmp_path / "model.ts"
    source.write_text(
        "export interface Contract { run(): void }\n"
        "export abstract class Base { abstract run(): void }\n"
        "export class Concrete { run() {} }\n"
        "export function helper() {}\n"
        "export const arrow = () => 1;\n"
    )

    _, _, abstraction, loc = build_ts_architecture_inputs([source], tmp_path, {})

    assert abstraction["model"] == {
        "abstractness": 0.4,
        "total_classes": 3,
        "abstract_classes": 2,
        "total_functions": 2,
        "abstract_methods": 0,
        "type_vars": 0,
        "protocols": 1,
    }
    assert loc["model"] == 5


def test_symlink_and_oversize_source_are_not_read(tmp_path, monkeypatch):
    import skylos.analysis.typescript_architecture as architecture

    real = tmp_path / "safe.ts"
    link = tmp_path / "link.ts"
    real.write_text("export interface API {}\n")
    link.symlink_to(real)
    monkeypatch.setattr(architecture, "_MAX_SOURCE_BYTES", 4)

    graph, files, abstractness, loc = build_ts_architecture_inputs(
        [real, link], tmp_path, {}
    )

    assert graph == {"safe": set()}
    assert files == {"safe": str(real)}
    assert abstractness == {}
    assert loc == {"safe": 0}


def test_parent_directory_swap_cannot_read_outside_project(tmp_path, monkeypatch):
    import skylos.analysis.typescript_architecture as architecture

    project = tmp_path / "project"
    source_dir = project / "src"
    source_dir.mkdir(parents=True)
    source = source_dir / "safe.ts"
    source.write_text("export const safe = 1;\n")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / source.name).write_text(
        "export interface Outside {}\nexport const value = 1;\n"
    )

    original_open = architecture.os.open
    swapped = False

    def swap_parent_before_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped:
            source_dir.rename(project / "original_src")
            source_dir.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(architecture.os, "open", swap_parent_before_open)

    graph, files, abstractness, loc = build_ts_architecture_inputs(
        [source], project, {}
    )

    assert swapped
    assert graph == {"src.safe": set()}
    assert files == {"src.safe": str(source)}
    assert abstractness == {}
    assert loc == {"src.safe": 0}


def test_source_read_fails_closed_without_no_follow(tmp_path, monkeypatch):
    import skylos.analysis.typescript_architecture as architecture

    source = tmp_path / "safe.ts"
    source.write_text("export interface Safe {}\n")
    monkeypatch.delattr(architecture.os, "O_NOFOLLOW", raising=False)

    graph, files, abstractness, loc = build_ts_architecture_inputs(
        [source], tmp_path, {}
    )

    assert graph == {"safe": set()}
    assert files == {"safe": str(source)}
    assert abstractness == {}
    assert loc == {"safe": 0}


def test_all_supported_ts_js_suffixes_are_included(tmp_path):
    suffixes = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
    paths = []
    for index, suffix in enumerate(suffixes):
        path = tmp_path / f"file{index}{suffix}"
        path.write_text("export const value = 1;\n")
        paths.append(path)
    paths.append(tmp_path / "skip.py")
    paths[-1].write_text("pass\n")

    graph, files, _, _ = build_ts_architecture_inputs(paths, tmp_path, {})

    assert len(graph) == len(suffixes)
    assert len(files) == len(suffixes)
    assert all(Path(path).suffix in suffixes for path in files.values())
