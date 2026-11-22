"""Build the personal UML map. Reads source; never runs project scripts or tests."""
from __future__ import annotations

import ast
import html
import importlib.util
import re
from collections import Counter, defaultdict
from pathlib import Path

from .cache import digest
from .review import workflow_jobs

KINDS = ["function", "method", "class", "script", "command", "workflow"]
LINKS = ["calls", "creates", "uses", "inherits", "callback", "reference", "starts", "routes", "runs script", "name match"]
SOURCE_PREFIXES = ("skylos/", "scripts/", "editors/vscode/src/")
SCRIPT_PATTERN = re.compile(r"(?<![\w./-])((?:skylos/)?scripts/[\w./-]+\.(?:py|sh|js|mjs))\b")


def source_file(path):
    parts = Path(path).parts
    actual_test = any(p in {"test", "tests", "fixtures"} for p in parts) or path.endswith(("_test.go", "_test.py", ".test.ts", ".spec.ts", ".test.js", ".spec.js"))
    return path.startswith(SOURCE_PREFIXES) and not actual_test


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = dotted(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def imports(tree, module, is_package=False):
    found = {}
    def in_scope(node):
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                yield from in_scope(child)
    for node in in_scope(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                found[item.asname or item.name.split(".")[0]] = item.name if item.asname else item.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            origin = node.module or ""
            if node.level:
                package = module if is_package else module.rpartition(".")[0]
                try:
                    origin = importlib.util.resolve_name("." * node.level + origin, package)
                except (ImportError, ValueError):
                    continue
            for item in node.names:
                if item.name != "*":
                    found[item.asname or item.name] = f"{origin}.{item.name}"
    return found


def resolve(expr, aliases, module, ids):
    name = dotted(expr)
    if not name:
        return None
    first, dot, rest = name.partition(".")
    candidate = aliases.get(first, f"{module}.{first}") + (dot + rest if dot else "")
    return candidate if candidate in ids else None


def outside_definitions(tree):
    """Calls at module startup, including the __main__ guard, excluding definitions."""
    if isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    if isinstance(tree, ast.Call):
        yield tree
    for child in ast.iter_child_nodes(tree):
        yield from outside_definitions(child)


def relation_record(path, module, tree):
    aliases = imports(tree, module, path.endswith("/__init__.py"))
    found = {"module": module, "called": {}, "callbacks": {}, "script_refs": [], "module_calls": [], "dispatch": [], "wrapper_calls_cli_main": False}

    def candidate(expr, local):
        name = dotted(expr)
        if not name:
            return None
        first, dot, rest = name.partition(".")
        return local.get(first, f"{module}.{first}") + (dot + rest if dot else "")

    for top in tree.body:
        entries = [(top.name, top)] if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)) else []
        if isinstance(top, ast.ClassDef):
            entries += [(top.name + "." + child.name, child) for child in top.body if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for qual, node in entries:
            key = module + "." + qual
            local = {**aliases, **imports(node, module)}
            names, callbacks = set(), set()
            for call in (part for part in ast.walk(node) if isinstance(part, ast.Call)):
                name = dotted(call.func)
                if name:
                    names.add(name.rsplit(".", 1)[-1])
                    names.add(candidate(call.func, local).rsplit(".", 1)[-1])
                for arg in [*call.args, *(kw.value for kw in call.keywords)]:
                    target = candidate(arg, local)
                    if target:
                        callbacks.add(target)
                first, dot, rest = name.partition(".")
                canonical = local.get(first, first) + (dot + rest if dot else "")
                if canonical in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "os.system", "os.execv", "os.execve"}:
                    for arg in call.args[:1]:
                        for value in ast.walk(arg):
                            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                                found["script_refs"].extend([key, match[1]] for match in SCRIPT_PATTERN.finditer(value.value))
            found["called"][key], found["callbacks"][key] = sorted(names), sorted(callbacks)
            if key == "skylos.entry._run_recording_failures":
                found["wrapper_calls_cli_main"] = "cli_main" in names
    found["main_guard"] = any(isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and "__name__" in ast.unparse(n.test) and "__main__" in ast.unparse(n.test) for n in tree.body)
    found["module_calls"] = [target for call in outside_definitions(tree) if (target := candidate(call.func, aliases))]
    if path == "skylos/cli_core/dispatch.py":
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "EARLY_COMMAND_HANDLERS" for t in node.targets) and isinstance(node.value, ast.Dict):
                found["dispatch"] = [[key.value, value.value, key.lineno] for key, value in zip(node.value.keys, node.value.values) if isinstance(key, ast.Constant) and isinstance(key.value, str) and isinstance(value, ast.Constant) and isinstance(value.value, str)]
    return found


def build_data(graph, root, cache, *, controls, scope=None):
    # test_aware.py and rules/quality/test_*.py are production analyzers.
    # The graph's test-name heuristic must not hide those source modules.
    native = [n for n in graph["nodes"] if source_file(n["file"])]
    by_id = {n["id"]: dict(n) for n in native}
    edges = set()
    records, called, callback_ids = {}, {}, {}
    extractor_key = digest(Path(__file__).read_bytes())
    module_for = {f["file"]: f["module"] for f in graph["files"]}
    # Launcher files can import and invoke main() without defining any symbols.
    # Include them from the file inventory so workflow -> script -> function
    # links survive even when the native graph has no node for the launcher.
    for path in sorted(f["file"] for f in graph["files"] if f["language"] == "python" and source_file(f["file"])):
        module = module_for[path]
        file = cache.file(path)
        record = file.get("relations")
        if not record or record.get("extractor") != extractor_key or record.get("module") != module:
            try:
                tree = cache.tree(path)
            except (OSError, SyntaxError, UnicodeError):
                continue
            record = relation_record(path, module, tree)
            record["extractor"] = extractor_key
            file["relations"] = record
            cache.changed(path)
            cache.stats["relation_files_analyzed"] += 1
        else:
            cache.stats["relation_files_reused"] += 1
        records[path] = record
        called.update((key, set(value)) for key, value in record["called"].items())
        callback_ids.update((key, set(value)) for key, value in record["callbacks"].items())

    for source, target, kind in graph["edges"]:
        if source not in by_id or target not in by_id:
            continue
        # Native graph relations also include passing a function as a value.
        # Keep those visible, but never describe them as direct calls.
        if kind == "calls" and source in called and target.rsplit(".", 1)[-1] not in called[source]:
            kind = "callback" if target in callback_ids[source] else "reference"
        edges.add((source, target, kind))
    for source, target, _kind in graph.get("name_edges", []):
        if source in by_id and target in by_id:
            edges.add((source, target, "name match"))

    def add(key, name, path, kind, line=1, module=""):
        by_id[key] = {"id": key, "name": name, "file": path, "kind": kind, "start": line, "module": module}
        return key

    def script(path):
        key = "script:" + path
        if key not in by_id:
            add(key, Path(path).name, path, "script", module=module_for.get(path, ""))
        return key

    def script_exists(path):
        full = root / path
        return (scope is None or (path in scope and not full.is_symlink())) and full.is_file() and full.resolve().is_relative_to(root)

    for path, record in records.items():
        if path.startswith("scripts/") or record["main_guard"]:
            key = script(path)
            for target in record["module_calls"]:
                if target not in by_id and path.startswith("scripts/"):
                    # Python puts the launched script's directory on sys.path.
                    # Resolve a qualified import from that known directory,
                    # rather than guessing a function from its bare name.
                    parts = target.split(".")
                    for size in range(len(parts) - 1, 0, -1):
                        origin = Path(path).parent.joinpath(*parts[:size]).with_suffix(".py").as_posix()
                        canonical = module_for.get(origin)
                        if canonical:
                            resolved = canonical + "." + ".".join(parts[size:])
                            if resolved in by_id:
                                target = resolved
                            break
                if target in by_id:
                    edges.add((key, target, "starts"))
        for owner, target_path in record["script_refs"]:
            if script_exists(target_path):
                edges.add((owner, script(target_path), "runs script"))

    dispatch_path = "skylos/cli_core/dispatch.py"
    for name, handler, line in records.get(dispatch_path, {}).get("dispatch", []):
        target = "skylos.cli." + handler
        if target in by_id:
            command = add("command:skylos " + name, "skylos " + name, dispatch_path, "command", line)
            edges.add(("skylos.cli_core.dispatch.dispatch_early_command", command, "routes"))
            edges.add((command, target, "routes"))
    # This callback is passed by entry.main and invoked by the failure wrapper.
    if records.get("skylos/entry.py", {}).get("wrapper_calls_cli_main") and "skylos.cli.main" in callback_ids.get("skylos.entry.main", set()):
        edges.add(("skylos.entry._run_recording_failures", "skylos.cli.main", "callback"))
    if "skylos.entry.main" in by_id and "pyproject.toml" in controls:
        line = next((i for i, line in enumerate(cache.source("pyproject.toml").splitlines(), 1) if line.startswith("skylos =")), 1)
        command = add("command:skylos", "skylos", "pyproject.toml", "command", line)
        edges.add((command, "skylos.entry.main", "starts"))

    workflow_count = 0
    for path in sorted(p for p in controls if p.startswith(".github/workflows/")):
        jobs = workflow_jobs(cache.source(path)) or {}
        targets = set()
        for job in jobs.values():
            if not isinstance(job.get("steps"), list):
                continue
            for step in job["steps"]:
                if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                    continue
                for match in SCRIPT_PATTERN.finditer(step["run"]):
                    if script_exists(match[1]):
                        targets.add(match[1])
        if targets or (jobs and scope is not None):
            key = add("workflow:" + path, Path(path).name, path, "workflow")
            workflow_count += 1
            edges.update((key, script(target), "runs script") for target in targets)

    files = sorted({n["file"] for n in by_id.values()})
    file_ids = {path: i for i, path in enumerate(files)}
    nodes = sorted(by_id.values(), key=lambda n: (n["file"], n["start"], n["id"]))
    indices = {n["id"]: i for i, n in enumerate(nodes)}
    edges = sorted(edge for edge in edges if edge[0] in indices and edge[1] in indices)
    counts = Counter(n["kind"] for n in nodes)
    compact = {
        "meta": {"commit": graph["commit"], "dirty": graph["dirty"], "builtAt": graph["built_at"], "counts": dict(counts), "links": dict(Counter(e[2] for e in edges)), "files": len(files), "sourceFilesParsed": graph["coverage"]["parsed"], "workflowsMapped": workflow_count},
        "files": files,
        "modules": [module_for.get(path, "") for path in files],
        "kinds": KINDS,
        "linkKinds": LINKS,
        "nodes": [[n["name"], file_ids[n["file"]], n["start"], KINDS.index(n["kind"])] for n in nodes],
        "edges": [[indices[a], indices[b], LINKS.index(kind)] for a, b, kind in edges],
        "starts": [indices[key] for key in ("command:skylos", "skylos.entry.main", "skylos.analyzer.analyze", "skylos.analysis.file_worker.process_file", "skylos.pipeline.run_pipeline", "script:scripts/corpus_ci.py", "script:scripts/build_repo_map.py", "skylos.analyzer.Skylos") if key in indices],
    }
    return compact, nodes, edges


SNAPSHOTS = {
    "01-entry-and-scan": ["command:skylos", "skylos.entry.main", "skylos.entry._run_recording_failures", "skylos.cli.main", "skylos.cli._dispatch_early_command", "skylos.cli_core.dispatch.dispatch_early_command", "skylos.cli._run_scan_command", "skylos.commands.scan_cmd.run_scan_command", "skylos.cli.run_analyze", "skylos.cli.run_pipeline", "skylos.analyzer.analyze", "skylos.analyzer.Skylos", "skylos.analyzer.Skylos.analyze", "skylos.config.load_config"],
    "02-static-analysis": ["skylos.analyzer.analyze", "skylos.analyzer.Skylos", "skylos.analyzer.Skylos.analyze", "skylos.analysis.file_worker.process_file", "skylos.analysis.file_worker._process_python_entry", "skylos.analysis.file_worker._process_python_file", "skylos.analysis.file_worker._prepare_python", "skylos.analysis.file_worker._quality_findings", "skylos.analysis.file_worker._danger_findings", "skylos.analysis.file_worker._run_visitors", "skylos.analysis.file_processing.scan_non_python_file", "skylos.visitors.base.Visitor", "skylos.visitors.framework_aware.FrameworkAwareVisitor", "skylos.visitors.test_aware.TestAwareVisitor", "skylos.analyzer.Skylos._build_result", "skylos.analyzer.Skylos._build_def_call_graph", "skylos.core.file_discovery.discover_source_files"],
    "03-cli-dispatch": ["skylos.cli.main", "skylos.cli._dispatch_early_command", "skylos.cli_core.dispatch.dispatch_early_command", *["command:skylos " + name for name in ("graph", "open", "done", "verify", "setup", "discover", "defend", "cicd", "cleanup")]],
    "04-hybrid-pipeline": ["skylos.cli.run_pipeline", "skylos.pipeline.run_pipeline", "skylos.pipeline.run_static_on_files", "skylos.analyzer.analyze", "skylos.llm.analyzer.SkylosLLM", "skylos.llm.runtime.resolve_llm_runtime"],
    "05-maintenance-scripts": ["script:" + name for name in ("scripts/corpus_ci.py", "scripts/build_repo_map.py", "scripts/check_rule_docs_parity.py", "scripts/skylos_gate.py", "scripts/security_benchmark.py", "scripts/quality_benchmark.py", "scripts/secrets_benchmark.py", "scripts/dead_code_benchmark.py")],
}


def snapshot_nodes(key, wanted, by_id, edges):
    selected = {n for n in wanted if n in by_id}
    if key in {"03-cli-dispatch", "05-maintenance-scripts", "04-hybrid-pipeline"}:
        starts = set(selected)
        if key == "03-cli-dispatch":
            starts = {key for key in starts if key.startswith("command:")}
        selected.update(target for source, target, kind in edges if source in starts and kind in {"calls", "starts", "routes", "callback"})
        if key == "05-maintenance-scripts":
            mains = set(selected) - starts
            selected.update(target for source, target, kind in edges if source in mains and kind == "calls")
            selected.update(source for source, target, kind in edges if target in starts and kind == "runs script" and source.startswith("workflow:"))
    if key == "02-static-analysis":
        # Preserve real intermediate helpers between the overview's seed nodes.
        from collections import deque
        outgoing = defaultdict(list)
        for a, b, kind in edges:
            if kind in {"calls", "callback", "creates", "uses"}:
                outgoing[a].append(b)
        pending = deque([("skylos.analyzer.analyze", [])])
        seen = set()
        targets = set(selected)
        while pending:
            current, path = pending.popleft()
            if current in seen or len(path) > 7:
                continue
            seen.add(current)
            if current in targets:
                selected.update(path)
            pending.extend((target, [*path, current]) for target in outgoing[current] if target not in seen)
    return selected


def mermaid(nodes, edges):
    names = {n["id"]: f"n{i}" for i, n in enumerate(nodes)}
    text = ["flowchart LR"]
    for n in nodes:
        label = html.escape(f"{n['name']}()" if n["kind"] in {"function", "method"} else n["name"], quote=True)
        path = html.escape(f"{n['file']}:{n['start']}", quote=True)
        text.append(f'  {names[n["id"]]}["«{n["kind"]}»<br/>{label}<br/>{path}"]')
    for a, b, kind in edges:
        arrow = "-.->" if kind in {"callback", "reference", "routes", "name match", "uses"} else "-->"
        text.append(f"  {names[a]} {arrow}|{kind}| {names[b]}")
    return "\n".join(text) + "\n"


def plantuml(nodes, edges):
    names = {n["id"]: f"n{i}" for i, n in enumerate(nodes)}
    text = ["@startuml", "left to right direction", "skinparam shadowing false", "skinparam linetype ortho"]
    for n in nodes:
        label = n["name"].replace('"', "'") + ("()" if n["kind"] in {"function", "method"} else "")
        text.append(f'rectangle "«{n["kind"]}»\\n{label}\\n{n["file"]}:{n["start"]}" as {names[n["id"]]}')
    for a, b, kind in edges:
        arrow = "..>" if kind in {"callback", "reference", "routes", "name match", "uses"} else "-->"
        if kind == "inherits":
            arrow = "--|>"
        text.append(f"{names[a]} {arrow} {names[b]} : {kind}")
    return "\n".join([*text, "@enduml", ""])


def write_diagrams(nodes, edges, output):
    """Export focused function-flow and class views as Mermaid and PlantUML."""
    directory = output / "diagrams"
    directory.mkdir(exist_ok=True)
    by_id = {n["id"]: n for n in nodes}
    sections, report = [], {}
    for key, wanted in SNAPSHOTS.items():
        selected = snapshot_nodes(key, wanted, by_id, edges)
        chosen = [n for n in nodes if n["id"] in selected]
        linked = [e for e in edges if e[0] in selected and e[1] in selected]
        mmd = mermaid(chosen, linked)
        (directory / f"{key}.mmd").write_text(mmd)
        (directory / f"{key}.puml").write_text(plantuml(chosen, linked))
        report[key] = {"nodes": len(chosen), "edges": len(linked), "missingSeeds": [key for key in wanted if key not in by_id]}
        sections.append(f"## {key.replace('-', ' ').title()}\n\n```mermaid\n{mmd}```\n")
    # A genuine UML class diagram, with method compartments and inheritance.
    chosen_ids = {key for key in ("skylos.analyzer.Skylos", "skylos.visitors.base.Visitor", "skylos.visitors.framework_aware.FrameworkAwareVisitor", "skylos.visitors.test_aware.TestAwareVisitor", "skylos.rules.base.SkylosRule", "skylos.llm.analyzer.SkylosLLM") if key in by_id}
    bases = set(chosen_ids)
    for base in sorted(bases):
        children = sorted(a for a, b, kind in edges if kind == "inherits" and b == base and by_id[a]["kind"] == "class")
        chosen_ids.update(children[:6])
    classes = sorted(chosen_ids)
    aliases = {key: f"c{i}" for i, key in enumerate(classes)}
    mmd, puml = ["classDiagram"], ["@startuml", "skinparam shadowing false"]
    for key in classes:
        node = by_id[key]
        methods = [n for n in nodes if n["kind"] == "method" and n["id"].rsplit(".", 1)[0] == key]
        public = sorted(methods, key=lambda n: (n["name"].split(".")[-1].startswith("_"), n["start"]))[:12]
        mmd.append(f'  class {aliases[key]}["{node["name"]}"] {{')
        puml.append(f'class "{node["name"]}" as {aliases[key]} {{')
        for method in public:
            name = method["name"].rsplit(".", 1)[-1] + "()"
            mmd.append("    " + name)
            puml.append("  " + name)
        mmd.append("  }")
        puml.append("}")
        mmd.append(f'  note for {aliases[key]} "{node["file"]}:{node["start"]}; {len(methods)} methods, showing {len(public)}"')
    for a, b, kind in edges:
        if a in aliases and b in aliases and kind == "inherits":
            mmd.append(f"  {aliases[b]} <|-- {aliases[a]}")
            puml.append(f"{aliases[b]} <|-- {aliases[a]}")
    (directory / "06-core-classes.mmd").write_text("\n".join(mmd) + "\n")
    (directory / "06-core-classes.puml").write_text("\n".join([*puml, "@enduml", ""]))
    sections.append("## Core classes\n\n```mermaid\n" + "\n".join(mmd) + "\n```\n")
    (output / "DIAGRAMS.md").write_text("# Skylos source diagrams\n\nArrows are statically resolved relationships, not execution order. Each focused view shows a subset; use the interactive map to follow every included function. Dashed arrows label callbacks, routes, references, or type use.\n\n" + "\n".join(sections))
    return report
