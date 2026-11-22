"""Build a reusable offline UI from changed source and cached analysis."""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import analyze, explain, review
from .cache import (
    ReportCache,
    affected_callers,
    build_lock,
    capture_inputs,
    digest,
    native_graph,
    runtime_key,
    write_changed,
    write_json,
)

ASSETS = Path(__file__).with_name("assets")
TOOLS = Path(__file__).parent


def resolve_base(root, requested):
    from skylos.core.git_context import GitContext
    context = GitContext.from_path(root)
    head = context.run("rev-parse", "--verify", "HEAD")
    if head.returncode:
        return None, None
    use_parent = not requested or set(requested) == {"0"}
    value = "HEAD^" if use_parent else requested
    result = context.run("rev-parse", "--verify", "--end-of-options", value + "^{commit}")
    if result.returncode:
        if use_parent:
            return None, None
        raise ValueError(f"Comparison base is unavailable: {requested}")
    comparison = context.run("merge-base", result.stdout.strip(), head.stdout.strip())
    if comparison.returncode:
        raise ValueError(f"No common ancestor for comparison base: {requested}")
    return value, comparison.stdout.strip()


def graph_changes(previous, current):
    before = {n["id"]: (n.get("code_hash"), n["file"]) for n in (previous or {}).get("nodes", [])}
    after = {n["id"]: (n.get("code_hash"), n["file"]) for n in current["nodes"]}
    changed = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
    return changed, affected_callers(previous, current, changed)


def build_report(root, output, *, base="HEAD", cache_directory=None, notes=None, force=False, ci=False, run_url=""):
    """Update the offline report, keeping unchanged analysis and descriptions."""
    root, output = Path(root).resolve(), Path(output).absolute()
    if output.is_symlink():
        raise ValueError("The UML output directory must not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    cache_directory = Path(cache_directory) if cache_directory else output / ".cache"
    notes = Path(notes) if notes else (output / "curation.json" if not ci and (output / "curation.json").is_file() else ASSETS / "default-descriptions.json")
    with build_lock(cache_directory):
        try:
            base_ref, base_commit = resolve_base(root, base)
        except ValueError:
            if not ci or not re.fullmatch(r"[0-9a-fA-F]{40}", base or ""):
                raise
            base_ref, base_commit = None, None
        files = review.changed_files(root, base_commit, ci=ci)
        scope = {file["path"] for file in files if file["status"] != "D"} if ci else None
        cache = ReportCache(root, cache_directory, force=force)
        repo, hashes, controls = capture_inputs(root, cache, scope=scope)
        tools = {p.name: cache.fingerprint(p, key="tool:" + p.name) for p in sorted(TOOLS.glob("*.py"))}
        assets = {p.name: cache.fingerprint(p, key="asset:" + p.name) for p in sorted(ASSETS.iterdir()) if p.is_file()}
        assets["README.md"] = cache.fingerprint(TOOLS / "README.md", key="asset:runner-readme")
        note_hash = cache.fingerprint(notes, key="notes") if notes.is_file() else None
        runtime = runtime_key()
        engine_files = {p: h for p, h in hashes.items() if p.startswith(("skylos/graph/", "skylos/changemap/", "skylos/visitors/")) or p in {"skylos/constants.py", "skylos/__init__.py", "skylos/core/git_context.py", "skylos/core/git_safety.py"}}
        engine_key = digest([engine_files, runtime])
        signature = digest([hashes, controls, files, tools, assets, note_hash, runtime, repo.head, repo.dirty, base_ref, base_commit, ci, run_url])
        report_sources = {p: value for p, value in {**hashes, **controls}.items() if value is not None}
        previous_sources = cache.prior.get("report_sources", cache.prior.get("native_sources", {}))
        changed_files = sorted(p for p in report_sources if previous_sources.get(p) != report_sources[p])
        removed_files = sorted(set(previous_sources) - set(report_sources))
        if not force and cache.prior.get("signature") == signature and cache.outputs_match(output):
            stats = {"cache_hit": True, "report_written": False, "changed_files": [], "removed_files": [], "source_files_reused": len(report_sources), "function_facts_analyzed": 0, "python_files_parsed": 0, "native_files_parsed": 0, "test_roots_analyzed": 0, "head_commit": repo.head, "base_commit": base_commit, **cache.summary()}
            write_json(output / "update-stats.json", stats, pretty=True)
            # Refresh only the stat index after harmless timestamp changes.
            state = dict(cache.prior)
            state["inputs"] = cache.inputs
            write_json(cache.state_path, state)
            return stats
        graph, native_key = native_graph(root, cache, repo, hashes, engine_key=engine_key, reuse_project_cache=not ci)
        changed_symbols, affected = graph_changes(getattr(cache, "previous_graph", None), graph)
        view_key = digest([native_key, controls, tools["analyze.py"], tools["review.py"], sorted(scope) if scope is not None else None])
        compact, nodes, edges = cache.blob(
            "view_graph", view_key, lambda: analyze.build_data(graph, root, cache, controls=controls, scope=scope),
        )
        cache.save_files()
        compact["meta"]["commit"], compact["meta"]["dirty"] = repo.head, repo.dirty
        review_key = digest([hashes, controls, files, repo.head, base_ref, base_commit, ci, engine_key, tools["review.py"]])
        detail_key = digest([view_key, note_hash, tools["explain.py"], review_key])

        def details():
            changes, meta, overview = cache.blob(
                "review", review_key, lambda: review.build_comparison(root, base_ref, base_commit, files, ci=ci),
            )
            explain.enrich(notes, graph, compact, nodes, edges, cache, changes=changes)
            meta["changedFunctions"] = sum(row["change"] is not None for row in compact["details"])
            return {"details": compact["details"], "source": compact["source"], "meta": compact["meta"], "reviewMeta": meta, "overview": overview}

        enriched = cache.blob("details", detail_key, details)
        compact.update({k: v for k, v in enriched.items() if k != "meta"})
        compact["meta"].update({k: v for k, v in enriched["meta"].items() if k in {"explainedFromSource", "sourceFacts", "testLinks"}})
        compact["meta"]["builtAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        compact["linkNotes"] = json.loads((ASSETS / "link-notes.json").read_text())
        stats = {"cache_hit": False, "report_written": True, "changed_files": changed_files, "removed_files": removed_files, "source_files_reused": len(report_sources) - len(changed_files), "changed_symbols": len(changed_symbols), "affected_callers": len(affected), "head_commit": repo.head, "base_commit": base_commit, "ci": ci, "run_url": run_url, **cache.summary()}
        compact["update"] = stats
        payload = json.dumps(compact, separators=(",", ":"), ensure_ascii=False).encode()
        compressed = gzip.compress(payload, compresslevel=3, mtime=0)
        encoded = base64.b64encode(compressed).decode("ascii")
        fragment = (ASSETS / "viewer-template.html").read_text().replace("__UML_PAYLOAD__", encoded)
        shell = (ASSETS / "shell-template.html").read_text()
        page = shell.replace("__UML_STYLES__", (ASSETS / "viewer.css").read_text()).replace("__UML_CONTENT__", fragment)
        write_changed(output / "index.html", page)
        write_changed(output / "call-map.json.gz", compressed)
        diagrams = {} if ci else analyze.write_diagrams(nodes, edges, output)
        manifest = {**compact["meta"], "nodeCount": len(nodes), "edgeCount": len(edges), "htmlBytes": len(page.encode()), "diagrams": diagrams, "update": stats}
        write_json(output / "manifest.json", manifest, pretty=True)
        outputs = ["index.html", "call-map.json.gz", "manifest.json"]
        if not ci:
            write_changed(output / "CODE_REVIEW.md", (ASSETS / "CODE_REVIEW.md").read_bytes())
            write_changed(output / "README.md", (TOOLS / "README.md").read_text())
            outputs.extend(["DIAGRAMS.md", "CODE_REVIEW.md", "README.md"])
            outputs.extend(p.relative_to(output).as_posix() for p in sorted((output / "diagrams").iterdir()) if p.suffix in {".mmd", ".puml"})
        cache.save_state(signature, output, outputs, native_key, engine_key, hashes)
        stats.update(cache.summary())
        write_json(output / "update-stats.json", stats, pretty=True)
        return stats


def main(argv=None):
    """Parse report options and run an incremental build."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root")
    parser.add_argument("--output", type=Path, default=None, help="Generated report directory (default: ROOT/UML)")
    parser.add_argument("--cache-dir", type=Path, default=None, help="Persistent analysis cache (default: OUTPUT/.cache)")
    parser.add_argument("--base", default="HEAD", help="Review comparison ref; pass the before-push SHA in CI")
    parser.add_argument("--notes", type=Path, help="Optional source descriptions; personal notes are never inferred in CI")
    parser.add_argument("--force", action="store_true", help="Recompute all analysis; keep authored notes")
    parser.add_argument("--cached", action="store_true", help="Compatibility flag: all runs are incremental by default")
    parser.add_argument("--ci", action="store_true", help="Map changed files only and use shared descriptions")
    parser.add_argument("--run-url", default="", help="CI run URL displayed in the report")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = args.output or root / "UML"
    try:
        stats = build_report(root, output, base=args.base, cache_directory=args.cache_dir, notes=args.notes, force=args.force, ci=args.ci, run_url=args.run_url)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"UML report: {error}\n")
    print(json.dumps(stats, indent=2))
    return 0
