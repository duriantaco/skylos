#!/usr/bin/env python3
"""agent-pr-bench: Skylos vs Semgrep CE vs Bandit (vs SonarQube when configured)
on agent-written code changes.

    python3 bench.py all        # prepare + run + score (what run.sh calls)
    python3 bench.py prepare    # clone pinned repos, build workspaces
    python3 bench.py run        # run every tool on every workspace
    python3 bench.py score      # normalize, apply labels, write results/
    python3 bench.py worksheet  # dump unlabeled in-scope findings for labeling

Method, corpus and labeling rules: docs/benchmark-agent-code.md.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness import corpus, score, tools  # noqa: E402

REPO_ROOT = HERE.parents[1]
LABELS = HERE / "labels" / "findings.json"
RESULTS = HERE / "results"


def default_work() -> Path:
    return Path(os.environ.get("AGENT_PR_BENCH_WORK") or Path(tempfile.gettempdir()) / "agent-pr-bench")


def tool_objects(args) -> dict:
    work = Path(args.work)
    semgrep_bin = args.semgrep or shutil.which("semgrep") or ""
    bandit_bin = args.bandit or shutil.which("bandit") or ""
    objs = {
        "skylos": tools.Skylos(REPO_ROOT, python=args.skylos_python),
        "semgrep": tools.Semgrep(semgrep_bin, work / "semgrep-rules"),
        "bandit": tools.Bandit(bandit_bin),
        "sonarqube": tools.Sonar(),
    }
    for name in ("semgrep", "bandit"):
        if not getattr(objs[name], "binary"):
            raise SystemExit(f"{name} not found; pass --{name} or run run.sh (creates a pinned venv)")
    return {k: v for k, v in objs.items() if k in args.tools}


def cmd_prepare(args) -> None:
    work = Path(args.work)
    only = set(args.only.split(",")) if args.only else None
    workspaces = []
    if args.corpus in ("all", "seeded"):
        workspaces += corpus.prepare_seeded(work, only)
    if args.corpus in ("all", "real"):
        for c in corpus.load_real_commits():
            if only and c["id"] not in only:
                continue
            print(f"  preparing {c['id']} {c['repo']}@{c['sha'][:10]}", file=sys.stderr)
            workspaces += corpus.prepare_real(work, {c["id"]})
    # Merge by id so seeded and real corpora can be prepared separately.
    path = work / "workspaces.json"
    merged = {w["id"]: w for w in (json.loads(path.read_text()) if path.exists() and not args.fresh else [])}
    for w in workspaces:
        merged[w.id] = w.to_json()
    ordered = sorted(merged.values(), key=lambda w: (w["kind"] != "seeded", w["id"]))
    path.write_text(json.dumps(ordered, indent=1))
    print(f"prepared {len(workspaces)} workspaces ({len(ordered)} total) in {work}", file=sys.stderr)


def load_workspaces(work: Path) -> list[corpus.Workspace]:
    path = work / "workspaces.json"
    if not path.exists():
        raise SystemExit("no workspaces.json; run `bench.py prepare` first")
    return [corpus.Workspace.from_json(w) for w in json.loads(path.read_text())]


def cmd_run(args) -> None:
    work = Path(args.work)
    workspaces = load_workspaces(work)
    only = set(args.only.split(",")) if args.only else None
    objs = tool_objects(args)
    if "semgrep" in objs:
        objs["semgrep"].fetch_rules()
    runs_path = work / "runs.json"
    runs = json.loads(runs_path.read_text()) if runs_path.exists() else {}
    for ws in workspaces:
        if only and ws.id not in only:
            continue
        corpus.materialize(ws)
        for name, tool in objs.items():
            out_dir = work / "raw" / name
            out_dir.mkdir(parents=True, exist_ok=True)
            try:
                rec = tool.run(ws, out_dir)
            except Exception as exc:  # noqa: BLE001 - record harness/tool failures, keep going
                rec = tools.RunRecord(name, ws.id, "error", None, None, [], None, f"{type(exc).__name__}: {exc}"[:2000])
            runs[f"{name}|{ws.id}"] = tools.record_to_json(rec)
            wall = f"{rec.wall_s:.1f}s" if rec.wall_s is not None else "-"
            print(f"  {ws.id:<32} {name:<10} {rec.status:<14} {wall}", file=sys.stderr)
            tmp = runs_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(runs, indent=1))
            tmp.replace(runs_path)
        if not args.keep_checkouts:
            corpus.snapshot_and_prune(ws, work / "snapshots")


def environment(args, objs: dict) -> dict:
    env = {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "cpu_count": os.cpu_count(),
        "python_for_skylos": subprocess.run([args.skylos_python, "--version"], capture_output=True, text=True).stdout.strip(),
    }
    for name, tool in objs.items():
        if name == "sonarqube":
            reason = tool.availability()
            env["sonarqube"] = f"not run: {reason}" if reason else tool.version()
        else:
            env[name] = tool.version()
        if name == "skylos":
            env["skylos_flags"] = " ".join(tools.Skylos.flags) + " --diff-base <base> --format json --no-upload"
        if name == "semgrep":
            manifest = tool.rules_dir / "manifest.json"
            env["semgrep_rules"] = json.loads(manifest.read_text()) if manifest.exists() else "not fetched"
        if name == "bandit":
            env["bandit_flags"] = "-f json -q <changed .py files> (default profile: all tests, all severities)"
    return env


def normalize_all(work: Path, workspaces, objs, runs) -> dict:
    normalized = {}
    ws_by_id = {w.id: w for w in workspaces}
    for key, rec in runs.items():
        name, ws_id = key.split("|", 1)
        if name not in objs or ws_id not in ws_by_id:
            continue
        if rec["status"] != "ok" or not rec.get("raw_path"):
            continue
        rec_obj = tools.RunRecord(**rec)
        normalized[(name, ws_id)] = objs[name].normalize(rec_obj, ws_by_id[ws_id])
    return normalized


def cmd_score(args) -> None:
    work = Path(args.work)
    workspaces = load_workspaces(work)
    objs = tool_objects(args)
    raw_runs = json.loads((work / "runs.json").read_text())
    runs = {tuple(k.split("|", 1)): v for k, v in raw_runs.items() if k.split("|", 1)[0] in objs}
    normalized = normalize_all(work, workspaces, objs, raw_runs)
    labels = score.load_labels(LABELS)
    tool_names = [t for t in ("skylos", "semgrep", "bandit", "sonarqube") if t in objs]
    # A tool that was never run (e.g. SonarQube without a server) is reported
    # in the environment block but kept out of the metric tables.
    ran = [t for t in tool_names if any(r["status"] == "ok" for (tt, _), r in runs.items() if tt == t)]
    report = score.build_report(workspaces, runs, normalized, labels, ran)
    scoped = report.pop("_scoped_findings")
    env = environment(args, objs)

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "summary.json").write_text(json.dumps({"environment": env, **report}, indent=1, sort_keys=True) + "\n")
    # Tool messages can echo the synthetic credentials of seeded cases (Bandit
    # B105 prints the literal). Redact them so the checked-in results do not
    # contain provider-format tokens.
    secrets = sorted(
        {"".join(parts) for case in corpus.load_cases() for parts in (case.get("materialize") or {}).values()},
        key=len,
        reverse=True,
    )
    with (RESULTS / "findings.jsonl").open("w") as fh:
        for f in sorted(scoped, key=lambda x: (x["workspace"], x["tool"], x["file"], x["line"], x["rule"])):
            for secret in secrets:
                f["message"] = f["message"].replace(secret, "<redacted seeded credential>")
            fh.write(json.dumps(f, sort_keys=True) + "\n")
    runs_out = {
        f"{t}|{w}": {k: r[k] for k in ("status", "exit_code", "wall_s", "note")}
        for (t, w), r in sorted(runs.items())
    }
    (RESULTS / "runs.json").write_text(json.dumps(runs_out, indent=1, sort_keys=True) + "\n")
    (RESULTS / "workspaces.json").write_text(
        json.dumps(
            [
                {**{k: v for k, v in w.to_json().items() if k not in ("path", "meta")},
                 "meta": {k: v for k, v in w.meta.items() if k != "cache"}}
                for w in workspaces
            ],
            indent=1,
        ) + "\n"
    )
    (RESULTS / "tables.md").write_text(score.render_tables(report, env))
    print((RESULTS / "tables.md").read_text())
    if report["labels"]["unlabeled"] and args.strict:
        raise SystemExit(f"{report['labels']['unlabeled']} in-scope findings are unlabeled (run `bench.py worksheet`)")


def cmd_worksheet(args) -> None:
    """Unlabeled in-scope findings with code context. Tool names are omitted and
    rows are sorted by location so tools interleave (labeling is blind-ish: rule
    IDs and message styles still reveal the tool)."""
    work = Path(args.work)
    workspaces = load_workspaces(work)
    objs = tool_objects(args)
    raw_runs = json.loads((work / "runs.json").read_text())
    normalized = normalize_all(work, workspaces, objs, raw_runs)
    labels = score.load_labels(LABELS)
    ws_by_id = {w.id: w for w in workspaces}
    rows = []
    for (name, ws_id), (findings, _sig) in normalized.items():
        ws = ws_by_id[ws_id]
        for f in score.in_scope(ws, score.dedupe(findings)):
            fp = score.fingerprint(ws_id, f)
            if fp in labels:
                continue
            path = ws.path / f["file"]
            if not path.is_file():
                path = work / "snapshots" / ws.id / f["file"]
            context = ""
            if path.is_file():
                src = path.read_text(errors="replace").splitlines()
                lo, hi = max(1, f["line"] - 3), min(len(src), f["end_line"] + 3)
                context = "\n".join(f"{n:>5}{'>' if f['line'] <= n <= f['end_line'] else ' '} {src[n - 1]}" for n in range(lo, hi + 1))
            rows.append(
                {
                    "fingerprint": fp,
                    "workspace": ws_id,
                    "kind": ws.kind,
                    "rule": f["rule"],
                    "category": f["category"],
                    "file": f["file"],
                    "line": f["line"],
                    "message": f["message"],
                    "defect_candidates": score.location_candidates(ws, f),
                    "context": context,
                }
            )
    rows.sort(key=lambda r: (r["workspace"], r["file"], r["line"], r["rule"]))
    out = Path(args.out or work / "worksheet.json")
    out.write_text(json.dumps(rows, indent=1))
    print(f"{len(rows)} unlabeled findings -> {out}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["prepare", "run", "score", "worksheet", "all"])
    ap.add_argument("--work", default=str(default_work()), help="scratch directory for clones and raw outputs")
    ap.add_argument("--corpus", choices=["all", "seeded", "real"], default="all")
    ap.add_argument("--only", help="comma-separated workspace ids")
    ap.add_argument("--tools", default="skylos,semgrep,bandit,sonarqube")
    ap.add_argument("--semgrep", help="semgrep binary (default: PATH)")
    ap.add_argument("--bandit", help="bandit binary (default: PATH)")
    ap.add_argument("--skylos-python", default=sys.executable, help="interpreter with Skylos' dependencies installed")
    ap.add_argument("--out", help="worksheet output path")
    ap.add_argument("--keep-checkouts", action="store_true", help="run: keep real-commit checkouts (default: snapshot changed files, delete checkout)")
    ap.add_argument("--fresh", action="store_true", help="prepare: discard previously prepared workspaces")
    ap.add_argument("--strict", action="store_true", help="score: fail if any in-scope finding is unlabeled")
    args = ap.parse_args()
    args.tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    Path(args.work).mkdir(parents=True, exist_ok=True)
    if args.command == "all":
        args.fresh = True
    if args.command in ("prepare", "all"):
        cmd_prepare(args)
    if args.command in ("run", "all"):
        cmd_run(args)
    if args.command in ("score", "all"):
        cmd_score(args)
    if args.command == "worksheet":
        cmd_worksheet(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
