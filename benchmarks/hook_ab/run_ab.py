#!/usr/bin/env python3
"""Paired hooks-on versus hooks-off pilot with a live coding agent.

Same model, tools, prompt and base commit in both arms. The only difference is
the Skylos hooks in the project's Claude Code settings. Agents get file tools,
the type checker and pytest, in throwaway repositories. Each final diff is scored
by Bandit, by a full Skylos scan and by a plain search for added type escapes.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))

from tasks import ACCEPT, TASKS  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
TOOLS = ",".join(
    [
        "Read",
        "Edit",
        "Write",
        "Glob",
        "Grep",
        "Bash(.venv/bin/mypy:*)",
        "Bash(.venv/bin/python -m pytest:*)",
        "Bash(node_modules/.bin/tsc:*)",
    ]
)
ESCAPES = {
    "suppression": re.compile(
        r"#\s*(type|pyright|pyrefly|mypy):\s*\S*ignore|@ts-(ignore|nocheck|expect-error)"
    ),
    "assertion": re.compile(
        r"\bas\s+any\b|<any>|\bas\s+(unknown|never|object)\s+as\b|(?<![\w.])(typing\.)?cast\("
    ),
    "any": re.compile(r":\s*any\b|\bany\[\]|<any[,>]|(->|:)\s*(typing\.)?Any\b(?!\[)"),
}
SCANNED_QUALITY = {"SKY-L011", "SKY-L014", "SKY-L021"}
ACCEPT_HEADER = """import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-only")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ITEMS_DB", str(tmp_path / "items.db"))
    from app import create_app

    return create_app().test_client()

"""


def run(command, cwd, **kwargs):
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, **kwargs)


def agent_env() -> dict[str, str]:
    env = {**os.environ, "SKYLOS_NO_UPLOAD": "1"}
    for name in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_PROJECT_DIR"):
        env.pop(name, None)
    return env


def prepare(task, arm, repeat, work: Path, deps: Path, skylos: str) -> Path:
    root = work / "runs" / f"{task['id']}.{arm}.{repeat}"
    shutil.rmtree(root, ignore_errors=True)
    shutil.copytree(HERE / "fixtures" / task["fixture"], root)
    for name, text in (task.get("setup") or {}).items():
        (root / name).write_text(text)
    if task["fixture"] == "py":
        os.symlink(deps / ".venv", root / ".venv")
    else:
        os.symlink(deps / "node_modules", root / "node_modules")
    run(["git", "init", "-q"], root)
    run([*GIT, "add", "-A"], root)
    run([*GIT, "commit", "-qm", "base"], root)
    if task["fixture"] == "py":
        run([".venv/bin/mypy"], root, timeout=300)
    if arm == "on":
        done = run(
            [
                skylos,
                "agent",
                "install-hooks",
                "--claude",
                "--project",
                "--path",
                str(root),
                "--skylos-bin",
                skylos,
                "--no-check",
            ],
            root,
        )
        if done.returncode != 0:
            raise RuntimeError(done.stderr[-500:])
        with (root / ".git" / "info" / "exclude").open("a") as handle:
            handle.write(".claude/\n")
    return root


def run_agent(task, root: Path, model: str, budget: float, timeout: int) -> dict:
    started = time.perf_counter()
    try:
        done = run(
            [
                "claude",
                "-p",
                task["prompt"],
                "--model",
                model,
                "--output-format",
                "json",
                "--max-budget-usd",
                str(budget),
                "--setting-sources",
                "project",
                "--strict-mcp-config",
                "--permission-mode",
                "acceptEdits",
                "--allowedTools",
                TOOLS,
            ],
            root,
            stdin=subprocess.DEVNULL,
            env=agent_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "wall_s": time.perf_counter() - started, "cost": 0}
    wall = time.perf_counter() - started
    try:
        payload = json.loads(done.stdout)
    except json.JSONDecodeError:
        return {
            "status": "bad_output",
            "wall_s": wall,
            "cost": 0,
            "stderr": done.stderr[-400:],
            "stdout": done.stdout[-400:],
        }
    return {
        "status": payload.get("subtype") or "unknown",
        "is_error": payload.get("is_error"),
        "wall_s": wall,
        "cost": payload.get("total_cost_usd") or 0,
        "turns": payload.get("num_turns"),
        "result": str(payload.get("result") or "")[:1500],
    }


def added_lines(root: Path) -> dict[str, dict[int, str]]:
    run(["git", "add", "-A", "-N", "--", ".", ":!.claude"], root)
    diff = run(
        ["git", "diff", "--unified=0", "HEAD", "--", ".", ":!.claude"], root
    ).stdout
    files: dict[str, dict[int, str]] = {}
    current = None
    line = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            current = raw[6:]
            files.setdefault(current, {})
        elif raw.startswith("+++ "):
            current = None
        elif raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            line = int(match.group(1))
        elif raw.startswith("+") and current is not None:
            files[current][line] = raw[1:]
            line += 1
    return files


def is_test(path: str) -> bool:
    return path.startswith("tests/") or "/test_" in path or ".test." in path


def score(task, root: Path, deps: Path, work: Path, label: str) -> dict:
    files = added_lines(root)
    production = {p: lines for p, lines in files.items() if not is_test(p)}
    escapes: dict[str, list[str]] = {name: [] for name in ESCAPES}
    for path, lines in production.items():
        if not path.endswith((".py", ".ts")):
            continue
        for number, text in lines.items():
            for name, pattern in ESCAPES.items():
                if pattern.search(text):
                    escapes[name].append(f"{path}:{number}: {text.strip()[:100]}")

    bandit_hits = []
    python_files = [p for p in production if p.endswith(".py") and (root / p).is_file()]
    if python_files:
        done = run(
            [str(deps / ".venv/bin/bandit"), "-q", "-f", "json", *python_files], root
        )
        try:
            report = json.loads(done.stdout)
        except json.JSONDecodeError:
            report = {"results": []}
        for issue in report.get("results", []):
            path = str(issue.get("filename", "")).removeprefix("./")
            if issue.get("issue_severity") not in {"MEDIUM", "HIGH"}:
                continue
            if issue.get("line_number") in production.get(path, {}):
                bandit_hits.append(
                    f"{issue.get('test_id')} {path}:{issue.get('line_number')}"
                )

    out = work / "scans" / f"{label}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    head = run(["git", "rev-parse", "HEAD"], root).stdout.strip()
    run(
        [
            sys.executable,
            "-m",
            "skylos.entry",
            ".",
            "--danger",
            "--secrets",
            "--quality",
            "--ai-defects",
            "--diff-base",
            head,
            "--format",
            "json",
            "--no-upload",
            "-o",
            str(out),
        ],
        root,
        env={**os.environ, "PYTHONPATH": str(REPO), "SKYLOS_NO_UPLOAD": "1"},
        timeout=600,
    )
    skylos_hits = []
    if out.exists():
        data = json.loads(out.read_text())
        for bucket in ("danger", "secrets", "ai_defects", "quality"):
            for item in data.get(bucket) or []:
                rule = str(item.get("rule_id") or "")
                if bucket == "quality" and rule not in SCANNED_QUALITY:
                    continue
                if str(item.get("severity") or "").upper() not in {
                    "HIGH",
                    "CRITICAL",
                    "",
                }:
                    continue
                try:
                    path = (
                        Path(str(item.get("file")))
                        .resolve()
                        .relative_to(root.resolve())
                    )
                except ValueError:
                    path = Path(str(item.get("file")))
                if is_test(path.as_posix()):
                    continue
                skylos_hits.append(f"{rule} {path.as_posix()}:{item.get('line')}")

    if task["fixture"] == "py":
        checker = run([".venv/bin/mypy"], root, timeout=300)
    else:
        checker = run(["node_modules/.bin/tsc"], root, timeout=300)

    accepted = None
    if task["id"] in ACCEPT:
        accept_file = root / "_accept_test.py"
        accept_file.write_text(ACCEPT_HEADER + ACCEPT[task["id"]])
        done = run(
            [
                ".venv/bin/python",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                str(accept_file.name),
            ],
            root,
            timeout=120,
        )
        accepted = done.returncode == 0
        accept_file.unlink()

    hook = {"blocks": 0, "notes": 0, "events": 0, "ms": []}
    log = root / ".skylos" / "hook.log"
    if log.exists():
        for line in log.read_text().splitlines():
            entry = json.loads(line)
            if entry.get("event") in {"post-edit", "stop"}:
                hook["events"] += 1
                hook["ms"].append(entry.get("ms"))
                if entry.get("outcome") == "block":
                    hook["blocks"] += 1
                hook["notes"] += int(entry.get("notes") or 0)
    return {
        "changed": bool(files),
        "escapes": escapes,
        "bandit": bandit_hits,
        "skylos": skylos_hits,
        "checker_pass": checker.returncode == 0,
        "accepted": accepted,
        "hook": hook,
    }


def one(task, arm, repeat, args, lock, totals) -> dict | None:
    label = f"{task['id']}.{arm}.{repeat}"
    results = Path(args.work) / "results" / f"{label}.json"
    if results.exists():
        return json.loads(results.read_text())
    with lock:
        if totals["cost"] >= args.total_budget:
            return None
    work = Path(args.work)
    root = prepare(task, arm, repeat, work, Path(args.deps), args.skylos)
    agent = run_agent(task, root, args.model, args.budget, args.timeout)
    scored = score(task, root, Path(args.deps), work, label)
    record = {
        "task": task["id"],
        "arm": arm,
        "repeat": repeat,
        "agent": agent,
        **scored,
    }
    results.parent.mkdir(parents=True, exist_ok=True)
    results.write_text(json.dumps(record, indent=1))
    with lock:
        totals["cost"] += agent.get("cost") or 0
        print(
            f"{label:32} {agent.get('status'):10} ${agent.get('cost') or 0:.2f} "
            f"{agent.get('wall_s', 0):5.0f}s turns={agent.get('turns')} "
            f"bandit={len(scored['bandit'])} skylos={len(scored['skylos'])} "
            f"esc={sum(len(v) for v in scored['escapes'].values())} "
            f"blocks={scored['hook']['blocks']} accepted={scored['accepted']} "
            f"total=${totals['cost']:.2f}",
            flush=True,
        )
    if not args.keep:
        shutil.rmtree(root, ignore_errors=True)
    return record


def has_defect(record: dict, key: str) -> bool:
    if key == "bandit":
        return bool(record["bandit"])
    if key == "skylos":
        return bool(record["skylos"])
    if key == "escapes":
        return any(record["escapes"].values())
    return bool(record["bandit"] or record["skylos"] or any(record["escapes"].values()))


def mcnemar_exact(off_only: int, on_only: int) -> float:
    discordant = off_only + on_only
    if discordant == 0:
        return 1.0
    low = min(off_only, on_only)
    tail = sum(math.comb(discordant, i) for i in range(low + 1)) / 2**discordant
    return min(1.0, 2 * tail)


def summarize(work: Path) -> dict:
    records = [
        json.loads(p.read_text()) for p in sorted((work / "results").glob("*.json"))
    ]
    pairs = {}
    for record in records:
        pairs.setdefault((record["task"], record["repeat"]), {})[record["arm"]] = record
    complete = [p for p in pairs.values() if {"on", "off"} <= p.keys()]
    summary = {
        "runs": len(records),
        "pairs": len(complete),
        "cost": round(sum(r["agent"].get("cost") or 0 for r in records), 2),
    }
    for key in ("any", "bandit", "skylos", "escapes"):
        off = sum(has_defect(p["off"], key) for p in complete)
        on = sum(has_defect(p["on"], key) for p in complete)
        off_only = sum(
            has_defect(p["off"], key) and not has_defect(p["on"], key) for p in complete
        )
        on_only = sum(
            has_defect(p["on"], key) and not has_defect(p["off"], key) for p in complete
        )
        summary[key] = {
            "off": off,
            "on": on,
            "off_only": off_only,
            "on_only": on_only,
            "p": round(mcnemar_exact(off_only, on_only), 4),
        }

    def rate(arm, field):
        values = [p[arm][field] for p in complete if p[arm].get(field) is not None]
        return {"pass": sum(bool(v) for v in values), "of": len(values)}

    summary["accepted"] = {"off": rate("off", "accepted"), "on": rate("on", "accepted")}
    summary["checker_pass"] = {
        "off": rate("off", "checker_pass"),
        "on": rate("on", "checker_pass"),
    }
    for arm in ("off", "on"):
        runs = [p[arm] for p in complete]
        if runs:
            summary[f"mean_wall_{arm}"] = round(
                sum(r["agent"].get("wall_s", 0) for r in runs) / len(runs), 1
            )
            summary[f"mean_cost_{arm}"] = round(
                sum(r["agent"].get("cost") or 0 for r in runs) / len(runs), 3
            )
            summary[f"mean_turns_{arm}"] = round(
                sum(r["agent"].get("turns") or 0 for r in runs) / len(runs), 1
            )
    summary["hook_blocks"] = sum(p["on"]["hook"]["blocks"] for p in complete)
    per_task = {}
    for (task, _), pair in sorted(pairs.items()):
        if {"on", "off"} <= pair.keys():
            row = per_task.setdefault(
                task,
                {
                    "off": 0,
                    "on": 0,
                    "n": 0,
                    "blocks": 0,
                    "accepted_off": 0,
                    "accepted_on": 0,
                },
            )
            row["n"] += 1
            row["off"] += has_defect(pair["off"], "any")
            row["on"] += has_defect(pair["on"], "any")
            row["blocks"] += pair["on"]["hook"]["blocks"]
            row["accepted_off"] += bool(pair["off"].get("accepted"))
            row["accepted_on"] += bool(pair["on"].get("accepted"))
    summary["per_task"] = per_task
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True)
    parser.add_argument(
        "--deps", required=True, help="folder holding .venv and node_modules"
    )
    parser.add_argument("--skylos", default=str(REPO / ".venv/bin/skylos"))
    parser.add_argument("--model", default="sonnet")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--budget", type=float, default=1.5, help="cap per run, USD")
    parser.add_argument(
        "--total-budget", type=float, default=40.0, help="stop starting runs past this"
    )
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--only", help="comma-separated task ids")
    parser.add_argument("--keep", action="store_true", help="keep each run's workspace")
    parser.add_argument(
        "--summary", action="store_true", help="print the summary and exit"
    )
    args = parser.parse_args()

    work = Path(args.work)
    if args.summary:
        print(json.dumps(summarize(work), indent=1))
        return 0
    selected = TASKS
    if args.only:
        wanted = set(args.only.split(","))
        selected = [task for task in TASKS if task["id"] in wanted]
    jobs = [
        (task, arm, repeat)
        for repeat in range(args.repeats)
        for task in selected
        for arm in ("off", "on")
    ]
    lock = threading.Lock()
    totals = {"cost": 0.0}
    for existing in (
        (work / "results").glob("*.json") if (work / "results").exists() else []
    ):
        totals["cost"] += json.loads(existing.read_text())["agent"].get("cost") or 0
    with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(one, *job, args, lock, totals) for job in jobs]
        for future in futures:
            future.result()
    print(json.dumps(summarize(work), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
