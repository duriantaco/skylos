#!/usr/bin/env python3
"""Time the agent edit hook on one real file, as found and after repeated edits.

Each round appends one harmless statement to the file, runs
``skylos hook recheck FILE`` (the policy the post-edit hook applies) as a
separate process, and records the wall-clock seconds. The file is restored
afterwards, byte for byte. The first run reports the caches as found; the
later runs are the warm edit loop an agent experiences.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MARKERS = {
    ".py": "bench_edit_marker_{n} = {n}\n",
    ".pyi": "bench_edit_marker_{n}: int\n",
    ".ts": "export const benchEditMarker{n} = {n};\n",
    ".tsx": "export const benchEditMarker{n} = {n};\n",
    ".js": "const benchEditMarker{n} = {n};\n",
    ".mjs": "export const benchEditMarker{n} = {n};\n",
    ".go": "var benchEditMarker{n} = {n}\n",
    ".rs": "pub const BENCH_EDIT_MARKER_{n}: i32 = {n};\n",
}


def _marker(path: Path, n: int) -> str:
    template = MARKERS.get(path.suffix.lower())
    if template is None:
        return "\n"
    return template.format(n=n)


def _skylos_bin(explicit: str | None) -> str:
    if explicit:
        return explicit
    beside_python = Path(sys.executable).with_name("skylos")
    if beside_python.is_file():
        return str(beside_python)
    found = shutil.which("skylos")
    if found:
        return found
    raise SystemExit("skylos executable not found; pass --skylos PATH")


def _git(repo: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _version(skylos: str) -> str:
    try:
        proc = subprocess.run(
            [skylos, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (proc.stdout or proc.stderr).strip() or "unknown"


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


STATS_PREFIX = "SKYLOS_VERIFY_STATS="


def _run_recheck(
    skylos: str, repo: Path, target: Path
) -> tuple[float, int, str, list[dict]]:
    started = time.perf_counter()
    proc = subprocess.run(
        [skylos, "hook", "recheck", str(target)],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "SKYLOS_VERIFY_STATS": "1"},
    )
    elapsed = time.perf_counter() - started
    stats = []
    diagnostic_lines = []
    for line in proc.stderr.splitlines():
        if line.startswith(STATS_PREFIX):
            try:
                record = json.loads(line[len(STATS_PREFIX) :])
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                stats.append(record)
        else:
            diagnostic_lines.append(line)
    tail = (proc.stdout or "\n".join(diagnostic_lines)).strip().splitlines()
    last_line = ""
    if tail:
        last_line = tail[-1]
    return elapsed, proc.returncode, last_line, stats


def _require_unchanged(target: Path, expected: bytes) -> None:
    try:
        unchanged = target.read_bytes() == expected
    except OSError:
        unchanged = False
    if not unchanged:
        raise SystemExit(
            f"{target} changed outside the benchmark; left it untouched. "
            "Run without editing or formatting the file concurrently."
        )


def benchmark(repo: Path, target: Path, edits: int, skylos: str) -> dict:
    original = target.read_bytes()
    expected = original
    runs: list[dict] = []

    def recheck(kind: str) -> None:
        seconds, code, verdict, stats = _run_recheck(skylos, repo, target)
        runs.append(
            {
                "kind": kind,
                "seconds": seconds,
                "exit_code": code,
                "verdict": verdict,
                "verification_stats": stats,
            }
        )
        if code not in (0, 1):
            raise SystemExit(f"hook recheck failed: {verdict!r}")

    try:
        recheck("first")
        for n in range(1, edits + 1):
            _require_unchanged(target, expected)
            marker = _marker(target, n).encode("utf-8")
            if expected and not expected.endswith((b"\n", b"\r")):
                marker = b"\n" + marker
            with target.open("ab") as handle:
                handle.write(marker)
            expected += marker
            recheck("warm")
    finally:
        _require_unchanged(target, expected)
        if expected != original:
            target.write_bytes(original)

    warm = [run["seconds"] for run in runs if run["kind"] == "warm"]
    verdicts = {(run["exit_code"], run["verdict"]) for run in runs}
    summary = {
        "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repo": str(repo),
        "file": str(target.relative_to(repo)),
        "file_lines": original.count(b"\n"),
        "tracked_files": len(_git(repo, "ls-files").splitlines()),
        "skylos_version": _version(skylos),
        "skylos_bin": skylos,
        "revision": _git(repo, "rev-parse", "--short", "HEAD") or "unknown",
        "dirty_paths": len(_git(repo, "status", "--short").splitlines()),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "edits": edits,
        "runs": runs,
        "first_seconds": runs[0]["seconds"],
        "verdicts_consistent": len(verdicts) == 1,
    }
    if warm:
        summary["warm_p50_seconds"] = statistics.median(warm)
        summary["warm_p95_seconds"] = _percentile(warm, 95)
        summary["warm_min_seconds"] = min(warm)
        summary["warm_max_seconds"] = max(warm)
    return summary


def _print_table(summary: dict) -> None:
    print(f"Warm-edit hook benchmark: {summary['file']} in {summary['repo']}")
    print(
        f"{summary['skylos_version']}  rev {summary['revision']} "
        f"({summary['dirty_paths']} dirty paths)  python {summary['python']}  "
        f"{summary['platform']}"
    )
    print(f"{'run':<4} {'kind':<6} {'seconds':>8} {'exit':>4}  verdict")
    for index, run in enumerate(summary["runs"]):
        print(
            f"{index:<4} {run['kind']:<6} {run['seconds']:>8.2f} "
            f"{run['exit_code']:>4}  {run['verdict']}"
        )
    line = f"first {summary['first_seconds']:.2f} s"
    if "warm_p50_seconds" in summary:
        line += (
            f"; warm p50 {summary['warm_p50_seconds']:.2f} s, "
            f"p95 {summary['warm_p95_seconds']:.2f} s, "
            f"min {summary['warm_min_seconds']:.2f} s, "
            f"max {summary['warm_max_seconds']:.2f} s "
            f"(n={summary['edits']})"
        )
    print(line)
    if summary["verdicts_consistent"]:
        print("verdict identical on every run")
    else:
        print(
            "WARNING: verdict changed between runs; cached and uncached results differ"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Time `skylos hook recheck` on one file across repeated edits."
    )
    parser.add_argument("file", help="File inside the repository to edit and recheck")
    parser.add_argument("--repo", default=".", help="Repository root (default: cwd)")
    parser.add_argument("--edits", type=int, default=5, help="Warm edit rounds")
    parser.add_argument("--skylos", default=None, help="skylos executable to time")
    parser.add_argument(
        "--json", action="store_true", help="Print JSON instead of a table"
    )
    parser.add_argument(
        "--output", default=None, help="Also write the JSON summary here"
    )
    args = parser.parse_args()

    repo = Path(args.repo).expanduser().resolve()
    target = Path(args.file).expanduser()
    if not target.is_absolute():
        target = repo / target
    target = target.resolve()
    if not target.is_file():
        raise SystemExit(f"not a file: {target}")
    if repo not in target.parents:
        raise SystemExit(f"{target} is outside {repo}")
    if args.edits < 1:
        raise SystemExit("--edits must be at least 1")

    summary = benchmark(repo, target, args.edits, _skylos_bin(args.skylos))
    if args.output:
        out = Path(args.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        _print_table(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
