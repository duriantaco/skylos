"""Optional profiling of Skylos analysis, independent of target-code tracing."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from time import perf_counter
from typing import Any, TextIO


class AnalysisProfile:
    """Parent-process scanner costs and elapsed progress phases for one call."""

    def __init__(self, *, limit: int = 20) -> None:
        self.limit = max(1, min(limit, 100))
        self._profiler = None
        self._previous_profiler = None
        self._started = 0.0
        self._phase_started = 0.0
        self._phase_name = "analysis setup"
        self._phases: dict[str, dict[str, Any]] = {}
        self._wall_seconds = 0.0
        self._completed = False

    def start(self) -> None:
        import cProfile

        self._profiler = cProfile.Profile()
        self._previous_profiler = sys.getprofile()
        self._started = self._phase_started = perf_counter()
        self._profiler.enable()

    def phase(self, name: str) -> None:
        """Mark a phase boundary; repeated updates of one phase add no boundary."""
        if name == self._phase_name:
            return
        now = perf_counter()
        self._finish_phase(now)
        self._phase_name = name
        self._phase_started = now

    def progress_callback(self, callback: Callable | None = None) -> Callable:
        def progress(current, total, file):
            label = Path(file).name
            if label.startswith("PHASE:"):
                self.phase(label[len("PHASE:") :].strip() or "analysis")
            elif self._phase_name == "analysis setup":
                self.phase("file analysis")
            if callback is not None:
                callback(current, total, file)

        return progress

    def _finish_phase(self, now: float) -> None:
        row = self._phases.setdefault(
            self._phase_name,
            {"name": self._phase_name, "seconds": 0.0, "visits": 0},
        )
        row["seconds"] += max(0.0, now - self._phase_started)
        row["visits"] += 1

    def stop(self, *, completed: bool) -> None:
        if self._profiler is None:
            return
        self._profiler.disable()
        if self._previous_profiler is not None:
            if callable(self._previous_profiler):
                sys.setprofile(self._previous_profiler)
            else:
                self._previous_profiler.enable()
        now = perf_counter()
        self._finish_phase(now)
        self._wall_seconds = max(0.0, now - self._started)
        self._completed = completed

    def summary(self) -> dict[str, Any]:
        import pstats

        rows = []
        package_root = Path(__file__).resolve().parents[1]
        if self._profiler is not None:
            for (filename, line, function), values in pstats.Stats(
                self._profiler
            ).stats.items():
                try:
                    relative = Path(filename).resolve().relative_to(package_root)
                except (OSError, RuntimeError, ValueError):
                    continue
                primitive, calls, own_seconds, cumulative_seconds, _callers = values
                rows.append(
                    {
                        "file": f"skylos/{relative.as_posix()}",
                        "line": line,
                        "function": function,
                        "calls": calls,
                        "primitive_calls": primitive,
                        "self_seconds": own_seconds,
                        "cumulative_seconds": cumulative_seconds,
                    }
                )

        def ranked(key: str) -> list[dict[str, Any]]:
            return sorted(
                rows,
                key=lambda row: (-row[key], row["file"], row["line"], row["function"]),
            )[: self.limit]

        return {
            "schema_version": 1,
            "kind": "skylos_analysis",
            "completed": self._completed,
            "wall_seconds": self._wall_seconds,
            "phases": [dict(row) for row in self._phases.values()],
            "functions": {
                "by_cumulative": ranked("cumulative_seconds"),
                "by_self": ranked("self_seconds"),
            },
            "notes": [
                "Profiling adds overhead; these are instrumented timings.",
                "Function rows cover Skylos code in the current process/thread; worker and subprocess internals are not profiled.",
                "Cumulative function times include child calls and overlap; do not sum them.",
                "This profiles scanner analysis and does not enable target-code execution.",
            ],
        }


@contextmanager
def profile_scan(
    enabled: bool = False, *, limit: int = 20
) -> Iterator[AnalysisProfile | None]:
    """Enable the stdlib profiler only for an explicitly requested analysis."""
    if not enabled:
        yield None
        return
    profile = AnalysisProfile(limit=limit)
    profile.start()
    completed = False
    try:
        yield profile
        completed = True
    finally:
        profile.stop(completed=completed)


def render_profile(summary: dict[str, Any], *, stream: TextIO | None = None) -> None:
    """Human diagnostics stay on stderr, including for machine-output scans."""
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    console = Console(file=stream or sys.stderr, highlight=False)
    console.print(
        Text(
            f"Skylos analysis profile: {summary['wall_seconds']:.3f} s (profiling overhead included)"
        )
    )
    phases = Table("Phase", "Wall seconds")
    for row in summary.get("phases", []):
        phases.add_row(Text(row["name"]), f"{row['seconds']:.3f}")
    console.print(phases)
    for key, title in (
        ("by_cumulative", "Top cumulative scanner functions"),
        ("by_self", "Top self-time scanner functions"),
    ):
        table = Table("Function", "Calls", "Self s", "Cumulative s", title=title)
        for row in summary.get("functions", {}).get(key, []):
            table.add_row(
                Text(f"{row['file']}:{row['line']} {row['function']}"),
                str(row["calls"]),
                f"{row['self_seconds']:.3f}",
                f"{row['cumulative_seconds']:.3f}",
            )
        console.print(table)
    console.print(
        Text("Cumulative rows overlap; worker/subprocess internals are excluded.")
    )


def write_profile_output(summary: dict[str, Any], path: str | Path) -> None:
    from skylos.core.safe_cache_io import write_text_no_symlink

    if not write_text_no_symlink(
        path, json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    ):
        raise OSError(f"could not safely write profile output: {path}")


def validate_profile_output(
    profile_path: str | Path | None, report_path: str | Path | None
) -> None:
    if profile_path is None or report_path is None:
        return
    try:
        profile_file = Path(profile_path).expanduser().resolve()
        report_file = Path(report_path).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError("cannot resolve profile/report output paths") from exc
    if profile_file == report_file:
        raise ValueError("--profile-output must differ from --output")
