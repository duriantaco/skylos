"""Interactive and plain-text status for the main static scan."""

from dataclasses import dataclass, replace
from pathlib import Path
from threading import Lock
from time import monotonic

from rich.cells import cell_len, set_cell_size
from rich.console import Console, Group
from rich.live import Live
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

_STAGES = ("Discover files", "Analyze files", "Cross-file checks", "Prepare report")
_DISCOVERY = {"file discovery", "scan preparation"}
_OPERATIONS = {
    "file discovery": "Finding source files",
    "scan preparation": "Preparing scan",
    "file analysis": "Analyzing source files",
    "combining file results": "Combining file results",
    "Reading Python modules": "Reading Python modules",
    "Django converter discovery": "Finding Django URL converters",
    "Django converter indexing": "Indexing Django URL converters",
    "Django converter registrations": "Checking Django URL registrations",
    "Django path converters": "Checking Django URL converters",
    "framework callbacks": "Checking framework callbacks",
    "web framework routes": "Checking web framework routes",
    "framework entry points": "Finding framework entry points",
    "framework analysis": "Checking framework usage",
    "dynamic registrations": "Finding dynamic registrations",
    "property and protocol liveness": "Checking property and protocol usage",
    "public API and dispatch": "Checking public APIs and dynamic calls",
    "mark refs": "Resolving references",
    "hierarchy refs": "Resolving type hierarchies",
    "grep verify": "Searching for uses of possibly unused code",
    "candidate verification": "Checking possibly unused code",
    "dead-code liveness": "Checking which code is used",
    "entry reachability": "Following calls from entry points",
    "transitive dead code": "Following calls from unused code",
    "building report": "Building report",
}
_COUNT_UNITS = {
    "file analysis": "files",
    "combining file results": "files",
    "Reading Python modules": "modules",
    "Django path converters": "modules",
    "framework callbacks": "modules",
    "web framework routes": "modules",
    "candidate verification": "candidates",
    "mark refs": "refs",
}
_ACTIVE_VERBS = {
    "file analysis": "Analyzing",
    "combining file results": "Combining",
    "Reading Python modules": "Reading",
    "Django path converters": "Checking converters in",
    "framework callbacks": "Checking callbacks in",
    "web framework routes": "Checking routes in",
}


def _safe_text(value: str) -> str:
    # File names may contain line breaks, terminal escapes, or bidi controls.
    return "".join(char if char.isprintable() else "?" for char in value)


def _duration(seconds: float) -> str:
    minutes, seconds = divmod(int(seconds), 60)
    return f"{minutes}:{seconds:02}"


@dataclass
class _Activity:
    phase: str
    started: float
    stages_done: int
    operation: str
    unit: str = ""
    current: int = 0
    total: int | None = None
    active: Path | None = None
    last_file: Path | None = None
    first_count: int = 0
    first_completion: float | None = None
    last_completion: float | None = None
    samples: int = 0

    def count(self, current: int, total: int, now: float):
        if current > self.current:
            if self.first_completion is None:
                self.first_completion = now
                self.first_count = current
            self.samples += 1
            self.last_completion = now
        self.current = current
        self.total = total

    @property
    def stage(self) -> str:
        return (
            _STAGES[self.stages_done] if self.stages_done < len(_STAGES) else "Complete"
        )

    @property
    def count_text(self) -> str:
        return "" if self.total is None else f"{self.current}/{self.total} {self.unit}"

    def timing(self, now: float) -> str:
        elapsed = now - self.started
        if self.total is None:
            return f"{int(elapsed)}s in phase · ETA unknown" if elapsed >= 5 else ""
        if self.current == self.total:
            return ""
        idle = now - (
            self.last_completion if self.last_completion is not None else self.started
        )
        if idle >= 10:
            return f"count unchanged for {int(idle)}s"
        # Exclude startup and wait for separated samples: a burst of fast file
        # completions after a slow first file makes a poor initial estimate.
        if (
            self.samples >= 3
            and elapsed >= 5
            and self.last_completion - self.first_completion >= 3
        ):
            seconds_per_unit = (self.last_completion - self.first_completion) / (
                self.current - self.first_count
            )
            remaining = max(1, round(seconds_per_unit * (self.total - self.current)))
            return f"phase ETA ~{_duration(remaining)}"
        return ""


class ScanProgress:
    """Track scan events; entering the context enables Rich's timed refresh."""

    def __init__(self, console: Console, project_root: Path | None = None):
        self.console = console
        self.project_root = (
            Path(project_root).absolute() if project_root is not None else None
        )
        self.started_at = monotonic()
        self._activity = _Activity(
            "scan preparation", self.started_at, 0, _OPERATIONS["scan preparation"]
        )
        self._lock = Lock()
        self._parallel_snapshot = None

    def __enter__(self):
        self._live = Live(
            console=self.console,
            get_renderable=self._render,
            refresh_per_second=4,
            transient=True,
            redirect_stdout=False,
            redirect_stderr=False,
        )
        self._live.start(refresh=True)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                with self._lock:
                    self._activity = _Activity(
                        "complete", monotonic(), len(_STAGES), "Complete"
                    )
        finally:
            self._live.stop()

    def update(self, current: int, total: int, path: Path):
        name = str(path)
        marker = name.startswith("PHASE: ")
        phase = name.removeprefix("PHASE: ") if marker else "file analysis"
        now = monotonic()
        with self._lock:
            activity = self._activity
            if phase != activity.phase or (marker and current == 0):
                if phase in _DISCOVERY:
                    stage = 0
                elif phase == "file analysis":
                    stage = 1
                elif phase == "building report":
                    stage = 3
                else:
                    stage = 2
                operation = _OPERATIONS.get(phase) or _safe_text(
                    phase[:1].upper() + phase[1:]
                )
                activity = _Activity(
                    phase, now, stage, operation, _COUNT_UNITS.get(phase, "")
                )
                self._activity = activity
            if not marker:
                activity.last_file = path
            # Some phase-start markers use (0, 1) for unmeasured operations.
            if activity.unit:
                activity.count(current, total, now)

    __call__ = update

    def file_started(self, path: Path):
        with self._lock:
            self._activity.active = path

    def file_finished(self, path: Path):
        with self._lock:
            self._activity.active = None
            self._activity.last_file = path

    def parallel_activity(self, snapshot):
        """Read the workers' active file paths at display time."""
        with self._lock:
            self._parallel_snapshot = snapshot

    def reporting(self, operation: str = "Preparing report"):
        with self._lock:
            self._activity = _Activity(
                "building report", monotonic(), 3, _safe_text(operation)
            )

    def _snapshot(self):
        with self._lock:
            activity = replace(self._activity)
            active = ()
            if (
                self._parallel_snapshot is not None
                and activity.phase == "file analysis"
            ):
                active = self._parallel_snapshot()
        if active:
            prefix = (
                "Analyzing" if len(active) == 1 else f"Analyzing ({len(active)} active)"
            )
            return activity, prefix, active[0]
        if activity.active is not None:
            return (
                activity,
                _ACTIVE_VERBS.get(activity.phase, "Checking"),
                activity.active,
            )
        if activity.last_file is not None:
            return activity, "Completed", activity.last_file
        return activity, activity.operation, None

    def _file_text(self, path: Path) -> str:
        path = Path(path)
        if self.project_root is not None:
            try:
                path = path.absolute().relative_to(self.project_root)
            except ValueError:
                if path.is_absolute():
                    path = Path(path.name)
        return _safe_text(str(path))

    def status_text(self) -> str:
        """Single-line snapshot for redirected output and CI logs."""
        activity, label, path = self._snapshot()
        now = monotonic()
        parts = (
            f"Scan · {activity.stages_done}/{len(_STAGES)} stages done",
            activity.stage,
            f"{label} {self._file_text(path)}" if path is not None else label,
            activity.count_text,
            activity.timing(now),
            f"{_duration(now - self.started_at)} elapsed",
        )
        return " · ".join(part for part in parts if part)

    def _render(self) -> Group:
        activity, label, path = self._snapshot()
        now = monotonic()
        width = self.console.width
        narrow = width < 70
        bar_width = min(26, max(6, width // 6))
        overall = Table.grid(padding=(0, 1), expand=True)
        overall.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        overall.add_column(width=bar_width)
        overall.add_column(no_wrap=True)
        overall.add_column(no_wrap=True, justify="right", style="dim")
        overall.add_row(
            Text(
                activity.stage if narrow else f"Scan · {activity.stage}",
                style="bold cyan",
            ),
            ProgressBar(
                total=len(_STAGES),
                completed=activity.stages_done,
                complete_style="cyan",
                finished_style="cyan",
            ),
            f"{activity.stages_done}/{len(_STAGES)} stages"
            + ("" if narrow else " done"),
            _duration(now - self.started_at) + ("" if narrow else " elapsed"),
        )
        details = Table.grid(padding=(0, 1), expand=True)
        details.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        fields = []
        label_width = width
        if activity.total is not None:
            details.add_column(width=bar_width)
            details.add_column(no_wrap=True)
            fields.extend(
                (
                    ProgressBar(
                        total=activity.total,
                        completed=activity.current,
                        complete_style="green",
                        finished_style="green",
                    ),
                    activity.count_text,
                )
            )
            label_width -= bar_width + len(activity.count_text) + 2
        timing = activity.timing(now)
        if timing:
            details.add_column(no_wrap=True, justify="right", style="dim")
            fields.append(timing)
            label_width -= len(timing) + 1
        if path is not None:
            shown = self._file_text(path)
            available = max(2, label_width - len(label) - 1)
            if cell_len(shown) > available:
                # Keep the filename visible even when its directory is long.
                shown = "…" + set_cell_size(shown[::-1], available - 1)[::-1]
            label = f"{label} {shown}"
        details.add_row(Text(label), *fields)
        return Group(overall, details)
