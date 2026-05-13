from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_DEMO_ROOT = Path("/Users/oha/skylos-demo")

# Audited stale labels in skylos-demo's benchmark ground truth. These currently
# appear only in benchmark/docs bookkeeping and not in real repo usage.
AUDITED_STALE_ALIVE = {
    ("app/core/auth.py", "verify_api_key"),
    ("app/core/plugins.py", "get_plugin"),
    ("app/db/crud.py", "get_note_by_id"),
    ("app/db/crud.py", "update_note"),
    ("app/db/crud.py", "delete_note"),
    ("app/services/audit_service.py", "log_action"),
}

HARD_DEAD_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("app/api/deps.py", "get_actor_from_headers"),
    ("app/config.py", "_parse_cors_origins"),
    ("app/config.py", "_is_prod"),
    ("app/api/routers/notes.py", "_normalize_query"),
    ("app/api/routers/reports.py", "generate_report"),
    ("app/db/session.py", "_drop_all"),
    ("app/db/crud.py", "_row_to_dict"),
    ("app/services/notes_services.py", "_validate_title"),
    ("app/services/report_service.py", "_search_v2"),
    ("app/services/report_service.py", "generate_report_v1"),
    ("app/core/events.py", "on_note_deleted_cleanup"),
    ("app/services/tasks.py", "generate_daily_report"),
)

HARD_ALIVE_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("app/services/export_service.py", "export_csv"),
    ("app/services/export_service.py", "export_json"),
    ("app/services/export_service.py", "export_xml"),
    ("app/api/handlers.py", "handle_create"),
    ("app/api/handlers.py", "handle_update"),
    ("app/api/handlers.py", "handle_delete"),
    ("app/core/events.py", "on_note_created_log"),
    ("app/core/events.py", "on_note_created_notify"),
    ("app/services/tasks.py", "send_welcome_email"),
    ("app/services/notification_service.py", "_dispatch_email"),
    ("app/services/notification_service.py", "_dispatch_slack"),
    ("app/services/notification_service.py", "_dispatch_sms"),
)


@dataclass(frozen=True)
class DemoDeadCodeCase:
    file: str
    symbol: str
    expected: str
    rationale: str

    @property
    def key(self) -> str:
        return case_key(self.file, self.symbol)


def case_key(file: str, symbol: str) -> str:
    return f"{file}::{symbol}"


def hard_cases() -> list[DemoDeadCodeCase]:
    cases: list[DemoDeadCodeCase] = []
    for file, symbol in HARD_DEAD_FUNCTIONS:
        cases.append(
            DemoDeadCodeCase(
                file=file,
                symbol=symbol,
                expected="dead",
                rationale="Explicitly marked or structured as dead demo code.",
            )
        )
    for file, symbol in HARD_ALIVE_FUNCTIONS:
        cases.append(
            DemoDeadCodeCase(
                file=file,
                symbol=symbol,
                expected="alive",
                rationale="Runtime-used via dynamic dispatch, registry, or decorator wiring.",
            )
        )
    return cases


def hard_case_keys() -> set[str]:
    return {case.key for case in hard_cases()}


def load_corrected_ground_truth(
    demo_root: str | Path = DEFAULT_DEMO_ROOT,
) -> dict[str, set[tuple[str, str]]]:
    demo_root = Path(demo_root)
    bench_path = demo_root / "benchmark_hybrid.py"
    spec = importlib.util.spec_from_file_location(
        "skylos_demo_benchmark_hybrid", bench_path
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"unable to load benchmark file: {bench_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    expected = {(file, name) for file, name, _ in module.get_all_expected()}
    used = {(file, name) for file, name in module.ACTUALLY_USED}
    dynamic_alive = {(file, name) for file, name in module.DYNAMIC_FALSE_POSITIVES}

    expected |= AUDITED_STALE_ALIVE
    used -= AUDITED_STALE_ALIVE

    return {
        "expected_dead": expected,
        "expected_alive": used,
        "dynamic_alive": dynamic_alive,
    }


def normalize_skylos_symbol(finding: dict[str, Any], demo_root: str | Path) -> str:
    root = f"{Path(demo_root).resolve().as_posix()}/"
    file = str(finding.get("file") or "").replace("\\", "/")
    if file.startswith(root):
        file = file[len(root) :]
    if file.startswith("./"):
        file = file[2:]
    symbol = str(
        finding.get("simple_name") or finding.get("name") or finding.get("symbol") or ""
    )
    if file == "app/api/routers/reports.py" and symbol == "format_money":
        symbol = "fmt_money"
    return case_key(file, symbol)


def score_case_predictions(
    predicted_dead: set[str], cases: list[DemoDeadCodeCase]
) -> dict[str, Any]:
    dead_cases = {case.key for case in cases if case.expected == "dead"}
    alive_cases = {case.key for case in cases if case.expected == "alive"}
    scoped_cases = dead_cases | alive_cases
    scored_predictions = predicted_dead & scoped_cases
    extra_predictions = predicted_dead - scoped_cases

    tp = scored_predictions & dead_cases
    fp = scored_predictions & alive_cases
    fn = dead_cases - scored_predictions
    tn = alive_cases - scored_predictions

    precision = len(tp) / len(scored_predictions) if scored_predictions else 0.0
    recall = len(tp) / len(dead_cases) if dead_cases else 0.0
    accuracy = (len(tp) + len(tn)) / len(cases) if cases else 0.0
    f1 = 0.0
    if precision and recall:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "tp": len(tp),
        "fp": len(fp),
        "fn": len(fn),
        "tn": len(tn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "accuracy": round(accuracy, 4),
        "f1": round(f1, 4),
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
        "extra_predictions": sorted(extra_predictions),
    }
