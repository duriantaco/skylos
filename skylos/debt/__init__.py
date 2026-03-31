from skylos.debt.baseline import (
    append_history,
    annotate_hotspots,
    compare_to_baseline,
    load_baseline,
    save_baseline,
)
from skylos.debt.policy import DebtPolicy, load_policy
from skylos.debt.report import format_debt_json, format_debt_table
from skylos.debt.result import (
    DebtAdvisory,
    DebtHotspot,
    DebtScore,
    DebtSignal,
    DebtSnapshot,
)


def augment_hotspots_with_advisories(*args, **kwargs):
    from skylos.debt.advisor import (
        augment_hotspots_with_advisories as augment_hotspots_with_advisories_impl,
    )

    return augment_hotspots_with_advisories_impl(*args, **kwargs)


def collect_debt_signals(*args, **kwargs):
    from skylos.debt.engine import collect_debt_signals as collect_debt_signals_impl

    return collect_debt_signals_impl(*args, **kwargs)


def run_debt_analysis(*args, **kwargs):
    from skylos.debt.engine import run_debt_analysis as run_debt_analysis_impl

    return run_debt_analysis_impl(*args, **kwargs)


__all__ = [
    "append_history",
    "annotate_hotspots",
    "augment_hotspots_with_advisories",
    "collect_debt_signals",
    "compare_to_baseline",
    "DebtAdvisory",
    "DebtHotspot",
    "DebtPolicy",
    "DebtScore",
    "DebtSignal",
    "DebtSnapshot",
    "format_debt_json",
    "format_debt_table",
    "load_baseline",
    "load_policy",
    "run_debt_analysis",
    "save_baseline",
]
