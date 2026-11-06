from scripts.security_compare_scanners import _format_table, _row


def _summary():
    return {
        "scanner": "skylos",
        "case_count": 2,
        "failure_count": 1,
        "counts": {
            "true_positives": 1,
            "false_positives": 0,
            "false_negatives": 0,
            "true_negatives": 1,
        },
        "scores": {"precision": 1.0, "recall": 1.0, "f1": 1.0, "overall_score": 100.0},
    }


def test_security_comparison_keeps_incomplete_metric_scope_visible():
    summary = _summary()
    summary.update(
        analysis_status="incomplete",
        scored_case_count=1,
        unscored_case_count=1,
        metrics_scoped_to_scored_cases=True,
    )
    row = _row(summary)
    assert row["status"] == "incomplete"
    assert row["scored"] == row["unscored"] == 1
    assert row["metric_scope"] == "scored cases only"
    assert row["failures"] == 1
    assert row["score"] == 100.0
    table = _format_table([row])
    assert "incomplete" in table
    assert "unscored" in table
    assert "scored cases only" in table


def test_security_comparison_accepts_legacy_summary_fields():
    row = _row(_summary())
    assert row["status"] == "complete"
    assert row["scored"] == 2
    assert row["unscored"] == 0
    assert row["metric_scope"] == "all cases"
