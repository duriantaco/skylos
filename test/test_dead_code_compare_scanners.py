from scripts.dead_code_compare_scanners import _format_table, _row


def test_comparison_preserves_incomplete_analysis_and_metric_scope():
    # One valid case scores perfectly; a parse failure must remain visible in
    # the comparison instead of implying that both selected cases scored 100.
    summary = {
        "scanner": "skylos",
        "case_count": 2,
        "scored_case_count": 1,
        "unscored_case_count": 1,
        "skipped_case_count": 0,
        "analysis_status": "incomplete",
        "metrics_scoped_to_scored_cases": True,
        "failure_count": 1,
        "counts": {
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "true_negatives": 1,
        },
        "scores": {"precision": 1.0, "recall": 1.0, "f1": 1.0, "overall_score": 100.0},
        "cases": [{"unlabeled_finding_count": 0}, {"unlabeled_finding_count": 0}],
    }

    row = _row(summary)
    assert row["status"] == "incomplete"
    assert row["scored"] == row["unscored"] == 1
    assert row["metric_scope"] == "scored cases only"
    assert row["score"] == 100.0
    assert row["failures"] == 1
    rendered = _format_table([row])
    assert "incomplete" in rendered
    assert "unscored" in rendered
    assert "scored cases only" in rendered


def test_legacy_comparison_summary_remains_compatible():
    summary = {
        "scanner": "vulture",
        "case_count": 1,
        "failure_count": 0,
        "counts": {
            "true_positives": 1,
            "false_positives": 0,
            "false_negatives": 0,
            "true_negatives": 1,
        },
        "scores": {"precision": 1.0, "recall": 1.0, "f1": 1.0, "overall_score": 100.0},
        "cases": [{"unlabeled_finding_count": 0}],
    }
    row = _row(summary)
    assert row["status"] == "complete"
    assert row["scored"] == 1
    assert row["unscored"] == 0
    assert row["metric_scope"] == "all cases"
    assert row["TP"] == row["TN"] == 1
