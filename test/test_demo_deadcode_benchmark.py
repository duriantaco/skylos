from skylos.demo_deadcode_benchmark import (
    DemoDeadCodeCase,
    case_key,
    hard_cases,
    normalize_skylos_symbol,
    score_case_predictions,
)


def test_hard_cases_are_unique_and_balanced():
    cases = hard_cases()
    keys = [case.key for case in cases]

    assert len(cases) == 24
    assert len(set(keys)) == len(keys)
    assert sum(1 for case in cases if case.expected == "dead") == 12
    assert sum(1 for case in cases if case.expected == "alive") == 12


def test_normalize_skylos_symbol_relativizes_demo_root():
    finding = {
        "file": "/Users/oha/skylos-demo/app/config.py",
        "simple_name": "_is_prod",
    }

    assert normalize_skylos_symbol(finding, "/Users/oha/skylos-demo") == case_key(
        "app/config.py", "_is_prod"
    )


def test_score_case_predictions_counts_tp_fp_fn_tn():
    cases = [
        DemoDeadCodeCase(
            file="a.py",
            symbol="dead_one",
            expected="dead",
            rationale="dead",
        ),
        DemoDeadCodeCase(
            file="b.py",
            symbol="dead_two",
            expected="dead",
            rationale="dead",
        ),
        DemoDeadCodeCase(
            file="c.py",
            symbol="alive_one",
            expected="alive",
            rationale="alive",
        ),
        DemoDeadCodeCase(
            file="d.py",
            symbol="alive_two",
            expected="alive",
            rationale="alive",
        ),
    ]

    predicted = {
        case_key("a.py", "dead_one"),
        case_key("c.py", "alive_one"),
    }

    scored = score_case_predictions(predicted, cases)

    assert scored["tp"] == 1
    assert scored["fp"] == 1
    assert scored["fn"] == 1
    assert scored["tn"] == 1
    assert scored["precision"] == 0.5
    assert scored["recall"] == 0.5
    assert scored["accuracy"] == 0.5
    assert scored["extra_predictions"] == []
