"""Saved scans and managed MR-comment delivery have independent outcomes."""

from types import SimpleNamespace

import pytest

import skylos.api as api
from skylos.cloud.gitlab import delivery_receipt


def _receipt(status="published", reason="complete", **overrides):
    return {
        "status": status,
        "reason": reason,
        "created": 1 if status in ("published", "partial") else 0,
        "updated": 0,
        "resolved": 0,
        "eligible": 1,
        **overrides,
    }


@pytest.mark.parametrize("status", ["published", "noop"])
def test_successful_delivery_prints_counts_without_failing_ci(status):
    result = delivery_receipt(_receipt(status))
    assert result["gitlab_delivery_exit_code"] == 0
    assert result["gitlab_delivery"]["status"] == status
    assert "Scan saved." in result["gitlab_delivery_message"]
    assert "created" in result["gitlab_delivery_message"]
    assert "updated" in result["gitlab_delivery_message"]
    assert "resolved" in result["gitlab_delivery_message"]


def test_protected_push_without_mr_is_an_expected_skip():
    result = delivery_receipt(_receipt("skipped", "not_merge_request", eligible=0))
    assert result["gitlab_delivery_exit_code"] == 0
    assert "not a merge-request pipeline" in result["gitlab_delivery_message"]


@pytest.mark.parametrize(
    "status,reason",
    [
        ("partial", "comment_limit"),
        ("failed", "gitlab_transport_error"),
        ("skipped", "stale_diff"),
        ("skipped", "lease_busy_or_stale"),
        ("skipped", "disconnected"),
        ("skipped", "scan_incomplete"),
        ("skipped", "connection_replaced"),
    ],
)
def test_incomplete_or_unexpected_delivery_outcomes_fail_independently(status, reason):
    result = delivery_receipt(_receipt(status, reason))
    assert result["gitlab_delivery_exit_code"] == 2
    assert reason in result["gitlab_delivery_message"]
    assert "Scan saved." in result["gitlab_delivery_message"]


@pytest.mark.parametrize(
    "status", ["published", "noop", "skipped", "partial", "failed"]
)
def test_plan_requirement_gives_a_clear_upgrade_and_setup_message(status):
    result = delivery_receipt(_receipt(status, "plan_required"))
    assert result["gitlab_delivery_exit_code"] == 2
    assert "upgrade" in result["gitlab_delivery_message"]
    assert "setup" in result["gitlab_delivery_message"]


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        "published",
        _receipt(status="unknown"),
        _receipt(created=-1),
        _receipt(created=True),
        _receipt(eligible="1"),
        _receipt(updated=100_001),
        _receipt(reason=None),
        _receipt(reason=""),
        _receipt("noop", created=1),
        _receipt("skipped", created=1),
        _receipt(created=0),
        _receipt("noop", "stale_diff"),
    ],
)
def test_missing_malformed_or_inconsistent_delivery_receipt_fails_closed(value):
    result = delivery_receipt(value)
    assert result["gitlab_delivery_exit_code"] == 2
    assert result["gitlab_delivery"]["reason"] == "invalid_receipt"
    assert "Scan saved." in result["gitlab_delivery_message"]


def test_unknown_reason_and_extra_server_fields_cannot_print_credentials():
    secret = "fixture.private.token\n\x1b[31m"
    result = delivery_receipt(_receipt("failed", secret, token=secret))
    assert result["gitlab_delivery_exit_code"] == 2
    assert result["gitlab_delivery"]["reason"] == "unrecognized_reason"
    assert secret not in str(result)


def test_partial_scope_success_explains_old_comments_are_retained():
    result = delivery_receipt(_receipt("noop", "partial_scope_no_resolution"))
    assert result["gitlab_delivery_exit_code"] == 0
    assert "previous comments were not resolved" in result["gitlab_delivery_message"]


@pytest.mark.parametrize("force", [False, True])
def test_managed_finalization_retains_saved_scan_and_gate_even_when_delivery_fails(
    force,
):
    response = SimpleNamespace(
        status_code=200,
        json=lambda: {
            "scan_id": "fixture-saved-scan",
            "plan": "pro",
            "quality_gate": {"passed": False},
            "gitlab_delivery": _receipt("partial", "comment_limit"),
        },
    )
    result = api._finalize_report_upload(
        response,
        grade_data=None,
        quiet=True,
        strict=True,
        is_forced=force,
        gitlab_managed=True,
    )
    assert result["success"] is True
    assert result["scan_id"] == "fixture-saved-scan"
    assert result["quality_gate_passed"] is False
    assert result["gitlab_delivery_exit_code"] == 2


def test_api_key_and_github_finalization_keep_existing_result_and_gate_behavior():
    response = SimpleNamespace(
        status_code=200,
        json=lambda: {
            "scan_id": "fixture-saved-scan",
            "quality_gate": {"passed": False},
            "gitlab_delivery": _receipt("partial", "comment_limit"),
        },
    )
    result = api._finalize_report_upload(response, grade_data=None, quiet=True)
    assert result == {
        "success": True,
        "scan_id": "fixture-saved-scan",
        "quality_gate_passed": False,
        "plan": "free",
        "credits_warning": False,
    }
    with pytest.raises(SystemExit) as caught:
        api._finalize_report_upload(response, grade_data=None, quiet=True, strict=True)
    assert caught.value.code == 1
