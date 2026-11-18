"""Upload success, policy conditions and authenticated origin are independent."""

import pytest

from skylos import api
from skylos.cloud.cloud_receipt import cloud_receipt_lines, sent_line
from skylos.cloud.gate_status import formatted_gate_line, gate_context
from skylos.cloud.upload_status import verification_receipt
from skylos.commands.scan_cmd import _public_upload_receipt

BASE = "https://skylos.dev"


def response(trust="unverified", passed=True):
    return {
        "success": True,
        "scan_id": "saved-scan",
        "upload_trust": trust,
        "quality_gate_passed": passed,
        "quality_gate_reported": True,
        "quality_gate": {"passed": passed},
        "destination": {"project_id": "project-1", "branch": "main"},
    }


@pytest.mark.parametrize("passed", [True, False])
def test_developer_receipt_confirms_saved_scan_and_explains_next_step(passed):
    result = response(passed=passed)
    receipt = _public_upload_receipt(result)
    assert receipt["status"] == "uploaded"
    assert receipt["upload_trust"] == "unverified"
    assert receipt["quality_gate_status"] == "preview"
    assert receipt["verification"]["status"] == "needs_ci"
    assert (
        receipt["verification"]["setup_url"]
        == f"{api.BASE_URL}/dashboard/projects/project-1/settings#merge-blocking"
    )
    lines = cloud_receipt_lines(None, result, BASE, ci_configured=True)
    assert "Scan saved" in lines[0]
    assert f"gate (not blocking): {'pass' if passed else 'fail'}" in lines[0]
    assert lines[1] == f"  Open: {BASE}/dashboard/projects/project-1/scans/saved-scan"
    assert "Only verified CI scans block merges" in lines[2]
    assert any("The Skylos workflow checks pull requests" in line for line in lines)
    assert not any("verification needed" in line or "finish CI setup" in line for line in lines)
    assert not any("Quality gate:" in line or ": PASSED" in line for line in lines)


@pytest.mark.parametrize(
    "trust", [None, {}, ["verified_ci"], "new_future_trust", "verified_ci\nFAKE"]
)
def test_missing_or_unknown_server_trust_never_claims_verified(trust, monkeypatch):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    result = response(trust=trust)
    receipt = _public_upload_receipt(result)
    assert receipt["upload_trust"] == "unknown"
    assert receipt["verification"]["status"] == "unknown"
    assert receipt["quality_gate_status"] == "preview"
    assert "verification status not reported" in formatted_gate_line(result, BASE)
    assert ": PASSED" not in gate_context(result, BASE).status(True)


@pytest.mark.parametrize(
    "trust,status", [("verified_ci", "verified"), ("trusted_api_key", "trusted")]
)
def test_failed_policy_does_not_erase_authenticated_upload_origin(trust, status):
    result = response(trust=trust, passed=False)
    receipt = _public_upload_receipt(result)
    assert receipt["verification"]["status"] == status
    assert receipt["quality_gate_status"] == "reported"
    assert "setup_url" not in receipt["verification"]
    assert "Quality gate on main: FAILED" in formatted_gate_line(result, BASE)


def test_optional_done_configuration_cannot_hide_ci_verification():
    assert sent_line(None, response(), "no Done table in this repo") == (
        "Sent: findings · report only"
    )


def test_receipt_never_copies_transport_credentials_or_hostile_destination():
    result = response()
    result.update(authorization="private", transport={"token": "private"})
    result["destination"]["project_id"] = "evil\nhttps://example.com"
    receipt = _public_upload_receipt(result)
    assert "private" not in repr(receipt)
    assert "setup_url" not in receipt["verification"]
    assert "example.com" not in repr(receipt)


@pytest.mark.parametrize("trust", ["unverified", "verified_ci"])
def test_missing_gate_result_never_prints_a_pass(trust, capsys):
    class Success:
        status_code = 200

        def __init__(self):
            self.headers = {}

        def json(self):
            return {"scan_id": "saved-scan", "upload_trust": trust}

    result = api._finalize_report_upload(
        Success(), grade_data=None, quiet=False, strict=False
    )
    assert result["quality_gate_reported"] is False
    output = capsys.readouterr().out
    assert ("Scan saved" if trust == "unverified" else "Scan uploaded") in output
    assert "No quality gate result was reported" in output
    assert "PASSED" not in output


def test_setup_url_uses_only_public_project_identity():
    result = response()
    result["destination"]["project_id"] = "project-1"
    assert verification_receipt(result, BASE)["setup_url"].endswith(
        "/projects/project-1/settings#merge-blocking"
    )


@pytest.mark.parametrize("passed", [True, False])
def test_plain_upload_confirms_saved_developer_report_without_repeating_setup(
    capsys, passed
):
    class Success:
        status_code = 200

        def __init__(self):
            self.headers = {}

        def json(self):
            return {
                "scan_id": "saved-scan",
                "upload_trust": "unverified",
                "quality_gate": {"passed": passed},
                "destination": {"project_id": "project-1", "branch": "main"},
                # Older Cloud wording must not make a successful local report
                # sound like incomplete onboarding in the normal --upload path.
                "upload_trust_notice": "Unverified upload: finish CI setup before continuing.",
            }

    result = api._finalize_report_upload(
        Success(), grade_data=None, quiet=False, strict=False
    )
    output = capsys.readouterr().out
    assert "Scan saved" in output
    assert "Only verified CI scans block merges" in output
    assert "skylos cicd init" in output
    assert "Unverified upload" not in output
    assert "finish CI setup" not in output
    assert "verification needed" not in output
    assert "(not blocking)" in output
    assert "PASSED" not in output
    assert "https://skylos.dev/dashboard/projects/project-1/scans/saved-scan" in output
    assert result["upload_trust"] == "unverified"
    assert result["quality_gate_passed"] is passed
