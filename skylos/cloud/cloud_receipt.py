from __future__ import annotations

from urllib.parse import quote

from skylos.cloud.upload_destination import (
    UploadDestination,
    _branch_query,
    _printable,
    receipt_note,
    with_cloud_destination,
)

LOCAL_NEXT_STEPS = (
    (
        "skylos cloud",
        "track these per branch on Skylos Cloud (sends findings, not your repository)",
    ),
    ("skylos cicd init", "check every pull request in CI"),
)

FAILED_NEXT_STEP = (
    "  Next: fix the issues behind the failed gate, then run skylos cloud again."
)
CI_NEXT_STEP = "  Next: skylos cicd init — adds a Skylos check to every pull request."


def local_next_steps(*, ci_configured: bool) -> list[tuple[str, str]]:
    if ci_configured:
        return [LOCAL_NEXT_STEPS[0]]
    return list(LOCAL_NEXT_STEPS)


def _gate_reasons(upload_resp: dict) -> list[str]:
    from skylos.api import _quality_gate_reasons

    gate = upload_resp.get("quality_gate")
    if not isinstance(gate, dict):
        return []
    return _quality_gate_reasons(gate.get("message"))


def _failed_detail(upload_resp: dict) -> str:
    from skylos.cloud.gate_status import new_issues_text

    reasons = _gate_reasons(upload_resp)
    if reasons:
        return "; ".join(reasons)
    gate = upload_resp.get("quality_gate")
    count = 0
    if isinstance(gate, dict) and isinstance(gate.get("new_violations"), int):
        count = gate["new_violations"]
    return new_issues_text(count, upload_resp.get("new_issue_baseline"))


def _gate_line(upload_resp: dict, base_url: str) -> str:
    from skylos.cloud.gate_status import gate_context

    passed = upload_resp.get("quality_gate_passed")
    if upload_resp.get("quality_gate_reported") is False or not isinstance(
        passed, bool
    ):
        return "✓ Uploaded to Skylos Cloud (no quality gate result was reported)"
    context = gate_context(upload_resp, base_url)
    word = "FAILED"
    if passed:
        word = "PASSED"
    status = f"Quality gate: {word}"
    if context is not None:
        status = context.status(passed)
    if passed:
        return f"✓ {status}"
    return f"✗ {status} · {_failed_detail(upload_resp)}"


def _open_url(dest: UploadDestination, upload_resp: dict, base_url: str) -> str | None:
    from skylos.cloud.gate_status import details_url

    base = base_url.rstrip("/")
    if dest.project_id:
        project_path = f"{base}/dashboard/projects/{quote(dest.project_id, safe='')}"
        return f"{project_path}{_branch_query(dest)}"
    return details_url(base, None, upload_resp.get("scan_id"))


def cloud_receipt_lines(
    dest: UploadDestination | None,
    upload_resp: dict,
    base_url: str,
    *,
    ci_configured: bool,
) -> list[str]:
    if dest is None:
        dest = UploadDestination(key_source="none")
    dest = with_cloud_destination(dest, upload_resp)
    lines = [_gate_line(upload_resp, base_url)]
    url = _open_url(dest, upload_resp, base_url)
    if url:
        lines.append(f"  Open: {url}")
    upload_trust = upload_resp.get("upload_trust")
    if dest.on_default_branch is True and upload_trust == "unverified":
        note = receipt_note(dest, upload_trust)
        if note:
            lines.append(f"  {note}")
    passed = upload_resp.get("quality_gate_passed")
    if upload_resp.get("quality_gate_reported") is False:
        return [_printable(line) for line in lines]
    if passed is False:
        lines.append(FAILED_NEXT_STEP)
    elif passed is True and not ci_configured:
        lines.append(CI_NEXT_STEP)
    return [_printable(line) for line in lines]
