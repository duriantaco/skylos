"""Public upload progress and verification, separate from policy conditions."""

from __future__ import annotations

from urllib.parse import quote

from skylos.cloud.upload_destination import _clean_project_id

TRUSTED_UPLOADS = frozenset({"verified_ci", "trusted_api_key"})
UPLOAD_TRUSTS = TRUSTED_UPLOADS | {"unverified"}

LOCAL_SCAN_NOTE = (
    "Saved for review. Only verified CI scans block merges and update the "
    "project verdict."
)
BLOCK_PULL_REQUESTS_NEXT = (
    "Next: to block pull requests, run skylos cicd init and merge the "
    "workflow it writes."
)
CI_BLOCKS_PULL_REQUESTS = (
    "The Skylos workflow checks pull requests in CI; this upload does not "
    "block them."
)


def local_scan_next_step(*, ci_configured: bool) -> str:
    """The one thing to do after a local upload: add CI, or nothing."""
    if ci_configured:
        return CI_BLOCKS_PULL_REQUESTS
    return BLOCK_PULL_REQUESTS_NEXT


def ci_workflow_present(root) -> bool:
    from pathlib import Path

    return (Path(root) / ".github" / "workflows" / "skylos.yml").exists()


def upload_trust(result: dict) -> str:
    value = result.get("upload_trust")
    return value if isinstance(value, str) and value in UPLOAD_TRUSTS else "unknown"


def verification_receipt(result: dict, base_url: str) -> dict[str, str]:
    trust = upload_trust(result)
    if trust == "verified_ci":
        return {
            "status": "verified",
            "message": "Cloud verified this upload's CI identity.",
        }
    if trust == "trusted_api_key":
        return {
            "status": "trusted",
            "message": "Cloud accepted this upload with a CI project token.",
        }
    if trust == "unverified":
        receipt = {"status": "needs_ci", "message": LOCAL_SCAN_NOTE}
    else:
        receipt = {
            "status": "unknown",
            "message": "Your scan is saved. Cloud did not report its upload verification status.",
        }
    destination = result.get("destination")
    if isinstance(destination, dict):
        project = _clean_project_id(destination.get("project_id"))
        if project:
            receipt["setup_url"] = (
                f"{base_url.rstrip('/')}/dashboard/projects/{quote(project, safe='')}/settings#merge-blocking"
            )
    return receipt


def verification_heading(result: dict) -> str:
    trust = upload_trust(result)
    if trust == "unverified":
        return "Scan saved"
    if trust == "unknown":
        return "Scan uploaded — verification status not reported"
    return "Scan uploaded"
