import contextlib
import gzip
import hashlib
import io
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from skylos.api._urls import _validate_artifact_upload_url
from skylos.constants import UPLOAD_TIMEOUT


__all__ = [
    "UPLOAD_PROTOCOL_VERSION",
    "PreparedReportUpload",
    "UploadArtifact",
    "_append_skipped_artifact",
    "_build_report_artifacts",
    "_build_report_complete_payload",
    "_build_report_init_idempotency_key",
    "_build_report_init_payload",
    "_build_uploaded_artifact_record",
    "_missing_artifact_instruction_result",
    "_sha256_file",
    "_write_gzip_json_artifact",
    "upload_artifact",
]


UPLOAD_PROTOCOL_VERSION = 1


@dataclass
class UploadArtifact:
    name: str
    file_path: Path
    filename: str
    required: bool
    content_type: str
    content_encoding: str
    size_bytes: int
    sha256: str

    def to_manifest(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "filename": self.filename,
            "content_type": self.content_type,
            "content_encoding": self.content_encoding,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }

    def cleanup(self) -> None:
        with contextlib.suppress(OSError):
            self.file_path.unlink()


@dataclass
class PreparedReportUpload:
    legacy_payload: dict[str, Any]
    core_payload: dict[str, Any]
    compatibility_payload: dict[str, Any]
    definitions_payload: dict[str, Any] | None
    metadata: dict[str, Any]
    scan_summary: dict[str, Any]
    grade_data: dict[str, Any] | None
    legacy_payload_size_bytes: int
    compatibility_payload_size_bytes: int


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:  # skylos: ignore[SKY-D325] hashing client-generated upload artifact
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_gzip_json_artifact(
    name: str,
    payload: dict[str, Any],
    *,
    required: bool,
) -> UploadArtifact:
    fd, path_str = tempfile.mkstemp(prefix=f"skylos-upload-{name}-", suffix=".json.gz")
    os.close(fd)
    path = Path(path_str)
    try:
        with path.open("wb") as raw_handle:  # skylos: ignore[SKY-D325] mkstemp creates this bounded local artifact
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=raw_handle,
                mtime=0,
            ) as gzip_handle:
                with io.TextIOWrapper(gzip_handle, encoding="utf-8") as handle:
                    json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
        return UploadArtifact(
            name=name,
            file_path=path,
            filename=f"{name}.json.gz",
            required=required,
            content_type="application/json",
            content_encoding="gzip",
            size_bytes=path.stat().st_size,
            sha256=_sha256_file(path),
        )
    except Exception:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _build_report_init_idempotency_key(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"report-upload:{digest}"


def _build_report_artifacts(
    prepared: PreparedReportUpload,
) -> dict[str, UploadArtifact]:
    artifacts = {
        "scan_report": _write_gzip_json_artifact(
            "scan-report", prepared.core_payload, required=True
        )
    }
    if prepared.definitions_payload:
        artifacts["definitions"] = _write_gzip_json_artifact(
            "definitions", prepared.definitions_payload, required=False
        )
    return artifacts


def _build_report_init_payload(
    prepared: PreparedReportUpload,
    artifacts: dict[str, UploadArtifact],
) -> dict[str, Any]:
    init_payload = dict(prepared.metadata)
    init_payload.update(
        {
            "upload_protocol_version": UPLOAD_PROTOCOL_VERSION,
            "summary": {
                **prepared.scan_summary,
                "legacy_payload_size_bytes": prepared.legacy_payload_size_bytes,
            },
            "artifacts": {
                name: artifact.to_manifest() for name, artifact in artifacts.items()
            },
        }
    )
    init_payload["idempotency_key"] = _build_report_init_idempotency_key(init_payload)
    return init_payload


def upload_artifact(
    artifact: UploadArtifact, instruction: dict[str, Any]
) -> dict[str, Any]:
    method = str(instruction.get("method") or "PUT").upper()
    url = instruction.get("url")
    if not url:
        return {"success": False, "error": f"Missing upload URL for {artifact.name}."}
    try:
        safe_url = _validate_artifact_upload_url(url)
    except ValueError as exc:
        return {
            "success": False,
            "error": f"Unsafe upload URL for {artifact.name}: {exc}",
        }

    headers = dict(instruction.get("headers") or {})
    accepted_statuses = tuple(instruction.get("accepted_statuses") or (200, 201, 204))
    timeout = instruction.get("timeout_seconds") or UPLOAD_TIMEOUT
    last_err = None

    for _ in range(3):
        try:
            response = _send_artifact_upload(
                artifact,
                instruction,
                method=method,
                safe_url=safe_url,
                headers=headers,
                timeout=timeout,
            )

            if response.status_code in accepted_statuses:
                return {
                    "success": True,
                    "etag": response.headers.get("ETag"),
                }
            last_err = f"Upload Error {response.status_code}: {response.text}"
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        except Exception as e:
            last_err = f"Upload connection error: {e}"

    return {"success": False, "error": last_err or "Unknown artifact upload error"}


def _send_artifact_upload(
    artifact: UploadArtifact,
    instruction: dict[str, Any],
    *,
    method: str,
    safe_url: str,
    headers: dict[str, Any],
    timeout: int,
):
    with artifact.file_path.open("rb") as handle:  # skylos: ignore[SKY-D325] upload artifacts are generated by this client
        if method == "PUT":
            return _put_artifact(artifact, safe_url, handle, headers, timeout)
        if method == "POST":
            return _post_artifact(artifact, instruction, safe_url, handle, headers, timeout)
    raise ValueError(f"Unsupported upload method for {artifact.name}: {method}")


def _put_artifact(
    artifact: UploadArtifact,
    safe_url: str,
    handle,
    headers: dict[str, Any],
    timeout: int,
):
    req_headers = {
        "Content-Type": artifact.content_type,
        "Content-Encoding": artifact.content_encoding,
        **headers,
    }
    return requests.put(  # skylos: ignore[SKY-D216] safe_url is validated before dispatch
        safe_url,
        data=handle,
        headers=req_headers,
        timeout=timeout,
        allow_redirects=False,
    )


def _post_artifact(
    artifact: UploadArtifact,
    instruction: dict[str, Any],
    safe_url: str,
    handle,
    headers: dict[str, Any],
    timeout: int,
):
    file_field = instruction.get("file_field") or "file"
    fields = dict(instruction.get("fields") or {})
    return requests.post(  # skylos: ignore[SKY-D216] safe_url is validated before dispatch
        safe_url,
        data=fields,
        files={file_field: (artifact.filename, handle, artifact.content_type)},
        headers=headers,
        timeout=timeout,
        allow_redirects=False,
    )


def _missing_artifact_instruction_result(
    artifact_name: str, artifact: UploadArtifact
) -> dict[str, Any]:
    if artifact.required:
        return {
            "success": False,
            "error": f"Large-upload response omitted required artifact instructions for {artifact_name}.",
        }
    return {"name": artifact_name, "reason": "not_requested"}


def _append_skipped_artifact(
    skipped_artifacts: list[dict[str, Any]],
    artifact_name: str,
    reason: str,
    error: str | None = None,
) -> None:
    record = {"name": artifact_name, "reason": reason}
    if error is not None:
        record["error"] = error
    skipped_artifacts.append(record)


def _build_uploaded_artifact_record(
    artifact: UploadArtifact,
    artifact_info: dict[str, Any],
    upload_result: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "artifact_id": artifact_info.get("artifact_id") or artifact_info.get("id"),
        "key": artifact_info.get("key") or artifact_info.get("artifact_key"),
        "filename": artifact.filename,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
        "content_type": artifact.content_type,
        "content_encoding": artifact.content_encoding,
    }
    if upload_result.get("etag"):
        record["etag"] = upload_result["etag"]
    return record


def _build_report_complete_payload(
    init_data: dict[str, Any],
    uploaded_artifacts: dict[str, dict[str, Any]],
    skipped_artifacts: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "upload_protocol_version": UPLOAD_PROTOCOL_VERSION,
        "scan_id": init_data.get("scan_id") or init_data.get("scanId"),
        "upload_id": init_data.get("upload_id") or init_data.get("uploadId"),
        "artifacts": uploaded_artifacts,
    }
    if metadata and "project_root" in metadata:
        payload["project_root"] = metadata["project_root"]
    if skipped_artifacts:
        payload["skipped_artifacts"] = skipped_artifacts
    return payload
