"""Optional, display-only EPSS/CISA KEV context for existing SCA findings."""

from __future__ import annotations

import datetime as dt
import importlib
import math
import re
import time
from collections.abc import Mapping

_CVE = re.compile(r"CVE-(?:1999|20\d{2})-\d{4,19}\Z", re.ASCII)
_MAX_CVES = 16
_MAX_AGE = dt.timedelta(days=7)
_NETWORK_SECONDS = 15.0


def _cves(values) -> list[str]:
    found = set()
    for value in values[:256]:
        if isinstance(value, str) and len(value) <= 48:
            value = value.strip().upper()
            if _CVE.fullmatch(value):
                found.add(value)
    return sorted(found)[:_MAX_CVES]


def finding_cves(finding) -> list[str]:
    metadata = finding.get("metadata") if isinstance(finding, Mapping) else None
    if not isinstance(metadata, Mapping) or not metadata.get("vuln_id"):
        return []
    aliases = metadata.get("aliases")
    return _cves(
        [
            metadata.get("vuln_id"),
            metadata.get("display_id"),
            *(aliases[:4096] if isinstance(aliases, list) else []),
        ]
    )


def _unknown(cve: str) -> dict:
    return {
        "cve_id": cve,
        "epss": {
            "status": "unknown",
            "score": None,
            "percentile": None,
            "score_date": None,
            "retrieved_at": None,
        },
        "kev": {
            "status": "unknown",
            "in_catalog": None,
            "date_added": None,
            "due_date": None,
            "catalog_date": None,
            "retrieved_at": None,
        },
    }


def _date(value, today, *, future=False):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return None
    try:
        parsed = dt.date.fromisoformat(value)
        return value if future or parsed <= today else None
    except ValueError:
        return None


def _instant(value, now):
    if not isinstance(value, str) or len(value) > 40:
        return None
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo and parsed <= now else None
    except ValueError:
        return None


def _number(value):
    return (
        value
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= 1
        and math.isfinite(value)
        else None
    )


def normalize_risk_context(value, *, allowed_cves=None) -> dict | None:
    """Validate the bounded v1 transport contract; never invent a zero/negative."""
    if (
        not isinstance(value, Mapping)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(value.get("cves"), list)
    ):
        return None
    now = dt.datetime.now(dt.timezone.utc)
    allowed = set(allowed_cves) if allowed_cves is not None else None
    records = {}
    for row in value["cves"][:256]:
        if not isinstance(row, Mapping):
            continue
        cve = row.get("cve_id")
        cve = cve.strip().upper() if isinstance(cve, str) else cve
        if (
            not isinstance(cve, str)
            or len(cve) > 48
            or not _CVE.fullmatch(cve)
            or (allowed is not None and cve not in allowed)
        ):
            continue
        item = _unknown(cve)
        for name, date_key in (("epss", "score_date"), ("kev", "catalog_date")):
            provider = row.get(name)
            if (
                not isinstance(provider, Mapping)
                or not isinstance(provider.get("status"), str)
                or provider["status"] not in {"current", "stale"}
            ):
                continue
            date = _date(provider.get(date_key), now.date())
            instant = _instant(provider.get("retrieved_at"), now)
            if (
                date is None
                or instant is None
                or date > instant.astimezone(dt.timezone.utc).date().isoformat()
            ):
                continue
            status = provider["status"]
            if (
                now - instant > _MAX_AGE
                or now
                - dt.datetime.combine(
                    dt.date.fromisoformat(date), dt.time(), dt.timezone.utc
                )
                > _MAX_AGE
            ):
                status = "stale"
            stamp = (
                instant.astimezone(dt.timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
            if name == "epss":
                score, percentile = (
                    _number(provider.get("score")),
                    _number(provider.get("percentile")),
                )
                if score is not None and percentile is not None:
                    item[name] = {
                        "status": status,
                        "score": score,
                        "percentile": percentile,
                        "score_date": date,
                        "retrieved_at": stamp,
                    }
            else:
                member = provider.get("in_catalog")
                added = _date(provider.get("date_added"), now.date())
                due = provider.get("due_date")
                if type(member) is not bool or (member and added is None):
                    continue
                if member and (
                    added > date
                    or _date(due, now.date(), future=True) is None
                    or due < added
                ):
                    continue
                if not member and (
                    provider.get("date_added") is not None or due is not None
                ):
                    continue
                if not member and status != "current":
                    continue
                item[name] = {
                    "status": status,
                    "in_catalog": member,
                    "date_added": added if member else None,
                    "due_date": due if member else None,
                    "catalog_date": date,
                    "retrieved_at": stamp,
                }
        records[cve] = (
            item if cve not in records or records[cve] == item else _unknown(cve)
        )
    return {
        "schema_version": 1,
        "cves": [records[cve] for cve in sorted(records)[:_MAX_CVES]],
    }


def enrich_with_threat_context(findings, project_root) -> dict:
    """Attach context only; return a separate optional-enrichment receipt.

    Every CVE alias gets a provider status, including unsupported ca9 versions
    and budget exhaustion. OSV completeness and policy decisions are untouched.
    """
    finding_ids = [(finding, finding_cves(finding)) for finding in findings]
    cves = sorted({cve for _, ids in finding_ids for cve in ids})
    records = {cve: _unknown(cve) for cve in cves}
    receipt = {"enabled": True, "status": "not_applicable", "cve_count": len(cves)}
    if not cves:
        return receipt
    reason = None
    try:
        api = importlib.import_module("ca9.api")
        lookup = getattr(api, "threat_context", None)
        if not callable(lookup):
            reason = "ca9_threat_context_unavailable_requires_0_9_0"
    except ImportError:
        lookup = None
        reason = "ca9_threat_context_unavailable_requires_0_9_0"
    deadline = time.monotonic() + _NETWORK_SECONDS
    if callable(lookup):
        for batch_index, offset in enumerate(range(0, len(cves), _MAX_CVES)):
            batch = cves[offset : offset + _MAX_CVES]
            remaining = max(0.0, deadline - time.monotonic())
            try:
                context = lookup(
                    batch,
                    network=remaining > 0 and batch_index < 16,
                    project_root=project_root,
                    timeout=remaining,
                )
                valid = normalize_risk_context(context, allowed_cves=batch)
                if valid is not None:
                    records.update({item["cve_id"]: item for item in valid["cves"]})
                else:
                    reason = "invalid_ca9_threat_context"
            except Exception:
                # This optional provider never hides an existing advisory.
                reason = "ca9_threat_context_lookup_failed"
    for finding, ids in finding_ids:
        if ids:
            finding["metadata"]["risk_context"] = {
                "schema_version": 1,
                "cves": [records[cve] for cve in ids],
            }
    counts = {
        name: {status: 0 for status in ("current", "stale", "unknown")}
        for name in ("epss", "kev")
    }
    for record in records.values():
        for name in counts:
            counts[name][record[name]["status"]] += 1
    receipt.update(counts)
    current = sum(counts[name]["current"] for name in counts)
    receipt["status"] = (
        "current"
        if current == 2 * len(cves)
        else "partial"
        if current or any(counts[name]["stale"] for name in counts)
        else "unknown"
    )
    if reason:
        receipt["reason"] = reason
    return receipt


def risk_context_details(value) -> list[str]:
    context = normalize_risk_context(value)
    if not context:
        return []
    details = []
    for row in context["cves"]:
        epss, kev = row["epss"], row["kev"]
        epss_text = "unknown"
        if epss["score"] is not None:
            epss_text = f"{epss['score']:.2%} ({epss['status']}, {epss['score_date']})"
        kev_text = "unknown"
        if kev["in_catalog"] is not None:
            kev_text = f"{'listed' if kev['in_catalog'] else 'not listed'} ({kev['status']}, {kev['catalog_date']})"
        details.append(f"{row['cve_id']}: EPSS {epss_text}; CISA KEV {kev_text}")
    return details


def package_risk_text(findings) -> str:
    """Compact package display, retaining uncertainty and stale labels."""
    rows = {}
    for finding in findings:
        metadata = finding.get("metadata") or {}
        context = normalize_risk_context(metadata.get("risk_context"))
        if context:
            rows.update({row["cve_id"]: row for row in context["cves"]})
    if not rows:
        return ""
    scores = [
        (row["epss"]["score"], row["epss"]["status"])
        for row in rows.values()
        if row["epss"]["score"] is not None
    ]
    if scores:
        score, status = max(scores)
        epss = f"EPSS max {score:.2%} ({status})"
    else:
        epss = "EPSS unknown"
    positives = [
        row["kev"] for row in rows.values() if row["kev"]["in_catalog"] is True
    ]
    if positives:
        kev = "KEV listed" + (
            " (stale)" if all(row["status"] == "stale" for row in positives) else ""
        )
    elif all(row["kev"]["in_catalog"] is False for row in rows.values()):
        kev = "KEV not listed"
    else:
        kev = "KEV unknown"
    partial = any(
        row[name]["status"] != "current"
        for row in rows.values()
        for name in ("epss", "kev")
    )
    return f"{epss}; {kev}" + ("; some context stale/unknown" if partial else "")
