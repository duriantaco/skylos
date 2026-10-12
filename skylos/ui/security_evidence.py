"""Compact, display-only summaries of analyzer-recorded security evidence."""

from collections.abc import Mapping

from skylos.cicd.evidence import sanitize_untrusted_text


def _text(value):
    if not isinstance(value, str):
        return ""
    return sanitize_untrusted_text(value, max_length=240, neutralize_mentions=False)


def _items(values, *, limit=4, separator=" → ", unique=False):
    if not isinstance(values, (list, tuple)):
        return ""
    labels = []
    for value in values:
        if isinstance(value, str):
            label = _text(value)
        elif isinstance(value, Mapping):
            label = _text(
                value.get("message") or value.get("label") or value.get("step")
            )
        else:
            continue
        if label and (not unique or label not in labels):
            labels.append(label)
    shown = labels[:limit]
    if len(labels) > limit:
        shown.append(f"+{len(labels) - limit} more in JSON")
    return separator.join(shown)


def security_evidence_details(finding):
    """Show recorded facts without inventing paths, locations or confidence.

    JSON remains the full receipt. An absent completeness flag does not mean
    that runtime reachability, exploitability or every guard was verified.
    """
    metadata = finding.get("metadata")
    evidence = (
        metadata.get("security_evidence") if isinstance(metadata, Mapping) else None
    )
    if not isinstance(evidence, Mapping):
        evidence = finding.get("security_evidence")
    if not isinstance(evidence, Mapping):
        return []

    details = []
    additional_sources = evidence.get("sources")
    source_values = [evidence.get("source")]
    if isinstance(additional_sources, (list, tuple)):
        source_values.extend(additional_sources)
    sources = _items(source_values, separator="; ", unique=True)
    sink = _text(evidence.get("sink"))
    if sources:
        details.append("Static source: " + sources)
    if sink:
        details.append("Static sink: " + sink)
    path = _items(evidence.get("path"))
    if path:
        details.append("Recorded path: " + path)
    for key, label in (
        ("guards_seen", "Guards observed"),
        ("guards_missing", "Guards not observed"),
    ):
        guards = _items(evidence.get(key), separator="; ")
        if guards:
            details.append(label + ": " + guards)
    if not details:
        return []
    if evidence.get("analysis_complete") is False:
        details.append(
            "Evidence scope: partial static analysis; review reachability and other guards"
        )
    else:
        details.append(
            "Evidence scope: static observations; runtime exploitability is not verified"
        )
    return details
