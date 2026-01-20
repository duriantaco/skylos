import re
from pathlib import Path
from difflib import SequenceMatcher
from functools import partial


def normalize_path(p):
    if not p:
        return ""
    return str(Path(p).resolve())


def normalize_message(msg):
    if not msg:
        return ""
    msg = msg.lower().strip()
    msg = re.sub(r"\s+", " ", msg)
    msg = re.sub(r"line \d+", "", msg)
    msg = re.sub(r":\d+", "", msg)
    return msg


def similar(a, b, threshold=0.6):
    if not a or not b:
        return False
    return SequenceMatcher(None, a, b).ratio() >= threshold


def findings_match(f1, f2, line_tolerance=5):
    file1 = normalize_path(f1.get("file"))
    file2 = normalize_path(f2.get("file"))

    if file1 != file2:
        return False

    line1 = f1.get("line") or f1.get("lineno") or 0
    line2 = f2.get("line") or f2.get("lineno") or 0

    try:
        line1 = int(line1)
        line2 = int(line2)
    except (ValueError, TypeError):
        line1 = 0
        line2 = 0

    if abs(line1 - line2) > line_tolerance:
        return False

    cat1 = f1.get("_category", "").lower()
    cat2 = f2.get("_category", "").lower()

    if cat1 and cat2 and cat1 == cat2:
        return True

    msg1 = normalize_message(f1.get("message", ""))
    msg2 = normalize_message(f2.get("message", ""))

    if similar(msg1, msg2, threshold=0.5):
        return True

    rule1 = f1.get("rule_id", "").lower()
    rule2 = f2.get("rule_id", "").lower()

    if rule1 and rule2:
        if rule1[:3] == rule2[:3]:
            return True

    return False


def deduplicate_input_findings(findings):
    if not findings:
        return []

    seen = set()
    unique = []

    for f in findings:
        file_path = normalize_path(f.get("file", ""))
        line = f.get("line") or f.get("lineno") or 0
        msg_key = normalize_message(f.get("message", ""))[:50]

        is_dup = False
        for line_offset in range(-2, 3):
            key = (file_path, line + line_offset, msg_key)
            if key in seen:
                is_dup = True
                break

        if not is_dup:
            key = (file_path, line, msg_key)
            seen.add(key)
            unique.append(f)

    return unique


def merge_findings(static_findings, llm_findings):
    static_findings = deduplicate_input_findings(static_findings)
    llm_findings = deduplicate_input_findings(llm_findings)

    merged = []
    used_llm_indices = set()
    used_static_indices = set()

    for sf_idx, sf in enumerate(static_findings):
        if sf_idx in used_static_indices:
            continue

        matched_llm = None
        matched_idx = None

        for idx, lf in enumerate(llm_findings):
            if idx in used_llm_indices:
                continue

            if findings_match(sf, lf):
                matched_llm = lf
                matched_idx = idx
                break

        if matched_llm:
            used_llm_indices.add(matched_idx)
            used_static_indices.add(sf_idx)
            merged_finding = {**sf}
            merged_finding["_source"] = "static+llm"
            merged_finding["_confidence"] = "high"
            merged_finding["_llm_message"] = matched_llm.get("message")
            merged_finding["_llm_suggestion"] = matched_llm.get("suggestion")
            merged.append(merged_finding)
        else:
            merged_finding = {**sf}
            merged_finding["_source"] = "static"
            merged_finding["_confidence"] = "medium"
            merged.append(merged_finding)

    for idx, lf in enumerate(llm_findings):
        if idx not in used_llm_indices:
            merged_finding = {**lf}
            merged_finding["_source"] = "llm"
            merged_finding["_confidence"] = "medium"
            merged_finding["_needs_review"] = True
            merged.append(merged_finding)

    merged = deduplicate_merged_findings(merged)

    def sort_key(f):
        confidence = f.get("_confidence")
        if confidence == "high":
            priority = 0
        else:
            priority = 1

        filename = f.get("file", "")
        line = f.get("line", 0)

        return (priority, filename, line)

    merged.sort(key=sort_key)

    return merged


def deduplicate_merged_findings(findings):
    if not findings:
        return []

    groups = {}

    for f in findings:
        file_path = normalize_path(f.get("file", ""))
        line = f.get("line") or f.get("lineno") or 0
        msg_key = normalize_message(f.get("message", ""))[:50]

        group_key = None
        for line_offset in range(-2, 3):
            potential_key = (file_path, line + line_offset, msg_key)
            if potential_key in groups:
                group_key = potential_key
                break

        if group_key is None:
            group_key = (file_path, line, msg_key)

        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(f)

    unique = []
    confidence_order = {"high": 0, "medium": 1, "low": 2}

    def finding_sort_key(f, confidence_order):
        conf_rank = confidence_order.get(f.get("_confidence", "medium"), 1)
        if f.get("_source") == "static+llm":
            source_rank = 0
        else:
            source_rank = 1

        return (conf_rank, source_rank)

    key_fn = partial(finding_sort_key, confidence_order=confidence_order)

    for _, group in groups.items():
        group.sort(key=key_fn)
        unique.append(group[0])

    return unique


def classify_confidence(finding):
    conf = finding.get("_confidence", "medium")
    source = finding.get("_source", "unknown")

    if conf == "high":
        return "HIGH (both)"
    elif source == "static":
        return "MED (static)"
    elif source == "llm":
        return "MED (LLM)"
    else:
        return "MED"
