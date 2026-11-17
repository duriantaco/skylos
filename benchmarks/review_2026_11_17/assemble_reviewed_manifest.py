"""Normalize preserved drafts and independent verdicts; does not run a scanner."""
from copy import deepcopy
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REVIEWS = (
    "SOURCE_LABELS_MUX_TINY_REVIEW.json",
    "hono_source_truth_independent_review.json",
    "slim_petclinic_source_truth_independent_review.json",
)


def assemble():
    targets = {}
    for review_name in REVIEWS:
        review = json.loads((ROOT / review_name).read_text())
        draft = json.loads((ROOT / review["draft_file"]).read_text())
        originals = {f["id"]: f for f in draft.get("rows", draft.get("facts", []))}
        author = draft.get("label_author", draft.get("reviewer", review.get("draft_author")))
        for verdict in review["verdicts"]:
            original = originals[verdict["id"]]
            fact = deepcopy(original)
            repo_id = original.get("repo_id", draft.get("repo_id"))
            if "repositories" in draft:
                source = draft["repositories"][repo_id]
                url, revision = source["url"], source["revision"]
            elif "targets" in draft:
                source = next(t for t in draft["targets"] if t["repo_id"] == repo_id)
                url, revision = "https://github.com/" + repo_id, source["revision"]
            else:
                url, revision = draft["repo"], draft["commit"]
            ident = url.removeprefix("https://github.com/").replace("/", "--")
            target = targets.setdefault(ident, dict(
                id=ident, repo=url, ref=revision, checkout=ident, scan_root=".",
                scope="Whole pinned checkout, including tests, examples and benchmarks; static analysis only",
                source_files={}, facts=[]))
            hashes = dict(draft.get("files_sha256", {}))
            for item in original.get("source_evidence", []):
                if isinstance(item, dict) and item.get("sha256"):
                    hashes[item["file"]] = item["sha256"]
            if original.get("file_sha256"):
                hashes[original["file"]] = original["file_sha256"]
            evidence = original.get("source_evidence", [])
            if evidence and all(isinstance(e, dict) for e in evidence):
                fact["source_evidence"] = deepcopy(evidence)
            else:
                fact["source_evidence_notes"] = deepcopy(evidence)
                fact["source_evidence"] = [dict(file=original["file"], sha256=hashes[original["file"]],
                                                line=original["line"], reason=original.get("rationale", "Reviewed declaration/site"))]
            reviewer_evidence = verdict.get("source_evidence", verdict.get("source_checked", []))
            fact["independent_review_evidence"] = deepcopy(reviewer_evidence)
            for item in reviewer_evidence:
                if isinstance(item, dict) and item.get("sha256", item.get("file_sha256")):
                    name, value = item["file"], item.get("sha256", item.get("file_sha256"))
                    if name in hashes and hashes[name] != value:
                        raise ValueError("Reviewer source hash conflict: " + name)
                    hashes[name] = value
            for name, value in hashes.items():
                if name in target["source_files"] and target["source_files"][name] != value:
                    raise ValueError("Target source hash conflict: " + name)
                target["source_files"][name] = value

            fact["truth"] = verdict["reviewed_truth"]
            span = verdict.get("recommended_match_span", original)
            fact["start_line"] = span.get("start_line", span.get("line"))
            fact["end_line"] = span.get("end_line", fact["start_line"])
            if fact["category"] == "dead_code" and not fact.get("finding_category"):
                fact["finding_category"] = verdict.get("finding_category") or {
                    "import": "unused_imports", "class": "unused_classes",
                    "function": "unused_functions"}.get(original.get("kind"), "unused_functions")
            eligibility = verdict["scoring_eligibility"]
            if isinstance(eligibility, dict):
                eligible, reason = eligibility["eligible"], eligibility["reason"]
            elif eligibility in {"eligible", "pending_explicit_scan_scope_and_parse_coverage"}:
                eligible, reason = True, "Whole-checkout scope fixed; extraction/completeness gate applies at scoring"
            elif eligibility.startswith("example_source_risk_only"):
                eligible, reason = True, "Only conditional source risk in the example; no core/deployment vulnerability claim"
            else:
                eligible = False
                reason = ("unknown_truth" if fact["truth"] == "unknown" else
                          "intentional_keep" if fact["truth"] == "unused" else "not_applicable")
            fact["score_eligible"] = eligible
            if not eligible:
                fact["unscored_reason"] = reason
            fact["label_author"] = author
            fact["independent_reviewer"] = review["reviewer"]
            fact["review_resolution"] = dict(status="resolved", review_artifact=review_name,
                                             reason=verdict["reason"] + " " + reason)
            target["facts"].append(fact)
    for target in targets.values():
        target["source_files"] = [dict(path=n, sha256=v) for n, v in sorted(target["source_files"].items())]
    return dict(version=1,
                study="Source-only drafting and independent review after exploratory scans; not a new blind study",
                scope="Selected facts only, not exhaustive repository precision/recall or removal authorization",
                scan=dict(conf=60, grep_verify=True),
                targets=list(targets.values()))


if __name__ == "__main__":
    output = ROOT / "reviewed_ground_truth_manifest.json"
    data = json.dumps(assemble(), indent=2) + "\n"
    if output.exists() and output.read_text() != data:
        raise FileExistsError("Refusing to replace existing manifest")
    output.write_text(data)
    print(output)
