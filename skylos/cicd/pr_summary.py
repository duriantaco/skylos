"""The brief at the top of the Skylos pull request comment.

`skylos cicd review` composes it from what the other jobs already produced:
the gate's result and reasons, the Done receipt, the change map JSON and the
risk review JSON. Every section degrades on its own when its input is absent.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from skylos.cicd.evidence import sanitize_markdown_text
from skylos.done.receipt import FIXES, LABELS, PROBLEMS, UNCHECKED

MAX_GATE_REASONS = 5
MAX_BLOCKING_FINDINGS = 10
MAX_READ_FIRST = 8
MAX_UNCHECKED = 10
MAX_NOT_TRACED = 5
MAX_API_SITES = 10
MAX_API_NOTES = 5
_TEXT = 300
_SHORT = 200
_NOT_RUN = "not run"
_WAITING_SUMMARY = "Earlier required checks failed or were incomplete"
_GATE_JOB_FAILED = "The Skylos Quality Gate job failed; its log says why."
_UNCHECKED_REASON = "no test checks this line"

_GATE_WORDS = {"success": "passed", "failure": "failed"}
_DONE_WORDS = {"pass": "passed", "fail": "failed", "incomplete": "unfinished"}
_RISK_WORDS = {
    "eligible": "passed",
    "needs_human_approval": "needs a person",
    "incomplete": "unfinished",
    "review_check_failed": "could not check",
    "error": "could not check",
}
_RISK_CLEARED = {"eligible", "human_approved"}
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_RUN_ID_RE = re.compile(r"^\d{1,20}$")
_SERVER_RE = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d{1,5})?$")
_DUNDER_RE = re.compile(r"＿＿(\w+)＿＿")


@dataclass(frozen=True)
class SummaryInputs:
    gate_result: str | None = None
    gate_reasons: tuple[str, ...] = ()
    done_requested: bool = False
    done_receipt: dict | None = None
    change_map: dict | None = None
    risk_requested: bool = False
    risk_review: dict | None = None
    run_url: str | None = None
    upgrade_api: dict | None = None


def upgrade_api_receipt(results: Any) -> dict | None:
    """The upgrade API comparison a scan recorded, or None when it did not run."""
    receipt = results
    for key in ("analysis_summary", "supply_chain_diff", "checks", "upgrade_api"):
        if not isinstance(receipt, dict):
            return None
        receipt = receipt.get(key)
    if isinstance(receipt, dict):
        return receipt
    return None


def run_url_from_env(env: Any = None) -> str | None:
    if env is None:
        env = os.environ
    server = env.get("GITHUB_SERVER_URL") or "https://github.com"
    repo = env.get("GITHUB_REPOSITORY") or ""
    run_id = env.get("GITHUB_RUN_ID") or ""
    if not _SERVER_RE.match(server):
        return None
    if not _REPO_RE.match(repo) or not _RUN_ID_RE.match(run_id):
        return None
    return f"{server}/{repo}/actions/runs/{run_id}"


def verdict_line(inputs: SummaryInputs) -> str:
    parts = []
    if inputs.gate_result is not None:
        parts.append(f"**Gate:** {_GATE_WORDS.get(inputs.gate_result, _NOT_RUN)}")
    if inputs.done_requested:
        word = _NOT_RUN
        if isinstance(inputs.done_receipt, dict):
            word = _DONE_WORDS.get(inputs.done_receipt.get("verdict"), "unfinished")
        parts.append(f"**Done:** {word}")
    if inputs.risk_requested:
        parts.append(f"**Risk review:** {_risk_word(inputs.risk_review)}")
    return " · ".join(parts)


def brief_lines(inputs: SummaryInputs) -> list[str]:
    lines: list[str] = []
    sections = (
        _section(
            "**Blocking**",
            _gate_lines(inputs) + _done_blocking_lines(inputs.done_receipt),
        ),
        _section("**Dependency API changes**", _upgrade_api_lines(inputs.upgrade_api)),
        _read_first_lines(inputs.change_map),
        _section(
            "**Not checked by tests**",
            _unverified_lines(inputs.done_receipt) + _not_traced_lines(inputs.change_map),
        ),
        _needs_person_lines(inputs.risk_review),
    )
    for section in sections:
        if section:
            lines.extend(section)
            lines.append("")
    if inputs.run_url:
        lines.extend([f"[Full receipt and change map]({inputs.run_url})", ""])
    if lines:
        lines.pop()
    return lines


def _section(title: str, lines: list[str]) -> list[str]:
    if not lines:
        return []
    return [title, *lines]


def _text(value: Any, limit: int = _TEXT) -> str:
    return sanitize_markdown_text(value, max_length=limit)


def _dicts(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _count(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _where(file: Any, line: Any) -> str:
    if not file:
        return ""
    where = str(file)
    if _count(line) >= 1:
        where += f":{line}"
    return where


def _approval(risk_review: dict | None) -> tuple[dict | None, Any]:
    if not isinstance(risk_review, dict):
        return None, None
    data = risk_review.get("approval")
    if not isinstance(data, dict):
        return None, None
    return data, data.get("verdict")


def _risk_word(risk_review: dict | None) -> str:
    data, verdict = _approval(risk_review)
    if data is None:
        return _NOT_RUN
    if verdict != "human_approved":
        return _RISK_WORDS.get(verdict, "could not check")
    human = data.get("human_approval")
    if isinstance(human, dict) and human.get("login"):
        return f"approved by {_text(human['login'], 80)}"
    return "approved"


def _summary_of(check: dict) -> str:
    evidence = check.get("evidence")
    if isinstance(evidence, dict) and evidence.get("summary"):
        return str(evidence["summary"])
    return ""


def _blocking_checks(receipt: dict) -> list[dict]:
    blocking = []
    for check in _dicts(receipt.get("checks")):
        if check.get("mode") != "block" or check.get("status") not in {"fail", "incomplete"}:
            continue
        if _summary_of(check) != _WAITING_SUMMARY:
            blocking.append(check)
    return blocking


def _gate_lines(inputs: SummaryInputs) -> list[str]:
    if inputs.gate_result != "failure":
        return []
    reasons = list(inputs.gate_reasons)
    if not reasons:
        return [f"- {_GATE_JOB_FAILED}"]
    lines = [f"- {_text(reason)}" for reason in reasons[:MAX_GATE_REASONS]]
    hidden = len(reasons) - MAX_GATE_REASONS
    if hidden > 0:
        lines.append(f"- … and {hidden} more gate reasons")
    return lines


def _check_lines(check: dict, budget: int) -> tuple[list[str], int]:
    check_id = check.get("id")
    fallback = UNCHECKED
    if check.get("status") == "fail":
        fallback = PROBLEMS
    summary = _summary_of(check) or fallback.get(check_id, "not checked")
    lines = [f"- {_text(LABELS.get(check_id, str(check_id)))}: {_text(summary)}"]
    findings = _dicts(check.get("findings"))
    shown = findings[: max(budget, 0)]
    for finding in shown:
        parts = []
        where = _where(finding.get("file"), finding.get("line"))
        if where:
            parts.append(f"`{_text(where, _SHORT)}`")
        if finding.get("rule"):
            parts.append(f"`{_text(finding['rule'], 40)}`")
        parts.append(_text(finding.get("message") or "finding"))
        lines.append("  - " + " ".join(parts))
    hidden = len(findings) - len(shown)
    if hidden > 0:
        lines.append(f"  - … and {hidden} more")
    if check.get("status") == "fail" and check_id in FIXES:
        lines.append(f"  - Fix: {FIXES[check_id]}")
    return lines, len(shown)


def _done_blocking_lines(receipt: dict | None) -> list[str]:
    if not isinstance(receipt, dict):
        return []
    lines: list[str] = []
    budget = MAX_BLOCKING_FINDINGS
    for check in _blocking_checks(receipt):
        check_lines, used = _check_lines(check, budget)
        lines.extend(check_lines)
        budget -= used
    return lines


def _not_traced(change_map: dict | None) -> list[str]:
    if not isinstance(change_map, dict):
        return []
    coverage = change_map.get("coverage")
    if not isinstance(coverage, dict):
        return []
    files = []
    for key in ("not_mapped", "unparsed"):
        value = coverage.get(key)
        if isinstance(value, list):
            files.extend(str(path) for path in value if path)
    return files


def _entry_line(entry: dict) -> str:
    side = entry.get("after") or entry.get("before")
    start = None
    if isinstance(side, dict):
        start = side.get("start")
    why = str(entry.get("review_why") or entry.get("verdict_text") or "")
    return (
        f"- `{_text(_where(entry.get('file'), start), _SHORT)}` · "
        f"`{_text(entry.get('name') or '', _SHORT)}` · "
        f"{_text(why.replace('`', ''), _SHORT)}"
    )


def _counts_line(change_map: dict, cut: int) -> str:
    counts = {}
    review = change_map.get("review")
    if isinstance(review, dict) and isinstance(review.get("counts"), dict):
        counts = review["counts"]
    parts = [f"{_count(counts.get('read')) + cut} more to read"]
    skim = _count(counts.get("skim"))
    if skim:
        parts.append(f"{skim} to skim")
    parts.append(f"{_count(counts.get('skip'))} proven unchanged")
    parts.append(f"{len(_not_traced(change_map))} file(s) not mapped")
    return "- " + ", ".join(parts)


def _read_first_lines(change_map: dict | None) -> list[str]:
    if not isinstance(change_map, dict):
        return []
    symbols = {s["id"]: s for s in _dicts(change_map.get("symbols")) if "id" in s}
    ids = change_map.get("read_first")
    if not isinstance(ids, list):
        ids = []
    entries = [symbols[i] for i in ids if i in symbols]
    lines = ["**Read first**"]
    lines.extend(_entry_line(entry) for entry in entries[:MAX_READ_FIRST])
    if not entries:
        lines.append("- Nothing to read first.")
    lines.append(_counts_line(change_map, max(0, len(entries) - MAX_READ_FIRST)))
    return lines


def _unchecked_reasons(receipt: dict) -> dict[tuple[str, Any], str]:
    reasons: dict[tuple[str, Any], str] = {}
    for check in _dicts(receipt.get("checks")):
        if check.get("id") != "changed_lines_checked":
            continue
        for finding in _dicts(check.get("findings")):
            key = (str(finding.get("file") or ""), finding.get("line"))
            reason = str(finding.get("message") or "").split(". ", 1)[0].rstrip(".")
            if reason:
                reasons.setdefault(key, reason)
    return reasons


def _unverified_lines(receipt: dict | None) -> list[str]:
    if not isinstance(receipt, dict):
        return []
    unverified = [item for item in _dicts(receipt.get("unverified")) if item.get("file")]
    reasons = _unchecked_reasons(receipt)
    lines = []
    for item in unverified[:MAX_UNCHECKED]:
        key = (str(item["file"]), item.get("line"))
        where = _where(item["file"], item.get("line"))
        lines.append(f"- `{_text(where, _SHORT)}` · {_text(reasons.get(key, _UNCHECKED_REASON))}")
    hidden = len(unverified) - MAX_UNCHECKED
    if hidden > 0:
        lines.append(f"- … and {hidden} more lines")
    return lines


def _not_traced_lines(change_map: dict | None) -> list[str]:
    not_traced = _not_traced(change_map)
    if not not_traced:
        return []
    shown = ", ".join(f"`{_text(path, _SHORT)}`" for path in not_traced[:MAX_NOT_TRACED])
    extra = len(not_traced) - MAX_NOT_TRACED
    if extra > 0:
        shown += f" +{extra} more"
    return [f"- not traced: {shown}"]


def _api_site_line(site: dict) -> str:
    return (
        f"  - `{_text(_where(site.get('file'), site.get('line')), _SHORT)}` · "
        f"`{_text(site.get('symbol') or '', _SHORT)}` removed in "
        f"{_text(site.get('package') or '', 120)} {_text(site.get('new') or '', 80)}"
    )


def _api_could_not_check_line(row: dict) -> str:
    line = f"- Could not check `{_text(row.get('subject') or '', _SHORT)}`"
    symbol = row.get("symbol")
    if symbol:
        line += f" at `{_text(symbol, _SHORT)}`"
    where = _where(row.get("file"), row.get("line"))
    if where:
        line += f" (`{_text(where, _SHORT)}`)"
    more = _count(row.get("count")) - 1
    if more > 0:
        line += f" and {more} more sites"
    reason = _text(row.get("reason") or "no reason recorded")
    reason = _DUNDER_RE.sub(r"`__\1__`", reason)
    return f"{line}: {reason}"


def _upgrade_api_lines(receipt: dict | None) -> list[str]:
    """The verdict is only ever one of the two fixed sentences, and the clean
    one needs every package compared and nothing left unread."""
    if not isinstance(receipt, dict):
        return []
    packages = _dicts(receipt.get("packages"))
    rows = _dicts(receipt.get("could_not_check"))
    if not packages and not rows:
        return []
    lines: list[str] = []
    sites = _dicts(receipt.get("sites"))
    review = _count(receipt.get("review_sites"))
    if review:
        lead = f"- Review these {review} call sites"
        if review == 1:
            lead = "- Review this call site"
        lines.append(lead)
        lines.extend(_api_site_line(site) for site in sites[:MAX_API_SITES])
        hidden = review - min(len(sites), MAX_API_SITES)
        if hidden > 0:
            lines.append(f"  - … and {hidden} more")
    elif not rows and receipt.get("status") == "complete":
        checked = _count(receipt.get("call_sites"))
        noun = "call sites"
        if checked == 1:
            noun = "call site"
        lines.append(
            f"- No API-level impact found in {checked} {noun} "
            "(behaviour changes not checked)"
        )
    lines.extend(_api_could_not_check_line(row) for row in rows[:MAX_API_NOTES])
    omitted = len(rows) - MAX_API_NOTES + _count(receipt.get("could_not_check_omitted"))
    if omitted > 0:
        lines.append(f"- Could not check {omitted} more; the run log lists them")
    private = sum(_count(item.get("private")) for item in packages)
    if private:
        lines.append(f"- {private} uses of underscore-private names were not compared")
    not_used = [item for item in packages if item.get("status") == "not_used"]
    for item in not_used[:MAX_API_NOTES]:
        lines.append(
            f"- `{_text(item.get('name') or '', 120)}` "
            f"{_text(item.get('old') or '', 80)} to {_text(item.get('new') or '', 80)}: "
            "not used, 0 call sites"
        )
    if len(not_used) > MAX_API_NOTES:
        lines.append(f"- … and {len(not_used) - MAX_API_NOTES} more not used")
    return lines


def _risk_class_line(name: Any, vetoes: list[dict]) -> str:
    risks = [v for v in vetoes if v.get("class") == name]
    text = f"- `{_text(name, 80)}`"
    if not risks:
        return text
    text += f" ({len(risks)})"
    where = _where(risks[0].get("file"), risks[0].get("line"))
    if where:
        text += f" · `{_text(where, _SHORT)}`"
    return text + f" · {_text(risks[0].get('reason') or '')}"


def _needs_person_lines(risk_review: dict | None) -> list[str]:
    data, verdict = _approval(risk_review)
    if data is None or verdict in _RISK_CLEARED:
        return []
    from skylos.commands.risk_review_cmd import HUMAN_APPROVAL_SENTENCE, headline

    lines = ["**Needs a person**"]
    if verdict != "needs_human_approval":
        try:
            reason = headline(risk_review)
        except (KeyError, TypeError, AttributeError):
            reason = "Could not decide: the risk review output is unreadable"
        lines.append(f"- {_text(reason)}")
        return lines
    classes = data.get("needs_human_approval")
    if not isinstance(classes, list):
        classes = []
    vetoes = _dicts(data.get("vetoes"))
    lines.extend(_risk_class_line(name, vetoes) for name in classes)
    lines.extend(["", HUMAN_APPROVAL_SENTENCE])
    return lines
