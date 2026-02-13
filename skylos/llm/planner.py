"""Prioritize findings and create a remediation plan."""

from __future__ import annotations

from dataclasses import dataclass, field


SEVERITY_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Rules with well-known mechanical fixes (high LLM fix confidence).
AUTO_FIXABLE = {
    "SKY-D205",  # yaml.load → yaml.safe_load
    "SKY-D206",  # md5 → sha256
    "SKY-D207",  # sha1 → sha256
    "SKY-D208",  # verify=False → remove kwarg
    "SKY-D232",  # JWT algorithms=['none'] → remove / verify=False → remove
    "SKY-D234",  # fields='__all__' → explicit list
    "SKY-D240",  # tool description poisoning → clean docstring
    "SKY-D244",  # hardcoded secret default → os.environ
}


@dataclass
class FindingItem:
    """Single finding to be remediated."""

    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    col: int = 0
    symbol: str = ""
    auto_fixable: bool = False
    priority: int = 99
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "FindingItem":
        rule_id = d.get("rule_id", "")
        severity = d.get("severity", "LOW").upper()
        return cls(
            rule_id=rule_id,
            severity=severity,
            message=d.get("message", ""),
            file=d.get("file", ""),
            line=d.get("line", 0),
            col=d.get("col", 0),
            symbol=d.get("symbol", ""),
            auto_fixable=rule_id in AUTO_FIXABLE,
            priority=SEVERITY_PRIORITY.get(severity, 99),
            raw=d,
        )


@dataclass
class FixBatch:
    """A group of findings in the same file to fix together."""

    file: str
    findings: list[FindingItem] = field(default_factory=list)
    status: str = "pending"
    source: str = ""
    fix_description: str = ""

    @property
    def top_severity(self) -> str:
        if not self.findings:
            return "LOW"
        return min(self.findings, key=lambda f: f.priority).severity

    @property
    def has_auto_fixable(self) -> bool:
        return any(f.auto_fixable for f in self.findings)


@dataclass
class RemediationPlan:
    """Ordered list of fix batches with summary tracking."""

    batches: list[FixBatch] = field(default_factory=list)
    total_findings: int = 0
    skipped_findings: int = 0

    @property
    def fixed_count(self) -> int:
        return sum(len(b.findings) for b in self.batches if b.status == "fixed")

    @property
    def failed_count(self) -> int:
        return sum(
            len(b.findings)
            for b in self.batches
            if b.status in ("failed", "test_failed", "not_resolved")
        )

    @property
    def skipped_count(self) -> int:
        return (
            sum(len(b.findings) for b in self.batches if b.status == "skipped")
            + self.skipped_findings
        )

    def summary(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "planned": sum(len(b.findings) for b in self.batches),
            "fixed": self.fixed_count,
            "failed": self.failed_count,
            "skipped": self.skipped_count,
            "batches": [
                {
                    "file": b.file,
                    "findings": len(b.findings),
                    "status": b.status,
                    "top_severity": b.top_severity,
                    "description": b.fix_description,
                }
                for b in self.batches
            ],
        }


class RemediationPlanner:
    """Create a prioritized remediation plan from scan results."""

    def __init__(self, *, severity_filter: str | None = None):
        self.severity_filter = severity_filter

    def create_plan(self, results: dict, *, max_fixes: int = 10) -> RemediationPlan:
        findings = self._extract_findings(results)
        total = len(findings)

        if self.severity_filter:
            cutoff = SEVERITY_PRIORITY.get(self.severity_filter.upper(), 99)
            findings = [f for f in findings if f.priority <= cutoff]

        # Sort: CRITICAL first, then auto-fixable first within same severity
        findings.sort(key=lambda f: (f.priority, not f.auto_fixable, f.file))

        # Group by file
        file_groups: dict[str, list[FindingItem]] = {}
        for f in findings:
            file_groups.setdefault(f.file, []).append(f)

        # Build batches — one per file, ordered by top severity
        batches: list[FixBatch] = []
        for filepath, items in file_groups.items():
            batches.append(FixBatch(file=filepath, findings=items))

        batches.sort(key=lambda b: SEVERITY_PRIORITY.get(b.top_severity, 99))

        # Cap total findings across batches
        capped: list[FixBatch] = []
        count = 0
        for batch in batches:
            if count >= max_fixes:
                break
            remaining = max_fixes - count
            if len(batch.findings) > remaining:
                batch.findings = batch.findings[:remaining]
            capped.append(batch)
            count += len(batch.findings)

        skipped = total - count
        return RemediationPlan(
            batches=capped,
            total_findings=total,
            skipped_findings=max(0, skipped),
        )

    def _extract_findings(self, results: dict) -> list[FindingItem]:
        """Pull findings from all categories in scan results."""
        items: list[FindingItem] = []
        for key in ("danger", "quality", "secrets"):
            for raw in results.get(key, []) or []:
                items.append(FindingItem.from_dict(raw))
        return items
