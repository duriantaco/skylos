from __future__ import annotations

import json
from pathlib import Path

from skylos.adapters.litellm_adapter import LiteLLMAdapter
from skylos.debt.result import DebtAdvisory, DebtHotspot

ADVISORY_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "summary",
        "root_cause",
        "refactor_steps",
        "remediation_notes",
        "confidence",
    ],
    "properties": {
        "summary": {"type": "string"},
        "root_cause": {"type": "string"},
        "refactor_steps": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 5,
        },
        "remediation_notes": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 4,
        },
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
}

ADVISORY_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "skylos_debt_advisory",
        "schema": ADVISORY_RESPONSE_SCHEMA,
        "strict": True,
    },
}


def _system_prompt() -> str:
    return """You are Skylos Technical Debt Advisor.

Your job is to explain a static debt hotspot without inventing evidence.

Rules:
1. The static hotspot data is authoritative. Do not contradict it.
2. Do not claim certainty beyond the evidence provided.
3. Keep recommendations incremental and production-safe.
4. Avoid rewrite-everything advice.
5. Refactor steps must be ordered, concrete, and low-risk.
6. Output ONLY valid JSON.
"""


def _safe_excerpt(path: Path, line: int, radius: int = 3, max_chars: int = 1200) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return ""

    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    excerpt_lines = []
    for idx in range(start, end + 1):
        excerpt_lines.append(f"{idx}: {lines[idx - 1]}")

    excerpt = "\n".join(excerpt_lines)
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars] + "\n... (truncated)"
    return excerpt


def _user_prompt(
    hotspot: DebtHotspot,
    *,
    project_root: Path,
    architecture_metrics: dict | None = None,
) -> str:
    signal_lines = []
    for signal in hotspot.signals[:5]:
        signal_lines.append(
            f"- [{signal.rule_id}] {signal.message} | "
            f"severity={signal.severity} | points={signal.points:.2f}"
        )

    excerpts = []
    for signal in hotspot.signals[:3]:
        file_path = project_root / signal.file
        excerpt = _safe_excerpt(file_path, signal.line)
        if excerpt:
            excerpts.append(f"[{signal.file}:{signal.line}]\n{excerpt}")

    arch_summary = ""
    if architecture_metrics:
        system_metrics = architecture_metrics.get("system_metrics") or {}
        if system_metrics:
            arch_summary = (
                "Architecture context:\n"
                f"- mean_distance={system_metrics.get('mean_distance')}\n"
                f"- architecture_fitness={system_metrics.get('architecture_fitness')}\n"
                f"- dip_violations={system_metrics.get('dip_violations')}\n"
            )

    return f"""Explain the following technical debt hotspot.

Hotspot:
- file={hotspot.file}
- score={hotspot.score:.2f}
- primary_dimension={hotspot.primary_dimension}
- signal_count={hotspot.signal_count}
- dimension_count={hotspot.dimension_count}
- changed={hotspot.changed}
- baseline_status={hotspot.baseline_status}

Static signals:
{chr(10).join(signal_lines)}

{arch_summary}
Code excerpts:
{chr(10).join(excerpts) if excerpts else "No code excerpts available."}

Respond with:
- summary: one short paragraph
- root_cause: one short paragraph grounded in the evidence
- refactor_steps: 2-5 ordered steps
- remediation_notes: 1-4 cautions or validation notes
- confidence: low|medium|high
"""


def _parse_json_object(raw: str) -> dict | None:
    text = (raw or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        text = text.rsplit("```", 1)[0].strip()
    try:
        return json.loads(text)
    except Exception:
        return None


class DebtAdvisor:
    def __init__(
        self,
        *,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        self.model = model
        self.adapter = LiteLLMAdapter(
            model=model,
            api_key=api_key,
            api_base=base_url,
        )

    def summarize_hotspot(
        self,
        hotspot: DebtHotspot,
        *,
        project_root: Path,
        architecture_metrics: dict | None = None,
    ) -> DebtAdvisory | None:
        system = _system_prompt()
        user = _user_prompt(
            hotspot,
            project_root=project_root,
            architecture_metrics=architecture_metrics,
        )
        raw = self.adapter.complete(
            system,
            user,
            response_format=ADVISORY_RESPONSE_FORMAT,
        )
        payload = _parse_json_object(raw)
        if not isinstance(payload, dict):
            return None

        summary = str(payload.get("summary") or "").strip()
        root_cause = str(payload.get("root_cause") or "").strip()
        refactor_steps = [
            str(item).strip()
            for item in (payload.get("refactor_steps") or [])
            if str(item).strip()
        ]
        remediation_notes = [
            str(item).strip()
            for item in (payload.get("remediation_notes") or [])
            if str(item).strip()
        ]
        confidence = str(payload.get("confidence") or "medium").strip().lower()

        if not summary or not root_cause:
            return None
        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"

        return DebtAdvisory(
            summary=summary,
            root_cause=root_cause,
            refactor_steps=refactor_steps[:5],
            remediation_notes=remediation_notes[:4],
            confidence=confidence,
            model=self.model,
        )


def augment_hotspots_with_advisories(
    hotspots: list[DebtHotspot],
    *,
    project_root: str | Path,
    model: str,
    api_key: str | None = None,
    base_url: str | None = None,
    top: int = 5,
    architecture_metrics: dict | None = None,
) -> int:
    if top <= 0 or not hotspots:
        return 0

    advisor = DebtAdvisor(model=model, api_key=api_key, base_url=base_url)
    root = Path(project_root).resolve()
    advised = 0

    for hotspot in hotspots[:top]:
        advisory = advisor.summarize_hotspot(
            hotspot,
            project_root=root,
            architecture_metrics=architecture_metrics,
        )
        if advisory is None:
            continue
        hotspot.advisory = advisory
        advised += 1

    return advised
