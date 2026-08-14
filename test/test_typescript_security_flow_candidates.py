from __future__ import annotations

from pathlib import Path

import pytest

from skylos.visitors.languages.typescript import danger as danger_module
from skylos.visitors.languages.typescript.core import TypeScriptCore


def _scan(file_path: Path, source: str) -> list[dict]:
    source_bytes = source.encode("utf-8")
    core = TypeScriptCore(str(file_path), source_bytes)
    assert core.root_node is not None
    assert core.lang is not None
    return danger_module.scan_danger(
        core.root_node,
        str(file_path),
        lang=core.lang,
        source=source_bytes,
    )


def _count_security_flow_builds(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    builds: list[str] = []
    original = danger_module.build_security_flow

    def counting_builder(root_node, source, file_path, lang):
        builds.append(file_path)
        return original(root_node, source, file_path, lang)

    monkeypatch.setattr(danger_module, "build_security_flow", counting_builder)
    return builds


def test_large_non_candidate_skips_security_flow_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builds = _count_security_flow_builds(monkeypatch)
    d281_constructions: list[str] = []
    original_analyzer = danger_module._ServerActionSQLTaint

    class CountingServerActionSQLTaint(original_analyzer):
        def __init__(self, root_node, source, file_path):
            d281_constructions.append(file_path)
            super().__init__(root_node, source, file_path)

    monkeypatch.setattr(
        danger_module,
        "_ServerActionSQLTaint",
        CountingServerActionSQLTaint,
    )
    source = "\n".join(
        f"export const ordinaryValue{index} = {index};" for index in range(4_000)
    )

    _scan(tmp_path / "src" / "generated-values.ts", source)

    assert builds == []
    assert d281_constructions == []


@pytest.mark.parametrize(
    ("relative_path", "source", "rule_id"),
    [
        (
            "src/http.ts",
            """
export function sendSession(res: any) {
  res.cookie("session", "value");
}
""",
            "SKY-D252",
        ),
        (
            "app/api/account/route.ts",
            """
export async function POST(request: Request) {
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
            "SKY-D280",
        ),
        (
            "app/api/stripe/webhook/route.ts",
            """
import Stripe from "stripe";

export async function POST(request: Request) {
  const raw = await request.text();
  await processEvent(raw);
  return new Response("ok");
}
""",
            "SKY-D282",
        ),
    ],
)
def test_security_flow_candidates_still_build_and_preserve_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    source: str,
    rule_id: str,
) -> None:
    builds = _count_security_flow_builds(monkeypatch)
    file_path = tmp_path / relative_path

    findings = _scan(file_path, source)

    assert builds == [str(file_path)]
    assert rule_id in {finding["rule_id"] for finding in findings}
