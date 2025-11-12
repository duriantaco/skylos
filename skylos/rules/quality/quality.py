from __future__ import annotations
from pathlib import Path

from .complexity import scan_complex_functions
from .nesting import scan_nesting

def _scan_file(root, file):
    try:
        src = file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    mod = ".".join(list(file.relative_to(root).with_suffix("").parts)).rstrip(".")
    ctx = {"file": str(file), "mod": mod, "source": src}

    findings = []

    for q in (scan_complex_functions(ctx, threshold=10) or []):
        q.setdefault("rule_id", "QUALITY_COMPLEXITY")
        findings.append(q)

    for q in (scan_nesting(ctx, threshold=3) or []):
        q.setdefault("rule_id", "QUALITY_NESTING")
        findings.append(q)

    return findings

def scan_ctx(root, files):

    root_path = Path(root)
    out = []
    for f in files:
        out.extend(_scan_file(root_path, Path(f)))
    return out
