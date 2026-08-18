#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.research.dead_code import (  # noqa: E402
    ResearchVariant,
    load_manifest,
    score_ablation,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score research dead-code ablations against a JSON manifest."
    )
    parser.add_argument("path", help="Project or fixture root to analyze.")
    parser.add_argument("manifest", help="Ground-truth manifest JSON path.")
    parser.add_argument(
        "--variant",
        action="append",
        choices=[variant.value for variant in ResearchVariant],
        help="Variant to score. Repeat to score multiple variants.",
    )
    parser.add_argument(
        "--output",
        help="Optional JSON output path. Prints to stdout when omitted.",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    variants = args.variant or [variant.value for variant in ResearchVariant]
    results = [
        score_ablation(args.path, manifest, variant=variant).to_dict()
        for variant in variants
    ]
    payload = {
        "project_root": str(Path(args.path).resolve()),
        "manifest_path": str(Path(args.manifest).resolve()),
        "variants": results,
    }
    text = json.dumps(payload, indent=2)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
