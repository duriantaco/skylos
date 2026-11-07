#!/usr/bin/env python3
"""Native Codex/Claude hook entry point for internal Skylos smoke evaluations."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    # A broken adapter must remain a blocking hook error, including before the
    # adapter can parse the event or construct its structured response.
    try:
        from skylos.benchmarks.eval_hooks import main as handle

        return handle()
    except Exception as error:
        print(f"Skylos eval hook could not run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
