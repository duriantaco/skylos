#!/usr/bin/env python3
"""Run a scoped, static Skylos evaluation before or after a code change."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from skylos.benchmarks.eval_workflow import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
