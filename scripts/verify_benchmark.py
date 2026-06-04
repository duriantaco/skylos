#!/usr/bin/env python3
from __future__ import annotations

from skylos.benchmarks.verify_benchmark import (
    DEFAULT_MANIFEST,
    format_report,
    main,
)
from skylos.benchmarks.verify_benchmark_runner import (
    tool_environment as _tool_environment,
)


if __name__ == "__main__":
    raise SystemExit(main())
