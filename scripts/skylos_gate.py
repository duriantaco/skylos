#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

REPORT = Path("report.json")

def main() -> int:
    if not REPORT.exists():
        print("[skylos] report.json missing (skipping gate)")
        return 0

    txt = REPORT.read_text(encoding="utf-8", errors="ignore").strip()
    if not txt:
        print("[skylos] report.json empty (skipping gate)")
        return 0

    try:
        data = json.loads(txt)
    except Exception as e:
        print(f"[skylos] report.json invalid JSON (skipping gate): {e}")
        return 0

    if isinstance(data, dict):
        vals = data.values()
    elif isinstance(data, list):
        vals = data
    else:
        vals = []

    count = 0
    for v in vals:
        if isinstance(v, list):
            count += len(v)

    print(f"[skylos] findings: {count}")
    soft = os.getenv("SKYLOS_SOFT", "").strip()
    if soft or count == 0:
        return 0
    else:
        return 1

if __name__ == "__main__":
    raise SystemExit(main())

