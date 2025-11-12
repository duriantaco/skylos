def omg_quality(x, ys):
    total = 0
    for y in ys:
        if y > 0:
            total += y
        else:
            total -= y

    if total > 10 and x:
        for i in range(5):
            if i % 2 == 0:
                total += i
            else:
                total -= i

    try:
        while total < 100:
            if total % 3 == 0 and total % 5 == 0:
                break
            if total % 2 == 0:
                total += 7
            else:
                total += 3
    except Exception:
        total = -1

    return total

import json
import os
from pathlib import Path

from skylos.analyzer import analyze as skylos_analyze

THIS_FILE = Path(__file__).resolve()

def main():
    result_json = skylos_analyze(str(THIS_FILE), conf=0, enable_quality=True)
    data = json.loads(result_json)

    assert "quality" in data, "Expected 'quality' key in analyzer result"
    assert data["analysis_summary"].get("quality_count", 0) >= 1, "Expected quality_count >= 1"

    findings = data["quality"]
    matches = [
        q for q in findings
        if (q.get("name","").endswith(".omg_quality") or q.get("simple_name") == "omg_quality")
    ]
    assert matches, "Expected a quality finding for omg_quality"

    q = matches[0]
    complexity = int(q.get("complexity", -1))
    assert complexity >= 10, f"Expected complexity >= 10, got {complexity}"

    print("OK ✓  Skylos quality rule fired:")
    print(f"  kind      : {q.get('kind','(missing)')}")
    print(f"  name      : {q.get('name') or q.get('simple_name')}")
    print(f"  file:line : {q.get('file')}:{q.get('line')}")
    print(f"  complexity: {complexity}")
    print(f"  length    : {q.get('length')}")

if __name__ == "__main__":
    main()
