from __future__ import annotations

import argparse
import json

from skylos.agents.evaluation import AgentBehaviorError
from skylos.benchmarks.agent_behavior import run_agent_behavior_manifest


DEFAULT_MANIFEST = "benchmarks/agent_behavior/manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the deterministic Skylos agent behavior benchmark",
    )
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        result = run_agent_behavior_manifest(args.manifest)
    except AgentBehaviorError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
