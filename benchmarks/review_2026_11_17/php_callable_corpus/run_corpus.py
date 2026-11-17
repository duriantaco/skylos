"""Run static synthetic PHP contracts against an explicit analyzer snapshot."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


parser = argparse.ArgumentParser()
parser.add_argument("--engine-root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
sys.path.insert(0, str(args.engine_root.resolve()))

from skylos.benchmarks import dead_code  # noqa: E402
from skylos.visitors.languages.php import core  # noqa: E402


manifest = Path(__file__).with_name("manifest.json")
raw = {}
result = dead_code.run_manifest(
    manifest,
    capture_result=lambda case, report: raw.__setitem__(case, report),
)
receipt = {
    "target_execution": False,
    "study": "source-derived development fixture, not blind evidence",
    "engine_root": str(args.engine_root.resolve()),
    "loaded_core": core.__file__,
    "core_sha256": hashlib.sha256(Path(core.__file__).read_bytes()).hexdigest(),
    "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
    "fixture_sha256": {
        str(path.relative_to(manifest.parent)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(manifest.parent.glob("fixtures/**/*.php"))
    },
    "result": result,
    "raw": raw,
}
args.output.write_text(json.dumps(receipt, indent=2) + "\n")
print(dead_code.format_summary(result))
