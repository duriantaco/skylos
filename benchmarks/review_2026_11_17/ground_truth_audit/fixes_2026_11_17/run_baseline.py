"""Run frozen source with a real main file for multiprocessing spawn workers."""
import argparse
import json
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True)
    p.add_argument('--manifest', required=True)
    p.add_argument('--suite', choices=['deadcode', 'security'], required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    sys.path.insert(0, args.source)
    if args.suite == 'deadcode':
        from skylos.benchmarks.dead_code import run_manifest
        result = run_manifest(args.manifest, strict_labels=True)
    else:
        from skylos.benchmarks.security import run_manifest
        result = run_manifest(args.manifest)
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(result['counts'], 'unscored', result.get('unscored_case_count', 0), flush=True)


if __name__ == '__main__':
    main()
