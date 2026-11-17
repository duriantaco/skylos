"""Static replay of fixed-label JS/TS contracts and frozen fresh source facts."""
from pathlib import Path
import copy
import hashlib
import json
import os
import shutil
import sys

ROOT = Path('/Users/oha/skylos')
OUT = Path(__file__).resolve().parent
AUDIT = OUT.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(AUDIT.parent))
from run_holdouts import evaluate
from skylos.analyzer import analyze
from skylos.benchmarks.dead_code import run_manifest
from skylos.benchmarks._analysis_validation import analysis_issues
from skylos.benchmarks.security_holdouts import _isolated_environment


def main():
    manifest = ROOT / 'benchmarks/dead_code/manifest.json'
    original = json.loads(manifest.read_text())
    original['cases'] = [c for c in original['cases'] if set(c.get('languages', [])) & {'javascript', 'typescript'}]
    # Preserve the pre-adjudication contract independently of canonical promotion.
    case = next(c for c in original['cases'] if c['id'] == 'javascript-path-join-literal-files')
    moved = {'tools/input.ts', 'src/bundle.ts'}
    for label in list(case['expect']['unused']):
        if label['file'] in moved:
            case['expect']['unused'].remove(label)
            case['expect']['used'].append(label)
    for c in original['cases']:
        source = (manifest.parent / c['path']).resolve()
        staged = OUT / 'fixtures' / source.name
        if not staged.exists():
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, staged)
        c['path'] = str(staged.relative_to(OUT))
    corrected = copy.deepcopy(original)
    case = next(c for c in corrected['cases'] if c['id'] == 'javascript-path-join-literal-files')
    for label in list(case['expect']['used']):
        if label['file'] in moved:
            case['expect']['used'].remove(label)
            case['expect']['unused'].append(label)
    for name, data in [('legacy_js38', original), ('source_corrected_js38', corrected)]:
        path = OUT / (name + '_manifest.json')
        path.write_text(json.dumps(data, indent=2) + '\n')
        summary = run_manifest(path, scanner='skylos', strict_labels=True)
        (OUT / (name + '.json')).write_text(json.dumps(summary, indent=2) + '\n')
        print(name, summary['counts'], summary['failure_count'], flush=True)
    labels = AUDIT / 'SOURCE_LABELS_TYPESCRIPT.json'
    results = []
    for target in json.loads(labels.read_text())['repositories']:
        checkout = Path(target['root'])
        for f in target['coverage']:
            assert hashlib.sha256((checkout / f['file']).read_bytes()).hexdigest() == f['sha256']
        with _isolated_environment():
            raw = analyze(str(checkout), conf=60, enable_danger=True,
                          enable_sca=False, enable_ai_defects=False, enable_quality=False,
                          enable_secrets=False, enable_dependency_hallucinations=False,
                          custom_rules_data=[], trace_file=False, all_advice=True,
                          grep_verify=True, grep_cache=False,
                          project_config_overrides={'ignore': [], 'exclude': []})
        report = json.loads(raw) if isinstance(raw, str) else raw
        (OUT / (target['id'] + '.json')).write_text(json.dumps(report, indent=2) + '\n')
        issues = analysis_issues(report, scanner='skylos')
        outcomes = evaluate(target, report, checkout, issues)
        results.append({'id': target['id'], 'analysis_issues': issues, 'labels': outcomes,
                        'finding_counts': {k: len(v) for k, v in report.items()
                                           if isinstance(v, list) and (k.startswith('unused_') or k == 'danger')}})
    (OUT / 'fresh_source_labels_after.json').write_text(json.dumps({
        'frozen_label_sha256': hashlib.sha256(labels.read_bytes()).hexdigest(),
        'go_engine': os.environ.get('SKYLOS_GO_BIN'),
        'targets': results,
    }, indent=2) + '\n')
    for r in results:
        from collections import Counter
        print(r['id'], dict(Counter(o['outcome'] for o in r['labels'])), flush=True)


if __name__ == '__main__':
    main()
