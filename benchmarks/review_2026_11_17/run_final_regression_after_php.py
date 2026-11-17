"""Run existing static suites against an explicitly reviewed saved analyzer.

Invoke only after root confirms the immutable snapshot's review has passed.
Captures reports without changing detector/scorer behavior or corpus labels.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
REVIEW = Path(__file__).resolve().parent
SAVED = Path('/Users/oha/Desktop/skylos-benchmark-2026-11-14/review_2026_11_17')
SUITES = {
    'shared': ('corpus/manifest.json', 'corpus_ci', 84, 'corpus_after.json'),
    'dead-default': ('benchmarks/dead_code/manifest.json', 'dead_code', 151, 'deadcode-sdk-default-after.json'),
    'dead-challenge': ('benchmarks/dead_code/adversarial_manifest.json', 'dead_code', 17, 'deadcode-sdk-challenge-after.json'),
    'security-default': ('benchmarks/security/manifest.json', 'security', 277, 'security_sdk_default_after.json'),
    'security-challenge': ('benchmarks/security/adversarial_manifest.json', 'security', 9, 'security_sdk_adversarial_after.json'),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    with path.open('x') as handle:
        json.dump(data, handle, indent=2)
        handle.write('\n')


def python_hashes(root):
    return {str(p.relative_to(root)): digest(p) for p in sorted((root / 'skylos').rglob('*.py'))}


def fixture_hashes(manifest):
    cases = json.loads(manifest.read_text())['cases']
    files = {manifest}
    for case in cases:
        path = (manifest.parent / case['path']).resolve()
        files.update(p for p in path.rglob('*') if p.is_file()) if path.is_dir() else files.add(path)
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(files)}


def run_shared(module, manifest, capture):
    """Observe the existing scanner return, preserving the existing scorer."""
    original_case, original_scan = module.run_case, module._scan_case
    active_id = None
    def case_wrapper(case, manifest_path):
        nonlocal active_id
        active_id = case['id']
        return original_case(case, manifest_path)
    def scan_wrapper(*args, **kwargs):
        result = original_scan(*args, **kwargs)
        capture(active_id, result)
        return result
    module.run_case, module._scan_case = case_wrapper, scan_wrapper
    try:
        return module.run_manifest(manifest)
    finally:
        module.run_case, module._scan_case = original_case, original_scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyzer-root', type=Path, required=True)
    parser.add_argument('--group', choices=('shared', 'dead', 'security'), required=True)
    args = parser.parse_args()
    engine = args.analyzer_root.resolve(strict=True)
    if engine.name != 'analyzer_after_php':
        raise ValueError('expected the reviewed analyzer_after_php snapshot')
    binary = SAVED / 'tools/skylos-go'
    os.environ.update(SKYLOS_GO_BIN=str(binary), GOROOT='/tmp/skylos-gap-go/go',
        GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', SKYLOS_JOBS='1',
        SKYLOS_CUSTOM_RULES='[]', DO_NOT_TRACK='1')
    sys.path.insert(0, str(engine))
    import skylos
    assert Path(skylos.__file__).resolve().is_relative_to(engine)
    sources = python_hashes(engine)
    receipt = dict(started_at=datetime.now(timezone.utc).isoformat(), analyzer_root=str(engine),
        analyzer_python_sha256=sources,
        analyzer_source_sha256=hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
        go_binary_sha256=digest(binary), sdk_version=Path('/tmp/skylos-gap-go/go/VERSION').read_text(),
        environment={k: os.environ[k] for k in ('SKYLOS_GO_BIN', 'GOROOT', 'GOTOOLCHAIN', 'GOPROXY', 'GOSUMDB', 'SKYLOS_JOBS', 'SKYLOS_CUSTOM_RULES')},
        method='Existing static suite runners and frozen fixture labels; no target code/tests/builds executed.', suites=[])
    for name, (relative, module_name, expected_count, previous) in SUITES.items():
        if not (name == args.group or name.startswith(args.group + '-')):
            continue
        output = REVIEW / ('regression-' + name + '-after-php.json')
        raw = REVIEW / ('regression-' + name + '-after-php-raw')
        if output.exists() or raw.exists():
            raise FileExistsError('refuse overwrite: ' + str(output))
        raw.mkdir()
        manifest = ROOT / relative
        fixtures = fixture_hashes(manifest)
        module = importlib.import_module('skylos.benchmarks.' + module_name)
        def capture(ident, report):
            save(raw / (ident + '.json'), report)
        if module_name == 'corpus_ci':
            summary = run_shared(module, manifest, capture)
        elif module_name == 'dead_code':
            summary = module.run_manifest(manifest, strict_labels=True, capture_result=capture)
        else:
            summary = module.run_manifest(manifest, capture_result=capture)
        assert summary['case_count'] == expected_count
        assert fixtures == fixture_hashes(manifest), 'fixture source changed during run'
        save(output, summary)
        receipt['suites'].append(dict(name=name, manifest_sha256=digest(manifest),
            fixture_sha256=fixtures, report=output.name, report_sha256=digest(output),
            previous_report=previous, previous_sha256=digest(REVIEW / previous),
            raw_sha256={p.name: digest(p) for p in sorted(raw.glob('*.json'))},
            case_count=summary['case_count'], failure_count=summary['failure_count']))
        print(name, summary['case_count'], summary['failure_count'], flush=True)
    assert sources == python_hashes(engine), 'saved analyzer changed during run'
    receipt['finished_at'] = datetime.now(timezone.utc).isoformat()
    save(REVIEW / ('final-regression-after-php-' + args.group + '-provenance.json'), receipt)


if __name__ == '__main__':
    main()
