"""Compare every final-regression case from saved JSON; never run scanners."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LABEL_KEYS = ('analysis_status', 'analysis_issues', 'scored', 'checked_expectation_count',
              'true_positives', 'false_positives', 'false_negatives', 'true_negatives', 'failures')
OBSERVATION_KEYS = ('findings_by_kind', 'findings_by_category', 'unlabeled_finding_count', 'unlabeled_findings')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def selected(case, keys):
    return {k: case.get(k) for k in keys}


def status(case):
    return 'unscored' if not case.get('scored', True) else ('pass' if not case['failures'] else 'fail (' + str(len(case['failures'])) + ')')


def main():
    output = ROOT / 'final-regression-after-php-comparison.json'
    if output.exists():
        raise FileExistsError('refuse to overwrite final comparison')
    result = dict(created_at=datetime.now(timezone.utc).isoformat(),
        scope='Existing frozen benchmark cases; selected-oracle regression evidence, not independent accuracy proof.',
        note='Security rule-only/count scoring limits and known aggregate F1 bug remain; compare case labels/counts, not inflated score.',
        suites=[])
    for group in ('shared', 'dead', 'security'):
        provenance_path = ROOT / ('final-regression-after-php-' + group + '-provenance.json')
        provenance = read(provenance_path)
        for entry in provenance['suites']:
            before_path, after_path = ROOT / entry['previous_report'], ROOT / entry['report']
            assert digest(before_path) == entry['previous_sha256']
            assert digest(after_path) == entry['report_sha256']
            raw = ROOT / ('regression-' + entry['name'] + '-after-php-raw')
            for name, expected in entry['raw_sha256'].items():
                assert digest(raw / name) == expected
            before, after = read(before_path), read(after_path)
            left = {c['id']: c for c in before['cases']}
            right = {c['id']: c for c in after['cases']}
            assert len(left) == len(before['cases']) and len(right) == len(after['cases']) and set(left) == set(right)
            rows = []
            for ident in right:
                b, a = left[ident], right[ident]
                rows.append(dict(id=ident, same_label_outcomes=selected(b, LABEL_KEYS) == selected(a, LABEL_KEYS),
                    same_finding_observations=selected(b, OBSERVATION_KEYS) == selected(a, OBSERVATION_KEYS),
                    previous_status=status(b), final_status=status(a),
                    previous=selected(b, LABEL_KEYS + OBSERVATION_KEYS), final=selected(a, LABEL_KEYS + OBSERVATION_KEYS)))
            result['suites'].append(dict(name=entry['name'], case_count=len(rows),
                manifest_sha256=entry['manifest_sha256'], previous_report=before_path.name,
                previous_sha256=digest(before_path), final_report=after_path.name, final_sha256=digest(after_path),
                provenance_path=provenance_path.name, provenance_sha256=digest(provenance_path),
                analyzer_source_sha256=provenance['analyzer_source_sha256'],
                started_at=provenance['started_at'], finished_at=provenance['finished_at'],
                previous_counts=before.get('counts'), final_counts=after.get('counts'),
                previous_pass_count=before['pass_count'], final_pass_count=after['pass_count'],
                previous_failure_count=before['failure_count'], final_failure_count=after['failure_count'],
                changed_label_ids=[r['id'] for r in rows if not r['same_label_outcomes']],
                changed_observation_ids=[r['id'] for r in rows if not r['same_finding_observations']], cases=rows))
    result['total_cases'] = sum(s['case_count'] for s in result['suites'])
    assert result['total_cases'] == 538
    with output.open('x') as handle:
        json.dump(result, handle, indent=2)
        handle.write('\n')
    lines = ['# Final regression after PHP callback correction', '', result['scope'], '',
        'All538 existing cases were rerun through their existing suite scorers against the reviewed saved `analyzer_after_php` snapshot, with the same explicit Go SDK and engine. Raw reports, fixtures, snapshot hashes, environment and times are captured in the linked provenance. Old reports and labels remain unchanged.', '',
        '| Suite | Cases | Previous pass | Final pass | Previous label failures | Final label failures | Changed label cases |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for suite in result['suites']:
        lines.append('| [' + suite['name'] + '](' + suite['final_report'] + ') | ' + ' | '.join(str(suite[k]) for k in ('case_count', 'previous_pass_count', 'final_pass_count', 'previous_failure_count', 'final_failure_count')) + ' | ' + str(len(suite['changed_label_ids'])) + ' |')
    lines += ['', result['note'], '',
        'Shared84 compares against the previous `corpus_after.json`; the other suites compare against their explicit-SDK `after` reports. Matching challenge outcomes preserve known misses and strict unlabelled penalties; they do not make those cases pass. Full counts, raw hashes and every comparison field are in [final-regression-after-php-comparison.json](final-regression-after-php-comparison.json).', '',
        '## Every case', '', '| Suite | Case | Previous | Final | Same labels | Same finding counts/observations |',
        '| --- | --- | --- | --- | --- | --- |']
    for suite in result['suites']:
        for row in suite['cases']:
            lines.append('| ' + ' | '.join(str(x) for x in (suite['name'], row['id'], row['previous_status'], row['final_status'], row['same_label_outcomes'], row['same_finding_observations'])) + ' |')
    with (ROOT / 'FINAL_REGRESSION_AFTER_PHP.md').open('x') as handle:
        handle.write('\n'.join(lines) + '\n')
    print(json.dumps({s['name']: dict(cases=s['case_count'], changed_labels=s['changed_label_ids'], changed_observations=s['changed_observation_ids'], final_counts=s['final_counts']) for s in result['suites']}, indent=2))


if __name__ == '__main__':
    main()
