"""Render sealed facts and existing reports; never import or run an analyzer."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent
ARMS = [('before', 'reviewed_sdk_before'), ('after', 'reviewed_sdk_after'),
        ('after_php', 'reviewed_sdk_after_php')]
SCORED = ('true_positive', 'false_positive', 'false_negative', 'true_negative')
SHORT = dict(zip(SCORED, ('TP', 'FP', 'FN', 'TN')))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def source_link(target, fact):
    start = fact.get('start_line', fact.get('line'))
    end = fact.get('end_line', start)
    anchor = f'#L{start}' + (f'-L{end}' if end != start else '')
    return target['repo'].removesuffix('.git') + '/blob/' + target['ref'] + '/' + quote(fact['file'], safe='/') + anchor


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def compact(outcome):
    return {k: outcome.get(k) for k in ('outcome', 'unscored_reason', 'truth',
                                      'score_eligible', 'matching_findings', 'issues')}


def main():
    freeze_path = ROOT / 'reviewed_ground_truth_freeze.json'
    seal = read(freeze_path)
    assert seal['status'] == 'frozen_after_independent_review'
    manifest_path = ROOT / seal['manifest']['path']
    assert digest(manifest_path) == seal['manifest']['sha256']
    for artifact in seal['review_artifacts']:
        assert digest(ROOT / artifact['path']) == artifact['sha256']
    manifest = read(manifest_path)
    facts = {f['id']: (t, f) for t in manifest['targets'] for f in t['facts']}
    assert len(facts) == sum(len(t['facts']) for t in manifest['targets'])
    result = dict(generated_at=datetime.now(timezone.utc).isoformat(),
        study='Source-only drafts, different-agent review and frozen labels before these scored scans; cohort previously explored, not a new blind study.',
        scope='Selected facts only; no whole-repository precision/recall, safety or removal claim.',
        freeze_sha256=digest(freeze_path), manifest_sha256=digest(manifest_path),
        frozen_at=seal['frozen_at'], review_artifacts=seal['review_artifacts'],
        fact_count=len(facts), score_eligible_count=sum(f['score_eligible'] for _, f in facts.values()),
        truth_counts=dict(Counter(f['truth'] for _, f in facts.values())), arms={}, comparisons={}, facts=[])
    indexed = {}
    for arm, dirname in ARMS:
        path = ROOT / dirname / 'summary.json'
        if not path.exists():
            if arm != 'after_php':
                raise FileNotFoundError(path)
            continue
        summary = read(path)
        assert summary['freeze_sha256'] == result['freeze_sha256']
        assert summary['manifest_sha256'] == result['manifest_sha256']
        assert summary['frozen_at'] == seal['frozen_at']
        assert datetime.fromisoformat(summary['run_started_at']) > datetime.fromisoformat(seal['frozen_at'])
        outcomes, raw_hashes, per_repo = {}, {}, {}
        for target in summary['targets']:
            raw = path.parent / target['raw_report']
            assert digest(raw) == target['raw_sha256']
            raw_hashes[raw.name] = digest(raw)
            per_repo[target['id']] = dict(Counter(o['outcome'] for o in target['outcomes']))
            for outcome in target['outcomes']:
                assert outcome['id'] not in outcomes
                frozen_target, fact = facts[outcome['id']]
                assert target['id'] == frozen_target['id'] and target['revision'] == frozen_target['ref']
                assert fact['truth'] == outcome['truth'] and fact['score_eligible'] == outcome['score_eligible']
                outcomes[outcome['id']] = compact(outcome)
        assert set(outcomes) == set(facts)
        counts = Counter(o['outcome'] for o in outcomes.values())
        assert {k: counts[k] for k in SCORED} == summary['counts']
        indexed[arm] = outcomes
        result['arms'][arm] = dict(summary_path=str(path.relative_to(ROOT)),
            summary_sha256=digest(path), run_started_at=summary['run_started_at'],
            frozen_at=summary['frozen_at'], analyzer_source_sha256=summary['analyzer_source_sha256'],
            go_engine_sha256=summary['go_engine_sha256'], raw_sha256=raw_hashes,
            counts=summary['counts'], scored_count=sum(counts[k] for k in SCORED),
            unscored_count=counts['unscored'] + counts['incomplete'],
            unscored_reasons=dict(Counter(o['unscored_reason'] for o in outcomes.values() if o['outcome'] not in SCORED)),
            by_repository=per_repo,
            by_category={category: dict(Counter(o['outcome'] for ident, o in outcomes.items()
                if facts[ident][1]['category'] == category)) for category in ('dead_code', 'security')})
    for arm in indexed:
        if arm == 'before':
            continue
        changed = [i for i in facts if indexed['before'][i] != indexed[arm][i]]
        result['comparisons']['before_to_' + arm] = dict(same_frozen_labels=True,
            exact_scoring_observations_equal=not changed, changed_fact_ids=changed)
    for ident, (target, fact) in facts.items():
        result['facts'].append(dict(id=ident, repo_id=target['id'], revision=target['ref'],
            file=fact['file'], line=fact.get('line'), start_line=fact.get('start_line', fact.get('line')),
            end_line=fact.get('end_line', fact.get('start_line', fact.get('line'))),
            source_url=source_link(target, fact), symbol=fact.get('symbol'),
            rule_id=fact.get('rule_id'), category=fact['category'], truth=fact['truth'],
            score_eligible=fact['score_eligible'], unscored_reason=fact.get('unscored_reason'),
            intentional_keep=fact.get('intentional_keep', False),
            label_author=fact['label_author'], independent_reviewer=fact['independent_reviewer'],
            outcomes={arm: indexed[arm][ident] for arm in indexed}))
    (ROOT / 'reviewed_comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    render(result, facts)
    print(json.dumps({k: result[k] for k in ('fact_count', 'score_eligible_count', 'truth_counts', 'comparisons')}, indent=2))


def render(result, facts):
    arms = list(result['arms'])
    def cite(ident, file=None, line=None, label=None):
        target, original = facts[ident]
        fact = dict(original)
        if file is not None:
            fact.update(file=file, line=line, start_line=line, end_line=line)
        title = label or (fact['file'] + ':' + str(fact.get('start_line', fact.get('line'))))
        return '[' + title + '](' + source_link(target, fact) + ')'
    lines = ['# Reviewed ground-truth results', '', result['study'], '', result['scope'], '',
        f"All **{result['fact_count']} frozen facts** are represented; **{result['score_eligible_count']}** are policy-eligible before runtime extraction checks. Truth totals: `{result['truth_counts']}`.", '',
        'Original no-SDK scans remain historical in `reviewed_before/` and `reviewed_after/`; they are not substituted for the explicit-SDK arms below. Unknowns, intentionally retained unused code, unsupported sites and missing extraction receive no accuracy credit.', '',
        '| Arm | TP | FP | FN | TN | Scored | Unscored | Run started UTC |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |']
    for arm, data in result['arms'].items():
        lines.append('| [' + arm + '](' + data['summary_path'] + ') | ' + ' | '.join(str(data['counts'][k]) for k in SCORED) + f" | {data['scored_count']} | {data['unscored_count']} | {data['run_started_at']} |")
    lines += ['', '| Arm / category | TP | FP | FN | TN | Unscored |',
              '| --- | ---: | ---: | ---: | ---: | ---: |']
    for arm, data in result['arms'].items():
        for category, counts in data['by_category'].items():
            lines.append('| ' + arm + ' / ' + category + ' | ' + ' | '.join(str(counts.get(k, 0)) for k in SCORED) + ' | ' + str(counts.get('unscored', 0) + counts.get('incomplete', 0)) + ' |')
    lines += ['', f"Freeze: `{result['frozen_at']}`. Manifest SHA-256: `{result['manifest_sha256']}`. Report/raw hashes, analyzer identities, times and exact per-fact comparisons are in [reviewed_comparison.json](reviewed_comparison.json). All arms are checked against the same frozen labels and review hashes.", '']
    for name, comparison in result['comparisons'].items():
        lines.append(f"`{name}`: " + ('all scoring observations identical.' if comparison['exact_scoring_observations_equal'] else 'changed facts: ' + ', '.join(comparison['changed_fact_ids']) + '.'))
    lines += ['', 'The optional `after_php` arm is an informed follow-up after reviewing these results, not independent holdout evidence. It appears automatically when its completed summary exists. Regenerate without scanning: `python benchmarks/review_2026_11_17/summarize_reviewed_results.py`.', '',
        '## Every frozen fact', '', 'TP/FP/FN/TN are selected-fact outcomes. `U` means unscored; parentheses give the reason and number of matching warning observations. Eligibility is the frozen policy decision, not a claim of extraction success.', '',
        '| Fact | Category | Pinned source / symbol or rule | Truth | Eligible | ' + ' | '.join(arms) + ' |',
        '| --- | --- | --- | --- | --- | ' + ' | '.join('---' for _ in arms) + ' |']
    for row in result['facts']:
        label = row['file'] + ':' + str(row['start_line'])
        symbol = ' · '.join(v for v in (row.get('symbol'), row.get('rule_id')) if v) or '(semantic site)'
        values = []
        for arm in arms:
            outcome = row['outcomes'][arm]
            reason = outcome.get('unscored_reason')
            if row['truth'] == 'unknown':
                reason = 'unknown_truth'
            elif reason and 'outside a specific implemented sink' in reason:
                reason = 'not_applicable'
            values.append(SHORT.get(outcome['outcome'], 'U (' + str(reason) + '; warnings=' + str(len(outcome['matching_findings'] or [])) + ')'))
        lines.append('| ' + row['id'] + ' | ' + row['category'] + ' | [' + label + '](' + row['source_url'] + ') — ' + cell(symbol) + ' | ' + row['truth'] + ' | ' + str(row['score_eligible']).lower() + ' | ' + ' | '.join(map(cell, values)) + ' |')
    lines += ['', '## Concrete evidence and limits', '',
        '- **Two Slim false positives in the original before/after arms:** `isRoute` and `isMiddleware` are ' + cite('slim-used-is-route-callback', 'Slim/CallableResolver.php', 70, 'passed as array callables at70/78') + ' and ' + cite('slim-used-is-route-callback', 'Slim/CallableResolver.php', 93, 'invoked as `$predicate` at93/98') + '. Production ' + cite('slim-used-is-route-callback', 'Slim/Routing/Route.php', 345) + ' and ' + cite('slim-used-is-middleware-callback', 'Slim/MiddlewareDispatcher.php', 176) + ' reach those resolution methods. Their warning observations conflict with source-proven usage.',
        '- **Two Slim true positives:** ' + cite('slim-unused-htmlentities-import', label='`htmlentities` import') + ' and ' + cite('slim-unused-runtimeexception-import', label='`RuntimeException` import') + ' occur only in their lexical import declarations. The complete file scopes were read independently; used neighboring `get_class`/`sprintf` imports remain separate negative controls, unscored where extraction is absent.',
        '- **One tiny-http security false negative:** ' + cite('tiny-example-file-read') + ' opens a path derived from the request URL and returns its content. The reviewed unsafe fact concerns an example that intentionally serves the filesystem root under untrusted-client assumptions; it is not a deployed/core vulnerability or severity claim. A complete scan without this labelled warning is FN.',
        '- **Unknowns retain observations:** Hono raw HTML insertion and caller-configured JWKS fetch each have a matching warning in the original arms, but their caller trust assumptions were not established. They stay unknown/unscored. Slim generic output and XML parser contracts likewise remain unscored; they are not declared safe merely because no warning appears.',
        '- **Intentional retention stays distinct:** tiny-http `FusedReader.into_inner` is source-unused with explicit dead-code suppression. Its policy exclusion remains visible and earns no accuracy credit.',
        '- **Coverage limit:** only two score-eligible unused positives and one unsafe example positive exist here. The selected sample does not establish whole-repository recall, Java/Go/TS/Rust dead-code recall, or general security safety. Eight policy-eligible negative controls lacked extraction in the original explicit-SDK arms; they were not counted as TN.', '',
        'The pinned table links identify each declaration/site. Declaration and consumer excerpts, assumptions, independent reviewer decisions and source hashes remain in [the frozen manifest](reviewed_ground_truth_manifest.json) and its sealed review artifacts. No labels, reviews or scanner output were modified by this summary generator.']
    (ROOT / 'REVIEWED_GROUND_TRUTH_RESULTS.md').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
