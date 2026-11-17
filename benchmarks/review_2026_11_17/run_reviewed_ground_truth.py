"""Static scans gated by an independently reviewed, hash-sealed fact manifest.

Labels are never passed to the analyzer. Scores cover selected facts only.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import time

DEAD_CATEGORIES = {"unused_functions", "unused_classes", "unused_variables",
                   "unused_imports", "unused_parameters", "unused_files"}
TRUTHS = {"dead_code": {"used", "unused", "unknown"},
          "security": {"safe", "unsafe", "unknown"}}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed


def relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("expected nonempty relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError("path must be canonical and relative")
    return path


def sealed_file(root, item):
    path = root / relative(item.get("path"))
    current = root
    for part in relative(item["path"]).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("sealed artifact must not be a symlink")
    if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
        raise ValueError("sealed artifact requires SHA-256")
    if digest(path) != item["sha256"]:
        raise ValueError(f"sealed artifact hash mismatch: {item['path']}")
    return path


def line_range(fact):
    start = fact.get("start_line", fact.get("line"))
    end = fact.get("end_line", start)
    if type(start) is not int or type(end) is not int or not 0 < start <= end:
        raise ValueError("fact requires a positive ordered source range")
    return start, end


def load_frozen(freeze_path, now=None):
    """Validate all review gates before importing an analyzer."""
    freeze_path = Path(freeze_path).absolute()
    if freeze_path.is_symlink():
        raise ValueError("freeze file must not be a symlink")
    seal = json.loads(freeze_path.read_text())
    if seal.get("status") != "frozen_after_independent_review":
        raise ValueError("facts are not frozen after independent review")
    if timestamp(seal.get("frozen_at")) > (now or datetime.now(timezone.utc)):
        raise ValueError("freeze is in the future")
    manifest_path = sealed_file(freeze_path.parent, seal["manifest"])
    reviews = seal.get("review_artifacts")
    if not isinstance(reviews, list) or not reviews:
        raise ValueError("freeze requires sealed review artifacts")
    review_names = {}
    for artifact in reviews:
        review_path = sealed_file(freeze_path.parent, artifact)
        if artifact["path"] in review_names:
            raise ValueError("duplicate sealed review artifact")
        review = json.loads(review_path.read_text())
        draft_path = sealed_file(freeze_path.parent, {
            "path": review.get("draft_file"), "sha256": review.get("draft_sha256")})
        review_names[artifact["path"]] = (review, json.loads(draft_path.read_text()))
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1 or not manifest.get("targets"):
        raise ValueError("manifest requires version 1 and nonempty targets")
    identities, fact_ids = set(), set()
    for target in manifest["targets"]:
        ident = target.get("id", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", ident) or ident in identities:
            raise ValueError("invalid or duplicate target id")
        identities.add(ident)
        if not re.fullmatch(r"[0-9a-f]{40}", target.get("ref", "")):
            raise ValueError("target requires exact pinned ref")
        relative(target["checkout"])
        relative(target["scan_root"])
        sources = target.get("source_files", [])
        if not isinstance(sources, list) or not sources:
            raise ValueError("target requires verify_checkout source_files list")
        hashes = {}
        for source in sources:
            name = relative(source["path"]).as_posix()
            if name in hashes or not re.fullmatch(r"[0-9a-f]{64}", source.get("sha256", "")):
                raise ValueError("duplicate or unhashed source")
            hashes[name] = source["sha256"]
        if not target.get("facts"):
            raise ValueError("target requires reviewed facts")
        for fact in target["facts"]:
            validate_fact(fact, hashes, review_names, fact_ids, target)
    reviewed_ids = {v['id'] for review, _ in review_names.values() for v in review.get('verdicts', [])}
    if reviewed_ids != fact_ids:
        raise ValueError('final manifest must retain every reviewed fact, including unscored facts')
    return seal, manifest


def validate_fact(fact, hashes, review_names, fact_ids, target):
    if not isinstance(fact.get("id"), str) or not fact["id"] or fact["id"] in fact_ids:
        raise ValueError("invalid or duplicate fact id")
    fact_ids.add(fact["id"])
    category = fact.get("category")
    if fact.get("truth") not in TRUTHS.get(category, set()):
        raise ValueError("invalid fact category/truth")
    if relative(fact["file"]).as_posix() not in hashes:
        raise ValueError("fact must point to hashed source")
    line_range(fact)
    if type(fact.get("score_eligible")) is not bool:
        raise ValueError("fact requires explicit score_eligible boolean")
    if not fact["score_eligible"] and not fact.get("unscored_reason"):
        raise ValueError("unscored fact requires reason")
    if fact["truth"] == "unknown" and fact["score_eligible"]:
        raise ValueError("unknown truth cannot earn accuracy credit")
    if category == "dead_code":
        if not fact.get("symbol") or fact.get("finding_category") not in DEAD_CATEGORIES:
            raise ValueError("dead-code fact requires symbol and finding_category")
    elif not (not fact['score_eligible'] and fact.get('rule_id') is None) and not re.fullmatch(r"SKY-[A-Z0-9-]+", fact.get("rule_id") or ""):
        raise ValueError("security fact requires exact rule id")
    author, reviewer = fact.get("label_author"), fact.get("independent_reviewer")
    if not isinstance(author, str) or not author.strip() or not isinstance(reviewer, str) or not reviewer.strip() or author.strip() == reviewer.strip():
        raise ValueError("fact requires distinct author and independent reviewer")
    resolution = fact.get("review_resolution", {})
    if resolution.get("status") != "resolved" or resolution.get("review_artifact") not in review_names or not resolution.get("reason"):
        raise ValueError("fact requires resolved review linked to sealed artifact")
    bind_review(fact, *review_names[resolution['review_artifact']], target, hashes)
    evidence = fact.get("source_evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("fact requires source evidence")
    for entry in evidence:
        name = relative(entry["file"]).as_posix()
        if name not in hashes or entry.get("sha256") != hashes[name]:
            raise ValueError("all fact evidence must match sealed source hashes")


def repo_identity(value):
    if not isinstance(value, str) or not value:
        raise ValueError('reviewed repository identity is missing')
    return value.removeprefix('https://github.com/').removeprefix('http://github.com/').removesuffix('.git').rstrip('/')


def reviewed_eligibility(value):
    """Normalize explicit review decisions; pending coverage is not a decision."""
    if value is None or type(value) is bool:
        return value
    if isinstance(value, dict):
        if type(value.get('eligible')) is not bool:
            raise ValueError('review eligibility requires boolean eligible')
        return value['eligible']
    if not isinstance(value, str):
        raise ValueError('invalid review eligibility decision')
    if value == 'eligible':
        return True
    if value in {'not_applicable', 'unknown', 'ineligible', 'unscored'} or value.startswith('exclude_unknown') or value.startswith('intentional_keep_exclude'):
        return False
    if value.startswith('pending_') or value.startswith('example_source_risk_only;'):
        return None
    raise ValueError('unrecognized review eligibility decision')


def bind_review(fact, review, draft, target, hashes):
    if review.get('reviewer') != fact['independent_reviewer']:
        raise ValueError('sealed reviewer identity does not match fact')
    author = draft.get('label_author', draft.get('reviewer', review.get('draft_author')))
    if author != fact['label_author']:
        raise ValueError('sealed draft author does not match fact')
    verdicts = [v for v in review.get('verdicts', []) if v.get('id') == fact['id']]
    originals = [v for v in draft.get('rows', draft.get('facts', [])) if v.get('id') == fact['id']]
    if len(verdicts) != 1 or len(originals) != 1:
        raise ValueError('fact must have one draft record and one independent verdict')
    verdict, original = verdicts[0], originals[0]
    if verdict.get('verdict') not in {'agree', 'agreed', 'resolved'} or verdict.get('reviewed_truth') != fact['truth']:
        raise ValueError('independent review is unresolved or disagrees with final truth')
    for key in ('score_eligible', 'scoring_eligibility'):
        decision = reviewed_eligibility(verdict.get(key))
        if decision is not None and decision != fact['score_eligible']:
            raise ValueError('final eligibility differs from independent review')
    for key in ('category', 'file', 'symbol', 'rule_id'):
        if original.get(key) != fact.get(key):
            raise ValueError(f'final fact identity differs from reviewed draft: {key}')
    approved_span = verdict.get('recommended_match_span', original)
    if line_range(approved_span) != line_range(fact):
        raise ValueError('final fact source range differs from reviewed draft')
    if original.get('finding_category') and original['finding_category'] != fact.get('finding_category'):
        raise ValueError('finding category differs from reviewed draft')
    if verdict.get('finding_category') and verdict['finding_category'] != fact.get('finding_category'):
        raise ValueError('finding category differs from independent review')
    derived_category = {'function': 'unused_functions', 'class': 'unused_classes',
                        'import': 'unused_imports'}.get(original.get('kind'))
    if fact['category'] == 'dead_code' and derived_category and derived_category != fact['finding_category']:
        raise ValueError('finding category differs from reviewed declaration kind')
    if 'owner_class' in original and original['owner_class'] != fact.get('owner_class'):
        raise ValueError('owner class differs from reviewed draft')
    if 'owner_class' in verdict and verdict['owner_class'] != fact.get('owner_class'):
        raise ValueError('owner class differs from independent review')
    if original.get('truth') == 'unused' and (original.get('intentional_keep') or original.get('explicit_suppression')) and fact['score_eligible']:
        raise ValueError('intentionally retained unused fact must remain unscored')
    repo_id = original.get('repo_id', draft.get('repo_id'))
    if repo_id in draft.get('repositories', {}):
        source_target = draft['repositories'][repo_id]
        repo = source_target.get('url')
    elif draft.get('targets'):
        candidates = [t for t in draft['targets'] if t.get('repo_id') == repo_id]
        if len(candidates) != 1:
            raise ValueError('reviewed target identity is ambiguous')
        source_target = candidates[0]
        repo = source_target.get('repo', source_target.get('repo_id'))
    else:
        source_target = draft
        repo = source_target.get('repo')
    revision = source_target.get('revision', source_target.get('commit'))
    if repo_identity(repo) != repo_identity(target.get('repo')) or revision != target['ref']:
        raise ValueError('target repository or revision differs from reviewed draft')
    if original.get('revision', revision) != revision:
        raise ValueError('draft fact revision differs from its repository')
    reviewed_hashes = dict(draft.get('files_sha256', {}))
    for entry in original.get('source_evidence', []):
        if isinstance(entry, dict) and entry.get('sha256'):
            reviewed_hashes[entry['file']] = entry['sha256']
    if original.get('file_sha256'):
        reviewed_hashes[original['file']] = original['file_sha256']
    for entry in verdict.get('source_evidence', []) + verdict.get('source_checked', []):
        if not isinstance(entry, dict):
            continue
        value = entry.get('sha256', entry.get('file_sha256'))
        if value:
            name = relative(entry['file']).as_posix()
            if name in reviewed_hashes and reviewed_hashes[name] != value:
                raise ValueError('review and draft disagree on source bytes')
            reviewed_hashes[name] = value
    if not reviewed_hashes or original['file'] not in reviewed_hashes:
        raise ValueError('draft requires pinned source bytes for fact')
    if any(hashes.get(name) != value for name, value in reviewed_hashes.items()):
        raise ValueError('target source bytes differ from reviewed draft')
    for entry in fact.get('source_evidence', []):
        if not isinstance(entry, dict) or reviewed_hashes.get(entry.get('file')) != entry.get('sha256'):
            raise ValueError('final evidence is not bound to reviewed source bytes')


def report_path(item, checkout):
    value = item.get('file', item.get('file_path'))
    if not isinstance(value, str) or not value:
        return None
    try:
        path = Path(value)
        return path.resolve().relative_to(checkout.resolve()).as_posix() if path.is_absolute() else relative(value).as_posix()
    except (ValueError, OSError):
        return None


def names(item):
    return {v.replace('::', '.') for k in ('full_name', 'qualified_name', 'name', 'simple_name', 'symbol') if isinstance(v := item.get(k), str) and v}


def symbol_matches(expected, item):
    expected = expected.replace('::', '.')
    return any(n == expected or n.endswith('.' + expected) for n in names(item))


def fact_symbol_matches(fact, item):
    expected = fact['symbol'].replace('::', '.')
    owner = fact.get('owner_class')
    if owner:
        owner = owner.replace('::', '.')
        if not expected.startswith(owner + '.'):
            expected = owner + '.' + expected
    return symbol_matches(expected, item)


def at_location(item, fact, checkout):
    line = item.get('line', item.get('start_line'))
    start, end = line_range(fact)
    return report_path(item, checkout) == fact['file'] and type(line) is int and start <= line <= end


def matching_observations(fact, report, checkout):
    if fact['category'] == 'security':
        # Without an implemented rule identity, preserve site observations but
        # never turn them into classification evidence (validation forbids score).
        return [f for f in report.get('danger', []) if isinstance(f, dict) and at_location(f, fact, checkout) and (fact.get('rule_id') is None or f.get('rule_id') == fact['rule_id'])], []
    hits = [f for f in report.get(fact['finding_category'], []) if isinstance(f, dict) and at_location(f, fact, checkout) and fact_symbol_matches(fact, f)]
    definitions = report.get('definitions', {})
    definitions = list(definitions.values()) if isinstance(definitions, dict) else []
    exact = [d for d in definitions if isinstance(d, dict) and at_location(d, fact, checkout) and fact_symbol_matches(fact, d)]
    if fact['truth'] == 'used':
        hits += [f for f in report.get('unused_files', []) if isinstance(f, dict) and report_path(f, checkout) == fact['file']]
        owners = {name.rsplit('.', 1)[0] for d in exact for name in names(d) if '.' in name}
        if '.' in fact['symbol'].replace('::', '.'):
            owners.add(fact['symbol'].replace('::', '.').rsplit('.', 1)[0])
        if fact.get('owner_class'):
            owners.add(fact['owner_class'].replace('::', '.'))
        hits += [f for f in report.get('unused_classes', []) if isinstance(f, dict) and report_path(f, checkout) == fact['file'] and any(symbol_matches(o, f) for o in owners)]
    return hits, exact


def evaluate_fact(fact, report, checkout, issues=()):
    hits, definitions = matching_observations(fact, report, checkout)
    result = dict(id=fact['id'], truth=fact['truth'], category=fact['category'], matching_findings=hits, issues=list(issues), score_eligible=fact['score_eligible'], intentional_keep=fact.get('intentional_keep', False))
    if not fact['score_eligible']:
        return dict(result, outcome='unscored', unscored_reason=fact['unscored_reason'])
    if issues:
        return dict(result, outcome='incomplete', unscored_reason='analysis_incomplete')
    if fact['category'] == 'dead_code' and fact['truth'] == 'used' and not hits and not definitions:
        return dict(result, outcome='unscored', unscored_reason='missing_extraction')
    if fact['category'] == 'security' and fact['truth'] == 'safe' and not hits:
        extracted = report.get('definitions', {})
        if not isinstance(extracted, dict) or not any(isinstance(d, dict) and report_path(d, checkout) == fact['file'] for d in extracted.values()):
            return dict(result, outcome='unscored', unscored_reason='missing_extraction')
    positive = fact['truth'] in {'unused', 'unsafe'}
    result['outcome'] = ('true_positive' if hits else 'false_negative') if positive else ('false_positive' if hits else 'true_negative')
    return result


def load_engine(root):
    root = root.resolve()
    sys.path.insert(0, str(root))
    import skylos
    if not Path(skylos.__file__).resolve().is_relative_to(root):
        raise ValueError('imported analyzer is outside --analyzer-root')
    from skylos.analyzer import analyze
    from skylos.benchmarks._analysis_validation import analysis_issues
    from skylos.benchmarks.security_holdouts import verify_checkout, _isolated_environment
    return analyze, analysis_issues, verify_checkout, _isolated_environment


def execute(args):
    seal, manifest = load_frozen(args.freeze)
    if args.output.exists():
        raise FileExistsError('output exists; overwrite forbidden')
    analyze, analysis_issues, verify_checkout, isolated = load_engine(args.analyzer_root)
    checkout_root = args.checkout_root.resolve()
    verified = {t['id']: verify_checkout(t, checkout_root) for t in manifest['targets']}
    started = datetime.now(timezone.utc).isoformat()
    args.output.mkdir(parents=True, exist_ok=False)
    source_hashes = {str(p.relative_to(args.analyzer_root)): digest(p) for p in sorted((args.analyzer_root / 'skylos').rglob('*.py'))}
    go_bin = os.environ.get('SKYLOS_GO_BIN')
    summary = dict(label_scope='Selected independently reviewed facts; no whole-repository accuracy claim', frozen_at=seal['frozen_at'], run_started_at=started, freeze_sha256=digest(args.freeze), manifest_sha256=seal['manifest']['sha256'], review_artifacts=seal['review_artifacts'], python=sys.version, analyzer_source_sha256=hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest(), go_engine_sha256=digest(go_bin) if go_bin else None, targets=[])
    (args.output / 'analyzer_sources.json').write_text(json.dumps(source_hashes, indent=2) + '\n')
    for target in manifest['targets']:
        checkout, scan_root, _, snapshot = verified[target['id']]
        row = dict(id=target['id'], revision=target['ref'])
        start = time.monotonic()
        try:
            options = manifest.get('scan', {})
            with isolated():
                if go_bin:
                    os.environ['SKYLOS_GO_BIN'] = go_bin
                raw = analyze(str(scan_root), conf=options.get('conf', 60), enable_danger=True,
                    grep_verify=bool(options.get('grep_verify', False)), grep_cache=False,
                    enable_sca=False, enable_ai_defects=False, enable_quality=False,
                    enable_secrets=False, enable_dependency_hallucinations=False,
                    custom_rules_data=[], trace_file=False, all_advice=True,
                    project_config_overrides={'ignore': [], 'exclude': []})
            report = json.loads(raw) if isinstance(raw, str) else raw
            raw_path = args.output / (target['id'] + '.json')
            with raw_path.open('x') as handle:
                json.dump(report, handle, indent=2)
                handle.write('\n')
            row.update(raw_report=raw_path.name, raw_sha256=digest(raw_path))
            _, _, _, after = verify_checkout(target, checkout_root)
            if after != snapshot:
                raise ValueError('checkout changed during scan')
            issues = analysis_issues(report, scanner='skylos')
            row.update(analysis_issues=issues, analysis_summary=report.get('analysis_summary'),
                       outcomes=[evaluate_fact(f, report, checkout, issues) for f in target['facts']])
        except Exception as error:
            row.update(error=str(error), outcomes=[evaluate_fact(f, {}, checkout, [str(error)]) for f in target['facts']])
        row['elapsed_seconds'] = round(time.monotonic() - start, 3)
        summary['targets'].append(row)
        print(target['id'], dict(Counter(o['outcome'] for o in row['outcomes'])), flush=True)
    load_frozen(args.freeze)
    if digest(args.freeze) != summary['freeze_sha256']:
        raise ValueError('freeze changed during run')
    totals = Counter(o['outcome'] for r in summary['targets'] for o in r['outcomes'])
    summary['counts'] = {k: totals[k] for k in ('true_positive', 'false_positive', 'false_negative', 'true_negative')}
    summary['unscored_counts'] = dict(Counter(o.get('unscored_reason', o['outcome']) for r in summary['targets'] for o in r['outcomes'] if o['outcome'] in {'unscored', 'incomplete'}))
    with (args.output / 'summary.json').open('x') as handle:
        json.dump(summary, handle, indent=2)
        handle.write('\n')
    return int(bool(totals['false_positive'] or totals['false_negative'] or totals['incomplete']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('freeze', 'checkout-root', 'analyzer-root', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    return execute(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
