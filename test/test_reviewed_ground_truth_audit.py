"""Independent audit controls; synthetic JSON and mock reports, never target scans."""
import json

import pytest

from test.test_reviewed_ground_truth_runner import fact, fixture_seal, runner


def _rewrite_manifest(tmp_path, freeze, mutate):
    path = tmp_path / 'manifest.json'
    manifest = json.loads(path.read_text())
    mutate(manifest['targets'][0])
    path.write_text(json.dumps(manifest))
    seal = json.loads(freeze.read_text())
    seal['manifest']['sha256'] = runner.digest(path)
    freeze.write_text(json.dumps(seal))


def test_review_cannot_be_reused_for_unreviewed_revision(tmp_path):
    freeze = fixture_seal(tmp_path)
    _rewrite_manifest(tmp_path, freeze, lambda target: target.update(ref='c' * 40))
    with pytest.raises(ValueError):
        runner.load_frozen(freeze)


def test_review_cannot_be_reused_for_changed_source_bytes(tmp_path):
    freeze = fixture_seal(tmp_path)

    def change_source(target):
        target['source_files'][0]['sha256'] = 'c' * 64
        target['facts'][0]['source_evidence'][0]['sha256'] = 'c' * 64

    _rewrite_manifest(tmp_path, freeze, change_source)
    with pytest.raises(ValueError):
        runner.load_frozen(freeze)


def test_explicitly_reviewed_matching_span_is_accepted(tmp_path):
    freeze = fixture_seal(tmp_path)
    path = tmp_path / 'review.json'
    review = json.loads(path.read_text())
    review['verdicts'][0]['recommended_match_span'] = {'start_line': 10, 'end_line': 12}
    path.write_text(json.dumps(review))
    seal = json.loads(freeze.read_text())
    seal['review_artifacts'][0]['sha256'] = runner.digest(path)
    freeze.write_text(json.dumps(seal))
    _rewrite_manifest(tmp_path, freeze, lambda target: target['facts'][0].update(start_line=10, end_line=12))
    assert runner.load_frozen(freeze)[1]['targets'][0]['facts'][0]['end_line'] == 12


def test_safe_security_cannot_earn_absence_credit_from_other_file(tmp_path):
    label = fact(category='security', truth='safe', rule_id='SKY-D226')
    report = {'analysis_summary': {'total_files': 1},
              'definitions': {'other': {'file': 'other.ts', 'line': 1, 'name': 'other'}}}
    outcome = runner.evaluate_fact(label, report, tmp_path)
    assert outcome['outcome'] == 'unscored'
    assert outcome['unscored_reason'] == 'missing_extraction'


def test_review_not_applicable_cannot_be_promoted_to_scored_safe(tmp_path):
    label = fact(category='security', truth='safe', rule_id='SKY-D212',
                 score_eligible=False, unscored_reason='method-name control only')
    freeze = fixture_seal(tmp_path, label, mutate_review=lambda review: review['verdicts'][0].update(scoring_eligibility='not_applicable'))
    _rewrite_manifest(tmp_path, freeze, lambda target: target['facts'][0].update(score_eligible=True))
    with pytest.raises(ValueError):
        runner.load_frozen(freeze)


def test_reviewed_positive_cannot_be_silently_removed_from_score(tmp_path):
    label = fact(truth='unused')
    freeze = fixture_seal(tmp_path, label, mutate_review=lambda review: review['verdicts'][0].update(scoring_eligibility={'eligible': True, 'reason': 'source-proven unused'}))
    _rewrite_manifest(tmp_path, freeze, lambda target: target['facts'][0].update(score_eligible=False, unscored_reason='arbitrary exclusion'))
    with pytest.raises(ValueError):
        runner.load_frozen(freeze)


def test_simple_method_name_requires_reviewed_owner(tmp_path):
    label = fact(truth='unused', symbol='work', owner_class='Service')
    report = {'unused_functions': [dict(file=label['file'], line=10, full_name='Other.work', simple_name='work')]}
    assert runner.evaluate_fact(label, report, tmp_path)['outcome'] == 'false_negative'


def test_reviewer_only_consumer_evidence_must_match_source_bytes(tmp_path):
    freeze = fixture_seal(tmp_path, mutate_review=lambda review: review['verdicts'][0].update(
        source_evidence=[{'file': 'tests/consumer.py', 'sha256': 'd' * 64}]))
    _rewrite_manifest(tmp_path, freeze, lambda target: target['source_files'].append(
        {'path': 'tests/consumer.py', 'sha256': 'e' * 64}))
    with pytest.raises(ValueError):
        runner.load_frozen(freeze)
