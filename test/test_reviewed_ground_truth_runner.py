"""Mock-only gates and scoring: never scan a third-party checkout."""
from contextlib import nullcontext
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

PATH = Path(__file__).resolve().parents[1] / 'benchmarks/review_2026_11_17/run_reviewed_ground_truth.py'
spec = importlib.util.spec_from_file_location('reviewed_runner', PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def fact(**changes):
    value = dict(id='fact-one', category='dead_code', truth='used', file='src/app.py',
        line=10, symbol='Service.work', finding_category='unused_functions',
        score_eligible=True, label_author='author', independent_reviewer='reviewer',
        review_resolution=dict(status='resolved', review_artifact='review.json', reason='source checked'),
        source_evidence=[dict(file='src/app.py', sha256='a'*64)])
    value.update(changes)
    return value


def fixture_seal(tmp_path, label=None, mutate_review=None, status='frozen_after_independent_review'):
    label = label or fact()
    original = {k:v for k,v in label.items() if k not in {'label_author','independent_reviewer','review_resolution'}}
    draft = dict(reviewer='author', repo='https://example.com/repo', revision='b'*40, rows=[original])
    (tmp_path/'draft.json').write_text(json.dumps(draft))
    review = dict(reviewer='reviewer', draft_file='draft.json', draft_sha256=runner.digest(tmp_path/'draft.json'),
        verdicts=[dict(id=label['id'], verdict='agree', reviewed_truth=label['truth'])])
    if mutate_review:
        mutate_review(review)
    (tmp_path/'review.json').write_text(json.dumps(review))
    manifest = dict(version=1, scan=dict(conf=60), targets=[dict(id='repo', repo='https://example.com/repo',
        checkout='repo', scan_root='.', ref='b'*40, source_files=[dict(path='src/app.py',sha256='a'*64)], facts=[label])])
    (tmp_path/'manifest.json').write_text(json.dumps(manifest))
    seal = dict(status=status, frozen_at='2026-01-01T00:00:00+00:00',
        manifest=dict(path='manifest.json',sha256=runner.digest(tmp_path/'manifest.json')),
        review_artifacts=[dict(path='review.json',sha256=runner.digest(tmp_path/'review.json'))])
    path=tmp_path/'freeze.json';path.write_text(json.dumps(seal))
    return path


def options(tmp_path, freeze):
    return SimpleNamespace(freeze=freeze, output=tmp_path/'results', checkout_root=tmp_path/'checkouts', analyzer_root=tmp_path/'engine')


@pytest.mark.parametrize('problem', ['missing','draft','same-author','altered-review','empty-review','unresolved','wrong-truth','missing-verdict','wrong-reviewer','changed-draft'])
def test_invalid_review_refuses_before_engine_load(tmp_path, monkeypatch, problem):
    label=fact()
    if problem=='same-author':label['independent_reviewer']='author'
    freeze=fixture_seal(tmp_path,label,status='draft' if problem=='draft' else 'frozen_after_independent_review')
    if problem=='missing':freeze.unlink()
    if problem=='altered-review':(tmp_path/'review.json').write_text('{}')
    if problem=='changed-draft':(tmp_path/'draft.json').write_text('{}')
    if problem in {'empty-review','unresolved','wrong-truth','missing-verdict','wrong-reviewer'}:
        review=json.loads((tmp_path/'review.json').read_text())
        if problem=='empty-review':review={}
        elif problem=='unresolved':review['verdicts'][0]['verdict']='disagree'
        elif problem=='wrong-truth':review['verdicts'][0]['reviewed_truth']='unused'
        elif problem=='missing-verdict':review['verdicts']=[]
        else:review['reviewer']='third-agent'
        (tmp_path/'review.json').write_text(json.dumps(review))
        seal=json.loads(freeze.read_text());seal['review_artifacts'][0]['sha256']=runner.digest(tmp_path/'review.json');freeze.write_text(json.dumps(seal))
    monkeypatch.setattr(runner,'load_engine',lambda _:pytest.fail('engine imported before valid freeze'))
    with pytest.raises((ValueError,FileNotFoundError,KeyError)):
        runner.execute(options(tmp_path,freeze))
    assert not (tmp_path/'results').exists()


def test_valid_review_gate(tmp_path):
    seal,manifest=runner.load_frozen(fixture_seal(tmp_path))
    assert manifest['targets'][0]['facts'][0]['truth']=='used'


@pytest.mark.parametrize('change', ['category', 'omit', 'intentional'])
def test_frozen_manifest_cannot_discard_review_semantics(tmp_path, change):
    label = fact(truth='unused', intentional_keep=change == 'intentional',
                 score_eligible=change != 'intentional', unscored_reason='explicit retention')
    freeze = fixture_seal(tmp_path, label)
    path = tmp_path / 'manifest.json'
    manifest = json.loads(path.read_text())
    final = manifest['targets'][0]['facts'][0]
    if change == 'category':
        final['finding_category'] = 'unused_variables'
    elif change == 'omit':
        review_path = tmp_path / 'review.json'
        review = json.loads(review_path.read_text())
        review['verdicts'].append(dict(id='omitted-positive', verdict='agree', reviewed_truth='unused'))
        review_path.write_text(json.dumps(review))
    else:
        final['score_eligible'] = True
    path.write_text(json.dumps(manifest))
    seal = json.loads(freeze.read_text())
    seal['manifest']['sha256'] = runner.digest(path)
    seal['review_artifacts'][0]['sha256'] = runner.digest(tmp_path / 'review.json')
    freeze.write_text(json.dumps(seal))
    with pytest.raises(ValueError):
        runner.load_frozen(freeze)


def test_safe_security_absence_requires_same_file_extraction(tmp_path):
    label = fact(category='security', truth='safe', rule_id='SKY-D215')
    report = {'definitions': {'d': dict(file=label['file'], line=1, name='handler')}}
    assert runner.evaluate_fact(label, report, tmp_path)['outcome'] == 'true_negative'


def test_semantic_security_fact_without_rule_is_only_unscored(tmp_path):
    label = fact(category='security', truth='safe', rule_id=None,
                 score_eligible=False, unscored_reason='no implemented rule site')
    runner.load_frozen(fixture_seal(tmp_path, label))
    warning = dict(file=label['file'], line=label['line'], rule_id='SKY-D228')
    result = runner.evaluate_fact(label, {'danger': [warning]}, tmp_path)
    assert result['outcome'] == 'unscored'
    assert result['matching_findings'] == [warning]
    label['score_eligible'] = True
    with pytest.raises(ValueError):
        runner.load_frozen(fixture_seal(tmp_path, label))


@pytest.mark.parametrize('change', ['owner', 'category'])
def test_reviewed_owner_and_derived_category_cannot_drift(tmp_path, change):
    label = fact(symbol='work', owner_class='Service')
    freeze = fixture_seal(tmp_path, label, mutate_review=lambda r: r['verdicts'][0].update(
        finding_category='unused_functions', owner_class='Service'))
    path = tmp_path / 'manifest.json'
    manifest = json.loads(path.read_text())
    final = manifest['targets'][0]['facts'][0]
    final['owner_class' if change == 'owner' else 'finding_category'] = 'Other' if change == 'owner' else 'unused_variables'
    path.write_text(json.dumps(manifest))
    seal = json.loads(freeze.read_text())
    seal['manifest']['sha256'] = runner.digest(path)
    freeze.write_text(json.dumps(seal))
    with pytest.raises(ValueError):
        runner.load_frozen(freeze)


def test_simple_method_owner_controls_extraction_and_enclosing_removal(tmp_path):
    label = fact(symbol='work', owner_class='Service')
    wrong = dict(file=label['file'], line=10, full_name='Other.work', simple_name='work')
    assert runner.evaluate_fact(label, {'definitions': {'d': wrong}}, tmp_path)['outcome'] == 'unscored'
    correct = dict(wrong, full_name='package.Service.work')
    assert runner.evaluate_fact(label, {'definitions': {'d': correct}}, tmp_path)['outcome'] == 'true_negative'
    unrelated = dict(file=label['file'], line=1, name='Other')
    assert runner.evaluate_fact(label, {'unused_classes': [unrelated]}, tmp_path)['outcome'] == 'unscored'
    parent = dict(unrelated, name='Service')
    assert runner.evaluate_fact(label, {'unused_classes': [parent]}, tmp_path)['outcome'] == 'false_positive'


@pytest.mark.parametrize('kind', ['unknown','intentional'])
def test_unscored_fact_preserves_matching_warning(kind,tmp_path):
    label=fact(truth='unknown' if kind=='unknown' else 'unused',score_eligible=False,unscored_reason=kind,intentional_keep=kind=='intentional')
    warning=dict(file='src/app.py',line=10,name='Service.work')
    result=runner.evaluate_fact(label,{'unused_functions':[warning]},tmp_path)
    assert result['outcome']=='unscored' and result['matching_findings']==[warning]


def test_missing_extraction_is_not_a_quiet_used_success(tmp_path):
    assert runner.evaluate_fact(fact(),{},tmp_path)['unscored_reason']=='missing_extraction'
    assert runner.evaluate_fact(fact(truth='unused'),{},tmp_path)['outcome']=='false_negative'
    assert runner.evaluate_fact(fact(truth='unused'),{},tmp_path,['parse failed'])['outcome']=='incomplete'


def test_deadcode_wrong_owner_category_file_and_line_do_not_match(tmp_path):
    label=fact(truth='unused')
    report={'unused_functions':[dict(file='other/app.py',line=10,name='Service.work'),dict(file='src/app.py',line=10,name='Other.work'),dict(file='src/app.py',line=11,name='Service.work')],
            'unused_variables':[dict(file='src/app.py',line=10,name='Service.work')]}
    assert runner.evaluate_fact(label,report,tmp_path)['outcome']=='false_negative'
    report['unused_functions'].append(dict(file=str(tmp_path/'src/app.py'),line=10,full_name='pkg.Service.work'))
    assert runner.evaluate_fact(label,report,tmp_path)['outcome']=='true_positive'


@pytest.mark.parametrize('kind',['owner','file'])
def test_used_member_protected_from_broader_removal(tmp_path,kind):
    warning=dict(file='src/app.py',line=1,name='Service')
    report={('unused_classes' if kind=='owner' else 'unused_files'):[warning]}
    assert runner.evaluate_fact(fact(),report,tmp_path)['outcome']=='false_positive'


def test_quiet_used_requires_exact_definition(tmp_path):
    report={'definitions':{'one':dict(file='src/app.py',line=10,name='Other.work')}}
    assert runner.evaluate_fact(fact(),report,tmp_path)['outcome']=='unscored'
    report['definitions']['one']['name']='Service.work'
    assert runner.evaluate_fact(fact(),report,tmp_path)['outcome']=='true_negative'


def test_security_requires_rule_file_and_range_on_same_finding(tmp_path):
    label=fact(category='security',truth='unsafe',rule_id='SKY-D215',start_line=10,end_line=12)
    report={'danger':[dict(file='src/app.py',line=11,rule_id='SKY-D212'),dict(file='other.py',line=11,rule_id='SKY-D215'),dict(file='src/app.py',line=13,rule_id='SKY-D215')]}
    assert runner.evaluate_fact(label,report,tmp_path)['outcome']=='false_negative'
    report['danger'].append(dict(file='src/app.py',line=12,rule_id='SKY-D215'))
    assert runner.evaluate_fact(label,report,tmp_path)['outcome']=='true_positive'
    assert runner.evaluate_fact(dict(label,truth='safe'),report,tmp_path)['outcome']=='false_positive'


def test_mock_run_withholds_labels_and_refuses_overwrite(tmp_path,monkeypatch):
    freeze=fixture_seal(tmp_path);args=options(tmp_path,freeze)
    (args.analyzer_root/'skylos').mkdir(parents=True)
    (args.analyzer_root/'skylos/__init__.py').write_text('# mock analyzer identity\n')
    scanned=[];verified=[]
    def analyze(path,**kwargs):
        scanned.append((path,kwargs))
        assert path==str(args.checkout_root/'repo')
        assert not {'facts','labels','truth','review_resolution'} & kwargs.keys()
        assert 'Service.work' not in json.dumps(kwargs)
        return {'analysis_summary':{'total_files':1},'definitions':{'one':dict(file='src/app.py',line=10,name='Service.work')}}
    def verify(target,root):
        verified.append(target['id']);return root/'repo',root/'repo',{}, {'source':'hash'}
    monkeypatch.setattr(runner,'load_engine',lambda _: (analyze,lambda *a,**k:[],verify,nullcontext))
    assert runner.execute(args)==0
    assert len(scanned)==1 and verified==['repo','repo']
    result=json.loads((args.output/'summary.json').read_text())
    assert result['counts']['true_negative']==1
    assert result['frozen_at'] < result['run_started_at']
    assert result['targets'][0]['raw_sha256']==runner.digest(args.output/'repo.json')
    with pytest.raises(FileExistsError):runner.execute(args)
    assert len(scanned)==1
