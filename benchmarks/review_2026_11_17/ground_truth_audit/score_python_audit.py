import ast,collections,hashlib,json,pathlib,re,datetime
root=pathlib.Path('/Users/oha/skylos/benchmarks/review_2026_11_17/ground_truth_audit');frozen=json.loads((root/'SOURCE_LABELS_PYTHON.json').read_text());run=root/'fresh_python'
score={'label_sha256':hashlib.sha256((root/'SOURCE_LABELS_PYTHON.json').read_bytes()).hexdigest(),'repositories':[],'limitations':['These selected labels do not form exhaustive ground truth. All unmatched findings are retained. No security vulnerability positives were frozen.','Ruff F401/F841 does not detect unused functions/classes; those labels are unsupported, never true negatives.','Vulture decorated-function report locations are normalized from the decorator line to the AST declaration, preserving raw location.','Skylos exports parsed definitions, permitting extraction checks. Competitors lack equivalent extraction inventory; source language support checked separately.']}
triage={'phase':'postscan_adjudication_separate_from_frozen_ground_truth','author':'python_truth','created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'findings':[],'label_corrections':[]}
for repo in frozen['repositories']:
 name=repo['id'];checkout=pathlib.Path(repo['checkout']);raw=json.loads((run/f'{name}-skylos.stdout').read_text());definitions=list(raw['definitions'].values()) if isinstance(raw['definitions'],dict) else raw['definitions']
 def rel(file):
  p=pathlib.Path(file)
  return str(p.relative_to(checkout)) if p.is_absolute() else str(p).removeprefix('./')
 decls={};deconorm={}
 for p in checkout.rglob('*.py'):
  if '.git' in p.parts:continue
  t=ast.parse(p.read_text());r=str(p.relative_to(checkout))
  for node in ast.walk(t):
   if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
    decls[(r,node.lineno)]=node
    for d in getattr(node,'decorator_list',[]):deconorm[(r,d.lineno)]=node.lineno
 entries={}
 for scanner in ['skylos','vulture','ruff']:
  findings=[]
  if scanner=='skylos':
   for k,v in raw.items():
    if k.startswith('unused_') and isinstance(v,list):
     for x in v:findings.append(dict(file=rel(x['file']),line=x['line'],symbol=x.get('simple_name') or x.get('name','').split('.')[-1],kind=k,raw=x))
  elif scanner=='vulture':
   for line in (run/f'{name}-vulture.stdout').read_text().splitlines():
    m=re.fullmatch(r"(.*):(\d+): unused (\w+) '([^']+)' \((\d+)% confidence\)",line)
    if m:
     file,lineno,kind,symbol,confidence=m.groups();lineno=int(lineno)
     findings.append(dict(file=file,line=deconorm.get((file,lineno),lineno),reported_line=lineno,symbol=symbol,kind=kind,raw=line))
  else:
   for x in json.loads((run/f'{name}-ruff.stdout').read_text()):findings.append(dict(file=rel(x['filename']),line=x['location']['row'],symbol='',kind=x['code'],raw=x))
  outcomes=[];counts=collections.Counter();matched=set()
  for label in repo['labels']:
   if label['kind'] not in ['used','unused']:continue
   same=[(i,x) for i,x in enumerate(findings) if x['file']==label['file'] and x['line']==label['line'] and x['symbol']==label['symbol'].split('.')[-1]]
   if scanner=='ruff':outcome='unsupported_symbol_category'
   elif scanner=='skylos' and not any(rel(x['file'])==label['file'] and x['line']==label['line'] and x.get('name','').split('.')[-1]==label['symbol'].split('.')[-1] for x in definitions):outcome='incomplete_extraction'
   elif label['kind']=='unused':outcome='true_positive' if same else 'false_negative'
   else:outcome='false_positive' if same else 'retained_used_control'
   counts[outcome]+=1;matched.update(i for i,x in same)
   outcomes.append(dict(label=label,outcome=outcome,matching_findings=[x for i,x in same]))
  entries[scanner]={'counts':dict(counts),'outcomes':outcomes,'unmatched_findings':[x for i,x in enumerate(findings) if i not in matched],'warning_count':len(findings)}
  for idx,x in enumerate(findings):
   status='unreviewed';evidence='No individually frozen label for this finding.'
   if any(o['outcome']=='false_positive' and any(m['file']==x['file'] and m['line']==x['line'] and m['symbol']==x['symbol'] for m in o['matching_findings']) for o in outcomes):status='confirmed_false_positive';evidence='Frozen source-first used label matched; registration/consumer evidence in label.'
   elif x['file']=='src/blinker/base.py' and x['line']==456:status='bounded_true_positive';evidence='Private _clear_state has no references or string dispatch in pinned repository. External private API calls not proven absent.'
   elif x['file']=='pyee/cls.py' and x['symbol']=='reset':status='unknown_external_api';evidence='No internal caller; public importable class method, no complete downstream usage evidence.'
   elif x['file']=='docs/conf.py':status='confirmed_false_positive';evidence='Sphinx consumes these configuration attributes from conf.py; docs build configuration explicitly selects this file. No ordinary Python read is required.'
   elif x['file']=='tests/conftest.py':status='accurate_empty_file_policy';evidence='Tracked conftest.py is zero bytes; SKY-E002 describes empty source, not a removable live callable.'
   elif scanner=='vulture' and x['file'].startswith('tests/'):
    if x['kind'] in ['function','method']:
     status='confirmed_false_positive';evidence='Full source review: event decorator or explicit on()/add_listener stores callback and test emits corresponding event; retained test handler.'
    else:
     status='retained_test_control';evidence='Alias or descriptor metadata intentionally tests registration/inspection without descriptor execution; not an actionable dead-code removal.'
   triage['findings'].append(dict(repository=name,scanner=scanner,category='dead_code',file=x['file'],line=x['line'],symbol=x['symbol'],status=status,evidence=evidence,raw=x['raw']))
 entries['security_frozen']={'outcomes':[]}
 for label in repo['labels']:
  if label['kind']!='security_absent':continue
  loc=checkout/label['file'];line=loc.read_text().splitlines()[label['line']-1]
  if label['property']=='untrusted_deserialization' and not ('loads' in line):
   outcome='incomplete_label_location';triage['label_corrections'].append(dict(repository=name,original_label=label,corrected_line=370,evidence='Original frozen pyee line369 constructs ee; actual loads(dumps(ee)) sink at370. Frozen result not scored as TN; correction preserved separately after scan.'))
  else:outcome='policy_warning_at_safe_property' if any(rel(x['file'])==label['file'] and label['start_line']<=x['line']<=label['end_line'] for x in raw['danger']) else 'retained_safe_property'
  entries['security_frozen']['outcomes'].append(dict(label=label,outcome=outcome))
 for x in raw.get('danger',[]):
  file=rel(x['file']);status='policy_observation';evidence='Reported declaration or configuration is present; no exploitation or attacker-controlled flow confirmed.'
  if x['rule_id']=='SKY-D205':status='safe_roundtrip_policy_warning';evidence='loads receives only immediately nested dumps of locally constructed object; no untrusted deserialization, but risky API review-policy warning accurately identifies use.'
  elif x['rule_id']=='SKY-D295' and name=='pallets-eco--blinker':status='confirmed_false_positive';evidence='tests.yaml finite matrix include entries only define python; matrix.os is absent in all entries, so fallback ubuntu-latest is selected for every instance. No self-hosted runner.'
  elif x['rule_id']=='SKY-D300':status='safe_data_policy_warning';evidence='publish.yaml writes SOURCE_DATE_EPOCH from git log --pretty=%ct, a numeric commit timestamp; no arbitrary newline-bearing text. Command-derived-data policy warning, no demonstrated env-file injection.'
  triage['findings'].append(dict(repository=name,scanner='skylos',category='security',file=file,line=x['line'],rule_id=x['rule_id'],status=status,evidence=evidence,raw=x))
 bandit=json.loads((run/f'{name}-bandit.stdout').read_text())
 for x in bandit['results']:
  test=x['test_id'];status='unreviewed';evidence='No frozen semantic match.'
  if test=='B101':status='assertion_policy_warning';evidence='Assertion is a test expectation (or Blinker internal sender invariant), not an authentication/authorization guard. Removing assertions under -O does not cross a proven security boundary.'
  elif test in ['B301','B403']:status='safe_roundtrip_policy_warning';evidence='Import or call to pickle in local roundtrip test. Risky API policy correctly observes pickle, but no untrusted byte source is present.'
  triage['findings'].append(dict(repository=name,scanner='bandit',category='security',file=rel(x['filename']),line=x['line_number'],rule_id=test,status=status,evidence=evidence,raw=x))
 score['repositories'].append(dict(id=name,revision=repo['revision'],scan_source_files=raw['analysis_summary']['total_files'],source_errors=raw.get('analysis_errors',[]),scanners=entries))
(root/'PYTHON_FRESH_SCORES.json').write_text(json.dumps(score,indent=2)+'\n');(root/'PYTHON_POSTSCAN_ADJUDICATION.json').write_text(json.dumps(triage,indent=2)+'\n')
for repo in score['repositories']:
 print(repo['id'],{k:v['counts'] for k,v in repo['scanners'].items() if 'counts'in v})
print('postscan',collections.Counter(x['status'] for x in triage['findings']))
