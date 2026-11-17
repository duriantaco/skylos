"""Source-only Go development remeasurement; never executes the target."""
import json,os,subprocess,sys,hashlib,tempfile,shutil
from pathlib import Path
repo=Path('/Users/oha/skylos');out=Path(__file__).parent/'final';out.mkdir(exist_ok=True);base=Path(__file__).parent.parents[1];labels=json.loads((base/'SOURCE_LABELS_GOJI.json').read_text());goji=Path(labels['repository']['checkout'])
targets={'goji':goji};targets.update({c['id']:(repo/'benchmarks/security'/c['path']).resolve() for c in json.loads((repo/'benchmarks/security/adversarial_manifest.json').read_text())['cases'] if c['id'].startswith('go-')})
fixture_copy=Path(tempfile.mkdtemp(prefix='skylos-go-review-static-'));original_targets=dict(targets)
for name,path in list(targets.items()):
 if name!='goji':
  shutil.copytree(path,fixture_copy/name);targets[name]=fixture_copy/name
env=os.environ.copy();env.update(GOROOT='/tmp/skylos-gap-go/go',PATH='/tmp/skylos-gap-go/go/bin:'+env['PATH'],GOWORK='',GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0',SKYLOS_CUSTOM_RULES='[]',SKYLOS_JOBS='1')
code='import sys,json;sys.path.insert(0,sys.argv[1]);from skylos.analyzer import analyze;print(analyze(sys.argv[2],conf=60,enable_danger=True,grep_verify=True,grep_cache=False,enable_dependency_hallucinations=False,enable_secrets=False,enable_quality=False,enable_ai_defects=False,enable_sca=False,custom_rules_data=[],project_config_overrides={"ignore":[],"exclude":[]}))'
result={}
for arm,source,binary in [('before','/Users/oha/Desktop/skylos-benchmark-2026-11-14/review_2026_11_17/analyzer_after','/tmp/skylos-review-20261117-go'),('after',str(repo),'/tmp/skylos-review-fixes-20261117-go')]:
 env['SKYLOS_GO_BIN']=binary;result[arm]={'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),'cases':{}}
 for id,root in targets.items():
  p=subprocess.run([sys.executable,'-c',code,source,str(root)],env=env,cwd=repo,capture_output=True,text=True,timeout=120);(out/f'{id}-{arm}.json').write_text(p.stdout);(out/f'{id}-{arm}.stderr').write_text(p.stderr);d=json.loads(p.stdout);defs=list(d['definitions'].values());unused=[f for k,v in d.items() if k.startswith('unused_') and isinstance(v,list) for f in v]
  row={'exit_code':p.returncode,'analysis_errors':d.get('analysis_errors',[]),'unused_functions':[(f['full_name'],f['line']) for f in d.get('unused_functions',[])],'danger':[(f['rule_id'],f['line']) for f in d.get('danger',[])]}
  if id=='goji':
   row['label_outcomes']=[]
   for r in labels['rows']:
    if r['category']!='dead_code':continue
    parsed=any(x['file']==str(root/r['file']) and x['line']==r['line'] for x in defs);matched=any(x['file']==str(root/r['file']) and x['line']==r['line'] for x in unused)
    row['label_outcomes'].append({'id':r['id'],'truth':r['truth'],'parsed':parsed,'reported':matched,'outcome':('false_positive' if matched else 'retained_control' if parsed else 'incomplete') if r['truth']=='used' else 'true_positive' if matched else 'missed_or_out_of_scope'})
  result[arm]['cases'][id]=row;print(arm,id,row['unused_functions'],row['danger'],flush=True)
result.update(source_hashes_unchanged=all(hashlib.sha256((goji/f['file']).read_bytes()).hexdigest()==f['sha256'] for f in labels['files']),context='Development remeasurement after source review; same host SDK both arms; no target execution; not new blind evidence.')
(out/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
