import json,os,sys,time,subprocess,hashlib
from pathlib import Path
sys.path.insert(0,'/Users/oha/skylos')
base=Path('/Users/oha/skylos/benchmarks/review_2026_11_17/ground_truth_audit');root=Path('/Users/oha/Desktop/skylos-benchmark-2026-11-14/review_2026_11_17/fresh_checkouts/goji--goji');out=base/'goji_raw';out.mkdir(exist_ok=True)
engine='/Users/oha/Desktop/skylos-benchmark-2026-11-14/review_2026_11_17/tools/skylos-go';os.environ['SKYLOS_GO_BIN']=engine
from skylos.analyzer import analyze
start=time.monotonic()
raw=analyze(str(root),conf=60,enable_danger=True,grep_verify=True,grep_cache=False,enable_sca=False,enable_ai_defects=False,enable_quality=False,enable_secrets=False,enable_dependency_hallucinations=False,custom_rules_data=[],trace_file=False,all_advice=True,project_config_overrides={'ignore':[],'exclude':[]})
report=json.loads(raw) if isinstance(raw,str) else raw
(out/'skylos.json').write_text(json.dumps(report,indent=2)+'\n')
meta={'skylos':{'seconds':time.monotonic()-start,'go_binary':engine,'go_binary_sha256':hashlib.sha256(Path(engine).read_bytes()).hexdigest()},'tools':{},'target_execution':False}
workspace=Path('/tmp/skylos-goji-source-workspace');(workspace/'src').mkdir(parents=True,exist_ok=True);link=workspace/'src/goji.io'
if not link.exists():link.symlink_to(root,target_is_directory=True)
env=os.environ.copy();env.update(PATH='/tmp/skylos-gap-go/go/bin:'+env.get('PATH',''),GOPATH=str(workspace),GO111MODULE='off',GOWORK='off',CGO_ENABLED='0',GOTOOLCHAIN='local')
commands={
 'staticcheck_default':['/tmp/skylos-source-review-tools/staticcheck','-checks=U1000','-f','json','-tests=false','./...'],
 'staticcheck_tests':['/tmp/skylos-source-review-tools/staticcheck','-checks=U1000','-f','json','-tests=true','./...'],
 'staticcheck_simple_tests':['/tmp/skylos-source-review-tools/staticcheck','-checks=U1000','-f','json','-tests=true','-tags=goji_router_simple','./...'],
 'gosec_default':['/tmp/skylos-source-review-tools/gosec','-fmt=json','./...'],
 'gosec_tests':['/tmp/skylos-source-review-tools/gosec','-fmt=json','-tests','./...'],
 'gosec_simple_tests':['/tmp/skylos-source-review-tools/gosec','-fmt=json','-tests','-tags=goji_router_simple','./...']}
for name,args in commands.items():
 start=time.monotonic()
 try:
  p=subprocess.run(args,cwd=link,env=env,capture_output=True,text=True,timeout=180)
  (out/(name+'.stdout')).write_text(p.stdout);(out/(name+'.stderr')).write_text(p.stderr)
  meta['tools'][name]={'command':args,'cwd':str(link),'returncode':p.returncode,'seconds':time.monotonic()-start,'stdout_bytes':len(p.stdout),'stderr_bytes':len(p.stderr)}
 except subprocess.TimeoutExpired as e:
  (out/(name+'.stdout')).write_bytes(e.stdout or b'');(out/(name+'.stderr')).write_bytes(e.stderr or b'');meta['tools'][name]={'command':args,'error':'timeout','seconds':time.monotonic()-start}
 print(name,meta['tools'][name],flush=True)
(out/'run_metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
