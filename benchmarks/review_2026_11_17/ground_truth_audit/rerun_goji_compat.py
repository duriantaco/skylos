import json,os,time,subprocess
from pathlib import Path
base=Path('/Users/oha/skylos/benchmarks/review_2026_11_17/ground_truth_audit');out=base/'goji_raw'/'compatible_go1.23';out.mkdir(exist_ok=True);env=os.environ.copy();env.update(PATH='/tmp/skylos-goji-compat-go/go/bin:'+env.get('PATH',''),GOROOT='/tmp/skylos-goji-compat-go/go',GOPATH='/tmp/skylos-goji-source-workspace',GO111MODULE='off',GOWORK='off',CGO_ENABLED='0',GOTOOLCHAIN='local')
commands={
 'staticcheck_default':['/tmp/skylos-source-review-tools/staticcheck','-checks=U1000','-f','json','-tests=false','./...'],
 'staticcheck_tests':['/tmp/skylos-source-review-tools/staticcheck','-checks=U1000','-f','json','-tests=true','./...'],
 'staticcheck_simple_tests':['/tmp/skylos-source-review-tools/staticcheck','-checks=U1000','-f','json','-tests=true','-tags=goji_router_simple','./...'],
 'gosec_default':['/tmp/skylos-source-review-tools/gosec','-fmt=json','./...'],
 'gosec_tests':['/tmp/skylos-source-review-tools/gosec','-fmt=json','-tests','./...'],
 'gosec_simple_tests':['/tmp/skylos-source-review-tools/gosec','-fmt=json','-tests','-tags=goji_router_simple','./...']}
meta={'target_execution':False,'environment':{k:env[k] for k in ['PATH','GOROOT','GOPATH','GO111MODULE','GOWORK','CGO_ENABLED','GOTOOLCHAIN']},'tools':{}}
for name,args in commands.items():
 start=time.monotonic()
 try:
  p=subprocess.run(args,cwd='/tmp/skylos-goji-source-workspace/src/goji.io',env=env,capture_output=True,text=True,timeout=180)
  (out/(name+'.stdout')).write_text(p.stdout);(out/(name+'.stderr')).write_text(p.stderr);meta['tools'][name]={'command':args,'returncode':p.returncode,'seconds':time.monotonic()-start,'stdout_bytes':len(p.stdout),'stderr_bytes':len(p.stderr)}
 except subprocess.TimeoutExpired as e:
  (out/(name+'.stdout')).write_bytes(e.stdout or b'');(out/(name+'.stderr')).write_bytes(e.stderr or b'');meta['tools'][name]={'command':args,'error':'timeout','seconds':time.monotonic()-start}
 print(name,meta['tools'][name],flush=True)
 (out/'run_metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
