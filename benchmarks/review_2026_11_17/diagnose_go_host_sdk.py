"""Static trusted fixtures: explicit host SDK control; no target execution."""
import pathlib,os,json,shutil,tempfile,hashlib
os.environ.update(SKYLOS_GO_BIN='/tmp/skylos-review-20261117-go',SKYLOS_JOBS='1',SKYLOS_CUSTOM_RULES='[]',DO_NOT_TRACK='1')
from skylos.analyzer import analyze
from skylos.engines.go_runner import run_go_engine_for_module
from skylos.visitors.languages.go import clear_go_cache
root=pathlib.Path(__file__).resolve().parents[2];out=root/'benchmarks/review_2026_11_17/go_loss_layer_diagnostic'
if (out/'host-sdk-receipt.json').exists():raise FileExistsError('Refusing to overwrite the diagnostic receipt')
receipt={'host_discovery_before':{'GOROOT':os.environ.get('GOROOT'),'go_on_path':shutil.which('go')},'host_discovery_after':{'GOROOT':'/tmp/skylos-gap-go/go'},'runs':[]}
os.environ['GOROOT']='/tmp/skylos-gap-go/go'
with tempfile.TemporaryDirectory(prefix='skylos-go-host-diagnostic-') as tmp:
 for case in ['go_dead_call_graph','go_private_test_helpers']:
  p=pathlib.Path(tmp)/case;shutil.copytree(root/'benchmarks/dead_code/fixtures'/case,p)
  native=run_go_engine_for_module(p);f=out/(case+'-explicit-host-native.json');f.write_text(json.dumps(native,indent=2)+'\n')
  row={'case':case,'native':[{'name':d['name'],'reachability':d.get('reachability')} for d in native['symbols']['defs']],'native_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'analyzer':[]}
  for grep in [False,True]:
   clear_go_cache();r=json.loads(analyze(str(p),conf=60,enable_quality=False,enable_danger=False,enable_secrets=False,grep_verify=grep,grep_cache=False,enable_dependency_hallucinations=False))
   f=out/(case+'-explicit-host-grep-'+str(grep).lower()+'.json');f.write_text(json.dumps(r,indent=2)+'\n')
   row['analyzer'].append({'grep_verify':grep,'findings':{k:[d['full_name'] for d in r.get(k,[])] for k in ['unused_functions','unused_variables']},'analysis_errors':r.get('analysis_errors'),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
  receipt['runs'].append(row)
(out/'host-sdk-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
