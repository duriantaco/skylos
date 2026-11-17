"""Static fixture-only diagnostic. Never run target Go/Python code or tests."""
from datetime import datetime, timezone
import hashlib,json,os,pathlib,shutil,tempfile
os.environ.update(SKYLOS_GO_BIN='/tmp/skylos-review-20261117-go',SKYLOS_JOBS='1',SKYLOS_CUSTOM_RULES='[]',DO_NOT_TRACK='1')
from skylos.analyzer import analyze
from skylos.engines.go_runner import run_go_engine_for_module
from skylos.visitors.languages.go import clear_go_cache
ROOT=pathlib.Path(__file__).resolve().parents[2]
OUT=pathlib.Path(__file__).with_name('go_loss_layer_diagnostic')
def digest(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,data):
 p=OUT/name;p.write_text(json.dumps(data,indent=2,default=str)+'\n');return {'path':p.name,'sha256':digest(p)}
def compact(report):
 return dict(analysis_summary=report.get('analysis_summary'),analysis_errors=report.get('analysis_errors'),
  unused={k:[{x:r.get(x) for x in ['name','full_name','file','line','confidence','score']} for r in report.get(k,[])] for k in ['unused_functions','unused_variables']},
  definitions=report.get('definitions'))
def main():
 OUT.mkdir(exist_ok=False)
 receipt=dict(created_at=datetime.now(timezone.utc).isoformat(),method='Static trusted fixture scans/native source parsing only. No target tests/build/code execution; no detector edits.',go_binary={'path':os.environ['SKYLOS_GO_BIN'],'sha256':digest(os.environ['SKYLOS_GO_BIN'])},cases=[])
 with tempfile.TemporaryDirectory(prefix='skylos-go-loss-diagnostic-') as tmp:
  for case in ['go_dead_call_graph','go_private_test_helpers']:
   src=ROOT/'benchmarks/dead_code/fixtures'/case;copy=pathlib.Path(tmp)/case;shutil.copytree(src,copy)
   row={'id':case,'source_hashes':{p.name:digest(p) for p in sorted(src.iterdir()) if p.is_file()},'runs':[]}
   for scope,path in [('in_repo',src),('isolated_copy',copy)]:
    native=run_go_engine_for_module(path)
    native_ref=save(case+'-'+scope+'-native.json',native)
    row['runs'].append(dict(mode='native',scope=scope,artifact=native_ref,reachability=[{k:d.get(k) for k in ['name','file','line','reachability']} for d in native['symbols']['defs']]))
    for grep in [False,True]:
     clear_go_cache()
     raw=analyze(str(path),conf=60,enable_quality=False,enable_danger=False,enable_secrets=False,grep_verify=grep,grep_cache=False,enable_dependency_hallucinations=False)
     report=json.loads(raw);ref=save(case+'-'+scope+'-grep-'+str(grep).lower()+'.json',report)
     summary=compact(report);summary.pop('definitions',None)
     row['runs'].append(dict(mode='analyzer',scope=scope,grep_verify=grep,artifact=ref,summary=summary))
   receipt['cases'].append(row)
 save('receipt.json',receipt)
 print(json.dumps(receipt,indent=2))
if __name__=='__main__':main()
