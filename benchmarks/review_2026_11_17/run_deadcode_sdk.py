"""Repeat frozen deterministic suites with explicit SDK; never execute fixtures."""
import argparse,datetime,hashlib,json,os,pathlib,sys
parser=argparse.ArgumentParser();parser.add_argument('--arm',choices=['before','after'],required=True);a=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[2];review=root/'benchmarks/review_2026_11_17';saved=pathlib.Path('/Users/oha/Desktop/skylos-benchmark-2026-11-14/review_2026_11_17');engine=saved/('analyzer_'+a.arm);binary=saved/'tools/skylos-go'
os.environ.update(SKYLOS_GO_BIN=str(binary),GOROOT='/tmp/skylos-gap-go/go',GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',SKYLOS_JOBS='1',SKYLOS_CUSTOM_RULES='[]',DO_NOT_TRACK='1')
sys.path.insert(0,str(engine))
import skylos
from skylos.benchmarks.dead_code import run_manifest
assert pathlib.Path(skylos.__file__).resolve().is_relative_to(engine.resolve())
def h(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
receipt={'arm':a.arm,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'analyzer_root':str(engine),'analyzer_python_hashes':{str(p.relative_to(engine)):h(p) for p in sorted((engine/'skylos').rglob('*.py'))},'environment':{k:os.environ[k] for k in ['SKYLOS_GO_BIN','GOROOT','GOTOOLCHAIN','GOPROXY','GOSUMDB','SKYLOS_JOBS','SKYLOS_CUSTOM_RULES']},'go_binary_sha256':h(binary),'sdk_version':pathlib.Path('/tmp/skylos-gap-go/go/VERSION').read_text(),'method':'Environment restoration arm, not detector improvement; original frozen labels and saved outputs unchanged. Static analysis only.','suites':[]}
for suite,name in [('default','manifest.json'),('challenge','adversarial_manifest.json')]:
 target=review/f'deadcode-sdk-{suite}-{a.arm}.json';rawdir=review/f'deadcode-sdk-{suite}-{a.arm}-raw'
 if target.exists() or rawdir.exists():raise FileExistsError('refuse overwrite '+str(target))
 rawdir.mkdir()
 def capture(case_id,report):
  with (rawdir/(case_id+'.json')).open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 manifest=root/'benchmarks/dead_code'/name
 result=run_manifest(manifest,strict_labels=True,capture_result=capture)
 with target.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 receipt['suites'].append({'suite':suite,'manifest_sha256':h(manifest),'report':target.name,'report_sha256':h(target),'raw_sha256':{p.name:h(p) for p in sorted(rawdir.glob('*.json'))},'case_count':result['case_count'],'failure_count':result['failure_count'],'counts':result.get('counts')})
 print(a.arm,suite,result['case_count'],result['failure_count'],flush=True)
with (review/f'deadcode-sdk-{a.arm}-provenance.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
