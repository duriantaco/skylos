from pathlib import Path
import json,hashlib,subprocess,sys,time,datetime
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[2];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(BASE.parent))
from run_holdouts import evaluate
from skylos.analyzer import analyze
from skylos.benchmarks._analysis_validation import analysis_issues
from skylos.benchmarks.security_holdouts import _isolated_environment
NODE='/Users/oha/.nvm/versions/node/v26.13.1/bin/node'
KNIP='/tmp/skylos-knip-tools/node_modules/knip/bin/knip.js'
def main():
    SOURCE=BASE/'SOURCE_LABELS_TYPESCRIPT_DRAFT.json'
    label_hash=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert label_hash=='98aca5cf07106c98276d48b0575027f1c056dce2836c2545c495bb466ac20cf7'
    labels=json.loads(SOURCE.read_text())
    (BASE/'SOURCE_LABELS_TYPESCRIPT.json').write_bytes(SOURCE.read_bytes())
    receipt={'draft_sha256':label_hash,'reviewer':'/root','review_evidence':'Parent independently read both production source implementations and registration/public export evidence; approved exact frozen draft over agent message before first scanner execution.','frozen_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'limitations':'Security regex control qualified on external dependency API contract; uninstalled dependency not dynamically validated.'}
    (BASE/'TYPESCRIPT_FREEZE_RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n')
    results=[]
    for r in labels['repositories']:
     root=Path(r['root'])
     for f in r['coverage']:assert hashlib.sha256((root/f['file']).read_bytes()).hexdigest()==f['sha256']
     target=dict(r)
     start=time.monotonic()
     with _isolated_environment():
      raw=analyze(str(root),conf=60,enable_danger=True,enable_sca=False,enable_ai_defects=False,enable_quality=False,enable_secrets=False,enable_dependency_hallucinations=False,custom_rules_data=[],trace_file=False,all_advice=True,grep_verify=True,grep_cache=False,project_config_overrides={'ignore':[],'exclude':[]})
     report=json.loads(raw) if isinstance(raw,str) else raw
     (BASE/(r['id']+'.skylos.json')).write_text(json.dumps(report,indent=2)+'\n')
     issues=analysis_issues(report,scanner='skylos')
     outcomes=evaluate(target,report,root,issues)
     cmd=[NODE,KNIP,'--directory',str(root),'--reporter','json','--include','files,exports,types,enumMembers,namespaceMembers','--no-progress','--no-config-hints']
     proc=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
     (BASE/(r['id']+'.knip.json')).write_text(proc.stdout)
     (BASE/(r['id']+'.knip.stderr.txt')).write_text(proc.stderr)
     warnings=[]
     try:
      data=json.loads(proc.stdout)
      for i in data.get('issues',[]):
       if i.get('files'):warnings.append((i['file'],None))
       for typ in ('exports','types','enumMembers','namespaceMembers'):
        for item in i.get(typ,[]):warnings.append((i['file'],item['name']))
     except Exception:data={'error':'Knip failed to emit JSON'}
     knip_labels=[]
     for l in r['labels']:
      if l['kind']=='security_absent':continue
      # Knip has no local-unused checker; public exports only here, unless whole file flagged.
      eligible=l['id'] in {'regexparam.parse','regexparam.inject','trouter.Trouter'}
      detected=(l['file'],None) in warnings or (l['file'],l['symbol']) in warnings
      knip_labels.append({'id':l['id'],'eligible':eligible,'outcome':'unsupported' if not eligible else 'false_positive' if detected else 'retained_control'})
     results.append({'id':r['id'],'revision':r['revision'],'seconds':time.monotonic()-start,'analysis_issues':issues,'skylos_labels':outcomes,'finding_counts':{k:len(v) for k,v in report.items() if isinstance(v,list) and (k.startswith('unused_') or k=='danger')},'knip':{'command':cmd,'exit_code':proc.returncode,'raw_issue_count':len(warnings),'labels':knip_labels},'security_competitor':'No JS security competitor available in installed environment; not scored.'})
     (BASE/'FRESH_JAVASCRIPT_RESULTS.json').write_text(json.dumps({'label_sha256':label_hash,'matching':'Used labels require exact parsed declarations; missing extraction is incomplete, never TN.','repositories':results},indent=2)+'\n')
     print(r['id'],[(o['label']['id'],o['outcome']) for o in outcomes],flush=True)

if __name__ == "__main__":
    main()
