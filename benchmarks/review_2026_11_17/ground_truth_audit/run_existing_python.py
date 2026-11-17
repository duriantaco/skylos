import sys,json,pathlib,concurrent.futures,os
sys.path.insert(0,'/Users/oha/skylos')
from skylos.benchmarks import dead_code,security

def main():
    out=pathlib.Path('/Users/oha/skylos/benchmarks/review_2026_11_17/ground_truth_audit') / (sys.argv[3] if len(sys.argv)>3 else 'existing_python')
    out.mkdir(parents=True,exist_ok=True)
    module,scanner=sys.argv[1:3]
    mod={'dead_code':dead_code,'security':security}[module]
    manifest=pathlib.Path('/Users/oha/skylos/benchmarks')/module/'manifest.json'
    cases=mod.validate_manifest(mod.load_manifest(manifest),manifest)
    selected={c['id'] for c in cases if set(mod._case_languages(c))=={'python'}}
    raw={}
    kwargs=dict(scanner=scanner,capture_result=lambda k,v:raw.__setitem__(k,v))
    if module=='dead_code':kwargs['strict_labels']=False
    result=mod.run_manifest(manifest,selected_cases=selected,**kwargs)
    (out/f'{module}-{scanner}-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/f'{module}-{scanner}-raw.json').write_text(json.dumps(raw,indent=2)+'\n')
    print(json.dumps({k:result.get(k) for k in ['scanner','case_count','counts','scores','failure_count','analysis_status']}))

if __name__ == '__main__':
    main()
