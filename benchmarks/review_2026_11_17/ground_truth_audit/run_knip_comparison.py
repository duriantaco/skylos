"""Restricted static Knip run: JSON config disables config-loading plugins.
No target source, target configs, package scripts, or tests are executed.
Raw diagnostics and capability exclusions preserved; selected labels open-set.
"""
from pathlib import Path
import json,subprocess,time,re,concurrent.futures,sys
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[2]
NODE=Path('/Users/oha/.nvm/versions/node/v26.13.1/bin/node')
KNIP=Path('/tmp/skylos-knip-tools/node_modules/knip/bin/knip.js')
SCHEMA=KNIP.parents[1]/'schema.json'
PROFILE={k:False for k in json.loads(SCHEMA.read_text())['definitions']['plugins']['properties'] if k not in {'node-test-runner','tanstack-start'}}
DEFAULT_PLUGINS='--default-plugins' in sys.argv
if DEFAULT_PLUGINS:PROFILE={}
PROFILE_PATH=BASE/('knip_default_plugins.json' if DEFAULT_PLUGINS else 'knip_restricted_static.json')
PROFILE_PATH.write_text(json.dumps(PROFILE,indent=2)+'\n')
MANIFEST=ROOT/'benchmarks/dead_code/manifest.json'
rawdir=BASE/('knip_existing_default' if DEFAULT_PLUGINS else 'knip_existing');rawdir.mkdir(exist_ok=True)

def run(c):
 target=(MANIFEST.parent/c['path']).resolve()
 cmd=[str(NODE),str(KNIP),'--directory',str(target),'--config',str(PROFILE_PATH),'--reporter','json','--include','files,exports,types,enumMembers,namespaceMembers','--no-progress','--no-config-hints']
 start=time.monotonic()
 try:r=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
 except Exception as e:return {'id':c['id'],'error':str(e)}
 (rawdir/(c['id']+'.stdout.json')).write_text(r.stdout)
 (rawdir/(c['id']+'.stderr.txt')).write_text(r.stderr)
 receipt={'id':c['id'],'command':cmd,'exit_code':r.returncode,'seconds':time.monotonic()-start,'labels':[],'totals':dict(TP=0,FP=0,FN=0,TN=0,unsupported=0)}
 try:data=json.loads(r.stdout)
 except Exception:receipt['error']='non-JSON output';return receipt
 warnings=[]
 for issue in data.get('issues',[]):
  f=issue['file']
  if issue.get('files'):warnings.append((f,None))
  for typ in ('exports','types','enumMembers','namespaceMembers'):
   for item in issue.get(typ,[]):warnings.append((f,item['name']))
 for expect in ('used','unused'):
  for x in c['expect'].get(expect,[]):
   f=x['file'];sym=x.get('symbol','');kind=x.get('kind');source=(target/f).read_text() if (target/f).is_file() else ''
   # Knip scopes files and exported symbols; it does not flag local bindings/imports.
   eligible=kind=='file' or (kind!='import' and bool(re.search(r'\bexport\s+(?:default\s+)?(?:(?:async|abstract|declare)\s+)?(?:function|class|const|let|var|enum|interface|type)\s+'+re.escape(sym)+r'\b',source)))
   detected=(f,None) in warnings or (f,sym) in warnings
   if not eligible:outcome='unsupported'
   elif expect=='unused':outcome='TP' if detected else 'FN'
   else:outcome='FP' if detected else 'TN'
   receipt['totals'][outcome]+=1
   receipt['labels'].append({**x,'expected':expect,'capability_eligible':eligible,'detected':detected,'outcome':outcome})
 receipt['raw_issue_count']=len(warnings)
 return receipt
if __name__=='__main__':
 cases=[c for c in json.loads(MANIFEST.read_text())['cases'] if set(c.get('languages',[]))&{'typescript','javascript'}]
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(run,cases))
 total={k:sum(r.get('totals',{}).get(k,0) for r in rows) for k in ('TP','FP','FN','TN','unsupported')}
 report={'tool':'Knip','version':subprocess.check_output([str(NODE),str(KNIP),'--version'],text=True).strip(),'profile':'Restricted static: all config-loading framework plugins disabled; default file/entry graph and export analysis retained. Does not execute target configs. This understates framework-aware normal Knip capabilities and must not support an unrestricted-tool winner claim.','matching':'Files plus directly exported declarations only. Local bindings/imports/non-exported methods are unsupported. File warning matches eligible declarations within that file. Unlabelled raw diagnostics are unadjudicated, never automatically false positives.','manifest':str(MANIFEST),'cases':rows,'totals':total,'errors':[r['id'] for r in rows if r.get('error')]}
 report['profile']=('Normal Knip plugin defaults on trusted authored corpus; external empty JSON avoids loading target Knip configuration. Tool configs inspected for non-destructive behavior before run.' if DEFAULT_PLUGINS else report['profile'])
 (BASE/('KNIP_EXISTING_DEFAULT_COMPARISON.json' if DEFAULT_PLUGINS else 'KNIP_EXISTING_COMPARISON.json')).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'totals':total,'errors':report['errors'],'version':report['version']}))
