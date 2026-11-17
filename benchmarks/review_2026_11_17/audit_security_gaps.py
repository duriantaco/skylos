from pathlib import Path
import ast,json,re,collections,hashlib
from skylos.rules.catalog import get_rule_catalog
ROOT=Path(__file__).resolve().parents[2]; OUT=Path(__file__).resolve().parent
CAT={x['id']:x for x in get_rule_catalog() if x['category']=='security'}
from skylos.visitors.languages.go.go import _GO_RULE_REMAP
ALL_IDS=set(CAT)|set(_GO_RULE_REMAP)
LANGS=['python','typescript','javascript','go','java','php','rust','ruby','dart','csharp','cpp','kotlin','swift','shell']
EXT={'.py':'python','.ts':'typescript','.tsx':'typescript','.mts':'typescript','.cts':'typescript','.js':'javascript','.jsx':'javascript','.mjs':'javascript','.cjs':'javascript','.go':'go','.java':'java','.php':'php','.rs':'rust','.rb':'ruby','.dart':'dart','.cs':'csharp','.cpp':'cpp','.cc':'cpp','.cxx':'cpp','.hpp':'cpp','.hh':'cpp','.hxx':'cpp','.kt':'kotlin','.kts':'kotlin','.swift':'swift','.sh':'shell','.bash':'shell','.zsh':'shell','.tf':'terraform','.hcl':'hcl','.sql':'sql','.html':'markup','.htm':'markup','.vue':'markup','.svelte':'markup','.astro':'markup'}
def rel(p):return p.relative_to(ROOT).as_posix()
def ids(p):
 s=p.read_text(errors='replace');out=[]
 if p.suffix=='.py':
  try:
   for n in ast.walk(ast.parse(s)):
    if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value in ALL_IDS:out.append((n.value,n.lineno))
  except SyntaxError: pass
 else:
  for n,line in enumerate(s.splitlines(),1):
   if line.lstrip().startswith('//'):continue
   for r in re.findall(r'"(SKY-[A-Z]+\d+)"',line):
    if r in ALL_IDS:out.append((r,n))
 return out
impl={l:collections.defaultdict(list) for l in LANGS+['terraform','configuration']}
for l in LANGS+['terraform','configuration']:
 if l=='python': paths=list((ROOT/'skylos/rules/danger').rglob('*.py'))
 elif l=='go':paths=[p for p in (ROOT/'skylos/engines/go/internal').rglob('*.go') if not p.name.endswith('_test.go')]
 elif l in ('terraform','configuration'):paths=list((ROOT/('skylos/rules/config/terraform' if l=='terraform' else 'skylos/rules/config')).rglob('*.py'))
 else: paths=list((ROOT/f'skylos/visitors/languages/{"typescript" if l=="javascript" else l}').rglob('*.py'))
 for p in paths:
  for rid,n in ids(p):
   canonical=_GO_RULE_REMAP.get(rid,rid) if l=='go' else rid
   if canonical in CAT: impl[l][canonical].append({'file':rel(p),'line':n,'native_id':rid})
manifest_names=['benchmarks/security/manifest.json','benchmarks/security/adversarial_manifest.json','corpus/manifest.json','benchmarks/review_2026_11_17/security_null_corpus/manifest.json']
cases=[]
for mn in manifest_names:
 p=ROOT/mn;s=p.read_text();man=json.loads(s)
 for c in man['cases']:
  path=(p.parent/c['path']).resolve();files=sorted(path.rglob('*')) if path.is_dir() else [path]
  source=[{'file':rel(f),'language':EXT.get(f.suffix),'lines':len(f.read_text(errors='replace').splitlines())} for f in files if f.is_file() and f.suffix in EXT]
  physical=sorted({x['language'] for x in source});declared=c.get('languages',(['python'] if mn.startswith('benchmarks/security/') else []))
  labels=[]
  for mode,m in c.get('expect',{}).items():
   for cat,items in m.items():
    if cat!='danger':continue
    for e in items:
     r=e.get('rule_id') if isinstance(e,dict) else e
     if r in CAT:labels.append({'mode':mode,'rule_id':r,'location':e if isinstance(e,dict) else None})
  if any(lab['rule_id'] in impl['configuration'] for lab in labels): physical.append('configuration')
  if any(lab['rule_id'] in impl['terraform'] for lab in labels): physical.append('terraform')
  line=s[:s.index('"id": "'+c['id']+'"')].count('\n')+1
  cases.append({'id':c['id'],'manifest':mn,'manifest_line':line,'declared_languages':declared,'physical_languages':physical,'source_files':source,'labels':labels})
# Test references remain lexical evidence only; a rule mention is not a passed paired test.
tests=collections.defaultdict(list)
for p in list((ROOT/'test').rglob('test_*.py'))+list((ROOT/'skylos/engines/go/internal').rglob('*_test.go')):
 for rid,n in ids(p):
  rid=_GO_RULE_REMAP.get(rid,rid) if p.suffix=='.go' else rid
  tests[rid].append({'file':rel(p),'line':n})
rows={}
for l in impl:
 rows[l]={}
 observed={lab['rule_id'] for c in cases if l in set(c['declared_languages']+c['physical_languages']) for lab in c['labels']}
 for rid in sorted(set(impl[l])|observed):
  evid=[]
  for c in cases:
   if l not in set(c['declared_languages']+c['physical_languages']):continue
   for lab in c['labels']:
    if lab['rule_id']==rid:evid.append({**{k:c[k] for k in ('id','manifest','manifest_line','declared_languages','physical_languages')},**lab})
  rows[l][rid]={'name':CAT[rid]['name'],'native_rule_literal_references':impl[l].get(rid,[]),'label_references':evid}
res={'method':'Static literal and expectation inventory, not executed tests or detector completeness proof. Native references may include guard tables; each highlighted detector is manually reviewed. Manifest languages and fixture extensions both retained; mixed-case attribution is not per-finding proof. Unit-test references are search leads, not proof of polarity or execution.','scope':'Direct native language directories; Python danger package; Go internal source; separate Terraform/configuration packages. Shared helpers may add rules not directly referenced in a language directory. Secret/SCA/quality rules excluded.','languages':rows,'cases':cases,'unit_test_literal_references_by_rule':dict(tests)}
cloud_path=ROOT/'benchmarks/cloud/manifest.json'
cloud_text=cloud_path.read_text(); cloud=json.loads(cloud_text)
res['supplemental_cloud_evidence']=[{'id':c['id'],'manifest':'benchmarks/cloud/manifest.json','manifest_line':cloud_text[:cloud_text.index(chr(34)+'id'+chr(34)+': '+chr(34)+c['id']+chr(34))].count(chr(10))+1,'checks':c.get('expect',{}).get('checks',[])} for c in cloud['cases']]
res['input_manifest_sha256']={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in manifest_names+['benchmarks/cloud/manifest.json']}
(OUT/'security_gap_matrix.json').write_text(json.dumps(res,indent=2)+'\n')
for l,rules in rows.items():
 default_cases=[c for c in cases if c['manifest']==manifest_names[0] and l in set(c['declared_languages']+c['physical_languages'])]
 scoped=[c for c in cases if c['manifest'] in (manifest_names[0],manifest_names[2]) and l in set(c['declared_languages']+c['physical_languages'])]
 pol=collections.defaultdict(set)
 for c in scoped:
  for lab in c['labels']:pol[lab['rule_id']].add(lab['mode'])
 missing={r:','.join(sorted({'present','absent'}-pol[r])) for r in impl[l] if pol[r]!={'present','absent'}}
 print(l,'native_refs',len(impl[l]),'default_cases',len(default_cases),'labels',len(pol),'missing',missing)
