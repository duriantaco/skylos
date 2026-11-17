"""Static scans of frozen Python source labels; never imports the target project."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[3]
TOOLS=pathlib.Path('/private/tmp/skylos-python-competitors-20261117/bin')
def main():
    p=argparse.ArgumentParser();p.add_argument('--labels',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);args=p.parse_args()
    labels=json.loads(args.labels.read_text());args.output.mkdir(exist_ok=False)
    result={'labels_sha256':hashlib.sha256(args.labels.read_bytes()).hexdigest(),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target_execution':False,'scans':[]}
    for repo in labels['repositories']:
        checkout=pathlib.Path(repo['checkout'])
        revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip();assert revision==repo['revision']
        for f in repo['review_coverage']:assert hashlib.sha256((checkout/f['file']).read_bytes()).hexdigest()==f['sha256'],f['file']
        for name,cmd in [
            ('skylos',[sys.executable,'-c','import sys;sys.path.insert(0,sys.argv[1]);from skylos.analyzer import analyze;print(analyze(sys.argv[2],conf=60,enable_danger=True,enable_quality=False,enable_secrets=False,enable_dependency_hallucinations=False,enable_ai_defects=False,enable_sca=False,trace_file=False,grep_cache=False))',str(ROOT),str(checkout)]),
            ('vulture',[str(TOOLS/'vulture'),'.','--min-confidence','60']),
            ('ruff',[str(TOOLS/'ruff'),'check','.','--select','F401,F841','--output-format','json','--isolated','--no-fix']),
            ('bandit',[str(TOOLS/'bandit'),'-r','.','-f','json','-q']),
        ]:
            started=time.monotonic();proc=subprocess.run(cmd,cwd=checkout,capture_output=True,text=True,timeout=180,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
            stem=f"{repo['id']}-{name}";(args.output/(stem+'.stdout')).write_text(proc.stdout);(args.output/(stem+'.stderr')).write_text(proc.stderr)
            result['scans'].append({'repository':repo['id'],'revision':revision,'scanner':name,'command':cmd,'cwd':str(checkout),'returncode':proc.returncode,'seconds':round(time.monotonic()-started,4),'stdout_sha256':hashlib.sha256(proc.stdout.encode()).hexdigest(),'stderr_sha256':hashlib.sha256(proc.stderr.encode()).hexdigest()})
            print(repo['id'],name,proc.returncode,flush=True)
        assert not subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=checkout,text=True).strip()
    (args.output/'receipts.json').write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
