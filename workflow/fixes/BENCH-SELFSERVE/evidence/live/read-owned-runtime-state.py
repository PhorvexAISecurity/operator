import json,pathlib,subprocess,datetime,shutil
r=pathlib.Path('/home/hami/phorvex-benchmark');m=r/'stage-data/mathlab'
def read(p):return json.loads(p.read_text()) if p.exists() else {}
rec=read(m/'reconcile-status.json');obs=read(m/'observer-current.json');pin=read(m/'stage.json');end=read(m/'endpoint-refresh/phorvex-staging-demo/stage-bench-defense.status.json')
units={}
for n in ['phorvex-benchmark-bot.service','phorvex-stage-reconcile.service','phorvex-stage-reconcile.timer','phorvex-stage-observer.service','phorvex-stage-endpoint-refresh.service','phorvex-stage-endpoint-refresh.timer']:
 p=subprocess.run(['systemctl','--user','show',n,'--property=ActiveState,SubState,MainPID,Result,ExecMainStatus'],capture_output=True,text=True,check=True,timeout=15);units[n]=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'free_bytes':shutil.disk_usage(r).free,'pin_source':pin.get('brain',{}).get('git_sha'),'reconcile':{k:rec.get(k) for k in ['status','phase','started_at','finished_at','elapsed_seconds','baseline_ticks','reasons']},'observer':{k:obs.get(k) for k in ['state','at','reason','owned_pid','journal']},'observer_source':obs.get('descriptor',{}).get('scope',{}).get('source_revision'),'endpoint':{k:end.get(k) for k in ['state','phase','reason','started_at','finished_at']},'units':units}))
