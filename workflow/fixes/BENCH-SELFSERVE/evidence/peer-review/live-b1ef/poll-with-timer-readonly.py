import json,pathlib,datetime,hashlib,subprocess
r=pathlib.Path('/home/hami/phorvex-benchmark/stage-data/mathlab');status=r/'reconcile-status.json';pin=r/'stage.json';s=json.loads(status.read_text());p=json.loads(pin.read_text());result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':s.get('status'),'phase':s.get('phase'),'started_at':s.get('started_at'),'finished_at':s.get('finished_at'),'baseline_ticks':s.get('baseline_ticks'),'reasons':s.get('reasons'),'status_sha256':hashlib.sha256(status.read_bytes()).hexdigest(),'pin_sha256':hashlib.sha256(pin.read_bytes()).hexdigest(),'pin_source':p['brain']['git_sha'],'pin_image_digest':p['brain']['image_digest']}
for name in ['phorvex-stage-reconcile.timer','phorvex-stage-reconcile.service']:
 raw=subprocess.run(['systemctl','--user','show',name,'--property=ActiveState,SubState,Result,ExecMainStatus,NextElapseUSecRealtime,NextElapseUSecMonotonic,LastTriggerUSec'],capture_output=True,text=True,check=True,timeout=10).stdout
 result[name]=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
print(json.dumps(result))
