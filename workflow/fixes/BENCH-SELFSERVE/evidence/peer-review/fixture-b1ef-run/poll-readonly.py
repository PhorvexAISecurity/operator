import datetime,hashlib,json,pathlib,subprocess
path=pathlib.Path('/home/hami/phorvex-benchmark/stage-data/live/selfserve-bot-fixture-225877a8ecb4-b1ef-r5/acceptance-status.json')
out={'at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
if path.is_file():
    raw=path.read_bytes();out['receipt_sha256']=hashlib.sha256(raw).hexdigest()
    try:
        value=json.loads(raw)
        out['receipt']={k:value.get(k) for k in ('source','phase','state','job_outcome','restoration','finished_at','error','restoration_errors')}
        out['jobs']=[{'request':j.get('request'),'batch_id':j.get('id'),'state':j.get('state'),'children':[{'id':r.get('job'),'state':r.get('state')} for r in (j.get('batch') or {}).get('results',[])]} for j in value.get('jobs',[])]
    except json.JSONDecodeError:out['status']='TRANSIENT_STATUS_WRITE'
else:out['status']='STATUS_NOT_YET_WRITTEN'
for name in ('phorvex-selfserve-acceptance-fixture-225877a8ecb4-b1ef-r5','phorvex-stage-observer.service','phorvex-benchmark-bot.service','phorvex-stage-endpoint-refresh.timer','phorvex-stage-reconcile.timer'):
    p=subprocess.run(['systemctl','--user','show',name,'--property=MainPID,ActiveState,SubState,Result,ExecMainStatus'],capture_output=True,text=True,timeout=10,check=True)
    out[name]=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
print(json.dumps(out,indent=2))
