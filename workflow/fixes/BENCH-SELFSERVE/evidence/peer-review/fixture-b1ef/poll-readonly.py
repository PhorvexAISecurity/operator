import datetime, hashlib, json, pathlib, subprocess
root=pathlib.Path('/home/hami/phorvex-benchmark/stage-data/mathlab')
files={'refresh':root/'endpoint-refresh/phorvex-staging-demo/stage-bench-defense.status.json',
       'observer':root/'observer-current.json','pin':root/'stage.json',
       'dataset':root/'endpoint-traces/phorvex-staging-demo/stage-bench-defense.manifest.json'}
out={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':{}}
for key,path in files.items():
    if path.is_file():
        raw=path.read_bytes(); value=json.loads(raw)
        if key=='pin':
            value={k:value.get(k) for k in ('schema','brain','manager','capture','policies','study_engine_lane')}
        out['files'][key]={'sha256':hashlib.sha256(raw).hexdigest(),'value':value}
    else:
        out['files'][key]={'missing':True}
for name in ('phorvex-stage-observer.service','phorvex-stage-endpoint-refresh.timer','phorvex-stage-endpoint-refresh.service','phorvex-stage-reconcile.service'):
    proc=subprocess.run(['systemctl','--user','show',name,'--property=MainPID,ActiveState,SubState,Result,ExecMainStatus,LastTriggerUSec,NextElapseUSecRealtime,NextElapseUSecMonotonic'],capture_output=True,text=True,timeout=10,check=True)
    out[name]=dict(line.split('=',1) for line in proc.stdout.splitlines() if '=' in line)
print(json.dumps(out,indent=2))
