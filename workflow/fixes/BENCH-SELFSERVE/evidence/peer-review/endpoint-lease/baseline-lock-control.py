import datetime,fcntl,hashlib,io,json,os,pathlib,subprocess,tarfile,tempfile,time
R=pathlib.Path('/workspace/operator-benchmark-selfserve');O=R/'workflow/fixes/BENCH-SELFSERVE/evidence/peer-review/endpoint-lease';SOURCE='4dc325d300993d0aaec5f5a6d607951cdadd3f62';POLICY='phorvex-staging-demo/stage-bench-defense';sha=lambda b:hashlib.sha256(b).hexdigest()
with tempfile.TemporaryDirectory(dir='/workspace/.phorvex-test-tmp',prefix='lease-peer-baseline-') as t:
 root=pathlib.Path(t);code=root/'source';code.mkdir();raw=subprocess.check_output(['git','archive',SOURCE,'benchmark'],cwd=R)
 with tarfile.open(fileobj=io.BytesIO(raw)) as a:a.extractall(code,filter='data')
 results=[]
 for kind in ['global-pin','policy-status']:
  data=root/kind;status=data/'mathlab/endpoint-refresh'/(POLICY+'.status.json');pointer=data/'mathlab/endpoint-traces'/(POLICY+'.manifest.json');status.parent.mkdir(parents=True);pointer.parent.mkdir(parents=True);status.write_text('{"state":"RUNNING","owner":"independent-review-control"}\n');pointer.write_text('{"trace_sha256":"last-good-review-sentinel"}\n')
  lock=data/'mathlab/stage.lock' if kind=='global-pin' else status.with_suffix('.lock');lock.parent.mkdir(parents=True,exist_ok=True)
  before={str(p.relative_to(data)):{'sha256':sha(p.read_bytes()),'mtime_ns':p.stat().st_mtime_ns} for p in [status,pointer]}
  cmd=['/workspace/.phorvex-tools/python312/python/bin/python3.12',str(code/'benchmark/worker/endpoint_refresh.py'),'--data',str(data),'--repo',str(R),'--policy',POLICY,'--journal',str(root/'nonexistent.db'),'--slo-target','.9','--window','600','--lookback','600','--worth-threshold','0','--ticks','64']
  with lock.open('a') as h:
   fcntl.flock(h,fcntl.LOCK_EX|fcntl.LOCK_NB);start=time.monotonic();p=subprocess.run(cmd,capture_output=True,text=True,timeout=35,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));elapsed=time.monotonic()-start
  (O/(kind+'-baseline-stdout.txt')).write_text(p.stdout);(O/(kind+'-baseline-stderr.txt')).write_text(p.stderr)
  after={str(q.relative_to(data)):{'sha256':sha(q.read_bytes()),'mtime_ns':q.stat().st_mtime_ns} for q in [status,pointer]};assert before==after
  assert p.returncode==1 and p.stdout==''
  if kind=='global-pin':assert elapsed>=20 and 'StageError: stage pin is busy' in p.stderr
  else:assert 'RefreshBlocked: REFRESH_ALREADY_RUNNING' in p.stderr
  results.append({'case':kind,'separate_actual_cli_process':True,'actual_flock_held':True,'exit_code':p.returncode,'elapsed_seconds':round(elapsed,3),'no_structured_stdout':True,'status_and_pointer_bytes_and_mtimes_preserved':True,'stale_owner_status':True,'stdout_sha256':sha(p.stdout.encode()),'stderr_sha256':sha(p.stderr.encode())})
 report={'schema':'phorvex-bench.independent-refresh-lease-baseline.v1','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':SOURCE,'cases':results,'verdict':'INCIDENT_AND_POLICY_CONTENTION_REPRODUCED','no_live_mutation':True};out=O/'baseline-lock-control.json';out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(out.relative_to(R)),'sha256':sha(out.read_bytes()),'cases':results},indent=2))
