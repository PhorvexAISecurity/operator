import datetime,json,pathlib,subprocess,time
root=pathlib.Path('/home/hami/phorvex-benchmark/stage-data/mathlab');raw=subprocess.run(['systemctl','--user','show','phorvex-stage-reconcile.service','--property=MainPID,ActiveState,SubState,ExecMainStatus,Result'],capture_output=True,text=True,check=True,timeout=10).stdout;unit=dict(x.split('=',1) for x in raw.splitlines() if '=' in x);pid=int(unit['MainPID']);processes=[];visited=set()
def walk(pid):
 if pid<=0 or pid in visited:return
 visited.add(pid);base=pathlib.Path('/proc')/str(pid)
 try:
  name=(base/'comm').read_text().strip();stat=(base/'stat').read_text();end=stat.rfind(')');parts=stat[end+2:].split();children=(base/'task'/str(pid)/'children').read_text().split();processes.append({'pid':pid,'name':name,'state':parts[0],'user_cpu_ticks':int(parts[11]),'system_cpu_ticks':int(parts[12])})
 except (FileNotFoundError,ProcessLookupError):return
 for child in children:walk(int(child))
walk(pid);progress=[];now=time.time()
for folder in sorted((root/'reconcile-work').glob('candidate-*')):
 groups={}
 for p in folder.rglob('*'):
  if not p.is_file():continue
  try:s=p.stat()
  except FileNotFoundError:continue
  key=p.suffix or '<none>';g=groups.setdefault(key,{'files':0,'bytes':0,'newest_mtime':0});g['files']+=1;g['bytes']+=s.st_size;g['newest_mtime']=max(g['newest_mtime'],s.st_mtime)
 row={'directory':folder.name,'groups':groups}
 for k,g in groups.items():g['seconds_since_newest_write']=round(now-g.pop('newest_mtime'),3)
 row['baseline_outputs']=[{'name':p.name,'bytes':p.stat().st_size} for p in folder.glob('baseline-*') if p.is_file()];progress.append(row)
status=json.loads((root/'reconcile-status.json').read_text());print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'unit':unit,'status':{k:status.get(k) for k in ['status','phase','started_at','finished_at','baseline_ticks','reasons']},'task_owned_process_names_only':processes,'task_owned_progress':progress,'scope':'Read-only /proc comm/stat/children and task-owned filenames/sizes/mtime; no argv/env/private bytes or mutations.'},indent=2))
