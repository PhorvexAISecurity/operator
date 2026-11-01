import ast,copy,datetime,hashlib,json,pathlib,subprocess,types
R=pathlib.Path('/workspace/operator-benchmark-selfserve');E=R/'workflow/fixes/BENCH-SELFSERVE/evidence';O=E/'peer-review/endpoint-lease';p=E/'live/install-runtime-lease-repair.py';raw=p.read_text();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw.encode())=='de6aebdcabd5cdf037449bfb657cc0c1fe18de6dbc79b571b15d28cf51772f27';tree=ast.parse(raw);handler=next(n.handlers[0] for n in tree.body if isinstance(n,ast.Try) and n.handlers and isinstance(n.handlers[0].type,ast.Name) and n.handlers[0].type.id=='BaseException')
expected=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='expected_units' for t in n.targets)));assert len(expected)==6
actual=json.loads((E/'live/runtime-install-receipt-a5d8.json').read_bytes());assert expected==actual['proposed_unit_hashes']
module=ast.fix_missing_locations(ast.Module(body=[ast.Try(body=[ast.Raise(exc=ast.Call(func=ast.Name(id='RuntimeError',ctx=ast.Load()),args=[ast.Constant(value='controlled original installation failure')],keywords=[]),cause=None)],handlers=[copy.deepcopy(handler)],orelse=[],finalbody=[])],type_ignores=[]))
active=['phorvex-benchmark-bot.service','phorvex-stage-observer.service','phorvex-stage-reconcile.timer','phorvex-stage-endpoint-refresh.timer'];cases=[]
for kind in ['all-recover','nonzero','oserror','timeout','copy-error','show-error']:
 calls=[];copies=[];shown=[];receipt={}
 def fake_run(args,**kw):
  calls.append(args[2:])
  if kind=='oserror':raise OSError('controlled transport unavailable')
  if kind=='timeout':raise subprocess.TimeoutExpired(args,120)
  return types.SimpleNamespace(returncode=7 if kind=='nonzero' else 0)
 def fake_copy(a,b):
  copies.append(b.name)
  if kind=='copy-error':raise OSError('controlled copy failure')
 def fake_show(name):
  shown.append(name)
  if kind=='show-error':raise subprocess.CalledProcessError(7,['systemctl'])
  return {'ActiveState':'active'}
 ns={'receipt':receipt,'mutated':True,'active':active,'stopped':active,'expected_units':expected,'backup':pathlib.Path('/private-test-backup'),'units':pathlib.Path('/private-test-units'),'subprocess':types.SimpleNamespace(run=fake_run,SubprocessError=subprocess.SubprocessError),'shutil':types.SimpleNamespace(copy2=fake_copy),'show':fake_show}
 try:exec(compile(module,'<exact-installer-rollback-handler>','exec'),ns)
 except RuntimeError as err:assert str(err)=='controlled original installation failure'
 else:raise AssertionError('original failure disappeared')
 assert len(calls)==11 and len(copies)==6 and len(shown)==4
 if kind=='all-recover':assert receipt['state']=='INSTALLATION_ERROR' and receipt['recovery_errors']==[] and receipt['recovery'].startswith('Previous owned units restored')
 else:assert receipt['state']=='RESTORATION_FAILED' and receipt['recovery_errors'] and 'Do not claim restored runtime' in receipt['recovery']
 cases.append({'case':kind,'state':receipt['state'],'recovery_errors':len(receipt['recovery_errors']),'all_owned_stops_copies_reload_starts_and_checks_attempted':True})
report={'schema':'phorvex-bench.peer-runtime-upgrade-rollback.v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'reviewer':'stage-review','installer_sha256':sha(raw.encode()),'expected_six_unit_hashes_match_actual_a5d_install_receipt':True,'controls':cases,'scope':'Exact parsed rollback handler with explicit transport/filesystem doubles; no service, filesystem target or cluster mutation. This verifies failure reporting and best-effort continuation, not actual recovery.','verdict':'PASS'};out=O/'runtime-rollback-control.json';out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(out.relative_to(R)),'sha256':sha(out.read_bytes()),'cases':cases},indent=2))
