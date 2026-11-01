import ast,datetime,hashlib,json,pathlib,subprocess,traceback,types
R=pathlib.Path('/workspace/operator-benchmark-selfserve');E=R/'workflow/fixes/BENCH-SELFSERVE/evidence';O=E/'peer-review/live-proposal-v4';p=E/'live/launch-bot-acceptance.py';raw=p.read_text();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw.encode())=='f3625d40a59621ba1f8854f2f22e34090e29c790c7351e7bed1ea5ce5ada2c0a'
node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='run');old=raw[:raw.index('def run(args):')]+"def run(args):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=30)\n"+raw[raw.index("props=run("):];assert sha(old.encode())=='9cd9cb87566b766d6d9a3c4a2565bf8b4b45f3f34fc70e38f0f3e91792d3f978';(O/'launcher-before-private-error-fix.py.txt').write_text(old)
sentinel='REVIEW_ONLY_NOT_A_REAL_SECRET_698183';args=['/usr/bin/false','--setenv=BENCH_TEST='+sentinel]
try:subprocess.run(args,capture_output=True,text=True,check=True,timeout=30)
except subprocess.CalledProcessError as ex:assert sentinel in ''.join(traceback.format_exception(ex));before=True
else:raise AssertionError('missing negative control')
def helper(provider):
 ns={'subprocess':provider,'RuntimeError':RuntimeError,'OSError':OSError};exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-launcher-helper>','exec'),ns);return ns['run']
checks=[]
def refusal(name,fn,argv):
 try:fn(argv)
 except RuntimeError as ex:
  display=''.join(traceback.format_exception(ex));assert sentinel not in display and 'withheld' in display and ex.__suppress_context__;checks.append({'case':name,'result':'SANITIZED_REFUSAL','exception':str(ex)})
 else:raise AssertionError(name+' did not refuse')
run=helper(subprocess);refusal('actual_nonzero_with_private_argv',run,args);refusal('actual_oserror_with_private_argv',run,['/nonexistent-'+sentinel,'--setenv=BENCH_TEST='+sentinel])
timeout_observed=[]
def shortened(argv,**kw):
 assert kw['timeout']==30 and kw['check'] is False
 kw['timeout']=.01
 try:return subprocess.run(argv,**kw)
 except subprocess.TimeoutExpired:
  timeout_observed.append(True);raise
proxy=types.SimpleNamespace(run=shortened,SubprocessError=subprocess.SubprocessError)
refusal('actual_timeout_with_test_transport_shortening_only',helper(proxy),['/usr/bin/python3','-c','import time;time.sleep(2)','--setenv=BENCH_TEST='+sentinel])
assert timeout_observed==[True]
assert run(['/usr/bin/true']).returncode==0;checks.append({'case':'actual_success_positive','result':'PASS'})
accept=E/'live/run-selfserve-bot-acceptance.py';assert sha(accept.read_bytes())=='4ed509d87adab058aa026e6f6f1d890e02e3263a5d5eb407641bf40337b37a28'
report={'schema':'phorvex-bench.peer-acceptance-launcher.v1','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verdict':'PASS_FOR_RECONCILED_BOUNDED_ACCEPTANCE_LAUNCH','launcher_sha256':sha(raw.encode()),'underlying_acceptance_sha256':sha(accept.read_bytes()),'original_negative_control':{'source_sha256':sha(old.encode()),'uncaught_nonzero_traceback_contains_fake_private_value':before},'fixed_controls':checks,'scope':['Reads current installed bot unit Environment privately, verifies exact WorkingDirectory and EnvironmentFile, and requires actualbee9 stage pin before creating a phase-specific transient unit.','Launches only exact previously reviewed4ed acceptance script against actual installeda5d runtime. Source labels correctly distinguish installed runtimea5d from capturebee9 and deployment-chart4dc.','No shell interpolation; subprocess argv is used. Error handling returns only fixed diagnostic/exitcode and suppresses original exception context; no private command or subprocess output is printed.','Underlying acceptance script retains idle/maintenance guards, real bot parser/queue/replay/outbound delivery and owned-unit restoration checks. Launcher LAUNCHED means process creation, not job success.'],'conditions':['Root runs only after successful actual source-native reconciliation and current scope verification.','Both phases must preserve real terminal job/delivery/restoration receipts. Existing unique phase output directories refuse overwrite; failed attempts stay failures.','No live launch was performed by the reviewer. Fake sentinel controls contain no real credentials; timeout transport alone shortens30s to10ms.'],'artifacts':{str(x.relative_to(R)):{'sha256':sha(x.read_bytes()),'bytes':x.stat().st_size} for x in [p,accept,pathlib.Path(__file__),O/'launcher-before-private-error-fix.py.txt']}}
out=O/'launcher-operational-verdict.json';out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(out.relative_to(R)),'sha256':sha(out.read_bytes()),'verdict':report['verdict']},indent=2))
