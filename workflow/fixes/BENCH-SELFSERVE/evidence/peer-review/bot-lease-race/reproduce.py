import contextlib,datetime,hashlib,json,os,pathlib,subprocess,sys,tempfile,time,unittest
from unittest import mock
R=pathlib.Path('/workspace/operator-benchmark-selfserve');O=R/'workflow/fixes/BENCH-SELFSERVE/evidence/peer-review/bot-lease-race';sys.path[:0]=[str(R/'benchmark/worker'),str(R/'benchmark/bot'),str(R)]
import service,test_bot as botkit,stage_cli,stage_reconcile as reconcile,test_stage_reconcile as fixture
from mathlab import binary,stage_scope
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs=['benchmark/bot/service.py','benchmark/bot/request_readiness.py','benchmark/bot/stage_runtime.py','benchmark/worker/mathlab/stage_scope.py'];hashes={p:sha(R/p) for p in inputs}
with tempfile.TemporaryDirectory(dir='/workspace/.phorvex-test-tmp',prefix='bot-lease-peer-') as temporary,contextlib.ExitStack() as contexts:
 p=fixture.Producer(pathlib.Path(temporary));contexts.enter_context(mock.patch.object(stage_cli,'kube',side_effect=p.kube));contexts.enter_context(mock.patch.object(binary,'ensure_binary',side_effect=p.ensure));contexts.enter_context(mock.patch('runner.Console',side_effect=p.console))
 installed=reconcile.reconcile(p.data,p.repo,ticks=2,timeout=30);assert installed['status']=='READY',installed
 kit=botkit.BotTest();kit.setUp();contexts.callback(kit.doCleanups)
 bot=kit.bot(BOT_REPO=str(p.repo),MATHLAB_DATA_DIR=str(p.data),BOT_POLICY=stage_scope.ALLOWED_POLICIES[0],BOT_MAX_TICKS='2');bot.dashboard=bot.cfg.dashboard()
 request='/param P-FEA-006 1.5 ticks=2 nosync'
 descriptor={'kind':'param','text':request.removeprefix('/param ')}
 ready=bot.readiness_for(descriptor);assert ready['status']=='READY' and ready['snapshot_count']>=2,ready
 bot.handle(botkit.message(botkit.OWNER,request));assert len(bot.queue)==1;positive=bot.queue[0];assert bot.run_next();assert positive.state=='DONE',kit.history()
 positive_activity=json.loads((positive.dir/'ACTIVITY.json').read_text())
 bot.handle(botkit.message(botkit.OWNER,request));assert len(bot.queue)==1;job=bot.queue[0]
 lock_path=p.data/'mathlab/stage.lock';holder=subprocess.Popen([sys.executable,'-c','import fcntl,sys; f=open(sys.argv[1],"a"); fcntl.flock(f,fcntl.LOCK_EX); print("LOCKED",flush=True); sys.stdin.read()',str(lock_path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);assert holder.stdout.readline().strip()=='LOCKED'
 def release():
  if holder.poll() is None:holder.stdin.close();holder.wait(timeout=5)
 contexts.callback(release);contexts.callback(holder.stdout.close)
 original_readiness=bot.readiness_for;corroboration=[];exceptions=[];actual_lock=stage_scope.pin_lock
 @contextlib.contextmanager
 def observed_lock(*args,**kwargs):
  started=time.monotonic()
  try:
   with actual_lock(*args,**kwargs) as held:yield held
  except stage_scope.StageLeaseBusy as error:
   exceptions.append({'type':type(error).__name__,'message':str(error),'wait_seconds':time.monotonic()-started,'source':'actual unchanged pin_lock/flock timeout'});raise
 def release_then_actual_readiness(spec):
  assert exceptions and exceptions[-1]['wait_seconds']>=20
  release();result=original_readiness(spec);corroboration.append(result);return result
 before_experiments=sorted(str(x) for x in (p.data/'mathlab/experiments').glob('*'))
 started=time.monotonic()
 with mock.patch.object(stage_scope,'pin_lock',side_effect=observed_lock),mock.patch.object(bot,'readiness_for',side_effect=release_then_actual_readiness):assert bot.run_next()
 elapsed=time.monotonic()-started;assert job.state=='FAILED';assert len(exceptions)==1 and exceptions[0]['wait_seconds']>=20;assert len(corroboration)==1 and corroboration[0]['status']=='READY';assert before_experiments==sorted(str(x) for x in (p.data/'mathlab/experiments').glob('*'))
 activity=json.loads((job.dir/'ACTIVITY.json').read_text());assert not any(activity['started'].values());history=kit.history();assert history[-1]['state']=='FAILED' and 'stage pin is busy' in history[-1]['headline']
 assert hashes=={s:sha(R/s) for s in inputs}
 report={'schema':'phorvex-bench.independent-bot-lease-race.v1','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_hashes':hashes,'head_at_run':subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),'producer':'Real reconciliation, Git source, PXMS content, native receipt, readonly readiness, StageRuntime and BenchBot queue/execute boundary; scripted external transports only.','positive':{'state':positive.state,'ticks':2,'activity':positive_activity},'counterexample':{'state':job.state,'elapsed_seconds':round(elapsed,3),'lock_error':exceptions[0],'rechecked_readiness':corroboration[0],'activity':activity,'new_experiments':0,'history':history[-1]},'interleaving':'Separate OS process holds EX; genuine20s pin_lock raises StageLeaseBusy; at actual fresh-readiness entry release EX and call original readiness. No readiness status/error/result is fabricated.','limits':['Kubernetes object transport, ECR binary retrieval, Console bytes and replay executable are explicit test fixtures; no live brain efficacy or actual Telegram delivery claimed.','Failure is in state classification after actual lock timeout, not the correctness of the changed-parameter replay.','No product edits or live mutations.'],'verdict':'COUNTEREXAMPLE_REPRODUCED'}
 out=O/'counterexample.json';out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(out.relative_to(R)),'sha256':sha(out),'positive':positive.state,'race':job.state,'rechecked':corroboration[0]['status'],'elapsed_seconds':round(elapsed,3)},indent=2))
