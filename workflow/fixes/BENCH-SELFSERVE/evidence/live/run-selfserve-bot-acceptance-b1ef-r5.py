"""Actual document parser/queue/execution and outbound Telegram; operator input only.

Only download_document substitutes the user's locally supplied original bytes.
No incoming Telegram update, historical coverage or actuation is fabricated.
"""
from pathlib import Path
import datetime,hashlib,json,os,re,subprocess,sys,threading,time

source,phase=sys.argv[1:]
assert re.fullmatch('[a-f0-9]{40}',source) and phase in ('initial','fixture')
root=Path('/home/hami/phorvex-benchmark');release=root/'releases'/('stage-selfserve-'+source[:12])
out=root/'stage-data/live'/('selfserve-bot-'+phase+'-'+source[:12]+'-b1ef-r5');assert not out.exists();out.mkdir(parents=True,mode=0o700)
sys.path.insert(0,str(release/'benchmark/bot'))
from service import Config,BenchBot
from telegram import Telegram
cfg=Config(os.environ)
assert cfg.repo==str(root/'operator-refactored') and cfg.data==str(root/'stage-data') and cfg.state==root/'bot'
owner=json.loads((cfg.state/'owner.json').read_text())['id'];assert owner in cfg.admins
inputs=root/'stage-data/live/selfserve-acceptance-inputs'
original=(inputs/'original-10d.txt').read_bytes()
assert hashlib.sha256(original).hexdigest()=='2e0a40127b9b9b65f7d42e5fa4eb1f155d8a1819aced313b8f39435ab493a9a3'
requests={
    'original-10d.txt':original,
    'demo-param-64.txt':b'[params]\npolicy: phorvex-staging-demo/demo-api-defense\nticks: 64\nsync: false\nP-FEA-006: 1.0 1.2 1.5\n',
    'fixture-endpoint-600s.txt':(release/'benchmark/bot/templates/endpoint-v3-fixture-600s.txt').read_bytes(),
    'fixture-endpoint-custom.txt':b'[endpoint]\ntitle: Separate dryRun fixture custom numeric control\npolicy: phorvex-staging-demo/stage-bench-defense\nticks: 64\nsync: false\ndataset: recorded\nstudy.window: 240\nconfig.lookback: 300\nstudy.slo_target: 0.95\nstudy.worth_threshold: 0.25\nconfig.delta: 2\n'}
selected=['original-10d.txt','demo-param-64.txt'] if phase=='initial' else ['fixture-endpoint-600s.txt','fixture-endpoint-custom.txt']
for name in selected:(out/name).write_bytes(requests[name])
expected={'original-10d.txt':'BLOCKED','demo-param-64.txt':'DONE','fixture-endpoint-600s.txt':'DONE','fixture-endpoint-custom.txt':'DONE'}
class RecordingTelegram(Telegram):
    def __init__(self,token):super().__init__(token);self.receipt_lock=threading.Lock()
    def download_document(self,file_id,max_bytes):
        data=requests[file_id];assert len(data)<=max_bytes;return data
    def call(self,method,params=None,files=None,timeout=70):
        result=super().call(method,params,files,timeout)
        if method in ('sendMessage','sendDocument'):
            row={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'method':method,
                'message_id':result.get('message_id') if isinstance(result,dict) else None}
            if files:row['files']=[{'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in files.values()]
            with self.receipt_lock:
                with (out/'telegram-delivery.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
        return result
def system(*args,check=True):return subprocess.run(['systemctl','--user',*args],text=True,capture_output=True,check=check)
def unit_state(name):
    raw=system('show',name,'--property=ActiveState,SubState,MainPID').stdout
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
def idle():
    r=subprocess.run(['journalctl','--user','-u','phorvex-benchmark-bot.service','--since','2026-11-01 00:00:00','-o','cat','--no-pager'],capture_output=True,text=True,check=True)
    queued=set(re.findall(r'queued \w+ job ([a-f0-9]{12}) from',r.stdout))
    h=[json.loads(x) for x in (cfg.state/'history.jsonl').read_text().splitlines() if x.strip()]
    assert not queued-{x['id'] for x in h},'pending accepted jobs'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
protected=[root/'config/bot.env',cfg.state/'owner.json',cfg.state/'members.json',root/'stage-data/mathlab/bin/current.json']
before={str(p):digest(p) for p in protected}
receipt={'schema':'phorvex-bench.operator-document-acceptance.v1','source':source,'phase':phase,'state':'RUNNING','jobs':[],
    'origin':'Operator-supplied bytes through actual BenchBot.receive_document, actual parsing/readiness/queue/replay/report and real outbound Telegram; no incoming Telegram update is claimed.',
    'expected_states':{n:expected[n] for n in selected},'protected_before':before}
def save():(out/'acceptance-status.json').write_text(json.dumps(receipt,indent=2)+'\n')
save();stopped=False;stopped_timers=[]
timers=['phorvex-stage-reconcile.timer','phorvex-stage-endpoint-refresh.timer']
observer_before=unit_state('phorvex-stage-observer.service')
receipt['observer_before']=observer_before
try:
    for timer in timers:assert system('is-active',timer).stdout.strip()=='active'
    for timer in timers:
        stopped_timers.append(timer);system('stop',timer)
    deadline=time.monotonic()+950
    while any(system('show',name,'--property=ActiveState','--value').stdout.strip() in ('active','activating','deactivating')
              for name in ('phorvex-stage-reconcile.service','phorvex-stage-endpoint-refresh.service')):
        assert time.monotonic()<deadline,'existing owned maintenance exceeded bounded wait'
        time.sleep(5)
    idle();assert unit_state('phorvex-benchmark-bot.service')['ActiveState']=='active'
    stopped=True;system('stop','phorvex-benchmark-bot.service');idle()
    bot=BenchBot(cfg,RecordingTelegram(cfg.token),cfg.dashboard())
    for name in selected:
        prior=set((cfg.state/'uploads').iterdir())
        bot.receive_document(owner,owner,{'file_id':name,'file_name':name,'file_size':len(requests[name])})
        assert len(bot.queue)==1,'document did not create exactly one actual batch'
        job=bot.queue[0]
        created=set((cfg.state/'uploads').iterdir())-prior;assert len(created)==1
        validation=json.loads((next(iter(created))/'VALIDATION.json').read_text())
        assert validation['source_sha256']==hashlib.sha256(requests[name]).hexdigest()
        row={'request':name,'request_sha256':validation['source_sha256'],'id':job.id,'state':'QUEUED',
             'upload_id':job.upload_id,'validation':validation}
        receipt['jobs'].append(row);save()
        assert bot.run_next()
        row.update(state=job.state,batch=json.loads((job.dir/'BATCH.json').read_text()))
        save();print(json.dumps({'job':job.id,'request':name,'state':job.state}),flush=True)
    receipt['protected_after']={str(p):digest(p) for p in protected};assert receipt['protected_after']==before
    receipt['job_outcome']='PASS' if all(x['state']==expected[x['request']] for x in receipt['jobs']) else 'FAIL'
    receipt['state']=receipt['job_outcome']
except BaseException as exc:
    receipt.update(state='ERROR',error_type=type(exc).__name__,error=str(exc));raise
finally:
    restore_errors=[];receipt['restored_units']={}
    for name in (['phorvex-benchmark-bot.service'] if stopped else [])+stopped_timers:
        result=system('start',name,check=False)
        state=unit_state(name);receipt['restored_units'][name]=state
        if result.returncode or state['ActiveState']!='active':restore_errors.append(name)
    receipt['observer_after']=unit_state('phorvex-stage-observer.service')
    if receipt['observer_after']!=observer_before:restore_errors.append('observer changed unexpectedly')
    receipt['restoration']='PASS' if not restore_errors else 'FAIL'
    if restore_errors:receipt.update(state='RESTORATION_FAILED',restoration_errors=restore_errors)
    receipt['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
    print(json.dumps({'state':receipt['state'],'receipt':str(out/'acceptance-status.json'),'sha256':digest(out/'acceptance-status.json')}),flush=True)
    if restore_errors:raise RuntimeError('owned service restoration did not pass')
