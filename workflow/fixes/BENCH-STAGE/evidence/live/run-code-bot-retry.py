from pathlib import Path
import os,sys,json,datetime,hashlib,threading,subprocess
root=Path('/home/hami/phorvex-benchmark');release=root/'releases/stage-bot-3e11f4e7';out=root/'stage-data/live/code-bot-retry';out.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(release/'benchmark/bot'))
from service import Config,BenchBot,Job
from telegram import Telegram
import file_requests
cfg=Config(os.environ)
assert cfg.repo==str(root/'operator-refactored') and cfg.data==str(root/'stage-data') and cfg.policy=='phorvex-staging-demo/stage-bench-defense'
owner=json.loads((cfg.state/'owner.json').read_text())['id'];assert owner in cfg.admins
class RecordingTelegram(Telegram):
 def __init__(self,token):super().__init__(token);self.receipt_lock=threading.Lock()
 def call(self,method,params=None,files=None,timeout=70):
  result=super().call(method,params,files,timeout)
  if method in ('sendMessage','sendDocument'):
   receipt={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'method':method,'message_id':result.get('message_id') if isinstance(result,dict) else None}
   if files:receipt['files']=[{'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in files.values()]
   with self.receipt_lock:
    with (out/'telegram-delivery.jsonl').open('a') as f:f.write(json.dumps(receipt)+'\n')
  return result
tg=RecordingTelegram(cfg.token);bot=BenchBot(cfg,tg,cfg.dashboard())
receipt={'previous_failed_batch':'474cff3249df','retry_policy':'one new actual model/queue attempt after owned refresh ends; original deadline unchanged','origin':'operator-submitted acceptance jobs using the actual BenchBot queue/execution and real Telegram delivery; no Telegram incoming update is claimed','bot_source':'3e11f4e7ca8424c31a387b53e04942a18ee7d977','capture_source':'ef94fad362dabb51469211388ef80cdfa6eee1d4','state':'RUNNING','jobs':[]}
def save():
 tmp=out/'acceptance-status.tmp';tmp.write_text(json.dumps(receipt,indent=2)+'\n');tmp.replace(out/'acceptance-status.json')
save()
try:
 for name in ['stage-v2a-helper-64.txt']:
  raw=(root/'runtime'/name).read_text();specs=file_requests.parse(raw,policy=cfg.policy,ticks=64)
  job=Job('batch',owner,owner,raw);job.specs=specs;job.upload_id='operator-submitted-'+hashlib.sha256(raw.encode()).hexdigest()[:12]
  row={'request':name,'request_sha256':hashlib.sha256(raw.encode()).hexdigest(),'id':job.id,'state':'QUEUED','origin':'operator acceptance, not Telegram ingestion'};receipt['jobs'].append(row);save()
  bot.queue.append(job);assert bot.run_next();row['state']=job.state;row['batch']=json.loads((job.dir/'BATCH.json').read_text());save()
  print(json.dumps({'job':job.id,'state':job.state,'request':name}),flush=True)
 receipt['state']='PASS' if all(j['state']=='DONE' for j in receipt['jobs']) else 'FAIL';save()
finally:
 receipt['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
 subprocess.run(['systemctl','--user','start','phorvex-benchmark-bot.service','phorvex-stage-endpoint-refresh.timer'],check=False)
