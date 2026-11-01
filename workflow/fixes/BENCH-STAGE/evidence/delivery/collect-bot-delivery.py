#!/usr/bin/env python3
"""Read-only SSH collection of terminal bot reports; never dispatches or controls services."""
import argparse
import base64
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import zipfile

REMOTE = r'''
import base64, datetime, gzip, hashlib, json, re, sys
from pathlib import Path
cfg = json.loads(sys.argv[1])
root = Path(cfg['root']).resolve()
state = root/'bot'; data = root/'stage-data'
terminal = {'DONE','COMPLETE','FAILED','PARTIAL','BLOCKED','NEEDS_DATA','INVALID','CANCELLED','INTERRUPTED'}
max_file = 32*1024*1024; max_total = 128*1024*1024
out = {'at':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'jobs':[], 'files':[], 'omitted':[]}
total = 0
def read(path):
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError('unsafe remote path')
    if path.stat().st_size > max_file:
        raise ValueError('file exceeds bounded collection size')
    return path.read_bytes()
def obj(path): return json.loads(read(path))
def add(path, dest):
    global total
    if not path.is_file(): return
    if path.stat().st_size > max_file or total + path.stat().st_size > max_total:
        out['omitted'].append({'path':str(path.relative_to(root)), 'reason':'collection size cap'})
        return
    raw = read(path); total += len(raw)
    out['files'].append({'path':dest, 'origin':str(path.relative_to(root)), 'sha256':hashlib.sha256(raw).hexdigest(),
                         'bytes':len(raw), 'base64':base64.b64encode(raw).decode()})
def generated(dest, value, origin):
    raw = (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    out['files'].append({'path':dest,'origin':origin,'sha256':hashlib.sha256(raw).hexdigest(),
                         'bytes':len(raw),'base64':base64.b64encode(raw).decode(),'derived':True})
history = {}
hp = state/'history.jsonl'
if hp.is_file():
    for line in read(hp).splitlines():
        try: row = json.loads(line)
        except ValueError: continue  # an unrelated concurrently appended row can be incomplete
        if row.get('state') in terminal: history[row['id']] = row
ids = list(dict.fromkeys(cfg['jobs']))
for jid in list(ids):
    batch = state/'jobs'/jid/'BATCH.json'
    if jid in history and batch.is_file():
        for row in obj(batch).get('results',[]):
            child = row.get('job')
            if child and child not in ids: ids.append(child)
artifacts = ('result.json','metrics.json','sweep_results.csv','candidate_gate_trace.csv','decision_funnel.csv',
             'cost_truth.csv','candidates.csv','Phorvex_Math_Lab_Results.xlsx','replay-summary.json',
             'replay-summary-control.json','replay-summary-base-local.json','replay-summary-candidate.json')
def experiment(path, dest):
    for name in artifacts: add(path/name,dest+'/'+name)
    manifest = path/'experiment_manifest.json'
    if manifest.is_file():
        value = obj(manifest)
        keep = ('schema_version','experiment_id','mode','parameter','arms','policy','cohort',
                'replay_binary','builds','stage_provenance','limitations','started_at','finished_at')
        generated(dest+'/provenance.json',{k:value[k] for k in keep if k in value},
                  {'path':str(manifest.relative_to(root)),'sha256':hashlib.sha256(read(manifest)).hexdigest(),
                   'note':'Derived field allowlist; personal hypothesis and arbitrary prompt omitted.'})
for jid in ids:
    if not re.fullmatch('[0-9a-f]{12}',jid): raise ValueError('invalid job id')
    row = history.get(jid)
    if row is None:
        out['jobs'].append({'id':jid,'state':'PENDING_OR_UNRECORDED','collected':False}); continue
    receipt = {k:row.get(k) for k in ('id','kind','state','created','finished','batch_id','headline')}
    receipt['collected'] = True
    out['jobs'].append(receipt)
    path = state/'jobs'/jid; dest = 'jobs/'+jid
    for name in ('BATCH.json','report.html','metrics.csv','TESTS.json','brain.diff',
                 'candidate.git.bundle','candidate-source-retention.json'):
        add(path/name,dest+'/'+name)
    experiment(path/'experiment',dest+'/experiment')
    for kind in ('endpoint','study'):
        for name in ('report.html','metrics.csv','result.json','trace.json','summary.json','study-settings.json',
                     'dataset-manifest.json','capture-control-summary.json','base-local-summary.json'):
            add(path/kind/name,dest+'/'+kind+'/'+name)
    if row.get('kind') == 'param':
        matches=[]
        for request in (data/'mathlab/experiments').glob('*/request.json'):
            if obj(request).get('title','').startswith('Telegram '+jid+': '): matches.append(request.parent)
        if len(matches) != 1: raise ValueError('parameter experiment mapping must be unique for '+jid)
        receipt['experiment_id'] = matches[0].name
        experiment(matches[0],dest+'/mathlab')
for phase in ('bot-acceptance','endpoint-bot-acceptance','code-bot-retry'):
    delivery = data/'live'/phase/'telegram-delivery.jsonl'
    if delivery.is_file():
        receipts=[]
        for line in read(delivery).splitlines():
            try: value=json.loads(line)
            except ValueError: continue
            files=[f for f in value.get('files',[]) if any(j in f.get('name','') for j in ids)]
            if files: receipts.append({k:value.get(k) for k in ('at','method','message_id')}|{'files':files})
        generated('receipts/'+phase+'/telegram-delivery.json',receipts,
                  {'path':str(delivery.relative_to(root)), 'note':'Selected file receipts only; no chat or user identity.'})
    acceptance=data/'live'/phase/'acceptance-status.json'
    if acceptance.is_file():
        value=obj(acceptance)
        keep={k:value.get(k) for k in ('origin','bot_source','capture_source','state','finished_at')}
        keep.update({k:value[k] for k in ('previous_failed_batch','retry_policy') if k in value})
        keep['phase']=phase
        keep['jobs']=[{k:j.get(k) for k in ('id','state','request','request_sha256','origin')}
                      for j in value.get('jobs',[]) if j.get('id') in ids]
        generated('receipts/'+phase+'/acceptance-status.json',keep,{'path':str(acceptance.relative_to(root)),
                  'sha256':hashlib.sha256(read(acceptance)).hexdigest(),'note':'Selected status fields; not an independent verification.'})
out['pending_jobs']=[r['id'] for r in out['jobs'] if not r['collected']]
out['collection_state']='PENDING_JOBS' if out['pending_jobs'] else 'REPORTS_COLLECTED'
sys.stdout.buffer.write(gzip.compress(json.dumps(out).encode(),mtime=0))
'''

DEFAULT_JOBS = ['8ffcfca38357', '474cff3249df', '4b8171ea3c83']
SECRET = re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|'
                    rb'\bsk-[A-Za-z0-9_-]{24,}|\b\d{6,12}:[A-Za-z0-9_-]{30,}|'
                    rb'-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._-]{20,}|'
                    rb'"(?:password|api_key|access_token|refresh_token|client_secret)"\s*:\s*"[^"\s]{4,})')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--job', action='append', help='Batch or child ID; repeat to include future endpoint jobs')
    p.add_argument('--output', required=True, type=Path, help='New private directory; existing output is never overwritten')
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[5])
    p.add_argument('--host', default='jh')
    p.add_argument('--ssh-config', default='/home/node/.ssh/jh/config')
    p.add_argument('--remote-root', default='/home/hami/phorvex-benchmark')
    p.add_argument('--remote-python', default='/home/hami/phorvex-benchmark/runtime/python/bin/python3.12')
    p.add_argument('--allow-pending', action='store_true', help='Exit 0 for an explicitly partial collection; pending state remains visible')
    args = p.parse_args()
    jobs = args.job or DEFAULT_JOBS
    if any(not re.fullmatch('[0-9a-f]{12}', j) for j in jobs): p.error('job IDs must be 12 lowercase hex characters')
    if args.output.exists() or args.output.with_suffix('.zip').exists(): p.error('output already exists; choose a fresh directory')
    os.umask(0o077)
    cfg = json.dumps({'root':args.remote_root,'jobs':jobs},separators=(',',':'))
    command = shlex.join([args.remote_python,'-B','-',cfg])
    proc = subprocess.run(['setsid','--wait','ssh','-F',args.ssh_config,'-o','StrictHostKeyChecking=yes',
                           '-o','ConnectTimeout=15',args.host,command],input=REMOTE.encode(),capture_output=True,timeout=180)
    if proc.returncode:
        raise RuntimeError('Read-only SSH collection failed (exit %s); remote stderr withheld to avoid leaking configuration.' % proc.returncode)
    payload=json.loads(gzip.decompress(proc.stdout))
    content={}; file_receipts=[]
    for item in payload.pop('files'):
        raw=base64.b64decode(item.pop('base64'),validate=True)
        if hashlib.sha256(raw).hexdigest()!=item['sha256'] or len(raw)!=item['bytes']: raise ValueError('transport hash mismatch')
        path=Path(item['path'])
        if path.is_absolute() or '..' in path.parts or str(path) in content: raise ValueError('unsafe delivery path')
        if SECRET.search(raw): raise ValueError('credential-shaped content refused in '+str(path))
        content[str(path)]=raw;file_receipts.append(item)
    local={
        'guide-fa.pdf':args.repo/'benchmark/bot/guide-fa.pdf',
        'README-fa.txt':Path(__file__).with_name('USER-GUIDANCE-fa.txt'),
        'RESULTS-fa.txt':Path(__file__).with_name('USER-RESULTS-fa.txt'),
        'requests/stage-parameters-64.txt':args.repo/'workflow/fixes/BENCH-STAGE/evidence/live/requests/stage-parameters-64.txt',
        'requests/stage-v2a-helper-64.txt':args.repo/'workflow/fixes/BENCH-STAGE/evidence/live/requests/stage-v2a-helper-64.txt',
        'requests/stage-endpoint-custom.json':args.repo/'workflow/fixes/BENCH-STAGE/evidence/live/requests/stage-endpoint-custom.json',
        'requests/stage-endpoint-600.json':args.repo/'workflow/fixes/BENCH-STAGE/evidence/live/requests/stage-endpoint-600.json',
        'requests/endpoint-v3-stage-600s.json':args.repo/'benchmark/bot/templates/endpoint-v3-stage-600s.json',
        'requests/endpoint-v3-original-30d-pending.json':args.repo/'benchmark/bot/templates/endpoint-v3-original-30d-pending.json',
    }
    for dest,source in local.items():
        raw=source.read_bytes()
        if SECRET.search(raw): raise ValueError('credential-shaped local artifact refused')
        content[dest]=raw
        file_receipts.append({'path':dest,'origin':'local:'+str(source.relative_to(args.repo)),
                              'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
    payload.update(schema='phorvex-bench.private-delivery.v1',requested_jobs=jobs,
                   note='Collection is not independent validation. Job states and limitations are preserved. No new jobs were dispatched.',
                   collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),files=file_receipts,
                   excluded=['secrets/configuration','raw service/build logs','source clones','raw snapshot corpus',
                             'PLAN.json/prompt.txt/personal request records','original evidence.zip (may contain excluded data)'])
    content['COLLECTION.json']=(json.dumps(payload,ensure_ascii=False,indent=2)+'\n').encode()
    for name,raw in content.items():
        if SECRET.search(raw): raise ValueError('credential-shaped delivery content refused in '+name)
    sums={name:hashlib.sha256(raw).hexdigest() for name,raw in sorted(content.items())}
    content['SHA256SUMS.json']=(json.dumps(sums,indent=2)+'\n').encode()
    args.output.mkdir(parents=True,mode=0o700)
    for name,raw in content.items():
        target=args.output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    archive=args.output.with_suffix('.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
        for name,raw in sorted(content.items()): z.writestr(name,raw)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(digest+'  '+archive.name+'\n')
    print(json.dumps({'collection_state':payload['collection_state'],'pending_jobs':payload['pending_jobs'],
                      'jobs':[{k:r.get(k) for k in ('id','kind','state','experiment_id')} for r in payload['jobs']],
                      'omitted':payload['omitted'],'archive':str(archive),'sha256':digest,'files':len(content)},indent=2))
    return 2 if payload['pending_jobs'] and not args.allow_pending else 0


if __name__ == '__main__':
    sys.exit(main())
