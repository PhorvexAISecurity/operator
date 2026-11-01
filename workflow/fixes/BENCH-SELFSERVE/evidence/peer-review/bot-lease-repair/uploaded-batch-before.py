import hashlib,json,pathlib,sys,zipfile
from unittest import mock
R=pathlib.Path('/workspace/operator-benchmark-selfserve-1457');O=pathlib.Path('/workspace/operator-benchmark-selfserve/workflow/fixes/BENCH-SELFSERVE/evidence/peer-review/bot-lease-repair');sys.path[:0]=[str(R/'benchmark/bot'),str(R/'benchmark/worker'),str(R)]
import test_job_lease as fixture,test_uploads
from mathlab import stage_scope
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();source=sha(R/'benchmark/bot/service.py');case=fixture.JobLeaseTests();case.setUp()
try:
 raw=(R/'benchmark/bot/testdata/endpoint-v3-10d-original.txt').read_bytes();assert hashlib.sha256(raw).hexdigest()=='2e0a40127b9b9b65f7d42e5fa4eb1f155d8a1819aced313b8f39435ab493a9a3'
 test_uploads.UploadTest.upload(case.kit,case.bot,raw);assert len(case.bot.queue)==1;parent=case.bot.queue[0];actual=stage_scope.pin_lock
 with case.busy_pin(),mock.patch.object(stage_scope,'pin_lock',side_effect=lambda data,**kw:actual(data,timeout=0)):case.bot.run_next()
 batch=json.loads((parent.dir/'BATCH.json').read_text());assert batch['state']=='BLOCKED';row=batch['results'][0];child=parent.dir.parent/row['job'];files=sorted(p.name for p in (child/'endpoint').iterdir());bundle=zipfile.ZipFile(child/'endpoint/evidence.zip');names=bundle.namelist();assert row['headline'] is None;assert not any('original-request' in n or 'compatibility-conversion' in n for n in files+names);assert source==sha(R/'benchmark/bot/service.py')
 report={'verdict':'UPLOADED_BATCH_OMISSIONS_REPRODUCED','source_sha256':source,'actual_upload_parser_queue_batch_child_executed':True,'actual_separate_process_flock':True,'test_wait_only':0,'parent_state':batch['state'],'child_state':row['state'],'child_headline':row['headline'],'endpoint_files':files,'delivered_bundle_members':names,'original_source_sha256':hashlib.sha256(raw).hexdigest(),'upload_original_retained':True,'missing':['batch child headline','original request copy in result bundle','compatibility conversion receipt in result bundle'],'scope':'Scripted external transports from existing producer fixture; no final flags/errors injected, no livecalls.'};p=O/'uploaded-batch-before.json';p.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(p),'sha256':sha(p)},indent=2))
finally:case.doCleanups()
