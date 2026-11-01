"""Collector boundary controls only; these fixtures are not benchmark acceptance evidence."""
import base64
import hashlib
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('collector',Path(__file__).with_name('collect-bot-delivery.py'))
collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)


class CollectionTest(unittest.TestCase):
    def test_terminal_batch_expansion_exact_parameter_mapping_and_no_private_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            def write(name,value):
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
                p.write_text(value if isinstance(value,str) else json.dumps(value))
            batch='a'*12;param='b'*12;endpoint='c'*12;pending='d'*12
            rows=[{'id':batch,'kind':'batch','state':'DONE'},
                  {'id':param,'kind':'param','state':'DONE','batch_id':batch,'user':999,'request':'personal request'},
                  {'id':endpoint,'kind':'endpoint','state':'BLOCKED','batch_id':batch}]
            write('bot/history.jsonl','\n'.join(map(json.dumps,rows))+'\n{')
            write('bot/jobs/'+batch+'/BATCH.json',{'state':'DONE','results':[{'job':param},{'job':endpoint}]})
            write('bot/jobs/'+param+'/report.html','actual report bytes')
            write('bot/jobs/'+param+'/candidate.git.bundle','retained incremental candidate bundle fixture')
            write('bot/jobs/'+param+'/candidate-source-retention.json',{'candidate_commit':'a'*40,'base_commit':'b'*40})
            write('stage-data/mathlab/experiments/e1/request.json',{'title':'Telegram '+param+': P-FEA-006','hypothesis':'private user'})
            write('stage-data/mathlab/experiments/e1/result.json',{'state':'COMPLETE','cohort_size':64})
            write('stage-data/mathlab/experiments/e1/experiment_manifest.json',{'experiment_id':'e1','hypothesis':'private user','policy':'stage/policy'})
            write('bot/jobs/'+endpoint+'/endpoint/result.json',{'state':'BLOCKED','comparable_ticks':0})
            phases=[('bot-acceptance',batch),('endpoint-bot-acceptance',endpoint),('code-bot-retry',param)]
            for phase,selected in phases:
                retry={'previous_failed_batch':batch,'retry_policy':'one bounded retry; original deadline unchanged'} if phase=='code-bot-retry' else {}
                write('stage-data/live/'+phase+'/acceptance-status.json',
                      {'bot_source':phase+'-source','state':'RUNNING','jobs':[{'id':selected,'state':'DONE'},
                                                                          {'id':'e'*12,'state':'DONE','user':999}],**retry})
                write('stage-data/live/'+phase+'/telegram-delivery.jsonl',json.dumps(
                    {'method':'sendDocument','chat_id':999,'message_id':7,'files':[
                        {'name':'result-'+selected+'.json','sha256':'f'*64},
                        {'name':'result-'+('e'*12)+'.json','sha256':'f'*64}]})+'\n')
            for name in ['PLAN.json','prompt.txt','endpoint/config.json','endpoint/evidence.zip','endpoint/go-execution.log','cohort/raw.pxms']:
                write('bot/jobs/'+endpoint+'/'+name,'DO NOT COLLECT')
            write('bot/jobs/'+pending+'/report.html','unfinished report')
            cfg={'root':d,'jobs':[batch,pending,batch]}
            proc=subprocess.run([sys.executable,'-',json.dumps(cfg)],input=collector.REMOTE.encode(),capture_output=True,check=True)
            decoded=gzip.decompress(proc.stdout).decode()
            result=json.loads(decoded)
            self.assertEqual(result['pending_jobs'],[pending])
            self.assertEqual(result['collection_state'],'PENDING_JOBS')
            self.assertEqual(len(result['jobs']),4)
            self.assertEqual(next(j for j in result['jobs'] if j['id']==param)['experiment_id'],'e1')
            files={f['path']:base64.b64decode(f['base64']) for f in result['files']}
            self.assertEqual(files['jobs/'+param+'/report.html'],b'actual report bytes')
            self.assertEqual(files['jobs/'+param+'/candidate.git.bundle'],b'retained incremental candidate bundle fixture')
            self.assertEqual(json.loads(files['jobs/'+param+'/candidate-source-retention.json'])['candidate_commit'],'a'*40)
            self.assertEqual(json.loads(files['jobs/'+param+'/mathlab/result.json'])['cohort_size'],64)
            self.assertEqual(json.loads(files['jobs/'+endpoint+'/endpoint/result.json'])['state'],'BLOCKED')
            for phase,selected in phases:
                status=json.loads(files['receipts/'+phase+'/acceptance-status.json'])
                self.assertEqual(status['phase'],phase)
                self.assertEqual(status['bot_source'],phase+'-source')
                self.assertEqual([j['id'] for j in status['jobs']],[selected])
                if phase=='code-bot-retry':
                    self.assertEqual(status['previous_failed_batch'],batch)
                    self.assertEqual(status['retry_policy'],'one bounded retry; original deadline unchanged')
                receipt=json.loads(files['receipts/'+phase+'/telegram-delivery.json'])
                self.assertEqual(len(receipt),1)
                self.assertEqual([f['name'] for f in receipt[0]['files']],['result-'+selected+'.json'])
                self.assertNotIn('chat_id',receipt[0])
            self.assertFalse(any('DO NOT COLLECT' in raw.decode() for raw in files.values()))
            self.assertFalse(any(pending in name for name in files))
            self.assertNotIn('personal request',decoded)
            self.assertNotIn('private user',decoded)
            for f in result['files']:
                self.assertEqual(hashlib.sha256(files[f['path']]).hexdigest(),f['sha256'])

    def test_credential_pattern_and_symlink_refusal(self):
        self.assertIsNotNone(collector.SECRET.search(b'ghp_'+b'x'*30))
        self.assertIsNone(collector.SECRET.search(b'{"state":"COMPLETE","source":"'+b'a'*40+b'"}'))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);job='a'*12;p=root/'bot/jobs'/job;p.mkdir(parents=True)
            (root/'bot/history.jsonl').write_text(json.dumps({'id':job,'state':'DONE','kind':'bench'})+'\n')
            (p/'report.html').symlink_to('/etc/hostname')
            proc=subprocess.run([sys.executable,'-',json.dumps({'root':d,'jobs':[job]})],
                                input=collector.REMOTE,text=True,capture_output=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertIn('unsafe remote path',proc.stderr)


if __name__=='__main__': unittest.main()
