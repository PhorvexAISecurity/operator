#!/usr/bin/env python3
import base64, copy, datetime, hashlib, importlib.util, pathlib, unittest
P=pathlib.Path(__file__).with_name('transfer_secret.py'); spec=importlib.util.spec_from_file_location('transfer_secret',P); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def sha(v): return hashlib.sha256(v).hexdigest()
class TransferTest(unittest.TestCase):
 def setUp(self):
  self.now=datetime.datetime.now(datetime.timezone.utc)
  self.value=b'private-value-never-printed'
  self.t={'source':{'namespace':'fixture','namespaceUID':'ns-source','name':'transfer','uid':'secret-uid','expiresAt':(self.now+datetime.timedelta(hours=1)).isoformat()},'destination':{'namespace':'system','namespaceUID':'ns-dest','name':'dest'},'type':'Opaque','dataSHA256':{'startup.json':sha(self.value)}}
  self.secret={'metadata':{'namespace':'fixture','name':'transfer','uid':'secret-uid','labels':{'phorvex.ai/secure-transfer':'m106-v5'},'annotations':{'phorvex.ai/expires-at':self.t['source']['expiresAt'],'phorvex.ai/transfer-destination':'system/dest'}},'immutable':True,'type':'Opaque','data':{'startup.json':base64.b64encode(self.value).decode()}}
 def fake(self,args):
  if args[:2]==['get','namespace']:
   return {'metadata':{'uid':'ns-source' if args[2]=='fixture' else 'ns-dest'}}
  return self.secret
 def runcheck(self,t=None):
  old=m.get_json; m.get_json=lambda k,args,allow_empty=False:self.fake(args)
  try:return m.check_transfer('kubectl',t or self.t,self.now)
  finally:m.get_json=old
 def test_valid_source(self):
  s,d,e=self.runcheck(); self.assertEqual(d,self.t['dataSHA256']); self.assertTrue(m.desired(self.t,s)['immutable'])
 def test_source_uid_drift(self):
  t=copy.deepcopy(self.t); t['source']['uid']='other'
  with self.assertRaises(ValueError):self.runcheck(t)
 def test_hash_drift(self):
  t=copy.deepcopy(self.t); t['dataSHA256']['startup.json']='0'*64
  with self.assertRaises(ValueError):self.runcheck(t)
 def test_expired(self):
  t=copy.deepcopy(self.t); t['source']['expiresAt']=(self.now-datetime.timedelta(seconds=1)).isoformat(); self.secret['metadata']['annotations']['phorvex.ai/expires-at']=t['source']['expiresAt']
  with self.assertRaises(ValueError):self.runcheck(t)
 def test_extra_key_rejected(self):
  self.secret['data']['extra']=base64.b64encode(b'x').decode()
  with self.assertRaises(ValueError):self.runcheck()
 def test_destination_binding(self):
  self.secret['metadata']['annotations']['phorvex.ai/transfer-destination']='other/dest'
  with self.assertRaises(ValueError):self.runcheck()
class StartupAuthorityTest(unittest.TestCase):
 def fixture(self):
  workload={'namespace':'fixture','ownerKind':'Deployment','ownerName':'app','ownerUID':'dep-uid'}; scope=sha(__import__('json').dumps(workload,sort_keys=True,separators=(',',':')).encode())
  prep={'policy':{'namespace':'fixture','name':'policy','uid':'policy-uid','generation':2},'workload':workload,'targetName':'pod','targetUID':'pod-uid','targetTerminationGraceSeconds':30,'old':{'url':'https://session/old','sessionID':'old','challenge':'a','targetUID':'pod-uid','workloadScopeSHA256':scope},'replacement':{'url':'https://session/new','sessionID':'new','challenge':'b','targetUID':'','workloadScopeSHA256':scope}}
  cfg={'data':{'startup.json':base64.b64encode(__import__('json').dumps({'prepare':prep}).encode()).decode()}}
  pin={'startupAuthority':{**{k:prep[k] for k in ('policy','workload','targetName','targetUID','targetTerminationGraceSeconds')},'policyMode':'active','targetLabels':{'fixture.phorvex.ai/m106-target':'nonce'}}}
  objects={('phorvexpolicy','policy'):{'metadata':{'uid':'policy-uid','generation':2},'spec':{'mode':'active'},'status':{'observedGeneration':2}},('pod','pod'):{'metadata':{'uid':'pod-uid','labels':{'fixture.phorvex.ai/m106-target':'nonce'},'ownerReferences':[{'controller':True,'kind':'ReplicaSet','name':'rs','uid':'rs-uid'}]},'spec':{'terminationGracePeriodSeconds':30},'status':{'conditions':[{'type':'Ready','status':'True'}]}},('replicaset','rs'):{'metadata':{'uid':'rs-uid','ownerReferences':[{'controller':True,'kind':'Deployment','name':'app','uid':'dep-uid'}]}},('deployment','app'):{'metadata':{'uid':'dep-uid'}}}
  return cfg,pin,objects
 def test_exact_live_startup_authority(self):
  cfg,pin,objects=self.fixture();old=m.get_json;m.get_json=lambda k,args,allow_empty=False:objects[(args[1],args[2])]
  try:self.assertEqual(m.validate_startup_authority('kubectl',pin,cfg)['targetUID'],'pod-uid')
  finally:m.get_json=old
 def test_unready_target_rejected(self):
  cfg,pin,objects=self.fixture();objects[('pod','pod')]['status']['conditions'][0]['status']='False';old=m.get_json;m.get_json=lambda k,args,allow_empty=False:objects[(args[1],args[2])]
  try:
   with self.assertRaises(ValueError):m.validate_startup_authority('kubectl',pin,cfg)
  finally:m.get_json=old

class PartialReceiptTest(unittest.TestCase):
 def test_second_create_failure_retains_first_uid(self):
  import json, tempfile
  now=datetime.datetime.now(datetime.timezone.utc); expiry=(now+datetime.timedelta(hours=1)).isoformat(); data=base64.b64encode(b'x').decode(); digest=sha(b'x')
  def transfer(name,dest,key): return {'source':{'namespace':'fixture','namespaceUID':'ns-source','name':name,'uid':name+'-uid','expiresAt':expiry},'destination':{'namespace':'system','namespaceUID':'ns-dest','name':dest},'type':'Opaque','dataSHA256':{key:digest}}
  pin={'schema':m.SCHEMA,'startupAuthority':{},'transfers':[transfer('one','dest-one','startup.json'),transfer('two','dest-two','tls.crt')]}
  sources={t['source']['name']:{'data':{next(iter(t['dataSHA256'])):data}} for t in pin['transfers']}; created={}; preflight=True
  oldcheck,olddest,oldvalidate,oldkubectl=m.check_transfer,m.destination,m.validate_startup_authority,m.kubectl
  m.check_transfer=lambda k,t,n:(sources[t['source']['name']],t['dataSHA256'],m.parse_time(t['source']['expiresAt']))
  m.validate_startup_authority=lambda k,p,s:{'targetUID':'target'}
  def destination(k,t):
   if preflight:return None
   return created.get(t['destination']['name'])
  m.destination=destination
  calls={'n':0}
  def kubectl(k,args,input_bytes=None):
   calls['n']+=1
   if calls['n']==2:raise ValueError('synthetic second create failure')
   want=json.loads(input_bytes); obj=copy.deepcopy(want);obj['metadata'].update({'uid':'dest-one-uid','resourceVersion':'1'});created[want['metadata']['name']]=obj;return b'secret/x'
  m.kubectl=kubectl
  try:
   with tempfile.TemporaryDirectory() as td:
    pp=pathlib.Path(td)/'pin.json';rr=pathlib.Path(td)/'receipt.json';pp.write_text(json.dumps(pin));preflight=False
    rc,result=m.execute('apply',pp,'kubectl',rr)
    self.assertEqual(rc,1);self.assertEqual(result['status'],'PARTIAL');self.assertEqual(result['transfers'][0]['state'],'CREATED');self.assertEqual(result['transfers'][0]['destinationUID'],'dest-one-uid');self.assertNotIn('private-value',rr.read_text())
  finally:m.check_transfer,m.destination,m.validate_startup_authority,m.kubectl=oldcheck,olddest,oldvalidate,oldkubectl
 def test_lost_create_ack_and_failed_readback_is_unsafe_partial(self):
  import json, tempfile
  now=datetime.datetime.now(datetime.timezone.utc); expiry=(now+datetime.timedelta(hours=1)).isoformat(); data=base64.b64encode(b'x').decode(); digest=sha(b'x')
  def transfer(name,dest,key): return {'source':{'namespace':'fixture','namespaceUID':'ns-source','name':name,'uid':name+'-uid','expiresAt':expiry},'destination':{'namespace':'system','namespaceUID':'ns-dest','name':dest},'type':'Opaque','dataSHA256':{key:digest}}
  pin={'schema':m.SCHEMA,'startupAuthority':{},'transfers':[transfer('one','dest-one','startup.json'),transfer('two','dest-two','tls.crt')]};sources={t['source']['name']:{'data':{next(iter(t['dataSHA256'])):data}} for t in pin['transfers']};state={'create':False}
  oldcheck,olddest,oldvalidate,oldkubectl=m.check_transfer,m.destination,m.validate_startup_authority,m.kubectl
  m.check_transfer=lambda k,t,n:(sources[t['source']['name']],t['dataSHA256'],m.parse_time(t['source']['expiresAt']))
  m.validate_startup_authority=lambda k,p,s:{'targetUID':'target'}
  def destination(k,t):
   if state['create']:raise ValueError('synthetic reconciliation read failure')
   return None
  m.destination=destination
  def kubectl(k,args,input_bytes=None):state['create']=True;raise ValueError('synthetic lost create acknowledgement')
  m.kubectl=kubectl
  try:
   with tempfile.TemporaryDirectory() as td:
    pp=pathlib.Path(td)/'pin.json';rr=pathlib.Path(td)/'receipt.json';pp.write_text(json.dumps(pin));rc,result=m.execute('apply',pp,'kubectl',rr);retained=json.loads(rr.read_text())
    self.assertEqual(rc,1);self.assertEqual(result['status'],'PARTIAL');self.assertTrue(result['unsafeToRetry']);self.assertEqual(result['transfers'][0]['state'],'CREATE_ATTEMPTING');self.assertEqual(result['transfers'][0]['destinationName'],'dest-one');self.assertEqual(retained,result)
  finally:m.check_transfer,m.destination,m.validate_startup_authority,m.kubectl=oldcheck,olddest,oldvalidate,oldkubectl

if __name__=='__main__':unittest.main()
