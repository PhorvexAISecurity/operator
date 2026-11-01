#!/usr/bin/env python3
import copy,datetime,hashlib,io,json,pathlib,subprocess,tarfile,tempfile
import yaml
ROOT=pathlib.Path('/workspace/operator-benchmark-selfserve')
PROPOSAL=ROOT/'workflow/fixes/BENCH-SELFSERVE/evidence/live-proposal'
OUT=ROOT/'workflow/fixes/BENCH-SELFSERVE/evidence/peer-review/live-proposal'
sha=lambda b:hashlib.sha256(b).hexdigest()
git=lambda *args:subprocess.check_output(['git',*args],cwd=ROOT)
manifest=json.loads((PROPOSAL/'proposal-manifest.json').read_bytes())
for path,digest in manifest['artifacts'].items():assert sha((PROPOSAL/path).read_bytes())==digest,path
operation=json.loads((PROPOSAL/'operation.json').read_bytes())
assert operation['value']==(PROPOSAL/'templatePatch.yaml.gotmpl').read_text()
assert operation['chart_source']==manifest['chart_source']=='6ae89857369468d4ca39a6856d9fd55c3b5debd3'
assert operation['values_source']=='main'
assert manifest['main_values_reviewed_at']==operation['values_reviewed_at']=='c3174a516bee6bf8eae39749825051c3cfcb8cc6'
before=json.loads((PROPOSAL/'before.json').read_bytes());app=before['applicationset']
assert app['metadata']['uid']==operation['expected_uid']
assert app['spec'].get('templatePatch') is None
assert app['spec']['goTemplate'] is True and app['spec']['goTemplateOptions']==['missingkey=error']
assert app['spec']['template']['spec']['syncPolicy']['automated']['prune'] is False
assert operation['operation']=='add /spec/templatePatch' and operation['test_fresh_resourceVersion'] is True
assert set(operation)=={'kind','namespace','name','expected_uid','test_fresh_resourceVersion','expected_existing_templatePatch','operation','value','chart_source','values_source','values_reviewed_at','prune'}
extra=json.loads((PROPOSAL/'overrides.json').read_bytes())
rows=json.loads((OUT/'template-output.json').read_bytes());assert len(rows)==24
patches={}
def substitute(v,params):
 if isinstance(v,str):
  for k,value in params.items(): v=v.replace('{{.'+k+'}}',value)
  return v
 if isinstance(v,list):return [substitute(x,params) for x in v]
 if isinstance(v,dict):return {k:substitute(x,params) for k,x in v.items()}
 return v
for row in rows:
 params=row['params'];patch=yaml.safe_load(row['patch'])
 expected=params['environment']=='staging' and params['service'] in extra
 if not expected:assert patch is None,(params,patch);continue
 assert set(patch)=={'spec'} and set(patch['spec'])=={'sources'}
 previous=substitute(app['spec']['template']['spec']['sources'],params)
 desired=copy.deepcopy(previous)
 desired[0]['targetRevision']=operation['chart_source'];desired[0]['helm']['valuesObject']=extra[params['service']]
 assert patch['spec']['sources']==desired,params
 assert desired[1]['targetRevision']=='main'
 patches[params['service']]=patch
assert len(patches)==3
for p in (PROPOSAL/'main-values').iterdir():
 assert p.read_bytes()==git('show',operation['values_reviewed_at']+':deploy/environments/staging/'+p.name),p.name
for service in extra:
 assert yaml.safe_load((PROPOSAL/(service+'-override.yaml')).read_bytes())==extra[service]
# Each override leaf is capture/read-only access only; no image, namespace or family field.
assert extra['brain']=={'phorvex':{'mathLab':{'capturePolicies':['phorvex-staging-demo/demo-api-defense','phorvex-staging-demo/stage-bench-defense'],'captureMaxBytes':1073741824}},'mathLabStore':{'existingClaim':'staging-brain-mathlab'}}
assert extra['manager']=={'phorvex':{'mathLab':{'captureCostEvidence':True}}}
grants=extra['console']['phorvex']['console']['auth']['grants']
assert list(grants)==['extraSubjects'] and len(grants['extraSubjects'])==1
reader=grants['extraSubjects'][0]
assert reader['subject']=='system:serviceaccount:phorvex-staging:staging-brain-benchmark' and reader['roles']==['investor'] and reader['tenants']==['phorvex-staging-demo'] and reader['targets']==['default']

def docs(raw):
 result={}
 for doc in yaml.safe_load_all(raw):
  if not doc:continue
  # Match documented offline-only redaction, never use any cluster secret material.
  if doc['kind']=='Secret':
   if 'data' in doc:doc['data']={k:'<redacted-render-generated>' for k in doc['data']}
   if 'stringData' in doc:doc['stringData']={k:'<redacted-render-generated>' for k in doc['stringData']}
  if doc['kind'] in ('MutatingWebhookConfiguration','ValidatingWebhookConfiguration'):
   for item in doc.get('webhooks',[]):item.get('clientConfig',{}).pop('caBundle',None)
  result[(doc['apiVersion'],doc['kind'],doc['metadata']['name'])]=doc
 return result

def render(source,service,override):
 chart='phorvex/charts/phorvex' if service=='manager' else 'deploy/charts/phorvex-'+service
 args=['/workspace/.phorvex-tools/helm','template','staging',str(source/chart),'-n','phorvex-staging','--api-versions','monitoring.coreos.com/v1/PodMonitor']
 for value in ['phorvex.yaml',service+'.yaml','catalogue-family.yaml']:args+=['-f',str(PROPOSAL/'main-values'/value)]
 if override:args+=['-f',str(PROPOSAL/(service+'-override.yaml'))]
 return docs(subprocess.check_output(args))
render_receipts={}
with tempfile.TemporaryDirectory(dir='/workspace/.phorvex-test-tmp',prefix='proposal-peer-') as d:
 tmp=pathlib.Path(d)
 for label,commit in [('main',operation['values_reviewed_at']),('proposed',operation['chart_source'])]:
  target=tmp/label;target.mkdir()
  raw=git('archive',commit,'deploy/charts','phorvex/charts')
  with tarfile.open(fileobj=io.BytesIO(raw)) as tf:tf.extractall(target,filter='data')
 for service in extra:
  previous=render(tmp/'main',service,False);current=render(tmp/'proposed',service,True)
  assert previous==docs((PROPOSAL/(service+'-render-main.yaml')).read_bytes()),service+' main render'
  assert current==docs((PROPOSAL/(service+'-render-proposed.yaml')).read_bytes()),service+' proposed render'
  assert set(previous)==set(current),service+' resources'
  images=[]
  for key,doc in previous.items():
   if doc['kind']=='Deployment':
    pre=doc['spec']['template']['spec']['containers'];post=current[key]['spec']['template']['spec']['containers']
    assert [(c['name'],c['image']) for c in pre]==[(c['name'],c['image']) for c in post]
    images.extend([c['image'] for c in post])
  if service=='console':
   key=next(k for k in previous if k[1]=='ConfigMap' and 'grants.json' in previous[k].get('data',{}))
   pre=json.loads(previous[key]['data']['grants.json']);post=json.loads(current[key]['data']['grants.json'])
   assert pre['subjects']==post['subjects'][:-1]
   assert all(g['tenants']==['p1-demo'] for g in pre['subjects'])
   assert post['subjects'][-1]==reader
  render_receipts[service]={'exact_main_and_proposed_render_match':True,'resource_set_preserved':True,'images':images}
record={'schema':'phorvex-bench.operational-proposal-peer-review.v1','reviewer':'stage-review','reviewed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verdict':'PASS','scope':'Exact proposed ApplicationSet templatePatch and effective Helm inputs; not proof that deployment has executed or succeeded.','proposal_manifest_sha256':sha((PROPOSAL/'proposal-manifest.json').read_bytes()),'operation_sha256':sha((PROPOSAL/'operation.json').read_bytes()),'template_sha256':sha((PROPOSAL/'templatePatch.yaml.gotmpl').read_bytes()),'before_sha256':sha((PROPOSAL/'before.json').read_bytes()),'chart_source':operation['chart_source'],'main_values_reviewed_at':operation['values_reviewed_at'],'go_template_cases':{'total':24,'staging_modified':3,'unmodified':21,'missing_key_rejected':True},'effective_source_changes':'Only source0 targetRevision and narrow helm.valuesObject change for staging brain/manager/console. Original source1 main, all three valueFiles, release/skipCrds, repo/path remain exactly equal. No patch to any other Application spec field or generator.','renders':render_receipts,'grant_result':'Both current quarantine/p1-demo family subjects fully preserved, one exact investor demo/default reader appended. No old identity-family scopes restored.','operational_conditions':['Lead must use fresh UID/resourceVersion compare-and-swap and verify existing templatePatch still absent, exact policyUID/image/source and rollout/disk conditions before applying.','Initial before.json showed upstream manager/console rollout Progressing; this source verdict does not establish later health.','Values source intentionally remains main; unexpected subsequent main changes require checking effective desired state. Temporary chart pin must be tracked for eventual GitOps handover.','No prune and no live writes performed by reviewer. Actual capture/download/benchmark acceptance remains required.'],'evidence':{str(p.relative_to(ROOT)):{'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in sorted(OUT.iterdir()) if p.is_file()}}
p=OUT/'operational-verdict.json';p.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'verdict':'PASS','path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes()),'go_template_cases':record['go_template_cases']},indent=2))
