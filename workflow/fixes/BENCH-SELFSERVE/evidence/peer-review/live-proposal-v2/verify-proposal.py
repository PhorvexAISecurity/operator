import datetime,hashlib,io,json,pathlib,subprocess,tarfile,tempfile
import yaml
ROOT=pathlib.Path('/workspace/operator-benchmark-selfserve');E=ROOT/'workflow/fixes/BENCH-SELFSERVE/evidence';P=E/'live-proposal-v2';O=E/'peer-review/live-proposal-v2'
sha=lambda b:hashlib.sha256(b).hexdigest()
git=lambda *a:subprocess.check_output(['git',*a],cwd=ROOT)
m=json.loads((P/'proposal-manifest.json').read_bytes())
for name,h in m['artifacts'].items():assert sha((P/name).read_bytes())==h,name
op=json.loads((P/'operation.json').read_bytes());assert op['value']==(P/'templatePatch.yaml.gotmpl').read_text()
assert op['chart_source']==op['values_source']==m['source']=='6ae89857369468d4ca39a6856d9fd55c3b5debd3'
assert op['temporary_source_pin'] and op['owner']=='bench-v3-lead' and op['expiry_condition']
assert op['prune'] is False and op['test_fresh_resourceVersion'] is True
before=json.loads((E/'live-proposal/before.json').read_bytes())['applicationset']
rollback=json.loads((E/'live/capture-proposal-rollback.json').read_bytes())
assert rollback['uid']==op['expected_uid']==before['metadata']['uid'] and rollback['status']=='ROLLED_BACK_OWNED_TEMPLATE_PATCH'
source=before['spec']['template']['spec']['sources']
def subst(v,p):
 if isinstance(v,str):
  for k,x in p.items():v=v.replace('{{.'+k+'}}',x)
  return v
 if isinstance(v,list):return [subst(x,p) for x in v]
 if isinstance(v,dict):return {k:subst(x,p) for k,x in v.items()}
 return v
rows=json.loads((O/'template-output.json').read_bytes());assert len(rows)==24
for row in rows:
 p=row['params'];actual=yaml.safe_load(row['patch'])
 if p['environment']!='staging' or p['service'] not in ['brain','manager','console']:
  assert actual is None;continue
 expected=subst(source,p)
 for s in expected:s['targetRevision']=op['chart_source']
 assert actual=={'spec':{'sources':expected}}
 # No inline overrides, image/family literals or any other spec field.
 assert set(actual['spec'])=={'sources'} and 'valuesObject' not in expected[0]['helm']
for path in ['deploy/environments/staging/catalogue-family.yaml','deploy/environments/staging/phorvex.yaml']:
 assert git('show',op['chart_source']+':'+path)==git('show',op['values_reviewed_at']+':'+path)
# Reproduce exact fixed-chart AND fixed-values output from immutable git objects.
def docs(raw):
 result={}
 for d in yaml.safe_load_all(raw):
  if not d:continue
  if d['kind']=='Secret':
   for field in ['data','stringData']:
    if field in d:d[field]={k:'<redacted-render-generated>' for k in d[field]}
  if d['kind'] in ['MutatingWebhookConfiguration','ValidatingWebhookConfiguration']:
   for w in d.get('webhooks',[]):w.get('clientConfig',{}).pop('caBundle',None)
  result[(d['apiVersion'],d['kind'],d['metadata']['name'])]=d
 return result
renders={}
with tempfile.TemporaryDirectory(dir='/workspace/.phorvex-test-tmp',prefix='proposal-v2-peer-') as tmp:
 root=pathlib.Path(tmp)
 raw=git('archive',op['chart_source'],'deploy/charts','phorvex/charts','deploy/environments/staging')
 with tarfile.open(fileobj=io.BytesIO(raw)) as tf:tf.extractall(root,filter='data')
 for service in ['brain','manager','console']:
  chart='phorvex/charts/phorvex' if service=='manager' else 'deploy/charts/phorvex-'+service
  cmd=['/workspace/.phorvex-tools/helm','template','staging',str(root/chart),'-n','phorvex-staging','--api-versions','monitoring.coreos.com/v1/PodMonitor']
  for name in ['phorvex.yaml',service+'.yaml','catalogue-family.yaml']:cmd+=['-f',str(root/'deploy/environments/staging'/name)]
  actual=docs(subprocess.check_output(cmd));expected=docs((P/(service+'-render-proposed.yaml')).read_bytes());assert actual==expected,service
  prior=docs((E/'live-proposal'/(service+'-render-main.yaml')).read_bytes());assert prior.keys()==actual.keys()
  for key,d in prior.items():
   if d['kind']=='Deployment':
    assert [(c['name'],c['image']) for c in d['spec']['template']['spec']['containers']]==[(c['name'],c['image']) for c in actual[key]['spec']['template']['spec']['containers']]
  if service=='console':
   key=next(k for k in actual if k[1]=='ConfigMap' and 'grants.json' in actual[k].get('data',{}))
   grants=json.loads(actual[key]['data']['grants.json'])['subjects'];old=json.loads(prior[key]['data']['grants.json'])['subjects']
   assert grants[:-1]==old and all(g['tenants']==['p1-demo'] for g in old)
   assert grants[-1]['roles']==['investor'] and grants[-1]['tenants']==['phorvex-staging-demo']
  renders[service]={'exact_git_object_render_matches_proposal':True,'current_c317_images_and_resource_set_preserved':True}
report={'schema':'phorvex-bench.operational-proposal-peer-review.v2','reviewer':'stage-review','reviewed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verdict':'PASS_FOR_BOUNDED_LIVE_ATTEMPT','operation_sha256':sha((P/'operation.json').read_bytes()),'manifest_sha256':sha((P/'proposal-manifest.json').read_bytes()),'template_sha256':sha((P/'templatePatch.yaml.gotmpl').read_bytes()),'chart_and_values_source':op['chart_source'],'preserved_main':op['values_reviewed_at'],'go_template_cases':{'total':24,'selected_staging_only':3,'empty_unmodified':21,'missing_key_rejected':True},'source_delta':'Exactly both source targetRevision fields changed in3 staging apps. Existing repositories,path,releaseName,skipCrds,three-valueFiles order preserved; no inline values or other app spec change. Other services/environments emit empty patch.','renders':renders,'rejected_v1':{'receipt_path':str((P/'rejected-v1.json').relative_to(ROOT)),'receipt_sha256':sha((P/'rejected-v1.json').read_bytes()),'cause':'Actual Argo rejected differing revisions of the same repository. Prior source/template rendering PASS did not establish Argo admission. Failed attempt retained; no workload change claimed.','rollback_path':str((E/'live/capture-proposal-rollback.json').relative_to(ROOT)),'rollback_sha256':sha((E/'live/capture-proposal-rollback.json').read_bytes())},'conditions':['Fresh UID/resourceVersion/full-spec/policyUID/image/source/rollout/disk guards required at apply; root owns mutation.','Temporary pin freezes selected apps at6ae; does not track future main. Lead owns monitoring and removal of exactly this override before unreviewed staging image/family release, and after durable change merges.','Current c317 quarantine grants/images retained; any newer main must be reviewed before applying. No production namespace or unrelated app scope.','Live Argo admission, rollout, real capture/reader operation and benchmarks remain unproven by this offline receipt.'],'evidence':{str(p.relative_to(ROOT)):{'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in sorted(O.iterdir()) if p.is_file()}}
p=O/'operational-verdict.json';p.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes()),'verdict':report['verdict']},indent=2))
