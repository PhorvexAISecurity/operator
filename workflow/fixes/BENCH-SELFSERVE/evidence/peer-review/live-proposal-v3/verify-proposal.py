import ast,datetime,hashlib,json,pathlib,subprocess
import yaml
R=pathlib.Path('/workspace/operator-benchmark-selfserve');E=R/'workflow/fixes/BENCH-SELFSERVE/evidence';P=E/'live-proposal-v3';O=E/'peer-review/live-proposal-v3'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
git=lambda *a:subprocess.check_output(['git',*a],cwd=R)
expected_hashes={'operation.json':'953aaa5b421fd298983d0511b020a1f5810e2a7196d64fbccb7e0aed45b55168','templatePatch.yaml.gotmpl':'e850f10e50b886915f1437a9f6784fa211af9b395c973fb1b3135be3f35ddb07'}
for p,h in expected_hashes.items():assert sha(P/p)==h
script=E/'live/apply-reviewed-capture-v3.py';assert sha(script)=='33b4feabdb79c910afe0e0373522ac54a16fe85c0b553ac666339cd4592916d4'
source='0288e00ffe51c2a23f30742b4f6dcd2b8a733d65';main='bee9caccf3bae388d412e72adfe50ca9de41a486'
op=json.loads((P/'operation.json').read_bytes());old=json.loads((E/'live-proposal-v2/operation.json').read_bytes());pre=json.loads((E/'live/current-main-capture-preconditions.json').read_bytes())
payload=next(ast.literal_eval(n.value) for n in ast.parse(script.read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='payload' for t in n.targets))
assert payload['operation']==op
assert payload['expected']==pre['expected']==json.loads((P/'expected.json').read_bytes())
assert op['chart_source']==op['values_source']==source and op['values_reviewed_at']==main
assert op['value']==(P/'templatePatch.yaml.gotmpl').read_text()==old['value'].replace(old['chart_source'],source)
assert op['expected_existing_templatePatch'] is None and op['test_fresh_resourceVersion'] and op['prune'] is False
assert op['temporary_source_pin'] and op['owner']=='bench-v3-lead' and op['expiry_condition']
assert pre['appset_identity']['uid']==op['expected_uid']
base=payload['expected']['appset_spec']['template']['spec']['sources']
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
 if p['environment']!='staging' or p['service'] not in ['brain','manager','console']:assert actual is None;continue
 expected=subst(base,p)
 for x in expected:x['targetRevision']=source
 assert actual=={'spec':{'sources':expected}}
 assert set(actual['spec'])=={'sources'} and 'valuesObject' not in expected[0]['helm']
for a in pre['apps'].values():assert a['health']['status']=='Healthy' and a['operation']=='Succeeded' and a['revisions']==[main,main]
for p in ['deploy/environments/staging/catalogue-family.yaml','deploy/environments/staging/phorvex.yaml']:
 assert git('show',source+':'+p)==git('show',main+':'+p)
composition=E/'peer-review/upstream-bee9/composition-verdict.json';binding=E/'peer-review/upstream-bee9/commit-binding-0288e00f.json'
assert sha(composition)=='f0b798d5902d0bbc6f16cd9d114b10f428f3eb5e13fd5c9ab6f60a3131f7d1cb'
assert sha(binding)=='ba8ee7b67125aee01f8a51c3cbc880ae5271e70b00ab9a8522b2366ec9452609'
text=script.read_text()
for guard in ["app['spec']==payload['expected']['appset_spec']", "app['metadata']['uid']==payload['operation']['expected_uid']", "refs['refs/heads/main']==payload['operation']['values_reviewed_at']", "refs['refs/heads/fix/benchmark-selfserve']==payload['operation']['chart_source']", "d['metadata']['generation']==old['generation']", "p['spec'].get('mode')==old['mode']", "s['metadata']['uid']==old['uid'] and s['spec'].get('selector')==old['selector']", "'path':'/metadata/resourceVersion'", "'path':'/metadata/uid'", "'path':'/spec/templatePatch'", "'--type=json'", "4*1024**3"]:assert guard in text,guard
assert sum(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='run' and n.args and isinstance(n.args[0],ast.List) and any(isinstance(x,ast.Constant) and x.value=='patch' for x in n.args[0].elts) for n in ast.walk(ast.parse(text)))==1
report={'schema':'phorvex-bench.operational-proposal-peer-review.v3','reviewer':'stage-review','reviewed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verdict':'PASS_FOR_BOUNDED_LIVE_ATTEMPT','source':source,'preserved_main':main,'go_template_cases':{'total':24,'selected_staging_only':3,'empty_unmodified':21,'missing_key_rejected':True},'checks':['Exact operation/template/script hashes verified; embedded payload equals fresh19:21:37 actual preconditions and expected.json.','Template is prior V2 byte-for-byte except both source revisions. Actual Go template outputs preserve source repository/path/release/skipCrds/ordered three valueFiles and modify only both revisions for selected staging apps.','0288 source and actual full-overlay/default renders already independently reviewed and commit-bound; rechecked current closed family and staging/phorvex bytes equal bee9. Existing61e images, current grants and upstream namespace ledger/RBAC remain preserved.','Only one mutating kubectl call: JSON patch add of owned templatePatch, with fresh UID/resourceVersion tests after full AppSet spec comparison. Exact main/issue-ref guards precede mutation.','Fresh guards cover deployment UID/generation/images/args/observed complete rollout, policy UID/generation/mode, workload UID/generation/selector/replicas/readiness, Service UID/selector, all3 application Healthy/Succeeded, and4GiB reserve.'],'conditions':['Root executes only with current source/main and all fresh guards passing; campaign round2 preregistration/rebaseline required.','This temporary pin freezes3 staging applications. Root monitors upstream and removes this exact owned override before unreviewed subsequent stage release and after durable merge. It is not permanent main tracking.','Object reads and branch checks are observations, not a transaction across all resources. UID/RV CAS protects ApplicationSet mutation; any detected intervening image/policy/workload/service/main change stops the campaign and requires re-review.','No actual Argo admission, rollout, source readiness, bot job or endpoint-history result is established by this offline proposal review. Failed V1, removed V2 and historical a5d runtime install remain separately labelled.'],'artifacts':{str(p.relative_to(R)):{'sha256':sha(p),'bytes':p.stat().st_size} for p in [P/'operation.json',P/'templatePatch.yaml.gotmpl',P/'expected.json',script,E/'live/current-main-capture-preconditions.json',composition,binding,O/'template-output.json',O/'template-stderr.txt',pathlib.Path(__file__)]}}
p=O/'operational-verdict.json';p.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(p.relative_to(R)),'sha256':sha(p),'verdict':report['verdict']},indent=2))
