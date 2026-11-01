import datetime,hashlib,json,pathlib,subprocess
import yaml
R=pathlib.Path('/workspace/operator-benchmark-selfserve');E=R/'workflow/fixes/BENCH-SELFSERVE/evidence';P=E/'live-proposal-v4';O=E/'peer-review/live-proposal-v4';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();git=lambda *a:subprocess.check_output(['git',*a],cwd=R)
m=json.loads((P/'proposal-manifest.json').read_bytes())
for f in m['files']:assert sha(R/f['path'])==f['sha256']
op=json.loads((P/'operation.json').read_bytes());old=json.loads((E/'live-proposal-v3/operation.json').read_bytes());pre=json.loads((E/'live/bee9-a5f-capture-preconditions.json').read_bytes());ex=json.loads((P/'expected.json').read_bytes());assert ex==pre['expected']
source='4dc325d300993d0aaec5f5a6d607951cdadd3f62';main='a5f32f9dba5ed6e756f11b73ece968d54805c3e2';live='bee9caccf3bae388d412e72adfe50ca9de41a486'
assert op['chart_source']==op['values_source']==source==m['source'] and op['values_reviewed_at']==main==m['upstream_main'];assert m['expected_live_source']==live
assert op['value']==(P/'templatePatch.yaml.gotmpl').read_text()==old['value'].replace(old['chart_source'],source)
assert op['expected_existing_templatePatch'] is None and op['test_fresh_resourceVersion'] and op['prune'] is False and op['temporary_source_pin'] and op['expiry_condition']
base=ex['appset_spec']['template']['spec']['sources']
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
for a in pre['apps'].values():assert a['health']['status']=='Healthy' and a['operation']=='Succeeded' and a['revisions']==[main,main]
byname={d['name']:d for d in ex['deployments']};images={}
for comp,name in [('brain','staging-brain'),('manager','staging-phorvex'),('console','staging-phorvex-console')]:
 v=yaml.safe_load(git('show',source+':deploy/environments/staging/'+comp+'.yaml'))
 i=v['image'] if comp=='brain' else v['phorvex']['image'] if comp=='manager' else v['phorvex']['console']['image']
 image=i['repository']+':'+i['tag']+'@'+i.get('digest',i.get('releaseDigest'));assert [c['image'] for c in byname[name]['containers']]==[image] and live in image;images[comp]=image
previous=json.loads((E/'live-proposal-v3/expected.json').read_bytes())
for kind,keys in [('policies',['name','uid','generation','mode']),('workloads',['name','uid','generation','selector','replicas']),('services',['name','uid','selector'])]:assert [{k:x[k] for k in keys} for x in ex[kind]]==[{k:x[k] for k in keys} for x in previous[kind]]
assert git('show',source+':deploy/environments/staging/phorvex.yaml')==git('show',main+':deploy/environments/staging/phorvex.yaml')
proof=E/'peer-review/upstream-a5f/commit-binding-4dc325d3.json';assert sha(proof)=='8382d871e40bd27968f78be640fc553f40c7f9e379ae7f2ca913fbe1355fe136';guard=json.loads((O/'guard-equivalence.json').read_bytes());assert guard['executable_ast_equal_except_exact_payload_and_output_directory'] and guard['script4_sha256']=='d8d3dce5d2f4182790d2f1cd59437558960e7d6684c568d8bcdc250290092230'
report={'schema':'phorvex-bench.operational-proposal-peer-review.v4','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verdict':'PASS_FOR_BOUNDED_LIVE_ATTEMPT','source':source,'main':main,'actual_image_source':live,'images':images,'template_cases':{'total':24,'selected_staging':3,'empty_unmodified':21,'missing_key_rejected':True},'checks':['Every proposal manifest file hash verified; embedded operator payload equals fresh19:48:24 actual preconditions and expected.json.','Executable Python AST identical to accepted V3 except exact embedded payload and evidence output directory. All fresh source/main, full AppSet/UID/RV, deployment/policy/workload/Service identity, complete rollout/health and4GiB guards preserved.','Go template differs V3 only both source revisions; all repository/path/release/skipCrds/orderedvalueFiles fields preserved. Only selected3 staging application source arrays change.','Committed4dc exact source binding accepted. Current closed a5f family preserved except independently proven canonical inactive-image field with no rendered effect; newbee9 image tags/digests exactly equal all3 actual deployment preconditions.','Both policy UID/generation/mode, workload UID/generation/selectors/replicas and Service UID/selectors remain unchanged from prior approved scope. Native61e historical receipts are not relabelled as currentbee9 evidence.'],'conditions':['Root applies only after round3 preregistration/rebaseline and fresh guard success; remote exact issue/main refs checked at execution.','Temporary pin freezes selected3 apps; root monitors main/effective images and removes exact override before unreviewed subsequent release and after durable merge.','ApplicationSet UID/RV CAS is atomic for that object; other fresh observations are not a cross-object transaction. Detected intervening changes require stop/review.','This is proposal acceptance only. Actual Argo rollout, source-native reconciliation, authenticated capture and real bot/history results remain separate pending evidence.'],'evidence':{str(p.relative_to(R)):{'sha256':sha(p),'bytes':p.stat().st_size} for p in [P/'proposal-manifest.json',P/'operation.json',P/'expected.json',P/'templatePatch.yaml.gotmpl',E/'live/apply-reviewed-capture-v4.py',E/'live/bee9-a5f-capture-preconditions.json',proof,O/'guard-equivalence.json',O/'template-output.json',O/'template-stderr.txt',pathlib.Path(__file__)]}}
p=O/'operational-verdict.json';p.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(p.relative_to(R)),'sha256':sha(p),'verdict':report['verdict']},indent=2))
