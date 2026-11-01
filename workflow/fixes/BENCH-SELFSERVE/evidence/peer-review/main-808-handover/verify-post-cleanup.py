import copy,datetime,hashlib,json,pathlib
B=pathlib.Path('workflow/fixes/BENCH-SELFSERVE/evidence'); P=B/'peer-review/main-808-handover'
load=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
x=load(P/'post-cleanup-read-1.json');obj=x['objects'];rt=x['runtime'];before=load(B/'live-proposal-main-808/preconditions.json');op=load(B/'live-proposal-main-808/operation.json');old=load(B/'live/capture-v8-rollout-1.json');install=load(B/'live/runtime-install-receipt-225877.json')
main='808079a03728b3ac5f449ba268bb91b20e95c93d';source='b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0'
expected=copy.deepcopy(before['expected']['appset_spec']);expected['templatePatch']=op['value']
assert obj['appset']['spec']==expected
assert obj['appset']['identity']['uid']==before['appset_identity']['uid'] and obj['appset']['identity']['generation']==21
assert hashlib.sha256(obj['appset']['spec']['templatePatch'].encode()).hexdigest()==op['target_templatePatch_sha256']
apps={}
for name in ('brain','manager','console'):
 key='app-'+name;y=obj[key];ss=copy.deepcopy(before['apps'][key]['sources'])
 for s in ss:s['targetRevision']='main'
 assert y['sources']==ss and y['sync']['comparedTo']['sources']==ss
 assert y['sync']['revisions']==[main,main] and y['health']['status']=='Healthy' and y['operation']=='Succeeded' and not y['conditions']
 residual=y['outofsync_resources']
 assert all(r.get('requiresPruning') and r['kind'] in ('ClusterRole','ClusterRoleBinding','Role','RoleBinding') for r in residual)
 assert residual==old[key]['outofsync_resources']
 apps[key]={'revisions':y['sync']['revisions'],'health':y['health']['status'],'operation':y['operation'],'sync_status':y['sync']['status'],'preexisting_prune_only_rbac':len(residual)}
for y in before['expected']['deployments']:
 z=obj[y['name']];assert z['identity']['uid']==y['uid'] and z['identity']['generation']==y['generation']
 assert [{k:c[k] for k in ('name','image','args')} for c in z['containers']]==y['containers']
 assert z['status']['observedGeneration']==z['identity']['generation']
 assert all(z['status'].get(k)==z['replicas']==1 for k in ('replicas','readyReplicas','updatedReplicas','availableReplicas'))
 assert z['volumes']==old[y['name']]['volumes'] and z['securityContext']==old[y['name']]['securityContext']
 assert z['containers']==[{k:c[k] for k in ('name','image','args','volumeMounts')} for c in old[y['name']]['containers']]
for y in before['expected']['policies']:
 z=obj[y['name']];assert all(z['identity'][k]==y[k] for k in ('uid','generation'));assert z['mode']==y['mode']
for y in before['expected']['workloads']:
 z=obj['workload-'+y['name']];assert all(z['identity'][k]==y[k] for k in ('uid','generation'));assert z['replicas']==y['replicas'] and z['selector']==y['selector']
 assert z['status']['observedGeneration']==y['generation'] and all(z['status'].get(k)==y['replicas'] for k in ('replicas','readyReplicas','updatedReplicas','availableReplicas'))
for y in before['expected']['services']:
 z=obj['service-'+y['name']];assert z['identity']['uid']==y['uid'] and z['selector']==y['selector']
assert obj['pvc']['identity']['uid']==old['pvc']['identity']['uid'] and obj['pvc']['status']==old['pvc']['status']
assert obj['grants']['identity']['uid']==old['grants']['identity']['uid'] and obj['grants']['data']==old['grants']['data'] and obj['grants']['sha256']==old['grants']['sha256']
assert x['pin_matches_observation'] and rt['pin']['sha256']=='a5f4f0909efe81b3277ddea029550eab970f5ff107fa4bc1738b90ed89173bcb'
assert rt['pin']['value']['brain']['git_sha']==rt['pin']['value']['manager']['git_sha']==source
assert x['live_observation']['brain']['git_sha']==x['live_observation']['manager']['git_sha']==source
assert x['live_observation']['capture']==rt['pin']['value']['capture']
assert x['replay_binary']['sha256']=='c5bf81d5a9589ec822a3ed9c2112c3e88603634530d573276662b5250fc6f51e' and x['replay_binary']['version']['gitSHA']==source
assert rt['protected_hashes']==install['protected_after'] and rt['checkout_head']==install['checkout_before'] and rt['current_link']==install['current_link_before']
for key,prior in install['unrelated_before'].items():
 assert all(rt[key][k]==v for k,v in prior.items())
for key in ('phorvex-stage-observer.service','phorvex-benchmark-bot.service','phorvex-stage-endpoint-refresh.timer','phorvex-stage-reconcile.timer'):
 assert rt[key]['ActiveState']=='active' and rt[key]['UnitFileState']=='enabled'
assert rt['phorvex-stage-observer.service']['MainPID']=='1648552' and rt['phorvex-stage-observer.service']['NRestarts']=='0'
assert rt['phorvex-benchmark-bot.service']['MainPID']=='1735737'
observer=rt['observer']['value'];assert observer['state']=='RUNNING' and observer['owned_pid']==1705633 and observer['descriptor']['scope']['source_revision']==source
assert observer['descriptor']['scope']['service_uid']==obj['service-stage-bench-api']['identity']['uid']
assert x['free_bytes']>=4*1024**3
files=[P/'post-cleanup-read-1.json',P/'read-post-cleanup.py',P/'source-equivalence.json',P/'operational-verdict.json',B/'live/main-808-cleanup-apply.json',B/'live-proposal-main-808/preconditions.json',B/'live/capture-v8-rollout-1.json',B/'live/runtime-install-receipt-225877.json',P/'verify-post-cleanup.py']
result={'verdict':'PASS_OBSERVED_MAIN808_HANDOVER_AND_TEMPORARY_PIN_CLEANUP','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'observation_start':x['started_at'],'observation_end':x['completed_at'],'main':main,'actual_brain_source':source,'installed_runtime':'225877a8ecb4c11eb39980ba932c114f7a8068a4','apps':apps,'appset':obj['appset']['identity'],'temporary_pin_removed':True,'protected_state_unchanged':True,'observer_supervisor_pid':1648552,'observer_child_pid':1705633,'bot_pid':1735737,'refresh_at_observation':rt['refresh']['value']['state'],'checks':['Full AppSet spec unchanged except approved two refs to main; all six app source resolutions808.','Three deployments retain exact UID/generation/image/args/volumes and complete health; both policy modes/UID/generation, workloads and Service identity/selectors retained.','Persistent capture both policies, PVC, manager cost evidence, exact closed-family grants plus investor preserved.','Fresh actual embedded B1 runtime observation matches unchanged atomic pin/native replay hash; no claim main808 is the running brain image.','Observer supervisor/child and bot PIDs continuous; maintenance timers enabled/active; private protected hashes, unrelated services, source checkout and current symlink preserved.'],'limits':['Read-only sampled post-state, not atomic global freeze or guarantee across future external changes.','Manager/console retain exact preexisting prune-only RBAC OutOfSync resources; no prune authorized or performed.','Automatic refresh RUNNING at sample, so this receipt does not claim that new refresh finished. Prior actual READY64 and paired results remain separately bound.','Prior original ten-day request remains BLOCKED; no physical calibration/security efficacy or long-history guarantee.','Historical Release workflow failure is separately retained; no all-workflows-green or new brain-image publication claim.'],'evidence':[{'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size} for p in files]}
(P/'post-cleanup-verdict.json').write_text(json.dumps(result,indent=2)+'\n');print(result['verdict']);print(sha(P/'post-cleanup-verdict.json'))
