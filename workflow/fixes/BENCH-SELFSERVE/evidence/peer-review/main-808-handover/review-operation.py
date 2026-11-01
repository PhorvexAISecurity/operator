import ast,copy,datetime,hashlib,json,pathlib,subprocess
import yaml
R=pathlib.Path('/workspace/operator-benchmark-selfserve');E=R/'workflow/fixes/BENCH-SELFSERVE/evidence';O=E/'peer-review/main-808-handover'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();textsha=lambda v:hashlib.sha256(v.encode()).hexdigest()
operator=E/'live/apply-main-808-cleanup.py';proposal=E/'live-proposal-main-808/operation.json';prepath=E/'live-proposal-main-808/preconditions.json'
assert sha(operator)=='460a115a8c2d4bd1f8d8419b50d8510d836a2ad0118f9b11abc52a712ec50419'
assert sha(proposal)=='c6d005d4b0753bd353a546482c8f9e73e85473cc45c602ba9cda123e0e4ff8e5'
assert sha(prepath)=='c05da25c8bdc56bbecdecb2df1dc81ae8b17f9e367633881a630cd8c92578016'
op=json.loads(proposal.read_text());pre=json.loads(prepath.read_text());oldop=json.loads((E/'live-proposal-v8/operation.json').read_text())
assert op['expected_existing_templatePatch']==oldop['value']==pre['expected']['appset_spec']['templatePatch']
assert textsha(op['expected_existing_templatePatch'])==op['prior_templatePatch_sha256']=='bf3a66c31a2468fad2a2afea721ca3a3970281b075be770eb855583e22df256b'
oldsource='287fd2e4cd97c1ef8a0475b16316b04c6938b518';main='808079a03728b3ac5f449ba268bb91b20e95c93d'
assert op['expected_existing_templatePatch'].count(oldsource)==2
assert op['value']==op['expected_existing_templatePatch'].replace(oldsource,'main')
assert textsha(op['value'])==op['target_templatePatch_sha256']=='f75b4b057b322ebe45e113600203e7dc14c9f1d0fbff5f44e78090de887fa854'
assert op['chart_source']==op['values_source']=='main' and op['values_reviewed_at']==main
assert op['prune'] is False and op['temporary_source_pin'] is False and op['abort_on_main_change'] is True
assert pre['appset_identity']['uid']==op['expected_uid'] and pre['appset_identity']['generation']==20
for app in pre['apps'].values():assert app['health']['status']=='Healthy' and app['operation']=='Succeeded' and app['revisions']==[oldsource,oldsource]

def split(path):
    tree=ast.parse(path.read_text());found={};rest=[];branch_guards=[]
    for node in tree.body:
        key=node.targets[0].id if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) else None
        if key in ('payload','out','remote','patch'):found[key]=node;continue
        if isinstance(node,ast.Assert) and 'refs/heads/fix/benchmark-selfserve' in ast.unparse(node):branch_guards.append(node);continue
        rest.append(node)
    return found,ast.dump(ast.Module(body=rest,type_ignores=[]),include_attributes=False),branch_guards
old,oldbody,oldguards=split(E/'live/apply-reviewed-capture-v8.py');new,newbody,newguards=split(operator)
assert oldbody==newbody and len(oldguards)==1 and not newguards
payload=ast.literal_eval(new['payload'].value);assert payload=={'operation':op,'expected':pre['expected']}
assert ast.unparse(new['remote'])=="remote = run(['git', '-C', str(root / 'operator-refactored'), 'ls-remote', 'origin', 'refs/heads/main']).stdout"
assert ast.unparse(new['out'])=="out = root / 'stage-data/live/selfserve-capture-main-808079a0'"
app={'metadata':{'uid':pre['appset_identity']['uid'],'resourceVersion':pre['appset_identity']['resourceVersion']},'spec':pre['expected']['appset_spec']}
patch=eval(compile(ast.Expression(new['patch'].value),'<independent-read-only-expression>','eval'),{'__builtins__':{}},{'payload':payload,'app':app})
assert patch==[{'op':'test','path':'/spec/templatePatch','value':op['expected_existing_templatePatch']},{'op':'test','path':'/metadata/resourceVersion','value':app['metadata']['resourceVersion']},{'op':'test','path':'/metadata/uid','value':app['metadata']['uid']},{'op':'replace','path':'/spec/templatePatch','value':op['value']}]
assert sum(p['op']!='test' for p in patch)==1
# The conditional is byte-identical to prior reviewed Go-template predicate. Parse the inner YAML for each selected service.
assert op['value'].splitlines()[0]==oldop['value'].splitlines()[0] and op['value'].splitlines()[-1]=='{{- end }}'
branches=[]
for environment in ('staging','production'):
    for service in ('brain','manager','console','sensor','actuator','attacks'):
        active=environment=='staging' and service in ('brain','manager','console')
        if active:
            body='\n'.join(op['value'].splitlines()[1:-1])
            for key,value in {'environment':environment,'service':service,'release':'staging','chart':next(e['chart'] for e in pre['expected']['appset_spec']['generators'][0]['matrix']['generators'][1]['list']['elements'] if e['service']==service)}.items():body=body.replace('{{.'+key+'}}',value)
            sources=yaml.safe_load(body)['spec']['sources'];expected=copy.deepcopy(pre['apps']['app-'+service]['sources'])
            for source in expected:source['targetRevision']='main'
            assert sources==expected
        branches.append({'environment':environment,'service':service,'conditional_applies':active})
equiv=O/'source-equivalence.json';assert sha(equiv)=='6ad4b804db4c758e9c1ae1c8d518383724599692e721eca175f700089c970fc5'
inputs=[operator,proposal,prepath,equiv,E/'peer-review/live-proposal-v8/operational-verdict.json',pathlib.Path(__file__)]
out={'verdict':'PASS_GUARDED_MAIN808_RETARGET_ATTEMPT','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'current_main_required':main,'old_template_sha256':op['prior_templatePatch_sha256'],'target_template_sha256':op['target_templatePatch_sha256'],
 'operator_sha256':sha(operator),'operation_sha256':sha(proposal),'scope_branches':branches,
 'checks':['Exact two source revisions change287fd to main; all conditional/Helm/repository/valueFiles fields and unrelated apps preserved.',
 'Actual808 Git tree equals reviewed64d2/tested merge; all169 installed225 runtime blobs verified unchanged.',
 'Executable AST otherwise equals reviewedV8 guard algorithm. Removed obsolete issue-branch head assertion; main must still equal808 immediately before apply.',
 'Retains fresh full AppSet spec, UID/RV, all deployment images/args/generations/complete health, policy modes/generations, workload and Service identity/selector,4GiB reserve guards.',
 'Adds atomic exact template-value test. Only one mutating JSONPatch operation targets/spec/templatePatch; no prune/service restart/workload mutation is issued.'],
 'conditions':['One lead-owned attempt only after all immediate guards succeed. Abort on changed current main, owned template, UID, generation, health or capacity.',
 'AppSet compare-and-swap does not atomically freeze Git or all other cluster resources; observe actual application resolution and workload identities after apply.',
 'Only the currently merged808 contents are reviewed. Subsequent main changes follow ordinary release ownership and require truthful runtime source reconciliation.',
 'This is operation approval, not an already-completed cleanup or future-release guarantee. Verify both application source refs resolve808/main, capture/grants remain, observer continuity and protected state remain, and no temporary287 source pin remains.',
 'Release CI failure is separately retained; no new brain image publication or claim that every main workflow passed.'],
 'evidence':[{'path':str(p.relative_to(R)),'sha256':sha(p),'bytes':p.stat().st_size} for p in inputs]}
p=O/'operational-verdict.json';p.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'path':str(p),'sha256':sha(p),'verdict':out['verdict']},indent=2))
