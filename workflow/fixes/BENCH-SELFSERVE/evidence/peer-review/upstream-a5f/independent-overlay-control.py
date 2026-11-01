import datetime,hashlib,io,json,os,pathlib,subprocess,tarfile,tempfile
import yaml
R=pathlib.Path('/workspace/operator-benchmark-selfserve');E=R/'workflow/fixes/BENCH-SELFSERVE/evidence';O=E/'peer-review/upstream-a5f';BASE='a5f32f9dba5ed6e756f11b73ece968d54805c3e2';HEAD='48b02fadf34decc26d3e3e4f16fce0eb0b8f3df5'
git=lambda *a:subprocess.check_output(['git',*a],cwd=R);sha=lambda b:hashlib.sha256(b).hexdigest();py='/workspace/.phorvex-tools/python312/python/bin/python3.12';env=dict(os.environ,PATH='/workspace/.phorvex-tools/python312/python/bin:/workspace/.phorvex-tools:'+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1')
expected=['deploy/environments/staging/catalogue-family.yaml','phorvex/internal/console/attack_catalog_integration_test.go','phorvex/internal/console/attack_catalog_runtime.go'];assert git('diff','--cached','--name-only').decode().splitlines()==expected
inputs=[]
for path in expected:
 raw=git('show',BASE+':'+path);assert raw==(R/path).read_bytes()==git('show',':'+path);inputs.append({'path':path,'sha256':sha(raw)})
rt=json.loads((E/'final-source/integrated-source-inputs-v3.json').read_bytes())['paths'];assert len(rt)==43
for p in rt:assert sha((R/p['path']).read_bytes())==p['sha256']
for p in ['phorvex/charts/phorvex/values.yaml','deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz']:assert (R/p).read_bytes()==git('show',HEAD+':'+p)
report={'schema':'phorvex-bench.inactive-image-control.v1','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'upstream':BASE,'three_upstream_paths_exact':inputs,'runtime43_unchanged':True,'prior_default_and_archive_unchanged':True}
with tempfile.TemporaryDirectory(dir='/workspace/.phorvex-test-tmp',prefix='a5f-overlay-peer-') as tmp:
 root=pathlib.Path(tmp);raw=git('archive',BASE,'tools','deploy/charts','deploy/environments','phorvex/charts','release')
 with tarfile.open(fileobj=io.BytesIO(raw)) as tf:tf.extractall(root,filter='data')
 cmd=[py,'-c','import json,staging_release as r; b=json.loads((r.ROOT/"release/staging-batch.json").read_text()); print(json.dumps({"consumers":len(r.active_catalogue_fixture_consumers(b))}))']
 red=subprocess.run(cmd,cwd=root/'tools',env=env,capture_output=True,text=True);(O/'actual-a5f-negative.txt').write_text(red.stdout+red.stderr);assert red.returncode==1 and 'active identity-sa-rotate catalogue window differs from the exact generated overlay' in red.stderr
 batch=json.loads((root/'release/staging-batch.json').read_bytes());a=batch['releases']['agent-sim'];pin=a['repository']+'@'+a['digest'];path=root/'deploy/environments/staging/catalogue-family.yaml';before=yaml.safe_load(path.read_bytes());gen=subprocess.check_output([py,str(root/'tools/render_catalogue_staging_values.py'),'--profile','identity-sa-rotate','--agent-image',pin],cwd=root,env=env);after=yaml.safe_load(gen);assert before['phorvex']['console']['attackCatalog']['agentAction']['enabled'] is False and before['phorvex']['console']['attackCatalog']['agentAction']['image']==''
 before['phorvex']['console']['attackCatalog']['agentAction']['image']=pin;assert before==after
 path.write_bytes(gen);green=subprocess.run(cmd,cwd=root/'tools',env=env,capture_output=True,text=True);(O/'actual-a5f-generated-positive.txt').write_text(green.stdout+green.stderr);assert green.returncode==0 and json.loads(green.stdout)=={'consumers':0}
 override=root/'inactive-image-override.yaml';override.write_text(yaml.safe_dump({'phorvex':{'console':{'attackCatalog':{'agentAction':{'image':pin}}}}}))
 def render(component,extra):
  chart=R/('phorvex/charts/phorvex' if component=='manager' else 'deploy/charts/phorvex-'+component);args=['/workspace/.phorvex-tools/helm','template','staging',str(chart),'-n','phorvex-staging','--api-versions','monitoring.coreos.com/v1/PodMonitor']
  for f in ['phorvex.yaml',component+'.yaml','catalogue-family.yaml']:args+=['-f',str(R/'deploy/environments/staging'/f)]
  if extra:args+=['-f',str(override)]
  docs=[d for d in yaml.safe_load_all(subprocess.check_output(args)) if d]
  for d in docs:
   if d['kind']=='Secret' and d['metadata']['name']=='staging-phorvex-webhook-cert':
    assert set(d['data'])=={'ca.crt','tls.crt','tls.key'};d['data']={k:'<existing-random-certificate>' for k in d['data']}
   if d['kind'] in ['MutatingWebhookConfiguration','ValidatingWebhookConfiguration']:
    for w in d['webhooks']:
     if w.get('clientConfig',{}).get('service',{}).get('name')=='staging-phorvex-webhook':w['clientConfig']['caBundle']='<existing-random-certificate>'
  return {(d['apiVersion'],d['kind'],d['metadata'].get('namespace',''),d['metadata']['name']):d for d in docs}
 renders={}
 for c in ['brain','manager','console','actuator','sensor','attacks']:
  old=render(c,False);new=render(c,True);assert old==new,c
  renders[c]={'rendered_objects':len(old),'unchanged':True}
 report.update(actual_a5f_gate={'negative_exit':red.returncode,'negative_predicate':'strict generated identity overlay mismatch','positive_exit':green.returncode,'positive_consumers':0},only_field={'path':'phorvex.console.attackCatalog.agentAction.image','before':'','proposed':pin,'enabled_unchanged':False},composed_actual_three_overlay_render_equivalence=renders,limits=['Candidate change occurred only in private test checkout/override, not repository or cluster.','Only existing random admission certificate bytes normalized; every other rendered field compared.','This control supports a one-field repair; source freeze/commit and coherent preflight are still required.'])
report['verdict']='PASS_FOR_BOUNDED_ONE_FIELD_REPAIR_PROPOSAL';p=O/'independent-overlay-control.json';p.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(p.relative_to(R)),'sha256':sha(p.read_bytes()),'verdict':report['verdict']},indent=2))
