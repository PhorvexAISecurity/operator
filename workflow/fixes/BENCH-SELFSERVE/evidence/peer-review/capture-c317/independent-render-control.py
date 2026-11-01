#!/usr/bin/env python3
"""Read-only component review: actual Argo overlays, defaults and archive payloads."""
import copy, hashlib, io, json, os, pathlib, subprocess, tarfile, tempfile
import yaml
ROOT=pathlib.Path('/workspace/operator-benchmark-selfserve')
BASE='c3174a516bee6bf8eae39749825051c3cfcb8cc6'
HELM='/workspace/.phorvex-tools/helm'
OUT=ROOT/'workflow/fixes/BENCH-SELFSERVE/evidence/peer-review/capture-c317'

def gitbytes(path): return subprocess.check_output(['git','show',BASE+':'+path],cwd=ROOT)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def membermap(raw):
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tf:
  return {m.name:tf.extractfile(m).read() for m in tf if m.isfile()}
def render(root,component,stage):
 chart='phorvex/charts/phorvex' if component=='manager' else 'deploy/charts/phorvex-'+component
 args=[HELM,'template','staging',str(root/chart),'-n','phorvex-staging','--api-versions','monitoring.coreos.com/v1/PodMonitor']
 if stage:
  for name in ['phorvex.yaml',component+'.yaml','catalogue-family.yaml']:
   args += ['-f',str(root/'deploy/environments/staging'/name)]
 raw=subprocess.check_output(args)
 docs={(d['apiVersion'],d['kind'],d['metadata']['name']):d for d in yaml.safe_load_all(raw) if d}
 # Helm's existing admission template creates random certificates at every offline render.
 # The exact source template must remain unchanged; normalize only its certificate bytes.
 assert (ROOT/'phorvex/charts/phorvex/templates/admission-webhook.yaml').read_bytes()==gitbytes('phorvex/charts/phorvex/templates/admission-webhook.yaml')
 for doc in docs.values():
  if doc['kind']=='Secret' and doc['metadata']['name']=='staging-phorvex-webhook-cert':
   assert set(doc['data'])=={'ca.crt','tls.crt','tls.key'}
   doc['data']={k:'<existing-template-generated-certificate>' for k in doc['data']}
  if doc['kind'] in ['MutatingWebhookConfiguration','ValidatingWebhookConfiguration']:
   for webhook in doc['webhooks']:
    if webhook.get('clientConfig',{}).get('service',{}).get('name')=='staging-phorvex-webhook':
     webhook['clientConfig']['caBundle']='<existing-template-generated-certificate>'
 return docs
def diff(a,b,path=''):
 if type(a)!=type(b): return [(path,a,b)]
 if isinstance(a,dict):
  out=[]
  for k in sorted(a.keys()|b.keys()):
   if k not in a or k not in b: out.append((path+'/'+str(k),a.get(k),b.get(k)))
   else: out.extend(diff(a[k],b[k],path+'/'+str(k)))
  return out
 if a!=b:return [(path,a,b)]
 return []
report={'schema':'phorvex-bench.capture-independent-control.v1','reviewer':'stage-review','base_sha':BASE,'default_comparison_note':'Only randomized admission webhook certificate bytes normalized; exact template bytes unchanged from base. All other rendered data compared.', 'overlay_order':['phorvex.yaml','COMPONENT.yaml','catalogue-family.yaml'],'renders':{},'archives':{}}
paths=['deploy/charts','deploy/environments','phorvex/charts']
with tempfile.TemporaryDirectory(dir='/workspace/.phorvex-test-tmp',prefix='capture-peer-') as name:
 base=pathlib.Path(name)
 archive=subprocess.check_output(['git','archive',BASE,*paths],cwd=ROOT)
 with tarfile.open(fileobj=io.BytesIO(archive)) as tf: tf.extractall(base,filter='data')
 for component in ['brain','manager','console','actuator','sensor','attacks']:
  before=render(base,component,False); after=render(ROOT,component,False)
  assert before==after,('default-changed',component,diff(before,after))
  before=render(base,component,True); after=render(ROOT,component,True)
  assert before.keys()==after.keys(),('objectset',component)
  changes=[]
  for key in before:
   for path,old,new in diff(before[key],after[key]): changes.append({'object':list(key),'path':path,'before':old,'after':new})
  if component not in ['brain','manager','console']: assert not changes,component
  else:
   for key,doc in before.items():
    if doc['kind']!='Deployment':continue
    previous=doc['spec']['template']['spec']['containers']
    current=after[key]['spec']['template']['spec']['containers']
    assert [(x['name'],x['image']) for x in previous]==[(x['name'],x['image']) for x in current],component
  report['renders'][component]={'defaults_identical':True,'stage_images_identical':True,'changes':changes}
 for archive in ['deploy/charts/phorvex-console/charts/phorvex-common-0.1.0.tgz','deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz']:
  old=membermap(gitbytes(archive)); new=membermap((ROOT/archive).read_bytes())
  assert old.keys()==new.keys(),archive
  changed=[name for name in new if old[name]!=new[name]]
  report['archives'][archive]={'sha256':sha((ROOT/archive).read_bytes()),'members':len(new),'changed_members':changed,'unchanged_members':len(new)-len(changed)}
  for name in changed:
   if archive.endswith('common-0.1.0.tgz'):
    source='deploy/charts/'+name
    assert new[name]==(ROOT/source).read_bytes(),name
   elif name.startswith('phorvex/charts/phorvex-common/'):
    source='deploy/charts/'+name.removeprefix('phorvex/charts/')
    assert new[name]==(ROOT/source).read_bytes(),name
   else:
    source='phorvex/charts/'+name
    if name.endswith('values.yaml'):
     assert yaml.safe_load(new[name])==yaml.safe_load((ROOT/source).read_bytes()),name
    else:assert new[name]==(ROOT/source).read_bytes(),name
common=list((ROOT/'deploy/charts').glob('*/charts/phorvex-common-0.1.0.tgz'))+[ROOT/'phorvex/charts/phorvex/charts/phorvex-common-0.1.0.tgz']
assert len(common)==6
assert len({sha(p.read_bytes()) for p in common})==1
report['six_common_archives_identical']=True
report['verdict']='PASS'
(OUT/'independent-render-control.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'verdict':'PASS','components':len(report['renders']),'render_deltas':{k:len(v['changes']) for k,v in report['renders'].items()},'archives':report['archives']},indent=2))
