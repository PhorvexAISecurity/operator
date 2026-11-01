import datetime,hashlib,json,subprocess
ctx='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
base=['kubectl','--context',ctx,'-n','argocd']
p=subprocess.run(base+['get','applicationset','phorvex-services','-o','json'],capture_output=True,text=True,check=True,timeout=30)
a=json.loads(p.stdout);v=a['spec'].get('templatePatch','')
assert a['metadata']['uid']=='e55f3b21-b600-423b-9f10-1faa1c09f6b5'
assert hashlib.sha256(v.encode()).hexdigest()=='042c633747e95d985ad1c5e6784a6f626bcd50fc66eb2aaf848143c7a2fe26a9'
patch=[{'op':'test','path':'/metadata/resourceVersion','value':a['metadata']['resourceVersion']},{'op':'test','path':'/spec/templatePatch','value':v},{'op':'remove','path':'/spec/templatePatch'}]
p=subprocess.run(base+['patch','applicationset','phorvex-services','--type=json','-p',json.dumps(patch),'-o','json'],capture_output=True,text=True,check=True,timeout=30)
b=json.loads(p.stdout);assert 'templatePatch' not in b['spec']
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'ROLLED_BACK_OWNED_TEMPLATE_PATCH','cause':'Argo forbids different revisions of same repository in source/value reference; no workload change observed','uid':b['metadata']['uid'],'resourceVersion':b['metadata']['resourceVersion'],'generation':b['metadata']['generation']}))
