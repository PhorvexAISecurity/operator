import datetime,hashlib,json,subprocess
ctx='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
base=['kubectl','--context',ctx,'-n','argocd']
p=subprocess.run(base+['get','applicationset','phorvex-services','-o','json'],capture_output=True,text=True,check=True,timeout=30)
a=json.loads(p.stdout);v=a['spec'].get('templatePatch','')
assert a['metadata']['uid']=='e55f3b21-b600-423b-9f10-1faa1c09f6b5'
assert hashlib.sha256(v.encode()).hexdigest()=='8fee86293373b85c8e1e2c42601f1424b81ca1bae3fe42cb70cb185cd63bba64'
patch=[{'op':'test','path':'/metadata/uid','value':a['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':a['metadata']['resourceVersion']},{'op':'test','path':'/spec/templatePatch','value':v},{'op':'remove','path':'/spec/templatePatch'}]
p=subprocess.run(base+['patch','applicationset','phorvex-services','--type=json','-p',json.dumps(patch),'-o','json'],capture_output=True,text=True,check=True,timeout=30)
b=json.loads(p.stdout);assert 'templatePatch' not in b['spec']
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'ROLLED_BACK_OWNED_TEMPLATE_PATCH','cause':'Concurrent reviewed upstream PR191 and PR192 close the quarantine window; remove only this campaign owned pin so current main operator settings are not held back. Runtime installation success remains separate from bot acceptance.','uid':b['metadata']['uid'],'resourceVersion':b['metadata']['resourceVersion'],'generation':b['metadata']['generation']}))
