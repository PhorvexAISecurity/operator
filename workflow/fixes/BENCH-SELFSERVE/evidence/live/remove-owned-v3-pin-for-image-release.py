import datetime,hashlib,json,subprocess
ctx='arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks'
base=['kubectl','--context',ctx,'-n','argocd']
p=subprocess.run(base+['get','applicationset','phorvex-services','-o','json'],capture_output=True,text=True,check=True,timeout=30)
a=json.loads(p.stdout);v=a['spec'].get('templatePatch','')
assert a['metadata']['uid']=='e55f3b21-b600-423b-9f10-1faa1c09f6b5'
assert hashlib.sha256(v.encode()).hexdigest()=='e850f10e50b886915f1437a9f6784fa211af9b395c973fb1b3135be3f35ddb07'
patch=[{'op':'test','path':'/metadata/uid','value':a['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':a['metadata']['resourceVersion']},{'op':'test','path':'/spec/templatePatch','value':v},{'op':'remove','path':'/spec/templatePatch'}]
p=subprocess.run(base+['patch','applicationset','phorvex-services','--type=json','-p',json.dumps(patch),'-o','json'],capture_output=True,text=True,check=True,timeout=30)
b=json.loads(p.stdout);assert 'templatePatch' not in b['spec']
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'ROLLED_BACK_OWNED_TEMPLATE_PATCH','cause':'Concurrent upstream PR193 pins new bee9 isolated images at main e9d796a5; remove only this campaign owned V3 pin so the actual release can roll. No new-source bot acceptance has occurred.','uid':b['metadata']['uid'],'resourceVersion':b['metadata']['resourceVersion'],'generation':b['metadata']['generation']}))
