import pathlib, json, subprocess, tempfile, os, hashlib, datetime
root=pathlib.Path('/home/hami/phorvex-benchmark/stage-data/deployment/relay-ef94fad3')
crane='/home/hami/phorvex-benchmark/runtime/crane/crane'
review=json.loads((root/'relay-oci-review.json').read_text())
assert review['result']=='PASS_FOR_AUTHORIZED_STAGE_ROLLOUT' and review['reviewer']=='stage_review', 'independent OCI review required'
r=json.loads((root/'composition-receipt.json').read_text())
assert r['source_revision']=='ef94fad362dabb51469211388ef80cdfa6eee1d4'
registry='753556437180.dkr.ecr.us-east-2.amazonaws.com'
def run(args,**kwargs):
 return subprocess.check_output(args,timeout=300,**kwargs)
with tempfile.TemporaryDirectory(prefix='ecr-auth-',dir='/home/hami/phorvex-benchmark/runtime') as tmp:
 os.chmod(tmp,0o700)
 auth=json.loads(run(['aws','ecr','get-authorization-token','--registry-ids','753556437180','--region','us-east-2','--output','json']))['authorizationData']
 token=next(v['authorizationToken'] for v in auth if v['proxyEndpoint']=='https://'+registry)
 config=pathlib.Path(tmp)/'config.json'
 config.write_text(json.dumps({'auths':{registry:{'auth':token}}}));os.chmod(config,0o600)
 env=dict(os.environ,DOCKER_CONFIG=tmp)
 published={}
 for service, image in r['images'].items():
  archive=root/(service+'-image.tar')
  assert hashlib.sha256(archive.read_bytes()).hexdigest()==image['archive_sha256']
  assert image['tag'].startswith(registry+'/phorvex/staging/'+service+':benchmark-relay-git-')
  local=run([crane,'digest','--tarball',str(archive)],env=env,text=True).strip()
  assert local==image['manifest_digest']==review['images'][service]['digest']
  assert image['archive_sha256']==review['images'][service]['archive_sha256']
  subprocess.run([crane,'push',str(archive),image['tag']],env=env,timeout=600,check=True)
  actual=run([crane,'digest',image['tag']],env=env,text=True).strip()
  assert actual==local
  published[service]={'tag':image['tag'],'digest':actual,'archive_sha256':image['archive_sha256']}
  (root/'publish-receipt.json').write_text(json.dumps({'source':r['source_revision'],'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'images':published},indent=2)+'\n')
  print(service,actual,flush=True)
print('Published reviewed immutable stage images; temporary ECR credentials removed',flush=True)
