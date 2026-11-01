#!/usr/bin/env python3
"""Compose and verify local stage image archives; does not publish or deploy."""
import argparse, hashlib, json, pathlib, subprocess, tarfile
p=argparse.ArgumentParser();p.add_argument('--build-dir',required=True);p.add_argument('--crane',required=True);a=p.parse_args()
root=pathlib.Path(a.build_dir).resolve();crane=str(pathlib.Path(a.crane).resolve());build=json.loads((root/'build-receipt.json').read_text());source=build['source_revision'];base=build['runtime_base']
assert len(source)==40 and all(c in '0123456789abcdef' for c in source)
commands=[]
def run(args,stdin=None):
 commands.append(args);r=subprocess.run(args,stdin=stdin,capture_output=True,timeout=300)
 if r.returncode:raise RuntimeError(r.stderr.decode(errors='replace')[-2000:])
 return r.stdout
base_config_raw=run([crane,'config','--platform','linux/amd64',base]);base_cfg=json.loads(base_config_raw)
assert (base_cfg['os'],base_cfg['architecture'])==('linux','amd64')
base_digest=run([crane,'digest','--platform','linux/amd64',base]).decode().strip()
(root/'runtime-base-config.json').write_bytes(base_config_raw)
receipt={'source_revision':source,'crane_sha256':hashlib.sha256(pathlib.Path(crane).read_bytes()).hexdigest(),'recipe':'source-matched local OCI composition; not bit-identical Docker reproduction','base':base,'base_platform_digest':base_digest,'images':{},'commands':commands}
for component,layer_meta in build['layers'].items():
 layer=root/(component+'-binaries.tar');assert hashlib.sha256(layer.read_bytes()).hexdigest()==layer_meta['sha256']
 tag='753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex/staging/'+component+':benchmark-relay-git-'+source
 archive=root/(component+'-image.tar');assert not archive.exists()
 entry='/service' if component=='brain' else '/manager'
 run([crane,'mutate','--platform','linux/amd64',base,'--append',str(layer),'--entrypoint',entry,'--user','65532:65532','--workdir','/','--label','org.opencontainers.image.revision='+source,'--label','org.opencontainers.image.version='+build['release_version'],'--tag',tag,'--output',str(archive)])
 run([crane,'validate','--tarball',str(archive)])
 manifest_digest=run([crane,'digest','--tarball',str(archive)]).decode().strip()
 assert manifest_digest.startswith('sha256:') and len(manifest_digest)==71
 with tarfile.open(archive,'r:*') as tar:
  rows=json.load(tar.extractfile('manifest.json'));assert len(rows)==1
  config_raw=tar.extractfile(rows[0]['Config']).read();cfg=json.loads(config_raw)
  assert (cfg['os'],cfg['architecture'])==('linux','amd64')
  expected={'Entrypoint':[entry],'User':'65532:65532','WorkingDir':'/'}
  assert all(cfg['config'].get(k)==v for k,v in expected.items())
  assert cfg['config'].get('Labels',{}).get('org.opencontainers.image.revision')==source
  assert cfg['config'].get('Labels',{}).get('org.opencontainers.image.version')==build['release_version']
  assert cfg['rootfs']['diff_ids'][:-1]==base_cfg['rootfs']['diff_ids']
  assert len(cfg['rootfs']['diff_ids'])==len(base_cfg['rootfs']['diff_ids'])+1
  assert cfg['config'].get('Env')==base_cfg['config'].get('Env')
 (root/(component+'-config.json')).write_bytes(config_raw)
 fs=root/(component+'-rootfs.tar')
 with archive.open('rb') as stream:run([crane,'export','-',str(fs)],stdin=stream)
 actual={}
 with tarfile.open(fs) as tar:
  byname={m.name.lstrip('./'):m for m in tar.getmembers()}
  for name in layer_meta['files']:
   member=byname[name];assert member.isfile() and member.mode&0o777==0o755
   value=hashlib.sha256(tar.extractfile(member).read()).hexdigest();assert value==build['binaries'][name]['sha256'];actual[name]=value
 fs.unlink()
 receipt['images'][component]={'tag':tag,'manifest_digest':manifest_digest,'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_size':archive.stat().st_size,'config_sha256':hashlib.sha256(config_raw).hexdigest(),'config':expected,'binary_sha256':actual,'validation':'crane validate full plus exported filesystem binary hash verification PASS'}
(root/'composition-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'result':'PASS','source_revision':source,'images':{k:v['tag'] for k,v in receipt['images'].items()}}))
