#!/usr/bin/env python3
"""Render nonsecret M100 value files from a fresh public identity/hash pin."""
import argparse, datetime, hashlib, json, pathlib, re, sys
B=pathlib.Path(__file__).resolve().parents[1]
def die(m): raise ValueError(m)
def tm(v):
 for parser in (lambda:datetime.datetime.fromisoformat(v.replace('Z','+00:00')).astimezone(datetime.timezone.utc),lambda:datetime.datetime.strptime(v,'%b %d %H:%M:%S %Y GMT').replace(tzinfo=datetime.timezone.utc)):
  try:return parser()
  except Exception:pass
 die('invalid timestamp in M100 pin')
def val(d,*keys):
 for k in keys:d=d[k]
 if isinstance(d,str) and (not d or d.startswith('REPLACE_WITH_')):die('M100 pin contains placeholder')
 return d
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--pin',required=True); ap.add_argument('--outdir',required=True); a=ap.parse_args(); p=json.loads(pathlib.Path(a.pin).read_text())
 if p.get('schema')!='phorvex.m100.deployment-pin.v1':die('M100 pin schema differs')
 now=datetime.datetime.now(datetime.timezone.utc); tm(val(p,'observedAt'))
 for k in ('ca','current','loss'):
  if tm(val(p,'observers',k,'certNotAfter'))<=now:die(f'{k} certificate expired')
 for path in (('observers','current','ruleSHA256'),('observers','loss','ruleSHA256'),('protectedProjection','expectedSHA256')):
  if not re.fullmatch(r'[0-9a-f]{64}',str(val(p,*path))):die(f'{path[-1]} is not SHA-256')
 if not isinstance(val(p,'protectedProjection','expectedBytes'),int) or p['protectedProjection']['expectedBytes']<=0:die('expectedBytes must be positive')
 q=lambda v:json.dumps(str(v))[1:-1]
 common={'REPLACE_WITH_TARGET_NAMESPACE':q(val(p,'namespace','name')),'REPLACE_WITH_TARGET_POD_NAME':q(val(p,'workload','target','name')),'REPLACE_WITH_TARGET_POD_UID':q(val(p,'workload','target','uid')),'REPLACE_WITH_POLICY_NAME':q(val(p,'policy','name')),'REPLACE_WITH_MTLS_SERVER_NAME':q(val(p,'servingAuthority','serverName')),'REPLACE_WITH_EXISTING_CA_SECRET_NAME':q(val(p,'observers','ca','secretName')),'REPLACE_WITH_PROTECTED_ASSET':q(val(p,'protectedProjection','asset')),'REPLACE_WITH_PROTECTED_VERSION':q(val(p,'protectedProjection','version'))}
 maps={
 'values-m100-phase-a-current.example.yaml':common|{'REPLACE_WITH_MTLS_MANIFEST_URL':q(val(p,'servingAuthority','manifestURL')),'REPLACE_WITH_EXISTING_CURRENT_CLIENT_SECRET_NAME':q(val(p,'observers','current','secretName')),'REPLACE_WITH_PROTECTED_CONFIGMAP_NAME':q(val(p,'protectedProjection','configMapName')),'REPLACE_WITH_PROTECTED_CONFIGMAP_KEY':q(val(p,'protectedProjection','configMapKey')),'REPLACE_WITH_TARGET_VOLUME_NAME':q(val(p,'protectedProjection','volumeName')),'REPLACE_WITH_TARGET_CONTAINER_NAME':q(val(p,'protectedProjection','containerName')),'REPLACE_WITH_TARGET_MOUNT_PATH':q(val(p,'protectedProjection','mountPath')),'REPLACE_WITH_PROJECTED_FILE_PATH':q(val(p,'protectedProjection','projectedPath')),'REPLACE_WITH_CURRENT_EVIDENCE_ID':q(val(p,'observers','current','evidenceID')),'REPLACE_WITH_CURRENT_RULE_SHA256':q(val(p,'observers','current','ruleSHA256'))},
 'values-m100-phase-b-loss.example.yaml':common|{'REPLACE_WITH_MTLS_CANARY_URL':q(val(p,'servingAuthority','canaryURL')),'REPLACE_WITH_EXISTING_LOSS_CLIENT_SECRET_NAME':q(val(p,'observers','loss','secretName')),'REPLACE_WITH_LOSS_EVIDENCE_ID':q(val(p,'observers','loss','evidenceID')),'REPLACE_WITH_RULE_VERSION':q(val(p,'observers','loss','ruleVersion')),'REPLACE_WITH_LOSS_RULE_SHA256':q(val(p,'observers','loss','ruleSHA256')),'REPLACE_WITH_EXPECTED_BYTES':str(val(p,'protectedProjection','expectedBytes')),'REPLACE_WITH_EXPECTED_SHA256':q(val(p,'protectedProjection','expectedSHA256'))}}
 out=pathlib.Path(a.outdir);out.mkdir(parents=True,exist_ok=True); receipts=[]
 for name,replacements in maps.items():
  text=(B/name).read_text()
  for old,new in replacements.items():text=text.replace(old,new)
  if 'REPLACE_WITH_' in text:die(f'unresolved marker in {name}')
  target=out/name;target.write_text(text);receipts.append({'path':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
 print(json.dumps({'status':'RENDERED','files':receipts},sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'status':'REFUSED','error':str(e)},sort_keys=True),file=sys.stderr);sys.exit(1)
