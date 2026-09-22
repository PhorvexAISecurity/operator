#!/usr/bin/env python3
import argparse, json, pathlib, re, subprocess, sys, tempfile
B=pathlib.Path(__file__).resolve().parents[1]; CHART=B.parents[1]
def fail(m): raise ValueError(m)
def run(cmd):
 p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if p.returncode: fail(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr.decode(errors='replace')[:1000]}")
 return p.stdout
def render(helm,values,show=None):
 cmd=[helm,'template','phorvex',str(CHART),'--namespace','phorvex-system','-f',str(CHART/'values.yaml'),'-f',str(CHART/'values-eks.yaml'),'-f',str(values)]
 if show: cmd += ['--show-only',show]
 return run(cmd)
def detector_arg(doc):
 m=re.findall(rb'--trusted-detectors=([^\n]+)',doc)
 if len(m)!=1: fail('trusted detector argument missing/duplicated')
 return set(m[0].decode().strip().split(','))
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--helm',default='helm'); ap.add_argument('--resolved-values',action='append',default=[]); a=ap.parse_args()
 files=[p for p in B.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
 for p in files:
  data=p.read_bytes()
  if p.suffix in ('.yaml','.yml','.json','.md') and (b'-----BEGIN ' in data or re.search(rb'(?m)^\s*(data|stringData):\s*$',data)):
   fail(f'secret material field/header in {p.name}')
 if b'lossHistory:' in (CHART/'values-eks.yaml').read_bytes() or b'scopedOutcome:' in (CHART/'values-eks.yaml').read_bytes(): fail('features were added to values-eks defaults')
 for p in a.resolved_values:
  if b'REPLACE_WITH_' in pathlib.Path(p).read_bytes(): fail(f'unresolved marker in {p}')
 phase_a=render(a.helm,B/'values-m100-phase-a-current.json')
 phase_b=render(a.helm,B/'values-m100-phase-b-loss.json')
 dep_a=render(a.helm,B/'values-m100-phase-a-current.json','charts/phorvex/templates/deployment.yaml')
 dep_b=render(a.helm,B/'values-m100-phase-b-loss.json','charts/phorvex/templates/deployment.yaml')
 if dep_a!=dep_b: fail('M100 manager Deployment differs between Phase A and Phase B')
 if b'command: ["/current-inventory-observer"]' not in phase_a or b'kind: Job' not in phase_a: fail('Phase A current observer missing')
 if b'command: ["/loss-observer"]' in phase_a: fail('Phase A unexpectedly creates loss observer')
 if b'command: ["/loss-observer"]' not in phase_b or b'kind: Job' not in phase_b: fail('Phase B loss observer missing')
 if b'command: ["/current-inventory-observer"]' in phase_b: fail('Phase B unexpectedly creates current observer')
 m106=render(a.helm,B/'values-m106.yaml'); base=run([a.helm,'template','phorvex',str(CHART),'--namespace','phorvex-system','-f',str(CHART/'values.yaml'),'-f',str(CHART/'values-eks.yaml')])
 for item in (b'--scoped-outcome-config=/etc/phorvex-scoped-outcome/config/startup.json',b'secretName: phorvex-m106-scoped-outcome-v4',b'secretName: phorvex-m106-scoped-outcome-v4-tls',b'claimName: phorvex-m106-scoped-outcome-v4-evidence'):
  if item not in m106: fail(f'M106 render missing {item.decode()}')
 expected=detector_arg(base)|{'phorvex-verify-m106-scoped-outcome-v4/m106-scoped-detector'}
 if detector_arg(m106)!=expected: fail('M106 detector list is not current base plus exact fixture detector')
 combined=[]
 for values in (B/'values-m100-phase-a-current.json',B/'values-m100-phase-b-loss.json'):
  combined.append(run([a.helm,'template','phorvex',str(CHART),'--namespace','phorvex-system','-f',str(CHART/'values.yaml'),'-f',str(CHART/'values-eks.yaml'),'-f',str(B/'values-m106.yaml'),'-f',str(values),'--show-only','charts/phorvex/templates/deployment.yaml']))
 if combined[0]!=combined[1] or b'--scoped-outcome-config=' not in combined[0] or b'--loss-history-dir=' not in combined[0]: fail('combined M100 phases do not preserve the M106 manager config')
 disable100=render(a.helm,B/'values-m100-disable.yaml'); disable106=render(a.helm,B/'values-m106-disable.yaml')
 if b'--loss-history-dir=' in disable100: fail('M100 disable still enables history')
 if b'--scoped-outcome-config=' in disable106: fail('M106 disable still enables scoped observer')
 m100=json.loads((B/'m100-deployment-pin.json').read_text());va=json.loads((B/'values-m100-phase-a-current.json').read_text());vb=json.loads((B/'values-m100-phase-b-loss.json').read_text())
 if m100.get('schema')!='phorvex.m100.deployment-pin.v1' or m100.get('status')!='FRESH_FIXTURE_VALID_CURRENT_TARGET' or not m100.get('policy',{}).get('acceptedDryRun') or not m100.get('workload',{}).get('ownerChainExact') or not m100.get('workload',{}).get('target',{}).get('ready'): fail('M100 public pin is not accepted fresh authority')
 for values in (va,vb):
  lh=values['phorvex']['phorvex']['lossHistory'];obs=lh['observer'];cur=lh['currentInventory']['observer']
  if obs['targetUID']!=m100['workload']['target']['uid'] or cur['targetUID']!=m100['workload']['target']['uid'] or obs['policyName']!=m100['policy']['name'] or cur['policyName']!=m100['policy']['name']: fail('M100 values differ from workload/policy pin')
  if obs['caSecretName']!=m100['observers']['ca']['secretName'] or cur['caSecretName']!=m100['observers']['ca']['secretName'] or obs['clientSecretName']!=m100['observers']['loss']['secretName'] or cur['clientSecretName']!=m100['observers']['current']['secretName']: fail('M100 values differ from Secret metadata pin')
  if obs['expectedBytes']!=m100['protectedProjection']['expectedBytes'] or obs['expectedSHA256']!=m100['protectedProjection']['expectedSHA256'] or cur['ruleSHA256']!=m100['observers']['current']['ruleSHA256'] or obs['ruleSHA256']!=m100['observers']['loss']['ruleSHA256']: fail('M100 values differ from protected evidence pin')
 pin=json.loads((B/'secure-transfer-pin.example.json').read_text())
 if pin.get('schema')!='phorvex.secure-secret-transfer.v1' or len(pin.get('transfers',[]))!=2: fail('transfer pin template differs')
 rbac=(B/'rbac-m106-fixture.yaml').read_text()
 for token in ('resources: [securityevents]','verbs: [create, get]','resources: [pods/eviction]','verbs: [create]'):
  if token not in rbac: fail('minimum RBAC differs')
 run([sys.executable,'-m','py_compile',str(B/'scripts/transfer_secret.py')])
 with tempfile.TemporaryDirectory() as td:
  run([sys.executable,str(B/'scripts/render_m100_values.py'),'--pin',str(B/'m100-deployment-pin.json'),'--outdir',td])
  rendered=sorted(pathlib.Path(td).glob('*.yaml'))
  if len(rendered)!=2 or any(b'REPLACE_WITH_' in p.read_bytes() for p in rendered): fail('live M100 pin did not render two resolved overlays')
  pairs=((rendered[0],B/'values-m100-phase-a-current.json','charts/phorvex/templates/current-inventory-observer.yaml'),(rendered[1],B/'values-m100-phase-b-loss.json','charts/phorvex/templates/loss-observer.yaml'))
  for generated,exact,observer_template in pairs:
   for template in ('charts/phorvex/templates/deployment.yaml',observer_template):
    if render(a.helm,generated,template)!=render(a.helm,exact,template): fail(f'live M100 pin renderer differs for {template}')
 print(json.dumps({'status':'PASS','m100ManagerTemplateBytes':len(dep_a),'m100ManagerTemplatesIdentical':True,'m106DetectorCount':len(expected),'filesChecked':len(files)},sort_keys=True))
if __name__=='__main__':
 try: main()
 except Exception as e: print(json.dumps({'status':'FAIL','error':str(e)},sort_keys=True),file=sys.stderr); sys.exit(1)
