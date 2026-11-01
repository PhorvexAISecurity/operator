import ast,json,hashlib,subprocess
from pathlib import Path
r=Path('workflow/fixes/BENCH-SELFSERVE/evidence'); source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
main='a5f32f9dba5ed6e756f11b73ece968d54805c3e2'
assert subprocess.run(['git','merge-base','--is-ancestor',main,source]).returncode==0
s=r/'live/apply-reviewed-capture-v3.py'; text=s.read_text(); node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='payload' for t in n.targets))
payload=ast.literal_eval(node.value); op=payload['operation']; old=op['chart_source'];op['value']=op['value'].replace(old,source);op.update(chart_source=source,values_source=source,values_reviewed_at=main)
payload['expected']=json.loads((r/'live/bee9-a5f-capture-preconditions.json').read_text())['expected']
lines=text.splitlines(keepends=True); lines[node.lineno-1:node.end_lineno]=['payload = '+repr(payload)+'\n']; new=''.join(lines).replace('selfserve-capture-v3','selfserve-capture-v4')
p=r/'live-proposal-v4';p.mkdir(exist_ok=False)
(p/'operation.json').write_text(json.dumps(op,indent=2)+'\n');(p/'expected.json').write_text(json.dumps(payload['expected'],indent=2)+'\n');(p/'templatePatch.yaml.gotmpl').write_text(op['value'])
f=r/'live/apply-reviewed-capture-v4.py';f.write_text(new);compile(new,str(f),'exec')
paths=[p/'operation.json',p/'expected.json',p/'templatePatch.yaml.gotmpl',f,r/'live/bee9-a5f-capture-preconditions.json']
manifest={'schema':'phorvex-bench.proposal-manifest.v1','source':source,'upstream_main':main,'expected_live_source':'bee9caccf3bae388d412e72adfe50ca9de41a486','files':[{'path':str(x),'sha256':hashlib.sha256(x.read_bytes()).hexdigest(),'bytes':x.stat().st_size} for x in paths],'render_authority':'evidence/peer-review/upstream-a5f/independent-overlay-control.json','qualification':'Fresh actualbee9 immutable images/identities; same accepted V3 guard logic; exact main/source publication and live preconditions checked before sole ApplicationSet mutation.'}
(p/'proposal-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest))
