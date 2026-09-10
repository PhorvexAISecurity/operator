"""Lead reproductions against real E2E functions. No live transport or mutation."""
import sys,json,math
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[4]/'End-to-End/pipeline'))
import checks,groundtruth,transport,trace

class DeniedTransport:
 def run(self,*args,**kwargs): return 1,'','Error from server (Forbidden): pods is forbidden'

c=transport.Cluster(DeniedTransport())
g=groundtruth.verify(c,[{'namespace':'n','pod':'p','action':'rotate'}],{'p':{'uid':'original'}})
assert g[0]['verdict']=='confirmed',g
print('REPRODUCED forbidden Pod read -> confirmed rotation:',g)
# Successful identical UID is a real negative control.
class SamePod:
 def pod_uids(self,namespace):return {'p':{'uid':'original'}}
assert groundtruth.verify(SamePod(),[{'namespace':'n','pod':'p','action':'rotate'}],{'p':{'uid':'original'}})[0]['verdict']=='contradicted'
print('CONTROL unchanged observed Pod -> contradicted')
ctx=SimpleNamespace(records=[{'pod':'p','trace':{'inputs':{'vramFraction':{'present':True,'value':float('nan')}}}}])
r=checks.ph02(ctx); assert r['status']=='pass',r
assert checks.ph02(SimpleNamespace(records=[{'pod':'p','risk':float('nan')}]))['status']=='fail'
print('REPRODUCED global numeric sweep misses nested trace NaN; top-level NaN control fails:',r)
for fn in [checks.c03,checks.c07]:
 r=fn(SimpleNamespace(records=[{'pod':'p'}]));assert r['status']=='pass',r;print('REPRODUCED absent compound inputs -> PASS',fn.__name__,r)
# Readiness means Ready, not simply Running.
r=checks.p04(SimpleNamespace(baseline_pods={'p':{'uid':'u','owner':'ReplicaSet','phase':'Running','ready':False}})); assert r['status']=='pass',r;print('REPRODUCED Running-but-not-Ready target -> PASS',r)
ctx=SimpleNamespace(ground_truth=[{'verdict':'confirmed','action':'rotate','pod':'p','detail':'observed'}, {'verdict':'unverifiable','action':'kv-reset','pod':'q','detail':'no observation'}]);r=checks.a03(ctx);assert r['status']=='pass';print('REPRODUCED partly unverified ground truth -> PASS',r)
# Old unrelated service log and a different namespace baseline still count as confirmation.
class OldLog:
 def container_log(self,*args,**kwargs):return 'historical lora config loaded at startup'
r=groundtruth.verify(OldLog(),[{'namespace':'n','pod':'p','action':'adapter-rotate'}],{});assert r[0]['verdict']=='confirmed';print('REPRODUCED generic historical lora text -> confirmed adapter rotation',r)
print('All characterizations reproduced; these PASS assertions describe defects, not acceptance.')
