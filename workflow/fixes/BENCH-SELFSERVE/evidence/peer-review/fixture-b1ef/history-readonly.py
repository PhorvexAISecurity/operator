"""Verify one live journal prefix without invoking its mutating constructor."""
import collections,datetime,hashlib,json,pathlib,sqlite3,sys,threading,time
sys.dont_write_bytecode=True
base=pathlib.Path('/home/hami/phorvex-benchmark')
release=base/'releases/stage-selfserve-225877a8ecb4'
data=base/'stage-data';policy='phorvex-staging-demo/stage-bench-defense'
sys.path[:0]=[str(release/'benchmark/worker'),str(release)]
from benchmark.stage.evidence import Journal,Reducer,sealed_sessions
from endpoint_refresh import segment
from stage_observer_runtime import resolve_journal
from mathlab import stage_scope
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
pinpath=data/'mathlab/stage.json';before=sha(pinpath);pin=json.loads(pinpath.read_text())
path=resolve_journal(data,pin,policy)
# URI mode=ro and query_only prevent append/DDL; bypass __init__ chmod/mkdir/PRAGMA writes.
j=Journal.__new__(Journal);j.path=path;j.db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=10)
j.db.execute('PRAGMA query_only=ON');j.lock=threading.RLock();j.scan_timeout=60
meta=dict(j.db.execute('SELECT key,value FROM meta'))
j.scope=json.loads(meta['scope']);j.encoding=meta.get('encoding','plain-v1')
with j.read_snapshot() as prefix:
    events=list(j.records(cutoff=prefix['seq']))
    observed=segment(j,prefix,now=time.time(),max_age=600)
    reducer=Reducer(j.scope)
    for event in events:reducer.apply(event)
    assert observed['session']==reducer.session and not reducer.reasons
    scope=j.scope;expected=pin['policies'][policy]
    assert scope['source_revision']==pin['brain']['git_sha']=='b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0'
    assert scope['policy_uid']==expected['uid'] and scope['service_uid']==expected['service_uid'] and scope['workload_uid']==expected['workload_uid']
    result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pin_sha256':before,
            'scope':scope,'journal':str(path),'encoding':j.encoding,'verified_prefix':prefix,
            'event_kinds':dict(collections.Counter(e['kind'] for e in events)),
            'observed_segment':observed,'current_coverage_seconds':observed['sealed_until']-observed['complete_from'],
            'move_states':dict(collections.Counter(m['state'] for m in reducer.moves.values())),
            'policy_generation':reducer.policy_generation,'workload_generation':reducer.generation,
            'ready_pod_count':len(reducer.ready),'scope_and_chain_verified':True,
            'limits':['Read-only SQLite frozen prefix and decoded hash-chain/reducer verification. No history bridge or write.','Current journal coverage alone does not establish a qualified normalized 64-tick dataset.']}
j.db.close();result['pin_unchanged']=sha(pinpath)==before
assert result['pin_unchanged']
print(json.dumps(result,indent=2))
