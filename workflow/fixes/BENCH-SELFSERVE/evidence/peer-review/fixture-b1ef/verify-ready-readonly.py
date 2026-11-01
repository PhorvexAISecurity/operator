import datetime,fcntl,hashlib,json,pathlib,sqlite3,sys,threading,time
sys.dont_write_bytecode=True
base=pathlib.Path('/home/hami/phorvex-benchmark');release=base/'releases/stage-selfserve-225877a8ecb4';data=base/'stage-data'
sys.path[:0]=[str(release/'benchmark/worker'),str(release)]
from mathlab import stage_scope,snapshots
from benchmark.stage.evidence import Journal,Reducer,sealed_sessions
from endpoint_refresh import clock,segment
from stage_reconcile import observe,same_observation
from stage_observer_runtime import resolve_journal
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
policy='phorvex-staging-demo/stage-bench-defense';source='b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0'
status_path=data/'mathlab/endpoint-refresh'/(policy+'.status.json');status_raw=status_path.read_bytes();status=json.loads(status_raw)
assert status['state']=='READY' and status['phase']=='COMPLETE' and status['ticks']==64,status.get('reason')
with stage_scope.pin_lock(data,readonly=True,timeout=10) as leased:
    assert leased
    pinpath=data/'mathlab/stage.json';pinsha=sha(pinpath);pin=json.loads(pinpath.read_text())
    assert pin['brain']['git_sha']==pin['manager']['git_sha']==source
    observed=observe(stage_scope.ALLOWED_POLICIES,time.monotonic()+60)
    assert same_observation(pin,observed)
    lock=data/'mathlab/snapshots/phorvex-staging-demo/stage-bench-defense.cache.lock'
    with lock.open('rb') as handle:
        deadline=time.monotonic()+20
        while True:
            try:fcntl.flock(handle,fcntl.LOCK_SH|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>deadline:raise
                time.sleep(.05)
        pointer=data/'mathlab/endpoint-traces'/(policy+'.manifest.json');psha=sha(pointer);manifest=json.loads(pointer.read_text())
        metadata=manifest['normalization'];prefix=metadata['journal_prefix'];scope=metadata['scope']
        assert manifest['source_revision']==manifest['snapshot_source_revision']==source
        assert manifest['image_digest']==pin['brain']['image_digest']
        assert metadata['state']=='READY' and not metadata['missing'] and metadata['cross_version'] is False
        assert metadata['study_settings']=={'target':.9,'window':600.0,'lookback':600.0,'worth_threshold':0.0}
        assert metadata['retention']=={'schema':'phorvex-stage.retained-history.v1','moves':'all-observed','samples':'all-observed','interval_clipping':False}
        assert metadata['refresh']['baseline_exact_count']==64
        assert metadata['refresh']['capture_binary_sha256']==metadata['refresh']['base_binary_sha256']==metadata['refresh']['study_binary_sha256']==pin['replay']['binary_sha256']
        tracepath=pointer.parent/manifest['trace_file'];assert tracepath.parent==pointer.parent and sha(tracepath)==manifest['trace_sha256']==status['published_trace_sha256']
        trace=json.loads(tracepath.read_text());assert trace['source_revision']==source and len(trace['ticks'])==64
        digests=manifest['snapshot_digests'];assert len(digests)==len(set(digests))==64
        assert set(digests)=={t['id'] for t in trace['ticks']}=={b['snapshot_digest'] for b in metadata['bindings']}
        journalpath=resolve_journal(data,pin,policy)
        j=Journal.__new__(Journal);j.path=journalpath;j.db=sqlite3.connect(journalpath.as_uri()+'?mode=ro',uri=True,timeout=10)
        j.db.execute('PRAGMA query_only=ON');j.lock=threading.RLock();j.scan_timeout=60
        meta=dict(j.db.execute('SELECT key,value FROM meta'));j.scope=json.loads(meta['scope']);j.encoding=meta.get('encoding','plain-v1')
        assert j.scope==scope
        with j.read_snapshot():
            events=list(j.records(cutoff=prefix['seq']));assert events[-1]['hash']==prefix['hash']
            sealed=sealed_sessions(iter(events));actual_segment=segment(j,prefix,now=time.time(),max_age=600)
            assert actual_segment==metadata['refresh']['observed_segment']==status['observed_segment']
            reducer=Reducer(scope);index=0;checks=[];bindings={b['snapshot_digest']:b for b in metadata['bindings']}
            for tick in sorted(trace['ticks'],key=lambda t:(t['at'],t['id'])):
                raw=data/'mathlab/snapshots'/policy/(tick['id']+'.pxms');assert sha(raw)==tick['id']
                header=snapshots.read_header(raw)
                assert all(header.get(k)==v for k,v in stage_scope.snapshot_header(pin,policy).items())
                assert header['namespace']=='phorvex-staging-demo' and header['policyName']=='stage-bench-defense'
                assert clock(header['decidedAt'])==tick['at']
                while index<len(events) and events[index]['at']<=tick['at']:
                    reducer.apply(events[index]);index+=1
                obs=reducer.snapshot(tick['at'],sealed.get(reducer.session),require_sealed=True);assert not obs['reasons']
                binding=bindings[tick['id']]
                assert binding['journal_seq']==obs['journal_seq'] and binding['journal_hash']==obs['journal_hash']
                assert binding['complete_from']==obs['complete_from'] and binding['sealed_until']==obs['watermark']
                assert binding['watch_session']==reducer.session
                assert binding['policy_generation']==pin['policies'][policy]['generation']==obs['policy_generation']
                assert binding['workload_generation']==pin['policies'][policy]['workload_generation']==obs['workload_generation']
                assert tick['ledger']['complete_from']==obs['complete_from']<=tick['at']-600
                assert tick['at']<=obs['watermark'] and tick['ledger']['moves']==obs['moves']
                assert tick['ledger']['at']==tick['at'] and tick['ledger']['authoritative'] is False
                assert tick['slo']=={'target':.9,'window':600.0,'accepted':False,'study_assumption':True}
                assert tick['spec_replicas']==obs['spec_replicas']
                for candidate in tick['candidates']:
                    assert candidate['samples']==obs['samples'] and candidate['history_known'] is True
                    assert candidate['class']==obs['class']
                    expected_k=1 if candidate['pod_uid'] in obs['ready_pod_uids'] else 0
                    if candidate['action']=='quarantine' and obs['ready_pod_uids']:expected_k=1
                    assert candidate['k']==expected_k
                checks.append({'snapshot_digest':tick['id'],'at':tick['at'],'journal_seq':binding['journal_seq'],
                               'journal_hash':binding['journal_hash'],'complete_from':obs['complete_from'],
                               'sealed_until':obs['watermark'],'moves':len(obs['moves']),'samples':len(obs['samples']),
                               'candidate_count':len(tick['candidates'])})
        j.db.close()
        assert sha(pointer)==psha and sha(pinpath)==pinsha
        fcntl.flock(handle,fcntl.LOCK_UN)
print(json.dumps({'verdict':'PASS_CURRENT_FIXTURE_READY64_SEALED_ASOF_HISTORY','reviewer':'stage-review',
 'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'runtime_source':'225877a8ecb4c11eb39980ba932c114f7a8068a4',
 'source':source,'image_digest':pin['brain']['image_digest'],'pin_sha256':pinsha,'status_sha256':hashlib.sha256(status_raw).hexdigest(),
 'dataset_manifest_sha256':psha,'trace_sha256':manifest['trace_sha256'],'journal_prefix':prefix,
 'scope':scope,'study_settings':metadata['study_settings'],'refresh_receipt':metadata['refresh'],
 'actual_live_observation':observed,'tick_checks':checks,
 'limits':['Read-only current live identity and actual retained prefix/header/hash/clock/as-of comparison. No replay or job launched.',
 'Refresh metadata retains64 exact baseline checks; this review does not re-execute them or imply endpoint paired output already completed.',
 'Observed fixture ledger and experimental SLO/window are not active-policy attributed history or measured application outage. No ten-day or efficacy claim.']},indent=2))
