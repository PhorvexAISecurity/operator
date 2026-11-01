import collections,copy,csv,datetime,hashlib,io,json,math,pathlib,sys,tarfile,zipfile
sys.dont_write_bytecode=True
REPO=pathlib.Path('/workspace/operator-benchmark-selfserve');E=REPO/'workflow/fixes/BENCH-SELFSERVE/evidence'
R=E/'live/bot-fixture-b1ef-r5-artifacts';O=E/'peer-review/fixture-b1ef-run'
sys.path.insert(0,str(REPO/'benchmark/worker'))
from mathlab import snapshots
from endpoint_refresh import clock
sha=lambda b:hashlib.sha256(b).hexdigest();read=lambda p:json.loads(p.read_text())
archive=E/'live/bot-fixture-b1ef-r5-artifacts.tar.gz'
assert sha(archive.read_bytes())=='912074c2930b7f307ee1275a92e2b2231704bb810fe0065ff69927f777d30984'
files=read(R/'MANIFEST.json');assert len(files)==len({f['path'] for f in files})==170
for f in files:
    p=R/f['path'];assert p.resolve().is_relative_to(R.resolve())
    assert p.stat().st_size==f['bytes'] and sha(p.read_bytes())==f['sha256']
with tarfile.open(archive) as tar:
    members=[m for m in tar if m.isfile()];assert len(members)==171
    for member in members:
        p=R/member.name;assert p.resolve().is_relative_to(R.resolve())
        assert tar.extractfile(member).read()==p.read_bytes()
acceptance=read(R/'acceptance/acceptance-status.json')
assert acceptance['state']==acceptance['job_outcome']==acceptance['restoration']=='PASS'
assert acceptance['source']=='225877a8ecb4c11eb39980ba932c114f7a8068a4'
assert acceptance['protected_before']==acceptance['protected_after']
assert acceptance['observer_before']==acceptance['observer_after']
assert acceptance['observer_before']['MainPID']=='1648552'
assert all(x['ActiveState']=='active' for x in acceptance['restored_units'].values())
assert [(j['id'],j['state']) for j in acceptance['jobs']]==[('9148cab8abaf','DONE'),('9979ac0c1117','DONE')]
ready_path=E/'peer-review/fixture-b1ef/ready64-verification.json';ready=read(ready_path)
assert sha(ready_path.read_bytes())=='3ecae52a96b331981a5b1fcbab9e2889090f0e7adaed17a9f0d7e1709bfec1d8'
checked={x['snapshot_digest']:x for x in ready['tick_checks']}
source='b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0';binary='c5bf81d5a9589ec822a3ed9c2112c3e88603634530d573276662b5250fc6f51e'
image='sha256:d208a9a53acd16cc146dce4c72b26d7614620862f2e1cecc1f526259033a1903'
studies=[('be9bc9fcd68f',600,600,.9,0,30,159,180,0),('4b45b14bbdb3',240,300,.95,.25,2,131,36,64)]
receipts=[];traces=[];manifests=[]
for child,W,L,s,theta,delta,Eforecast,Rbudget,noop in studies:
    root=R/'jobs'/child/'endpoint';request=read(root/'request.json');result=read(root/'result.json')
    trace=read(root/'trace.json');manifest=read(root/'dataset-manifest.json');study=read(root/'study-settings.json')
    traces.append(trace);manifests.append(manifest)
    assert request['policy']=='phorvex-staging-demo/stage-bench-defense' and request['ticks']==64 and request['sync'] is False
    assert request['study']=={'window':W,'slo_target':s,'worth_threshold':theta}
    assert request['config']['lookback']==L
    assert read(root/'config.json')==request['config']
    assert result['state']=='COMPLETE' and result['mode']=='PAIRED_BRAIN_REPLAY' and result['evidence']=='recorded'
    assert result['source_revision']==result['snapshot_source_revision']==result['replay_git_sha']==source
    assert result['cross_version'] is False and result['observational'] is False and result['brain_selection_parity'] is True
    assert result['baseline_exact_count']==result['comparable_ticks']==len(result['ticks'])==64
    assert result['changed_choices']==0 and result['missing_reasons']=={}
    assert result['counterfactual_actual_charges'] is None and result['counterfactual_verified_facts'] is None
    assert result['required_windows']=={'budget_seconds':W,'burn_seconds':L}
    assert result['requested_study']==request['study'] and result['requested_config']==request['config']
    assert result['requested_policy']==request['policy'] and result['requested_ticks']==64 and result['requested_sync'] is False
    assert result['config']['lookback']==L and result['config']['delta']==delta
    runner=result['runner'];assert runner['git_sha']==runner['capture_control']['git_sha']==source
    assert runner['binary_sha256']==runner['capture_control']['binary_sha256']==binary
    assert runner['image_digest']==image and runner['comparison_status']=='MATCHED_REPLAY' and runner['cross_version'] is False
    assert runner['study_engine']['lane']=='native-stage-image'
    assert runner['study_engine']['source_revision']==runner['study_engine']['base_source']==source
    assert manifest['trace_sha256']==study['original_trace_sha256']==ready['trace_sha256']
    assert manifest['normalization']['journal_prefix']==ready['journal_prefix']
    assert manifest['normalization']['scope']==ready['scope']
    assert manifest['normalization']['missing']=={} and manifest['normalization']['state']=='READY'
    assert study['original_normalization_study_settings']==ready['study_settings']
    assert study['requested']==request['study'] and study['config_lookback']==L
    assert result['trace_sha256']==sha((root/'trace.json').read_bytes()) and result['study']==study
    digests={t['id'] for t in trace['ticks']};assert len(digests)==64 and digests==set(checked)==set(result['snapshot_digests'])
    assert digests=={p.stem for p in (root/'cohort').glob('*.pxms')}
    bindings={b['snapshot_digest']:b for b in manifest['normalization']['bindings']}
    headers={}
    for digest in digests:
        p=root/'cohort'/(digest+'.pxms');assert sha(p.read_bytes())==digest;h=snapshots.read_header(p)
        assert h['finalized'] is True and h['gitSHA']==source and h['brainImage'].endswith('@'+image)
        assert h['captureIdentitySource']=='recorder-process' and h['namespace']=='phorvex-staging-demo'
        assert h['policyName']=='stage-bench-defense' and h['policyUID']==ready['scope']['policy_uid'] and h['policyGeneration']==1
        assert clock(h['decidedAt'])==checked[digest]['at'];headers[digest]=h
    for label in ('capture-control','base-local'):
        rows=[json.loads(line) for line in (root/(label+'.jsonl')).read_text().splitlines()]
        assert len(rows)==64 and {r['snapshot']['snapshot_digest'] for r in rows}==digests
        for row in rows:
            assert row['status']=='OK' and row['baseline_check']['reproduced'] is True
            assert row['replay_git_sha']==source and row['cross_version'] is False
            assert row['snapshot']['git_sha']==source and row['snapshot']['brain_image'].endswith('@'+image)
        summary=read(root/(label+'-summary.json'));assert summary['baseline_checked']==summary['baseline_reproduced']==64
    original_ticks={t['id']:t for t in trace['ticks']};csv_rows=[]
    for tick in result['ticks']:
        raw=original_ticks[tick['tick_id']];b=bindings[tick['tick_id']];prior=checked[tick['tick_id']]
        assert tick['at']==raw['at']==b['at']==prior['at']
        assert b['journal_seq']==prior['journal_seq'] and b['journal_hash']==prior['journal_hash']
        assert raw['ledger']['complete_from']==b['complete_from']==prior['complete_from']<=raw['at']-max(W,L)
        assert raw['at']<=b['sealed_until']==prior['sealed_until']
        assert raw['ledger']['moves']==[] and raw['ledger']['authoritative'] is False
        assert raw['slo']=={'target':s,'window':W,'accepted':False,'study_assumption':True}
        assert raw['spec_replicas']==3 and all(c['samples']==[] and c['history_known'] is True for c in raw['candidates'])
        assert tick['state']=='COMPLETE' and tick['changed'] is False
        assert math.isclose(tick['budget']['R'],3*(1-s)*W) and math.isclose(tick['budget']['R'],Rbudget)
        assert tick['budget']['used']==tick['budget']['held']==tick['budget']['S']==0
        assert tick['budget']['acting_admission']=='BLOCKED: shadow ledger is not authoritative'
        assert tick['lambda']['lambda_prev']==tick['lambda']['lambda_next']==.0001
        assert tick['lambda']['lambda_eff']==0 and tick['lambda']['reason']=='AT_FLOOR_UNPRICED'
        facts={c['id']:sum(dict(sorted((f['id'],f['weight']) for f in c['facts'])).values()) for c in raw['candidates']}
        for arm in ('v2','v3'):
            assert tick[arm]['executed'] is True and len(tick[arm]['candidates'])==3
            for c in tick[arm]['candidates']:
                prior_candidate=next(p for p in raw['candidates'] if p['id']==c['candidate_id'])
                assert prior_candidate['class']=='stateless' and prior_candidate['k']==1 and prior_candidate['gates']==[]
                assert prior_candidate['worth_threshold']==theta
                assert math.isclose(c['V'],facts[c['candidate_id']],rel_tol=1e-12) and c['J']==c['V']
                cost=c['cost'];assert cost['sample_count']==0 and cost['T_mid']==cost['T_upper']==43 and cost['p_f']==1
                assert cost['rollback']=='STUDY_PROXY_T_UPPER'
                assert cost['C_flow']==43 and cost['C_norm']==86+delta
                assert cost['E']==cost['rho']==43+86+delta==Eforecast
                assert c['refusals']==(['BUDGET'] if noop else []) and c['admitted'] is (not bool(noop))
                csv_rows.append({'tick':tick['tick_id'],'at':tick['at'],'state':tick['state'],'arm':arm,'candidate':c['candidate_id'],'action':c['action'],'V':c['V'],
                    **{k:cost.get(k) for k in ('E','rho','T_mid','T_upper','p_f')},**{k:tick['budget'].get(k) for k in ('R','used','held','S')},
                    **{k:tick['lambda'].get(k) for k in ('lambda_prev','lambda_next','b','g','dt','state_write','reason')},'lambda_eff':tick['lambda']['lambda_eff'] if arm=='v3' else 0,
                    'J':c['J'],'selected':c['selected'],'refusals':'; '.join(c['refusals'])})
            if noop:assert tick[arm]['pick'] is None and all(c['selected'] is False for c in tick[arm]['candidates'])
            else:
                pick=max(facts,key=facts.get);assert tick[arm]['pick']==pick
                assert [c['candidate_id'] for c in tick[arm]['candidates'] if c['selected']]==[pick]
        assert tick['v2']['pick']==tick['v3']['pick']
    assert result['noop']=={'v2':noop,'v3':noop}
    assert result['forecast_endpoint_seconds']=={'v2':Eforecast*(64-noop),'v3':Eforecast*(64-noop)}
    csv_actual=list(csv.reader(io.StringIO((root/'metrics.csv').read_text())))
    assert len(csv_actual)==385
    assert csv_actual[1:]==[['' if row.get(k) is None else str(row[k]) for k in csv_actual[0]] for row in csv_rows]
    with zipfile.ZipFile(root/'evidence.zip') as bundle:
        for name,digest in read(root/'SHA256SUMS.json').items():
            assert sha((root/name).read_bytes())==sha(bundle.read(name))==digest
    activity=read(R/'jobs'/child/'ACTIVITY.json');assert activity['state']=='DONE'
    assert activity['started']=={'model_started':False,'tests_started':False,'build_started':False,'replay_started':True,'preflight_started':True}
    receipts.append({'child':child,'state':'COMPLETE','ticks':64,'captured_control_exact':64,'local_base_exact':64,'mode':'PAIRED_BRAIN_REPLAY','W':W,'L':L,'s':s,'worth_threshold':theta,'delta':delta,
        'R':Rbudget,'forecast_candidate_E':Eforecast,'noop':result['noop'],'forecast_total':result['forecast_endpoint_seconds'],'changed_v2_v3_choices':0,'candidate_csv_rows_verified':384,'result_sha256':sha((root/'result.json').read_bytes()),'trace_sha256':sha((root/'trace.json').read_bytes())})
assert manifests[0]==manifests[1]
original=copy.deepcopy(traces[0]);original_settings=manifests[0]['normalization']['study_settings']
for t in original['ticks']:
    t['slo'].update(target=original_settings['target'],window=original_settings['window'])
    for c in t['candidates']:c['worth_threshold']=original_settings['worth_threshold']
assert sha((json.dumps(original,sort_keys=True,separators=(',',':'))+'\n').encode())==ready['trace_sha256']
expected=copy.deepcopy(traces[0])
for t in expected['ticks']:
    t['slo'].update(target=.95,window=240)
    for c in t['candidates']:c['worth_threshold']=.25
assert expected==traces[1]  # No source facts, gates, scope, samples or ledger rewritten by custom settings.
delivery=[json.loads(line) for line in (R/'acceptance/telegram-delivery.jsonl').read_text().splitlines()]
assert len(delivery)==34 and collections.Counter(d['method'] for d in delivery)=={'sendMessage':20,'sendDocument':14}
reconstructed={}
for job in acceptance['jobs']:
    validation=dict(job['validation']);validation.pop('batch_id')
    reconstructed['validation-'+validation['id']+'.json']=(json.dumps(validation,indent=2)+'\n').encode()
    stream=io.StringIO(newline='');w=csv.writer(stream);w.writerow(('batch_id','index','kind','state','job_id'))
    w.writerows((job['id'],x['index'],x['kind'],x['state'],x['job'] or '') for x in job['batch']['results'])
    reconstructed['batch-'+job['id']+'.csv']=stream.getvalue().encode()
raw_hashes={x['sha256'] for x in files};docs=[]
for event in delivery:
    assert isinstance(event.get('message_id'),int)
    for doc in event.get('files',[]):
        method='retained_raw_file'
        if doc['sha256'] not in raw_hashes:
            payload=reconstructed[doc['name']];assert sha(payload)==doc['sha256'] and len(payload)==doc['bytes'];method='byte_exact_retained_validation_or_batch_reconstruction'
        docs.append({**doc,'verification':method})
assert len(docs)==14
out={'verdict':'PASS_BOUNDED_ACTUAL_NATIVE_FIXTURE_ENDPOINT_CONTROLS','reviewer':'stage-review','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'archive_sha256':sha(archive.read_bytes()),'retained_files_verified':170,'ready64_review_sha256':sha(ready_path.read_bytes()),'runtime_source':acceptance['source'],
    'captured_source':source,'image_digest':image,'binary_sha256':binary,'controls':receipts,'shared_original_dataset_trace':ready['trace_sha256'],
    'custom_only_declared_trace_settings_changed':True,'duration_samples':0,'calibration_moves':0,'stateless_duration_prior_seconds':43,
    'restoration':'PASS','protected_files_and_observer_unchanged':True,'outbound_messages':34,'outbound_documents':docs,
    'limits':['Actual bot parser/queue/execution/outbound transport; supplied bytes replace incoming download only. No incoming Telegram update is claimed.',
        'Both arms use the same image-native shared brain predicates and experimental endpoint costs. The64 observations in each control share one cohort and are not128 independent trials.',
        'Default control selects a counterfactual rotate per tick; custom controls veto every candidate on known budget. No physical action occurred; shadow admission remains BLOCKED.',
        'Zero measured duration samples uses the explicit43s stateless prior, failure bound1 and rollback proxy. Forecast10176 endpoint-seconds is not actual charge, actual outage or security benefit.',
        'Lambda stays at its floor, making V2/V3 ordering identical. These runs do not establish adaptive-lambda efficacy or behavior under a positive burn signal.',
        'Original10d active-policy request remains separately BLOCKED. Durable main release survival and temporary override cleanup remain unverified/pending.']}
dest=O/'artifact-review.json';dest.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'path':str(dest),'sha256':sha(dest.read_bytes()),'verdict':out['verdict']},indent=2))
