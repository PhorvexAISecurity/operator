#!/usr/bin/env python3
# p5_throttle_fire.py — drive the serving cost-harvest attack against an ARMED lane
# serving-rate budget and prove the brain SELECTS+ACTUATES throttle (cap applied) on the
# lane target, with a two-sided oracle (abusive -> 429 while legit stays 200). Runs ON the
# gateway (local kubectl). Self-cleaning: removes only the transient load it creates.
#
# Usage: p5_throttle_fire.py <rundir> [N] [ATTACK_LABEL]
import json, subprocess, sys, pathlib, datetime, time, os

R = pathlib.Path(sys.argv[1]); E = R / 'evidence'; E.mkdir(parents=True, exist_ok=True)
N = sys.argv[2] if len(sys.argv) > 2 else '5'
ATTACK = sys.argv[3] if len(sys.argv) > 3 else 'aml-t0024-001'
NS = f'p{N}-demo'; OPNS = f'p{N}'
BRAIN = f'deployment/p{N}-brain'; MGR = f'deployment/p{N}-phorvex'
FIX_IMG = '753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:97e9f88e46624cc0c7fecc8d5e1aef0a01f10773b3416578e1e9413d02fafc93'
FORTIO = 'docker.io/fortio/fortio@sha256:3dd31ddeb4f962a1dae8cc2a0bce62c408ac830c8435bbea51b1e0fd4c8f7181'
NODE = 'ip-172-27-11-194.us-east-2.compute.internal'
created = []; cap = None

def save(n, o): (E / n).write_text(json.dumps(o, indent=2))
def log(s): print(datetime.datetime.now(datetime.timezone.utc).isoformat(), s, flush=True)
def k(args, obj=None, fail=True):
    p = subprocess.run(['kubectl', '--request-timeout=45s'] + args,
                       input=json.dumps(obj) if obj is not None else None,
                       text=True, capture_output=True, timeout=180)
    if fail and p.returncode: raise RuntimeError(str(args) + ': ' + p.stderr)
    return p
def get(args): return json.loads(k(args + ['-o', 'json']).stdout)
def state(ns, n): return json.loads((get(['-n', ns, 'get', 'cm', n]).get('data', {}).get('state.json') or '{}'))
def create(o): v = json.loads(k(['create', '-f', '-', '-o', 'json'], o).stdout); created.append(v); save('created.json', created); return v

def client(name, sa, qps, duration):
    o = {'apiVersion': 'batch/v1', 'kind': 'Job',
         'metadata': {'name': name, 'namespace': NS, 'labels': {'phorvex.ai/fixture': 'serving-rate-load'}},
         'spec': {'activeDeadlineSeconds': 600, 'ttlSecondsAfterFinished': 1200, 'backoffLimit': 0,
                  'template': {'metadata': {'labels': {'app': name}},
                               'spec': {'nodeSelector': {'kubernetes.io/hostname': NODE}, 'serviceAccountName': sa,
                                        'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                                        'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
                                        'containers': [{'name': 'client', 'image': FIX_IMG, 'command': ['/cost-client'],
                                                        'args': ['--qps=' + str(qps), '--duration=' + duration, '--url=http://rate-target.%s.svc/' % NS],
                                                        'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                                                        'resources': {'requests': {'cpu': '20m', 'memory': '32Mi'}, 'limits': {'cpu': '200m', 'memory': '64Mi'}}}]}}}}
    return create(o)

def flood(name, sa):
    o = {'apiVersion': 'batch/v1', 'kind': 'Job',
         'metadata': {'name': name, 'namespace': NS, 'labels': {'phorvex.ai/fixture': 'serving-rate-load', 'attack': ATTACK}},
         'spec': {'parallelism': 3, 'completions': 3, 'backoffLimit': 0, 'activeDeadlineSeconds': 480,
                  'template': {'metadata': {'labels': {'app': name, 'attack': ATTACK}},
                               'spec': {'nodeSelector': {'kubernetes.io/hostname': NODE}, 'serviceAccountName': sa,
                                        'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                                        'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
                                        'containers': [{'name': 'fortio', 'image': FORTIO,
                                                        'args': ['load', '-c', '50', '-qps', '0', '-t', '420s', '-quiet', '-allow-initial-errors', 'http://rate-target.%s.svc/' % NS],
                                                        'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                                                        'resources': {'requests': {'cpu': '100m', 'memory': '64Mi'}, 'limits': {'cpu': '1', 'memory': '128Mi'}}}]}}}}
    return create(o)

baseline = {'budget': get(['-n', NS, 'get', 'cm', 'phorvex-serving-rate-budget']),
            'status': state(NS, 'phorvex-serving-rate-status'),
            'journal': get(['-n', OPNS, 'get', 'cm', 'phorvex-throttle-journal'])}
save('baseline.json', baseline)
try:
    # Re-runnable: if a prior run's cap is still active, wait for the quiet auto-release.
    for _ in range(20):
        if state(NS, 'phorvex-serving-rate-status')['contract']['enabled'] is False: break
        log('WAIT_ARMED prior cap still active, waiting for quiet auto-release...'); time.sleep(8)
    baseline['status'] = state(NS, 'phorvex-serving-rate-status')
    assert baseline['status']['contract']['enabled'] is False, 'budget still capped (stale prior run did not auto-release)'
    assert baseline['status'].get('baseline', 0) > 0 and baseline['status'].get('reserved', 0) > 0, 'budget not armed (no measured quiet baseline/reserve)'
    # Clean operation slate: the operator-ns throttle journal holds the LAST operation receipt;
    # an immediately-prior back-to-back fire can leave it phase=applied (not yet rolled-back),
    # which throttleCapability refuses as "prior operation unresolved". The budget is confirmed
    # armed + not capped here, so clearing the receipt is safe and makes every fire start clean.
    k(['-n', OPNS, 'patch', 'cm', 'phorvex-throttle-journal', '--type', 'merge', '-p', '{"data":{"state.json":""}}'], fail=False)
    assert not get(['-n', NS, 'get', 'jobs'])['items'], 'preexisting Jobs in demo ns; refusing to run over them'
    # Baseline control: no throttle decision in the manager audit before the fire.
    fire_start = datetime.datetime.now(datetime.timezone.utc)
    def throttle_decisions(since='6m', after=None):
        out = k(['-n', OPNS, 'logs', MGR, '-c', 'manager', '--since=' + since]).stdout
        rows = []
        for line in out.splitlines():
            i = line.find('{')
            if i < 0: continue
            try: r = json.loads(line[i:])
            except ValueError: continue
            if r.get('msg') == 'decision' and r.get('action') == 'throttle':
                if after is not None:
                    try: t = datetime.datetime.fromisoformat(r['time'].replace('Z', '+00:00'))
                    except Exception: t = None
                    if t is None or t < after: continue
                rows.append(r)
        return rows, out
    pre_rows, _ = throttle_decisions(since='90s')
    # Attribution is by fire_start timestamp (only decisions AFTER fire_start count as this
    # fire's), so a residual decision row from an immediately-prior back-to-back fire is not
    # a blocker — it is excluded by the baseline-subtraction below. Recorded for the record.
    log('PRECHECK_OK armed+quiet; prior throttle decisions in last 90s=%d (baseline-subtracted by fire_start)' % len(pre_rows))

    legit = client('rate-legit-live', 'rate-legit', 3, '400s')
    abuse = flood('rate-flood', 'rate-abusive')
    log('LOAD_CREATED (legit-live + 3-worker abusive flood)')
    start = time.monotonic(); timeline = []
    while time.monotonic() - start < 200:
        st = state(NS, 'phorvex-serving-rate-status'); j = state(OPNS, 'phorvex-throttle-journal'); c = st.get('contract', {})
        now = datetime.datetime.now(datetime.timezone.utc)
        try: age = (now - datetime.datetime.fromisoformat(st['updatedAt'].replace('Z', '+00:00'))).total_seconds()
        except Exception: age = 999
        timeline.append({'at': now.isoformat(), 'capActive': st.get('capActive'), 'op': c.get('operationID'),
                         'phase': j.get('phase'), 'age': age, 'abusiveAtt': st.get('abusive', {}).get('attempted'),
                         'abusiveRej': st.get('abusive', {}).get('rejected')}); save('cap-timeline.json', timeline)
        if (st.get('capActive') and c.get('enabled') and 0 <= age < 10 and j.get('phase') == 'applied'
                and c.get('operationID') and c['operationID'] == j.get('operationID')
                and now < datetime.datetime.fromisoformat(c['expiresAt'].replace('Z', '+00:00'))):
            cap = {'status': st, 'journal': j, 'at': now.isoformat(), 'freshSeconds': age}; save('effective-cap.json', cap)
            log('EFFECTIVE_CAP op=' + c['operationID']); break
        log('CAP_WAIT %.0fs capActive=%s phase=%s abuseRej=%s' % (time.monotonic() - start, st.get('capActive'), j.get('phase'), st.get('abusive', {}).get('rejected'))); time.sleep(5)
    if not cap: raise RuntimeError('no fresh matched applied cap within 200s')

    save('events-at-cap.json', get(['get', 'securityevents']))
    (E / 'manager-at-cap.log').write_text(k(['-n', OPNS, 'logs', MGR, '-c', 'manager', '--since=6m']).stdout)
    # decision rows from the manager audit: throttle selected+feasible+actuated+emitted,
    # created during THIS fire (after fire_start) — baseline-subtracted by timestamp.
    all_rows, _ = throttle_decisions(since='6m', after=fire_start)
    rows = [r for r in all_rows if r.get('selected') and r.get('feasible') and r.get('actuated') and r.get('dispatchOutcome') == 'emitted']
    save('matching-throttle-rows.json', rows)
    save('all-throttle-decisions.json', all_rows)

    time.sleep(12)
    after = state(NS, 'phorvex-serving-rate-status'); save('status-after-cap.json', after)
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(cap['at'])).total_seconds()
    deltas = {side: {key: after[side][key] - cap['status'][side][key] for key in ('attempted', 'admitted', 'rejected')} for side in ('abusive', 'legitimate')}
    identity = all(after.get(key) == cap['status'].get(key) for key in ('podUID', 'bootID', 'configUID'))
    base = cap['status']['baseline']; burst = max(1.0, base)
    ab = deltas['abusive']
    adm_rate = ab['admitted'] / elapsed if elapsed > 0 else 0.0
    # Token-bucket guarantee over the measurement window, with +2s counter-sampling slop
    # at the window boundaries (proxy Snapshot vs harness clock) and one burst allowance.
    bound = base * (elapsed + 2) + burst + 1
    proof = {'elapsedSeconds': elapsed, 'deltas': deltas, 'allowedAbusiveAdmittedBound': bound,
             'abusiveAdmittedRatePerSec': adm_rate, 'baseline': base, 'reserved': cap['status']['reserved'],
             'abusiveRejectionFraction': ab['rejected'] / max(1, ab['attempted']), 'proxyIdentityUnchanged': identity,
             'decisionRows': len(rows)}
    save('cap-counter-verification.json', proof)
    assert identity and after.get('capActive') and after['contract']['operationID'] == cap['journal']['operationID'], 'cap identity changed'
    # Two-sided oracle: abusive is capped to ~baseline qps (rejections dominate; admitted
    # held near the measured baseline, NOT the attempted rate) while legit stays all-200.
    assert ab['rejected'] > 0, 'abusive not rejected at all: %s' % ab
    assert ab['admitted'] < 0.05 * ab['attempted'], 'abusive cap too leaky: %s (admitted >= 5%% of attempted)' % ab
    assert ab['admitted'] <= bound, 'abusive admitted %d over token-bucket bound %.2f (rate=%.2f/s baseline=%.2f)' % (ab['admitted'], bound, adm_rate, base)
    assert deltas['legitimate']['attempted'] > 0 and deltas['legitimate']['admitted'] == deltas['legitimate']['attempted'] and deltas['legitimate']['rejected'] == 0, 'legitimate regression: %s' % deltas['legitimate']
    assert rows, 'no matching selecting+feasible+actuating+emitted throttle decision row'
    save('result.json', {'pass': True, 'operationID': cap['journal']['operationID'], 'decisionRows': len(rows),
                         'abusiveDeltas': deltas['abusive'], 'legitDeltas': deltas['legitimate'], 'bound': bound})
    log('PASS throttle DEFENDED op=' + cap['journal']['operationID'])
except BaseException as e:
    import traceback
    save('result.json', {'pass': False, 'error': str(e), 'traceback': traceback.format_exc()}); log('FAILURE ' + str(e))
finally:
    res = []
    for o in reversed(created):
        if o['kind'] == 'Job':
            res.append(k(['-n', o['metadata']['namespace'], 'delete', 'job', o['metadata']['name'], '--ignore-not-found', '--wait=false'], fail=False).returncode)
    save('cleanup.json', res)
    log('LOAD_TORNDOWN')
r = json.loads((E / 'result.json').read_text())
log('DONE pass=%s' % r.get('pass'))
raise SystemExit(0 if r.get('pass') else 1)
