#!/usr/bin/env python3
"""Trusted local transactional register; no cluster calls or evidence certification."""
import argparse
import copy
import csv
import datetime as dt
import io
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((ROOT / 'templates/milestones.json').read_text())
STATUS = {'NOT_STARTED', 'RUNNING', 'BLOCKED', 'SUBMITTED', 'ACCEPTED', 'STALE'}
OUTCOMES = {'PENDING', 'DEFENDED', 'NOT_DEFENDED', 'MITIGATED_UNACCEPTABLE', 'INCONCLUSIVE', 'NOT_APPLICABLE', 'OUT_OF_SCOPE', 'NON_TRANSFERABLE'}
CLOSURES = {'OPEN', 'INITIAL_WIN_ONLY', 'FULL_PHASE1', 'FULL_FULL', 'CLOSED_NEGATIVE', 'CLOSED_UNRESOLVED', 'CLOSED_NOT_APPLICABLE'}
METRICS = ['G1', 'G2', 'G3', 'S1', 'S2', 'S3', 'S4']
STAGES = {'S0_SCOPE','S1_SCAN_SELECT','S2_BIND_REVIEW','S3_TWIN_ADMIT','S4_ESTABLISH_REAL','S5_PROPOSE_DEFENSE','S6_BRAIN_EXECUTE','S7_MEASURE_REVIEW','S8_CHALLENGE','S9_REPEAT_RELEASE','S10_PUBLISH','SD_DESIGN','SE_ENGINEERING'}
METRIC_MILESTONES = {'M08':'G1', 'M09':'G2', 'M10':'G3', 'M11':'S1', 'M16':'S2', 'M17':'S3', 'M18':'S4'}
G2_COMPONENTS = {'availability_floor', 'slo_headroom', 'bound_proof', 'ledger_hold', 'co_tenant_isolation'}
BATTERY_FAMILIES = {'plain', 'stateful', 'neighbors', 'gpu*', 'sensitive-output', 'vector-*'}
BATTERY_ASSERTIONS = {
    'action-status-completeness':'INTEGRITY_ASSERTION',
    'slo-gate-rejection':'EXPECTED_REJECTION',
    'nan-fail-closed':'EXPECTED_REJECTION',
    'reactive-only-honesty':'INTEGRITY_ASSERTION',
    'trace-on-off-selection-equivalence':'INTEGRITY_ASSERTION',
    'adversarial-disjointness':'INTEGRITY_ASSERTION',
}
RESOLUTIONS = {'EXISTING_ACTUATOR', 'NEW_ACTUATOR', 'ACTUATOR_CORRECTION', 'OBSERVATION_INTEGRATION', 'HARNESS_CORRECTION'}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def dump(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def required(profile, branches):
    if profile not in ('PHASE1', 'FULL') or not isinstance(branches, list) or any(not isinstance(x, str) for x in branches) or len(branches) != len(set(branches)) or set(branches) - {'ACTUATOR_ENGINEERING'}:
        raise ValueError('Invalid profile or branch list')
    return PLAN['phase1' if profile == 'PHASE1' else 'full'] + (PLAN['actuator_branch'] if branches else [])


def new_case(campaign, ident, stack, profile):
    stamp = now()
    return {
        'schema_version':1, 'campaign_id':campaign, 'case_id':ident, 'revision':0,
        'title':'Unbound reviewed-library candidate', 'stack':stack, 'synthetic':False,
        'target':{'customer':None,'twin':None},
        'library':{'entry_id':None,'version':None,'bucket':None,'review_ref':None},
        'capability':None, 'profile':profile, 'branches':[], 'progress_plan_revision':1,
        'stage':'S1_SCAN_SELECT', 'substep':'Bind reviewed entry and observed target', 'work_state':'QUEUED', 'scheduling_state':'PARKED',
        'owner':None, 'round':1, 'attempt_id':None, 'epoch':'UNBOUND', 'pins':{},
        'observation_mode':'UNBOUND', 'claim_scope':'UNASSESSED',
        'milestones':{key:{'status':'NOT_STARTED','author':None,'depends_on':[],'evidence_refs':[],'acceptance':None,'reason':''} for key in required(profile, [])},
        'metrics':{key:{'status':'NOT_RUN','value':None,'units':None,'window':None,'measurement_type':None,'evidence_refs':[],'reason':''} for key in METRICS},
        'checks':{}, 'chain':{'expected_actuator':None,'selected_actuator':None,'dispatch':'NOT_RUN','native_effect':'NOT_RUN','brain_trace_ref':None},
        'outcome':'PENDING', 'current_validation':'UNKNOWN', 'defended_at':None,
        'evidence_level':'NONE', 'threat_effect':'NOT_ESTABLISHED',
        'failure_layer':'UNESTABLISHED', 'resolution':[], 'planned_resolution':[],
        'closure':'OPEN', 'competition_state':'ACTIVE', 'final_review_ref':None,
        'blocker':None, 'next_action':'Select an admitted library entry and bind observed facts',
        'assignments':[], 'prs':[], 'attempts':[], 'history_notes':[],
        'timing':{'active_seconds':None,'wait_seconds':None,'stage_started_at':None},
        'created_at':stamp, 'updated_at':stamp, 'last_evidence_at':None, 'last_heartbeat_at':None,
    }


def timestamp(value, label):
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed
    except (ValueError, TypeError, AttributeError):
        raise ValueError('Timezone-aware timestamp required: ' + label) from None


def refs(value, label):
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x.strip() for x in value):
        raise ValueError('Nonempty reference list required: ' + label)


def passed_check(check, label):
    if not isinstance(check, dict) or check.get('status') != 'PASS':
        raise ValueError('Passing check required: ' + label)
    refs(check.get('evidence_refs'), label)


def validate_battery(c):
    battery = c['checks'].get('scenario_battery')
    passed_check(battery, 'scenario_battery')
    if not battery.get('manifest_ref') or not battery.get('review_ref'):
        raise ValueError('Scenario battery requires manifest and review references')
    required_ids = battery.get('required_scenario_ids')
    refs(required_ids, 'required_scenario_ids')
    if len(set(required_ids)) != len(required_ids):
        raise ValueError('Duplicate required scenario ID')
    families = battery.get('required_archetype_families')
    refs(families, 'required_archetype_families')
    if BATTERY_FAMILIES - set(families):
        raise ValueError('Rev5 battery requires all six canonical archetype families')
    scenarios = battery.get('scenarios')
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError('Scenario battery must contain executed scenarios')
    found = set()
    invariant_ids = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ValueError('Scenario must be an object')
        sid = scenario.get('scenario_id')
        if not isinstance(sid, str) or not sid or sid in found:
            raise ValueError('Missing/duplicate scenario identity')
        found.add(sid)
        passed_check(scenario, 'scenario/' + sid)
        if scenario.get('epoch') != c['epoch'] or not scenario.get('fixture_ref') or not scenario.get('fixture_hash') or not scenario.get('review_ref'):
            raise ValueError('Scenario requires current epoch, fixture/hash and review: ' + sid)
        if scenario.get('expected_outcome') not in ('SELECTED_AND_CONFIRMED', 'EXPECTED_REJECTION', 'INTEGRITY_ASSERTION'):
            raise ValueError('Unknown scenario expectation: ' + sid)
        assertions = scenario.get('assertions')
        if not isinstance(assertions, list) or not assertions:
            raise ValueError('Actual scenario assertions required: ' + sid)
        assertion_ids = set()
        for assertion in assertions:
            if not isinstance(assertion, dict):
                raise ValueError('Assertion must be an object')
            aid = assertion.get('assertion_id')
            if not isinstance(aid, str) or not aid or aid in assertion_ids:
                raise ValueError('Missing/duplicate assertion identity: ' + sid)
            assertion_ids.add(aid)
            passed_check(assertion, sid + '/' + aid)
            if aid in BATTERY_ASSERTIONS:
                if scenario['expected_outcome'] != BATTERY_ASSERTIONS[aid] or sid not in required_ids:
                    raise ValueError('Invariant must be required and use its expected outcome: ' + aid)
                invariant_ids.add(aid)
    if set(required_ids) - found:
        raise ValueError('Required battery scenarios are missing')
    if set(BATTERY_ASSERTIONS) - invariant_ids:
        raise ValueError('Named Rev5 invariant assertions missing: ' + ', '.join(sorted(set(BATTERY_ASSERTIONS) - invariant_ids)))
    archetypes = {s.get('archetype') for s in scenarios}
    for family in families:
        if not any(isinstance(a, str) and (a.startswith(family[:-1]) if family.endswith('*') else a == family) for a in archetypes):
            raise ValueError('Required archetype family missing: ' + family)
    if timestamp(battery.get('completed_at'), 'battery.completed_at') > timestamp(c.get('defended_at'), 'defended_at'):
        raise ValueError('Scenario battery must complete before the initial WIN')


def validate(c):
    if not isinstance(c, dict):
        raise ValueError('Case must be an object')
    dump(c)  # Reject non-finite numbers anywhere, including nested receipts.
    # Keep admission aligned with the complete case template used by rendering.
    need = set(new_case('schema','schema','UNBOUND','FULL'))
    if need - c.keys():
        raise ValueError('Missing fields: ' + ', '.join(sorted(need - c.keys())))
    if c['schema_version'] != 1 or not isinstance(c['case_id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', c['case_id']):
        raise ValueError('Invalid schema version or case ID')
    for field in ('revision', 'progress_plan_revision'):
        if type(c[field]) is not int or c[field] < (1 if field == 'progress_plan_revision' else 0):
            raise ValueError('Invalid ' + field)
    for field in ('target','library','pins','milestones','metrics','checks','chain'):
        if not isinstance(c[field], dict):
            raise ValueError('Object required: ' + field)
    for field in ('stage','substep','observation_mode','claim_scope'):
        if not isinstance(c[field],str):
            raise ValueError('String required: ' + field)
    if type(c['synthetic']) is not bool:
        raise ValueError('Boolean required: synthetic')
    if c['stage'] not in STAGES:
        raise ValueError('Invalid Rev5 stage: ' + c['stage'])
    if 'entry_id' not in c['library']:
        raise ValueError('Missing library field: entry_id')
    if {'selected_actuator','native_effect'} - c['chain'].keys():
        raise ValueError('Missing chain fields: selected_actuator/native_effect')
    for field in ('resolution','planned_resolution','assignments','prs','attempts'):
        if not isinstance(c.get(field, []), list):
            raise ValueError('List required: ' + field)
    for assignment in c['assignments']:
        if not isinstance(assignment,dict) or (assignment.get('harness_job_id') is not None and not isinstance(assignment['harness_job_id'],str)):
            raise ValueError('Assignment requires object and string/null harness_job_id')
    if c['current_validation'] not in ('CURRENT','STALE','UNKNOWN'):
        raise ValueError('Invalid current_validation')
    if c['scheduling_state'] not in ('ACTIVE','PARKED','TERMINAL'):
        raise ValueError('Invalid scheduling_state')
    if c['evidence_level'] not in ('NONE','REPORTED','INDEPENDENTLY_VERIFIED'):
        raise ValueError('Invalid evidence level')
    ids = required(c['profile'], c['branches'])
    if set(c['milestones']) != set(ids):
        raise ValueError('Milestones must exactly match declared profile and branches')
    if c['outcome'] not in OUTCOMES or c['closure'] not in CLOSURES:
        raise ValueError('Invalid outcome or closure')
    if set(c['resolution']) - RESOLUTIONS or set(c.get('planned_resolution', [])) - RESOLUTIONS:
        raise ValueError('Resolution outside this Rev5 loop')
    for key, item in c['milestones'].items():
        if not isinstance(item, dict) or item.get('status') not in STATUS:
            raise ValueError('Invalid milestone status: ' + key)
        if item.get('acceptance') is not None and not isinstance(item['acceptance'],dict):
            raise ValueError('Milestone acceptance must be object or null: ' + key)
        if item['status'] == 'ACCEPTED':
            a = item.get('acceptance') or {}
            if not item.get('author') or not a.get('reviewer') or a['reviewer'] == item['author'] or not a.get('review_ref'):
                raise ValueError('Independent acceptance and evidence required: ' + key)
            refs(item.get('evidence_refs'), key)
            timestamp(a.get('at'), key + '.acceptance.at')
            if item.get('author_job_id') and a.get('reviewer_job_id') == item['author_job_id']:
                raise ValueError('Producer and reviewer job IDs must differ: ' + key)
            deps = item.get('depends_on', [])
            refs(deps, key + '.depends_on')
            for dep in deps:
                expected = c['epoch'] if dep == 'epoch' else c['pins'].get(dep)
                if expected in (None, 'UNBOUND') or a.get('pins', {}).get(dep) != expected:
                    raise ValueError('Stale/missing dependency acceptance: ' + key + '/' + dep)
            if key not in ('M01','M02') and 'epoch' not in deps:
                raise ValueError('Runtime milestone must bind epoch: ' + key)
    if set(c['metrics']) != set(METRICS):
        raise ValueError('All seven metric fields are required')
    for key, metric in c['metrics'].items():
        if not isinstance(metric, dict) or metric.get('status') not in ('NOT_RUN','PENDING','PASS','FAIL','UNKNOWN'):
            raise ValueError('Invalid metric status: ' + key)
        if 'value' not in metric:
            raise ValueError('Metric value field is required: ' + key)
        if metric['status'] in ('UNKNOWN','NOT_RUN','PENDING') and metric.get('value') is not None:
            raise ValueError('Unknown/unmeasured values must be null: ' + key)
        if metric['status'] in ('PASS','FAIL'):
            refs(metric.get('evidence_refs'), key)
        if key.startswith('S') and metric['status'] == 'PASS' and (metric.get('value') is None or not metric.get('units')):
            raise ValueError('Passing score requires value and units: ' + key)
        if key.startswith('S') and metric['status'] in ('PASS','FAIL') and metric.get('value') is not None:
            value = metric['value']
            if type(value) not in (int,float) or not math.isfinite(value) or value < 0:
                raise ValueError('Measured score must be a finite nonnegative number: ' + key)
    if c['metrics']['G2']['status'] == 'PASS':
        components = c['checks'].get('g2_components')
        if not isinstance(components, dict) or set(components) != G2_COMPONENTS:
            raise ValueError('G2 requires all five separate components')
        for key, component in components.items():
            passed_check(component, 'g2_components/' + key)
        if components['bound_proof'].get('value') not in ('ZERO','BOUNDED'):
            raise ValueError('G2 bound_proof must be ZERO or BOUNDED')
    for mid, metric in METRIC_MILESTONES.items():
        if c['milestones'].get(mid, {}).get('status') == 'ACCEPTED' and c['metrics'][metric]['status'] != 'PASS':
            raise ValueError('Milestone contradicts metric: ' + mid)
    if c['milestones']['M11']['status'] == 'ACCEPTED' and c['metrics']['S1'].get('measurement_type') != 'PHYSICAL_MONOTONIC':
        raise ValueError('S1 must be physical elapsed time')
    if c['claim_scope'] == 'NATURAL_DETECTION_AND_RESPONSE' and c['observation_mode'] != 'NATURAL_OBSERVATION':
        raise ValueError('Natural detection cannot be claimed from injected/replayed input')
    if c['outcome'] == 'DEFENDED':
        mandatory = [f'M{i:02d}' for i in range(1,12)]
        if c['current_validation'] == 'STALE':
            if c['closure'] != 'OPEN' or not any(m['status'] == 'STALE' for m in c['milestones'].values()):
                raise ValueError('Historical DEFENDED must expose stale obligations and reopen closure')
        elif c['current_validation'] == 'CURRENT':
            if c['evidence_level'] != 'INDEPENDENTLY_VERIFIED' or c.get('threat_effect') != 'CAPABILITY_REMOVED' or any(c['milestones'][x]['status'] != 'ACCEPTED' for x in mandatory) or not c['chain'].get('selected_actuator') or not c['chain'].get('brain_trace_ref') or c['chain'].get('dispatch') != 'CONFIRMED' or c['chain'].get('native_effect') != 'CONFIRMED':
                raise ValueError('DEFENDED requires accepted causal chain, gates and S1')
            validate_battery(c)
        else:
            raise ValueError('DEFENDED must be CURRENT or explicitly historical STALE')
        if c['observation_mode'] in ('REPLAY_INPUT','UNBOUND'):
            raise ValueError('Replay/unbound result cannot claim physical DEFENDED')
    if c['closure'] == 'INITIAL_WIN_ONLY' and (c['outcome'] != 'DEFENDED' or c['current_validation'] != 'CURRENT'):
        raise ValueError('Initial win closure requires a current accepted defense')
    if c['closure'] in ('FULL_PHASE1','FULL_FULL'):
        if c['outcome'] != 'DEFENDED' or c['current_validation'] != 'CURRENT' or not c.get('final_review_ref') or any(c['milestones'][x]['status'] != 'ACCEPTED' for x in ids):
            raise ValueError('Full closure requires every obligation and final review')
        if c['closure'] != ('FULL_FULL' if c['profile'] == 'FULL' else 'FULL_PHASE1'):
            raise ValueError('Closure/profile mismatch')
    if any(not isinstance(pr,dict) or not isinstance(pr.get('url'),str) for pr in c['prs']):
        raise ValueError('PR requires an object with string url')
    if len({pr.get('url') for pr in c['prs']}) != len(c['prs']):
        raise ValueError('Duplicate PR identity')
    for pr in c['prs']:
        if not pr.get('url') or not pr.get('repo') or type(pr.get('number')) is not int or pr['number'] <= 0 or not isinstance(pr.get('retests', []), list) or not isinstance(pr.get('deployments', []), list):
            raise ValueError('PR requires identity and deployment/retest lists')
        if {'repo','number','url','change_types','state','head_sha','merge_sha','review_ref','follow_up_to','deployments','retests'} - pr.keys():
            raise ValueError('Incomplete PR delivery record')
        for deployment in pr['deployments']:
            if not isinstance(deployment,dict) or {'target','image_digest','source','at','status','evidence_refs'} - deployment.keys():
                raise ValueError('Incomplete deployment observation')
            refs(deployment['evidence_refs'],'deployment')
            timestamp(deployment['at'],'deployment.at')
        for retest in pr['retests']:
            if not isinstance(retest,dict) or {'attempt_id','epoch','source','deployment_ref','outcome','evidence_level','evidence_refs'} - retest.keys() or retest['outcome'] not in OUTCOMES:
                raise ValueError('Incomplete retest record')
            refs(retest['evidence_refs'],'retest')
    return c


def completion(c):
    ids = required(c['profile'], c['branches'])
    count = sum(c['milestones'][x]['status'] == 'ACCEPTED' for x in ids)
    return count, len(ids), round(100 * count / len(ids), 1)


def connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=30)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('CREATE TABLE IF NOT EXISTS campaign (id INTEGER PRIMARY KEY, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL, case_id TEXT NOT NULL, revision INTEGER NOT NULL, previous_payload TEXT, payload TEXT NOT NULL);')
    return db


def init(db, campaign):
    if not campaign.get('campaign_id'):
        raise ValueError('campaign_id required')
    for key in ('case_parallelism','max_active_agents','max_parallel_experiments'):
        if type(campaign.get(key)) is not int or campaign[key] <= 0:
            raise ValueError('Positive integer campaign limit required: ' + key)
    db.execute('BEGIN IMMEDIATE')
    try:
        old = db.execute('SELECT payload FROM campaign WHERE id=1').fetchone()
        if old and json.loads(old[0]) != campaign:
            raise ValueError('Existing campaign manifest differs; do not overwrite it')
        if not old:
            db.execute('INSERT INTO campaign VALUES (1, ?)', (dump(campaign),))
        db.commit()
    except Exception:
        db.rollback()
        raise


def invalidate(c, old):
    """Only invalidate accepted obligations whose declared pins no longer match."""
    stale = []
    for key, item in c['milestones'].items():
        if item.get('status') != 'ACCEPTED':
            continue
        a = item.get('acceptance') or {}
        prior = old['milestones'].get(key,{})
        previous_acceptance = prior.get('acceptance') or {}
        deps = set(item.get('depends_on', [])) | set(prior.get('depends_on', []))
        changed = [p for p in deps if (old['epoch'] if p == 'epoch' else old['pins'].get(p)) != (c['epoch'] if p == 'epoch' else c['pins'].get(p)) or (previous_acceptance and previous_acceptance.get('pins',{}).get(p) != (c['epoch'] if p == 'epoch' else c['pins'].get(p)))]
        fresh = bool(previous_acceptance and a.get('review_ref') != previous_acceptance.get('review_ref') and timestamp(a.get('at'),'acceptance.at') > timestamp(previous_acceptance.get('at'),'previous acceptance.at'))
        mismatched = [p for p in changed if a.get('pins', {}).get(p) != (c['epoch'] if p == 'epoch' else c['pins'].get(p)) or (previous_acceptance and not fresh)]
        if mismatched:
            item['status'] = 'STALE'
            item['reason'] = 'Dependency changed: ' + ', '.join(mismatched)
            if previous_acceptance:
                item['acceptance'] = copy.deepcopy(previous_acceptance)
                item['depends_on'] = copy.deepcopy(prior.get('depends_on',[]))
                item['evidence_refs'] = copy.deepcopy(prior.get('evidence_refs',[]))
            stale.append(key)
            metric = METRIC_MILESTONES.get(key)
            if metric:
                c['metrics'][metric]['status'] = 'UNKNOWN'
                c['metrics'][metric]['value'] = None
                c['metrics'][metric]['reason'] = item['reason']
    if stale:
        c['current_validation'] = 'STALE'
        c['closure'] = 'OPEN'
        if old.get('scheduling_state') == 'ACTIVE':
            c['scheduling_state'] = 'ACTIVE'
            c['work_state'] = 'RECONCILE_REQUIRED'
        else:
            c['scheduling_state'] = 'PARKED'
            c['work_state'] = 'BLOCKED'
        c.setdefault('history_notes', []).append({'at':now(), 'reason':'Dependency invalidation', 'milestones':stale})
    return c


def put(db, c, expected, actor, reason):
    if not actor or not reason or type(expected) is not int or expected < 0 or c.get('revision') != expected:
        raise ValueError('Actor/reason and matching submitted revision required')
    c = copy.deepcopy(c)
    db.execute('BEGIN IMMEDIATE')
    try:
        campaign = db.execute('SELECT payload FROM campaign WHERE id=1').fetchone()
        if not campaign or json.loads(campaign[0])['campaign_id'] != c.get('campaign_id'):
            raise ValueError('Campaign identity mismatch or uninitialized store')
        manifest = json.loads(campaign[0])
        oldrow = db.execute('SELECT revision,payload FROM cases WHERE case_id=?', (c.get('case_id'),)).fetchone()
        actual = oldrow[0] if oldrow else 0
        if actual != expected:
            raise ValueError(f'REVISION_CONFLICT: expected {expected}, actual {actual}')
        if oldrow:
            old = json.loads(oldrow[1])
            if c['profile'] != old['profile'] or not set(old['branches']).issubset(c['branches']):
                raise ValueError('Cannot remove profile/branch obligations in place')
            if c['progress_plan_revision'] < old['progress_plan_revision'] or (c['branches'] != old['branches'] and c['progress_plan_revision'] <= old['progress_plan_revision']):
                raise ValueError('New obligations require an increasing progress-plan revision')
            if c['branches'] != old['branches']:
                c.setdefault('history_notes', []).append({'at':now(), 'reason':'Engineering branch added', 'old_required':len(required(old['profile'],old['branches'])), 'new_required':len(required(c['profile'],c['branches'])), 'plan_revision':c['progress_plan_revision']})
            if c['attempts'][:len(old['attempts'])] != old['attempts']:
                raise ValueError('Attempt references are append-only')
            if [p['url'] for p in c['prs'][:len(old['prs'])]] != [p['url'] for p in old['prs']]:
                raise ValueError('Ordered PR history cannot be removed or reordered')
            for prior, current in zip(old['prs'], c['prs']):
                if any(current.get(k) != prior.get(k) for k in ('url','repo','number')):
                    raise ValueError('PR identity is immutable')
                for field in ('retests','deployments'):
                    if current.get(field, [])[:len(prior.get(field, []))] != prior.get(field, []):
                        raise ValueError('PR/' + field + ' history cannot be removed or rewritten')
            invalidate(c, old)
        validate(c)
        if c['scheduling_state'] == 'ACTIVE':
            other_active = sum(json.loads(row[0]).get('scheduling_state') == 'ACTIVE' for row in db.execute('SELECT payload FROM cases WHERE case_id != ?', (c['case_id'],)))
            if other_active + 1 > manifest['case_parallelism']:
                raise ValueError('CASE_CAPACITY_CONFLICT: active case admission exceeds case_parallelism')
        if c['outcome'] == 'DEFENDED' and c['current_validation'] == 'STALE' and (not oldrow or old['outcome'] != 'DEFENDED'):
            raise ValueError('Historical DEFENDED requires a previously admitted defense')
        c['revision'] = actual + 1
        c['updated_at'] = now()
        payload = dump(c)
        db.execute('INSERT INTO cases VALUES (?,?,?) ON CONFLICT(case_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload', (c['case_id'], c['revision'], payload))
        db.execute('INSERT INTO events(at,actor,reason,case_id,revision,previous_payload,payload) VALUES (?,?,?,?,?,?,?)', (c['updated_at'], actor, reason, c['case_id'], c['revision'], oldrow[1] if oldrow else None, payload))
        db.commit()
        return c
    except Exception:
        db.rollback()
        raise


def esc(value):
    if value is None:
        return '—'
    if isinstance(value, (dict,list)):
        value = dump(value)
    return str(value).replace('|', '\\|').replace('\n', '<br>')


def table(headers, rows):
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |'] + ['| ' + ' | '.join(esc(x) for x in row) + ' |' for row in rows])


def atomic(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def render(db, out):
    db.execute('BEGIN')
    try:
        manifest = db.execute('SELECT payload FROM campaign WHERE id=1').fetchone()
        if not manifest:
            raise ValueError('Initialize campaign first')
        campaign = json.loads(manifest[0])
        cases = [validate(json.loads(x[0])) for x in db.execute('SELECT payload FROM cases ORDER BY case_id')]
        events = [dict(zip(['seq','at','actor','reason','case_id','revision'], x)) for x in db.execute('SELECT seq,at,actor,reason,case_id,revision FROM events ORDER BY seq')]
        db.commit()
    except Exception:
        db.rollback()
        raise
    generated = now()
    running = [a for c in cases for a in c['assignments'] if a.get('work_state') == 'RUNNING' and a.get('harness_job_id')]
    job_ids = {a['harness_job_id'] for a in running}
    accepted = sum(completion(c)[0] for c in cases)
    total = sum(completion(c)[1] for c in cases)
    summary = {'registered':len(cases), 'active':sum(c['scheduling_state'] == 'ACTIVE' for c in cases), 'parked':sum(c['scheduling_state'] == 'PARKED' for c in cases), 'terminal':sum(c['scheduling_state'] == 'TERMINAL' for c in cases), 'admitted':sum(c['milestones']['M03']['status'] == 'ACCEPTED' for c in cases), 'initial_defenses':sum(c['outcome'] == 'DEFENDED' and c['current_validation'] == 'CURRENT' for c in cases), 'full_phase1':sum(c['closure'] == 'FULL_PHASE1' for c in cases), 'full_full':sum(c['closure'] == 'FULL_FULL' for c in cases), 'negative_or_unresolved':sum(c['closure'] in ('CLOSED_NEGATIVE','CLOSED_UNRESOLVED') for c in cases), 'stale':sum(c['current_validation'] == 'STALE' or any(m['status'] == 'STALE' for m in c['milestones'].values()) for c in cases), 'accepted_obligations':accepted, 'required_obligations':total}
    physical = campaign.get('observed_physical_experiments')
    if physical is not None and (type(physical) is not int or physical < 0):
        raise ValueError('Observed physical experiment count must be nonnegative or null')
    physical_at = campaign.get('observed_physical_experiments_at')
    if physical_at is not None:
        timestamp(physical_at,'observed_physical_experiments_at')
    md = ['# Verification-loop progress', '', f"Campaign: **{esc(campaign['campaign_id'])}**. Generated: {generated}.", '', '**Synthetic demonstration data — no cluster results. References beginning synthetic:// are fake.**' if any(c.get('synthetic') for c in cases) else 'Register projection. Accepted states rely on referenced reviews; this renderer does not certify physical evidence.', '', f'**Active cases: {summary["active"]} / case parallelism {campaign.get("case_parallelism", "UNKNOWN")}. Parked cases: {summary["parked"]}. Recorded RUNNING case-worker jobs: {len(job_ids)}; total active agents: UNKNOWN (root/shared jobs not included); configured max_active_agents: {campaign.get("max_active_agents", "UNKNOWN")}. Physical experiments last reported: {physical if physical is not None else "UNKNOWN"} (at {physical_at or "UNKNOWN"}) / configured limit {campaign.get("max_parallel_experiments", "UNKNOWN")}.**', '', 'Campaign counts: ' + esc(summary) + '.', '', f'Queued assignments: {sum(a.get("work_state") == "QUEUED" for c in cases for a in c["assignments"])}. Scheduling states are coordinator records. Parking a case does not prove an operation stopped or a lease was released; reconcile physical resources separately.', '', 'Completion counts accepted obligations, not time remaining. Heartbeats and report generation do not advance evidence. Reviewer identity and job IDs are recorded metadata; the local tool cannot authenticate independence.', '']
    rows = []
    csv_rows = []
    for c in cases:
        k,n,pct = completion(c)
        rows.append([c['case_id'],c['stack'],c['target'],c['library']['entry_id'],c['stage']+': '+c['substep'],c['scheduling_state']+' / '+c['work_state'],f'{k}/{n} ({pct}%)',c['outcome']+' / '+c['evidence_level']+' / '+c['current_validation'],c['closure'],{'action':c['chain']['selected_actuator'],'effect':c['chain']['native_effect']},c['observation_mode']+' / '+c['claim_scope'],', '.join(p['url'] for p in c['prs']) or 'None',c.get('blocker'),c.get('next_action'),c['last_evidence_at']])
        csv_rows.append([c['case_id'],c['synthetic'],c['stack'],c['stage'],c['substep'],c['scheduling_state'],c['work_state'],k,n,pct,c['outcome'],c['evidence_level'],c['current_validation'],c['closure'],c['last_evidence_at']])
    md += [table(['Case','Stack','Target','Entry','Stage / substep','Scheduling / work','Milestones','Outcome / evidence / current validation','Closure','Brain action / effect','Observation / claim','PRs','Blocker','Next action','Last evidence'], rows), '']
    for c in cases:
        md += [f"## {esc(c['case_id'])} — {esc(c['title'])}", '', f"Synthetic: {c['synthetic']}. Target: {esc(c['target'])}. Profile: {c['profile']}; epoch: {esc(c['epoch'])}; plan revision: {c['progress_plan_revision']}; case revision: {c['revision']}.", '', f"Observation: {c['observation_mode']}; claim: {c['claim_scope']}; current validation: {c['current_validation']}. Resolution: {esc(c['resolution'])}. Planned: {esc(c.get('planned_resolution', []))}.", '', f"Owner: {esc(c.get('owner'))}; round/attempt: {esc(c.get('round'))}/{esc(c.get('attempt_id'))}. Timing: {esc(c.get('timing'))}. Heartbeat: {esc(c.get('last_heartbeat_at'))}.", '']
        md += [table(['Milestone','Status','Author / reviewer','Reason / remaining work','Evidence'], [[key+' '+PLAN['labels'][key],m['status'],str(m.get('author'))+' / '+str((m.get('acceptance') or {}).get('reviewer')),m.get('reason'),m.get('evidence_refs')] for key,m in c['milestones'].items()]), '']
        md += [table(['Metric','Status','Value','Units','Window / type','Evidence / reason'], [[key,m['status'],m['value'],m.get('units'),str(m.get('window'))+' / '+str(m.get('measurement_type')),{'evidence':m.get('evidence_refs'),'reason':m.get('reason')}] for key,m in c['metrics'].items()]), '']
        for label,value in [('Chain',c['chain']),('Checks',c['checks']),('Assignments',c['assignments']),('PR deployment and retest history',c['prs']),('Attempt references',c['attempts']),('Plan and stale history',c.get('history_notes',[]))]:
            md += [f'**{label}**','','```json',json.dumps(value,indent=2,ensure_ascii=False),'```','']
        ce = [e for e in events if e['case_id'] == c['case_id']]
        md += [table(['Revision','Time','Actor','Change'], [[e['revision'],e['at'],e['actor'],e['reason']] for e in ce]), '']
    out = Path(out)
    atomic(out/'PROGRESS.md', '\n'.join(md).rstrip()+'\n')
    atomic(out/'cases.json', json.dumps({'campaign':campaign,'generated_at':generated,'summary':summary,'cases':cases,'events':events},indent=2,ensure_ascii=False)+'\n')
    csv_text = io.StringIO(newline='')
    writer = csv.writer(csv_text,lineterminator='\n')
    writer.writerow(['case_id','synthetic','stack','stage','substep','scheduling_state','work_state','accepted','required','completion_percent','outcome','evidence_level','current_validation','closure','last_evidence_at'])
    writer.writerows(csv_rows)
    atomic(out/'cases.csv', csv_text.getvalue())
    return len(cases)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    x=sub.add_parser('init'); x.add_argument('--db',required=True); x.add_argument('--campaign',required=True)
    x=sub.add_parser('new-case'); x.add_argument('--campaign',required=True); x.add_argument('--id',required=True); x.add_argument('--stack',required=True); x.add_argument('--profile',choices=['PHASE1','FULL'],default='FULL'); x.add_argument('--out',required=True)
    x=sub.add_parser('put'); x.add_argument('--db',required=True); x.add_argument('--file',required=True); x.add_argument('--expected-revision',type=int,required=True); x.add_argument('--actor',required=True); x.add_argument('--reason',required=True)
    x=sub.add_parser('get'); x.add_argument('--db',required=True); x.add_argument('--case',required=True); x.add_argument('--out',required=True)
    x=sub.add_parser('render'); x.add_argument('--db',required=True); x.add_argument('--out',required=True)
    x=sub.add_parser('validate'); x.add_argument('--file',required=True)
    a=p.parse_args()
    try:
        if a.command == 'new-case':
            c=new_case(a.campaign,a.id,a.stack,a.profile); validate(c); atomic(a.out,json.dumps(c,indent=2)+'\n'); print(a.out); return
        if a.command == 'validate':
            c=validate(json.loads(Path(a.file).read_text())); print(json.dumps({'case_id':c['case_id'],'milestones':completion(c)})); return
        with connect(a.db) as db:
            if a.command == 'init': init(db,json.loads(Path(a.campaign).read_text())); print('Initialized')
            elif a.command == 'put': print(json.dumps({'revision':put(db,json.loads(Path(a.file).read_text()),a.expected_revision,a.actor,a.reason)['revision']}))
            elif a.command == 'get':
                row=db.execute('SELECT payload FROM cases WHERE case_id=?',(a.case,)).fetchone()
                if not row: raise ValueError('Unknown case')
                atomic(a.out,json.dumps(json.loads(row[0]),indent=2)+'\n'); print(a.out)
            elif a.command == 'render': print(json.dumps({'cases':render(db,a.out),'report':str(Path(a.out)/'PROGRESS.md')}))
    except (ValueError,KeyError,TypeError,AttributeError,sqlite3.Error,OSError) as error:
        p.exit(2,str(error)+'\n')


if __name__ == '__main__':
    main()
