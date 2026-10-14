#!/usr/bin/env python3
"""Generate fake local records/reports. This performs no Phorvex or cluster run."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rev5_progress', ROOT/'tools/progress.py')
progress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(progress)
STAMP = '2026-10-13T00:00:00+00:00'


def fake(name):
    return 'synthetic://fake/' + name


def accept(c, key):
    deps = ['scope','source'] if key in ('M01','M02') else ['epoch','source','policy','fixture','runtime']
    c['milestones'][key].update(status='ACCEPTED', author='synthetic-producer', author_job_id='synthetic-job-producer', depends_on=deps, evidence_refs=[fake(key+'/evidence')], acceptance={'reviewer':'synthetic-reviewer','reviewer_job_id':'synthetic-job-reviewer','review_ref':fake(key+'/review'),'at':STAMP,'pins':{d:c['epoch'] if d == 'epoch' else c['pins'][d] for d in deps}})


def base(ident='DEMO-FULL', profile='FULL'):
    c = progress.new_case('synthetic-demo', ident, 'synthetic-stack', profile)
    c.update(synthetic=True, title='SYNTHETIC: formatting example, no real experiment', epoch='synthetic-epoch-1', pins={p:'synthetic-'+p+'-1' for p in ('scope','source','policy','fixture','runtime')}, created_at=STAMP, updated_at=STAMP, library={'entry_id':'SYNTHETIC-ENTRY','version':'fake-1','bucket':'synthetic','review_ref':fake('library-review')}, target={'customer':'synthetic-read-only-target','twin':'synthetic-isolated-target'}, owner='synthetic-orchestrator', observation_mode='AUTHENTICATED_FIXTURE_INPUT', claim_scope='RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT', attempts=[fake('attempt-1')])
    return c


def battery(c):
    archetypes = ['plain','stateful','neighbors','gpu-shared','sensitive-output','vector-shared']
    scenarios = []
    for index, archetype in enumerate(archetypes):
        sid = 'synthetic-scenario-' + str(index)
        scenarios.append({'scenario_id':sid,'archetype':archetype,'fixture_ref':fake(sid+'/fixture'),'fixture_hash':'0'*64,'expected_outcome':'EXPECTED_REJECTION' if archetype == 'neighbors' else 'SELECTED_AND_CONFIRMED','status':'PASS','evidence_refs':[fake(sid+'/result')],'review_ref':fake(sid+'/review'),'epoch':c['epoch'],'assertions':[{'assertion_id':'expected-rejection-observed' if archetype == 'neighbors' else 'effect-and-gates-confirmed','status':'PASS','evidence_refs':[fake(sid+'/assertion')]}]})
    for aid, expected in progress.BATTERY_ASSERTIONS.items():
        sid = 'synthetic-invariant-' + aid
        scenarios.append({'scenario_id':sid,'archetype':'integrity','fixture_ref':fake(sid+'/fixture'),'fixture_hash':'0'*64,'expected_outcome':expected,'status':'PASS','evidence_refs':[fake(sid+'/result')],'review_ref':fake(sid+'/review'),'epoch':c['epoch'],'assertions':[{'assertion_id':aid,'status':'PASS','evidence_refs':[fake(sid+'/assertion')]}]})
    return {'manifest_ref':fake('battery-manifest'),'review_ref':fake('battery-review'),'evidence_refs':[fake('battery-results')],'status':'PASS','completed_at':STAMP,'required_archetype_families':['plain','stateful','neighbors','gpu*','sensitive-output','vector-*'],'required_scenario_ids':[s['scenario_id'] for s in scenarios],'scenarios':scenarios}


def defended(ident='DEMO-FULL', profile='FULL'):
    c = base(ident,profile)
    for key in c['milestones']:
        accept(c,key)
    for key,m in c['metrics'].items():
        m.update(status='PASS',value=1.25 if key.startswith('S') else True,units='seconds' if key == 'S1' else 'synthetic-unit',window={'start':STAMP,'end':STAMP},measurement_type='PHYSICAL_MONOTONIC' if key == 'S1' else 'SYNTHETIC_PLACEHOLDER',evidence_refs=[fake(key+'/measurement')])
    c['checks']['g2_components'] = {key:{'status':'PASS','evidence_refs':[fake('g2/'+key)]} for key in progress.G2_COMPONENTS}
    c['checks']['g2_components']['bound_proof']['value'] = 'BOUNDED'
    c['checks']['scenario_battery'] = battery(c)
    c['chain'].update(expected_actuator='synthetic-actuator',selected_actuator='synthetic-actuator',dispatch='CONFIRMED',native_effect='CONFIRMED',brain_trace_ref=fake('brain-trace'))
    c.update(outcome='DEFENDED',current_validation='CURRENT',defended_at='2026-10-13T00:01:00+00:00',evidence_level='INDEPENDENTLY_VERIFIED',threat_effect='CAPABILITY_REMOVED',resolution=['EXISTING_ACTUATOR'],closure='FULL_FULL' if profile == 'FULL' else 'FULL_PHASE1',final_review_ref=fake('final-review'),stage='S10_PUBLISH',substep='Synthetic scoped report complete',scheduling_state='TERMINAL',work_state='DONE',last_evidence_at=STAMP,next_action='None: synthetic example only')
    return c


def cases():
    full = defended()
    pending = base('DEMO-PENDING')
    pending.update(work_state='BLOCKED',blocker='Synthetic missing adapter',next_action='Bind a real adapter before execution')
    negative = base('DEMO-NEGATIVE')
    for key in ('M01','M02','M03','M04','M05','M06','M07'):
        accept(negative,key)
    negative['metrics']['G1'].update(status='FAIL',value=False,evidence_refs=[fake('negative/G1')],reason='Synthetic capability persists')
    negative.update(outcome='NOT_DEFENDED',current_validation='CURRENT',closure='CLOSED_NEGATIVE',evidence_level='INDEPENDENTLY_VERIFIED',stage='S7_MEASURE_REVIEW',substep='Synthetic capability-removal gate failed',scheduling_state='TERMINAL',work_state='DONE',failure_layer='NATIVE_EFFECT',last_evidence_at=STAMP)
    engineering = base('DEMO-ENGINEERING')
    engineering.update(branches=['ACTUATOR_ENGINEERING'],progress_plan_revision=2,planned_resolution=['NEW_ACTUATOR'],stage='SE_ENGINEERING',substep='Await synthetic deployment',scheduling_state='ACTIVE',work_state='BLOCKED',blocker='Synthetic engineering dependency')
    for key in progress.PLAN['actuator_branch']:
        engineering['milestones'][key] = {'status':'NOT_STARTED','author':None,'depends_on':[],'evidence_refs':[],'acceptance':None,'reason':'Synthetic admitted engineering obligation'}
    for key in ('M01','M02','M03','M04','M05','M06','M07','E01','E02','E03','E04'):
        accept(engineering,key)
    engineering['history_notes'] = [{'at':STAMP,'reason':'Synthetic admitted engineering branch','old_required':18,'new_required':24,'plan_revision':2}]
    engineering['prs'] = [{'repo':'synthetic-repository','number':1,'url':fake('pr/1'),'change_types':['NEW_ACTUATOR'],'state':'OPEN','head_sha':'0'*40,'merge_sha':None,'review_ref':fake('source-review'),'follow_up_to':[],'deployments':[{'deployment_id':'synthetic-deploy-1','target':'synthetic-isolated-target','image_digest':'sha256:'+'0'*64,'source':'synthetic-source-1','at':STAMP,'status':'OBSERVED','evidence_refs':[fake('deployment')]}],'retests':[{'attempt_id':'synthetic-retest-1','epoch':engineering['epoch'],'source':'synthetic-source-1','deployment_ref':fake('deployment'),'outcome':'INCONCLUSIVE','evidence_level':'REPORTED','evidence_refs':[fake('retest-1')]},{'attempt_id':'synthetic-retest-2','epoch':engineering['epoch'],'source':'synthetic-source-1','deployment_ref':fake('deployment'),'outcome':'NOT_DEFENDED','evidence_level':'INDEPENDENTLY_VERIFIED','evidence_refs':[fake('retest-2')]}]}]
    return [pending,negative,engineering,full]


def generate(destination):
    destination = Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    campaign = json.loads((ROOT/'templates/campaign.json').read_text())
    campaign.update(campaign_id='synthetic-demo',mode='PLAN',notes='SYNTHETIC formatting only; fake references; no adapters or real results.')
    progress.atomic(destination/'campaign.json',json.dumps(campaign,indent=2)+'\n')
    # A temporary store prevents an example rerun from appending to an earlier demo.
    with tempfile.TemporaryDirectory() as tmp:
        db = progress.connect(Path(tmp)/'demo.sqlite')
        try:
            progress.init(db,campaign)
            for c in cases():
                progress.put(db,c,0,'synthetic-coordinator','Synthetic example registration')
            stale = progress.put(db,defended('DEMO-STALE'),0,'synthetic-coordinator','Synthetic historical accepted defense')
            stale['epoch'] = 'synthetic-epoch-2'
            stale['stage'] = 'S3_TWIN_ADMIT'
            stale['substep'] = 'Blocked on synthetic readmission and fresh dependency reviews'
            stale['next_action'] = 'Reconcile synthetic dependencies and obtain fresh acceptance before retesting'
            progress.put(db,stale,1,'synthetic-coordinator','Synthetic epoch change; dependent evidence becomes stale')
            progress.render(db,destination)
        finally:
            db.close()
    return destination


if __name__ == '__main__':
    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT/'examples/report')
