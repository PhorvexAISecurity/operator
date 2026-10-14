"""Local structural/CAS checks only; no Phorvex or physical-harness certification."""
import copy
import csv
import importlib.util
import json
import multiprocessing
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('examples_generate', ROOT/'examples/generate.py')
examples = importlib.util.module_from_spec(spec)
spec.loader.exec_module(examples)
p = examples.progress


def competing_writer(db_path, case, barrier, queue):
    db = p.connect(db_path)
    try:
        barrier.wait(timeout=10)
        result = p.put(db,case,case['revision'],'synthetic-writer','Concurrent local update')
        queue.put(('committed',result['revision']))
    except ValueError as error:
        queue.put(('rejected',str(error)))
    finally:
        db.close()


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'progress.sqlite'
        self.db = p.connect(self.path)
        self.campaign = {'campaign_id':'synthetic-demo','case_parallelism':10,'max_active_agents':8,'max_parallel_experiments':1}
        p.init(self.db,self.campaign)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def store(self,c):
        return p.put(self.db,c,c['revision'],'synthetic-coordinator','Local unit test update')

    def assertInvalid(self,c,message=None):
        with self.assertRaisesRegex(ValueError,message or '.'):
            p.validate(c)

    def test_defaults_and_denominators(self):
        for profile,n in [('PHASE1',15),('FULL',18)]:
            c = p.new_case('synthetic-demo','C-'+profile,'synthetic',profile)
            self.assertEqual(p.completion(p.validate(c)),(0,n,0.0))
        self.assertEqual(len(p.required('FULL',['ACTUATOR_ENGINEERING'])),24)
        self.assertEqual(len(p.required('PHASE1',['ACTUATOR_ENGINEERING'])),21)

    def test_render_required_fields_are_rejected_before_storage(self):
        mutations = [
            lambda c:c.pop('synthetic'),
            lambda c:c.pop('competition_state'),
            lambda c:c['chain'].pop('selected_actuator'),
            lambda c:c['chain'].pop('native_effect'),
            lambda c:c['library'].pop('entry_id'),
            lambda c:c['metrics']['S1'].pop('value'),
            lambda c:c.update(substep=None),
            lambda c:c.update(assignments=[None]),
            lambda c:c.update(assignments=[{'harness_job_id':[]}]),
            lambda c:c['milestones']['M01'].update(acceptance='invalid-object'),
        ]
        for index,mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                c = examples.base()
                mutate(c)
                self.assertInvalid(c)
                with self.assertRaises(ValueError):
                    self.store(c)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM cases').fetchone()[0],0)
        self.assertFalse(self.db.in_transaction)

    def test_only_declared_rev5_stages_can_be_stored(self):
        for stage in ('S10_ENGINEERING','S12_FINAL_REVIEW','S7_GATES','UNKNOWN_STAGE'):
            with self.subTest(stage=stage):
                c = examples.base()
                c['stage'] = stage
                self.assertInvalid(c,'Invalid Rev5 stage')
                with self.assertRaisesRegex(ValueError,'Invalid Rev5 stage'):
                    self.store(c)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM cases').fetchone()[0],0)

    def test_independent_acceptance_metadata(self):
        c = examples.base()
        examples.accept(c,'M01')
        self.assertEqual(p.completion(p.validate(c))[0],1)
        c['milestones']['M01']['acceptance']['reviewer'] = c['milestones']['M01']['author']
        self.assertInvalid(c,'Independent')
        c = examples.base()
        examples.accept(c,'M01')
        c['milestones']['M01']['acceptance']['reviewer_job_id'] = c['milestones']['M01']['author_job_id']
        self.assertInvalid(c,'job IDs')
        c = examples.base()
        c['milestones']['M01']['status'] = 'SUBMITTED'
        self.assertEqual(p.completion(c)[0],0)

    def test_dependency_pins_reject_stale_acceptance(self):
        c = examples.base()
        examples.accept(c,'M01')
        c['pins']['source'] = 'changed-source'
        self.assertInvalid(c,'Stale/missing')
        c = examples.defended()
        c['milestones']['M08']['depends_on'] = ['source']
        self.assertInvalid(c,'bind epoch')

    def test_unknown_metrics_are_null_and_complete(self):
        c = examples.base()
        for state in ('UNKNOWN','NOT_RUN','PENDING'):
            c['metrics']['S1'].update(status=state,value=0)
            self.assertInvalid(c,'must be null')
        c['metrics']['S1'].update(value=None)
        p.validate(c)
        del c['metrics']['S4']
        self.assertInvalid(c,'seven metric')

    def test_pass_requires_measurement_evidence_and_physical_s1(self):
        c = examples.defended()
        c['metrics']['G1']['evidence_refs'] = []
        self.assertInvalid(c,'reference list')
        c = examples.defended()
        c['metrics']['S1']['measurement_type'] = 'REPLAY'
        self.assertInvalid(c,'physical elapsed')
        c = examples.defended()
        c['metrics']['S1']['value'] = None
        self.assertInvalid(c,'value and units')

    def test_g2_requires_every_component(self):
        for key in p.G2_COMPONENTS:
            with self.subTest(component=key):
                c = examples.defended()
                del c['checks']['g2_components'][key]
                self.assertInvalid(c,'five separate')
                c = examples.defended()
                c['checks']['g2_components'][key]['status'] = 'UNKNOWN'
                self.assertInvalid(c,'Passing check')
                c = examples.defended()
                c['checks']['g2_components'][key]['evidence_refs'] = []
                self.assertInvalid(c,'reference list')
        c = examples.defended()
        c['checks']['g2_components']['bound_proof']['value'] = 'UNBOUNDED'
        self.assertInvalid(c,'ZERO or BOUNDED')

    def test_defended_requires_complete_passed_battery(self):
        p.validate(examples.defended())
        mutations = [
            lambda b:b.update(status='UNKNOWN'),
            lambda b:b.update(manifest_ref=None),
            lambda b:b.update(review_ref=None),
            lambda b:b.update(evidence_refs=[]),
            lambda b:b.update(scenarios=[]),
            lambda b:b['scenarios'].pop(),
            lambda b:b['required_archetype_families'].remove('neighbors'),
            lambda b:b['scenarios'][0].update(status='UNSUPPORTED'),
            lambda b:b['scenarios'][0].update(epoch='old-epoch'),
            lambda b:b['scenarios'][0].update(assertions=[]),
            lambda b:b['scenarios'][0]['assertions'][0].update(status='FAIL'),
            lambda b:b['scenarios'][0]['assertions'][0].update(evidence_refs=[]),
            lambda b:b.update(completed_at='2026-10-13T00:02:00+00:00'),
        ]
        for index,mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                c = examples.defended()
                mutate(c['checks']['scenario_battery'])
                self.assertInvalid(c)
        c = examples.defended()
        del c['checks']['scenario_battery']
        self.assertInvalid(c,'scenario_battery')

    def test_expected_rejection_is_a_passing_test(self):
        c = examples.defended()
        negatives = [s for s in c['checks']['scenario_battery']['scenarios'] if s['expected_outcome'] == 'EXPECTED_REJECTION']
        self.assertTrue(negatives)
        self.assertTrue(all(s['status'] == 'PASS' for s in negatives))
        self.assertEqual(p.validate(c)['outcome'],'DEFENDED')

    def test_replay_and_injected_scope_guards(self):
        c = examples.defended()
        c['observation_mode'] = 'REPLAY_INPUT'
        self.assertInvalid(c,'Replay/unbound')
        c = examples.defended()
        c['claim_scope'] = 'NATURAL_DETECTION_AND_RESPONSE'
        self.assertInvalid(c,'Natural detection')
        c = examples.defended()
        c['chain']['native_effect'] = 'DISPATCHED'
        self.assertInvalid(c,'causal chain')

    def test_cas_conflict_preserves_snapshot_and_rolls_back(self):
        c = self.store(examples.base())
        next_case = copy.deepcopy(c)
        next_case['blocker'] = 'first writer'
        self.store(next_case)
        c['blocker'] = 'stale writer'
        with self.assertRaisesRegex(ValueError,'REVISION_CONFLICT'):
            self.store(c)
        rows = self.db.execute('SELECT revision,previous_payload,payload FROM events ORDER BY seq').fetchall()
        self.assertEqual([x[0] for x in rows],[1,2])
        self.assertEqual(json.loads(rows[1][1])['revision'],1)
        self.assertEqual(json.loads(rows[1][2])['blocker'],'first writer')
        self.assertFalse(self.db.in_transaction)

    def test_multiprocess_cas_exactly_one_writer(self):
        c = self.store(examples.base())
        context = multiprocessing.get_context('spawn')
        barrier = context.Barrier(2)
        queue = context.Queue()
        workers = [context.Process(target=competing_writer,args=(str(self.path),c,barrier,queue)) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=20)
            self.assertFalse(worker.is_alive())
            self.assertEqual(worker.exitcode,0)
        results = [queue.get(timeout=5) for _ in workers]
        self.assertEqual(sorted(x[0] for x in results),['committed','rejected'])
        self.assertIn('REVISION_CONFLICT',next(x[1] for x in results if x[0] == 'rejected'))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],2)
        queue.close()

    def test_pin_change_invalidates_only_declared_dependents(self):
        c = self.store(examples.defended())
        c['epoch'] = 'synthetic-epoch-2'
        stale = self.store(c)
        self.assertEqual(stale['outcome'],'DEFENDED')
        self.assertEqual(stale['current_validation'],'STALE')
        self.assertEqual(stale['closure'],'OPEN')
        self.assertEqual(stale['work_state'],'BLOCKED')
        self.assertEqual(p.completion(stale),(2,18,11.1))
        self.assertEqual(stale['milestones']['M01']['status'],'ACCEPTED')
        self.assertEqual(stale['milestones']['M08']['status'],'STALE')
        self.assertEqual(stale['metrics']['G1']['status'],'UNKNOWN')
        self.assertIsNone(stale['metrics']['S1']['value'])
        self.assertTrue(stale['milestones']['M08']['acceptance'])
        historical = json.loads(self.db.execute('SELECT previous_payload FROM events ORDER BY seq DESC LIMIT 1').fetchone()[0])
        self.assertEqual(historical['closure'],'FULL_FULL')
        self.assertEqual(historical['metrics']['S1']['value'],1.25)

    def test_new_case_cannot_invent_stale_historical_defense(self):
        c = examples.defended()
        c.update(current_validation='STALE',closure='OPEN')
        c['milestones']['M08']['status'] = 'STALE'
        with self.assertRaisesRegex(ValueError,'previously admitted'):
            self.store(c)

    def test_branch_denominator_grows_and_requirements_cannot_shrink(self):
        c = self.store(examples.base())
        c['branches'] = ['ACTUATOR_ENGINEERING']
        for key in p.PLAN['actuator_branch']:
            c['milestones'][key] = {'status':'NOT_STARTED','author':None,'depends_on':[],'evidence_refs':[],'acceptance':None,'reason':''}
        with self.assertRaisesRegex(ValueError,'increasing progress-plan'):
            self.store(c)
        c['progress_plan_revision'] += 1
        c = self.store(c)
        self.assertEqual(p.completion(c)[1],24)
        self.assertEqual(c['history_notes'][-1]['old_required'],18)
        c['branches'] = []
        with self.assertRaisesRegex(ValueError,'Cannot remove'):
            self.store(c)

    def test_pr_attempt_deployment_retest_history_append_only(self):
        c = self.store(next(c for c in examples.cases() if c['case_id'] == 'DEMO-ENGINEERING'))
        for field in ('attempts','retests','deployments'):
            with self.subTest(field=field):
                changed = copy.deepcopy(c)
                if field == 'attempts':
                    changed[field] = []
                else:
                    changed['prs'][0][field] = []
                with self.assertRaisesRegex(ValueError,'append-only|history'):
                    self.store(changed)
        changed = copy.deepcopy(c)
        changed['prs'][0]['retests'][0]['outcome'] = 'DEFENDED'
        with self.assertRaisesRegex(ValueError,'rewritten'):
            self.store(changed)
        changed = copy.deepcopy(c)
        retest = copy.deepcopy(changed['prs'][0]['retests'][0])
        retest['attempt_id'] = 'synthetic-third'
        changed['prs'][0]['retests'].append(retest)
        updated = self.store(changed)
        self.assertEqual(len(updated['prs'][0]['retests']),3)
        self.assertEqual(updated['prs'][0]['retests'][0]['outcome'],'INCONCLUSIVE')

    def test_full_closure_requires_measurements_review_and_matching_profile(self):
        c = examples.defended()
        c['milestones']['M18']['status'] = 'SUBMITTED'
        self.assertInvalid(c,'every obligation')
        c = examples.defended()
        c['closure'] = 'FULL_PHASE1'
        self.assertInvalid(c,'profile mismatch')
        c = examples.defended()
        c['final_review_ref'] = None
        self.assertInvalid(c,'final review')
        c = next(c for c in examples.cases() if c['case_id'] == 'DEMO-NEGATIVE')
        self.assertLess(p.completion(p.validate(c))[2],100)

    def test_synthetic_render_json_csv_and_unknown_display(self):
        output = Path(self.tmp.name)/'report'
        examples.generate(output)
        data = json.loads((output/'cases.json').read_text())
        self.assertEqual(len(data['cases']),5)
        self.assertTrue(all(c['synthetic'] for c in data['cases']))
        self.assertEqual(data['summary']['stale'],1)
        self.assertEqual(data['summary']['initial_defenses'],1)
        markdown = (output/'PROGRESS.md').read_text()
        self.assertTrue(markdown.endswith('\n'))
        self.assertFalse(markdown.endswith('\n\n'))
        self.assertNotIn(b'\r',(output/'cases.csv').read_bytes())
        self.assertIn('Synthetic demonstration data',markdown)
        self.assertIn('synthetic://fake/',markdown)
        self.assertIn('UNKNOWN',markdown)
        self.assertIn('STALE',markdown)
        self.assertIn('old_required',markdown)
        stale = next(c for c in data['cases'] if c['case_id']=='DEMO-STALE')
        self.assertEqual(stale['work_state'],'BLOCKED')
        self.assertEqual(stale['stage'],'S3_TWIN_ADMIT')
        self.assertNotIn('| S1 | UNKNOWN | 0 |',markdown)
        with (output/'cases.csv').open(newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows),5)
        self.assertEqual(next(r for r in rows if r['case_id']=='DEMO-ENGINEERING')['required'],'24')
        self.assertTrue(all(r['last_evidence_at'] != data['generated_at'] for r in rows))

    def test_campaign_identity_and_immutability(self):
        with self.assertRaisesRegex(ValueError,'differs'):
            p.init(self.db,{**self.campaign,'campaign_id':'another'})
        c = examples.base()
        c['campaign_id'] = 'another'
        with self.assertRaisesRegex(ValueError,'Campaign identity'):
            self.store(c)

    def test_numeric_scores_and_nested_nonfinite_are_rejected(self):
        for value in (-1, True, '1.25', float('nan'), float('inf')):
            with self.subTest(value=value):
                c = examples.defended()
                c['metrics']['S1']['value'] = value
                self.assertInvalid(c)
        c = examples.base()
        c['checks']['nested'] = {'nonfinite':float('-inf')}
        self.assertInvalid(c)

    def test_win_requires_every_pre_win_milestone_and_capability_removed(self):
        for key in ('M01','M02','M03','M06'):
            c = examples.defended()
            c['milestones'][key]['status'] = 'NOT_STARTED'
            self.assertInvalid(c,'causal chain')
        c = examples.defended()
        c['threat_effect'] = 'CAPABILITY_PRESENT'
        self.assertInvalid(c,'causal chain')

    def test_named_invariants_cannot_be_omitted_or_mislabeled(self):
        for aid,expected in p.BATTERY_ASSERTIONS.items():
            with self.subTest(assertion=aid):
                c = examples.defended()
                b = c['checks']['scenario_battery']
                s = next(s for s in b['scenarios'] if s['assertions'][0]['assertion_id'] == aid)
                s['assertions'][0]['assertion_id'] = 'unrelated-assertion'
                self.assertInvalid(c,'invariant assertions missing')
                c = examples.defended()
                s = next(s for s in c['checks']['scenario_battery']['scenarios'] if s['assertions'][0]['assertion_id'] == aid)
                s['expected_outcome'] = 'SELECTED_AND_CONFIRMED'
                self.assertInvalid(c,'expected outcome')

    def test_patched_old_review_pins_do_not_reaccept_stale_evidence(self):
        c = self.store(examples.defended())
        old_review = copy.deepcopy(c['milestones']['M08']['acceptance'])
        c['epoch'] = 'synthetic-epoch-2'
        for key,m in c['milestones'].items():
            if 'epoch' in m['depends_on']:
                m['acceptance']['pins']['epoch'] = c['epoch']
        stale = self.store(c)
        self.assertEqual(stale['milestones']['M08']['status'],'STALE')
        self.assertEqual(stale['milestones']['M08']['acceptance'],old_review)
        stale['milestones']['M08']['status'] = 'ACCEPTED'
        stale['milestones']['M08']['acceptance']['pins']['epoch'] = stale['epoch']
        stale['metrics']['G1'].update(status='PASS',value=True)
        still_stale = self.store(stale)
        self.assertEqual(still_stale['milestones']['M08']['status'],'STALE')
        self.assertEqual(still_stale['milestones']['M08']['acceptance'],old_review)

    def test_active_case_invalidation_keeps_slot_for_reconciliation(self):
        c = examples.defended()
        c.update(closure='INITIAL_WIN_ONLY',scheduling_state='ACTIVE',work_state='WAITING_REVIEW')
        c = self.store(c)
        c['epoch'] = 'synthetic-epoch-2'
        changed = self.store(c)
        self.assertEqual(changed['scheduling_state'],'ACTIVE')
        self.assertEqual(changed['work_state'],'RECONCILE_REQUIRED')
        self.assertEqual(changed['current_validation'],'STALE')

    def test_case_parallelism_is_enforced_between_concurrent_admissions(self):
        # Replace this test's empty manifest with a capacity-one fixture.
        self.db.execute('DELETE FROM campaign')
        self.db.commit()
        p.init(self.db,{**self.campaign,'case_parallelism':1})
        context = multiprocessing.get_context('spawn')
        barrier = context.Barrier(2)
        queue = context.Queue()
        candidates = [examples.base('CONCURRENT-'+str(i)) for i in range(2)]
        for c in candidates:
            c['scheduling_state'] = 'ACTIVE'
        workers = [context.Process(target=competing_writer,args=(str(self.path),c,barrier,queue)) for c in candidates]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=20)
            self.assertFalse(worker.is_alive())
            self.assertEqual(worker.exitcode,0)
        results = [queue.get(timeout=5) for _ in workers]
        self.assertEqual(sorted(x[0] for x in results),['committed','rejected'])
        self.assertIn('CASE_CAPACITY_CONFLICT',next(x[1] for x in results if x[0]=='rejected'))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM cases').fetchone()[0],1)
        queue.close()

    def test_report_separates_case_capacity_workers_and_unknown_physics(self):
        c = examples.base()
        c['scheduling_state'] = 'ACTIVE'
        c['assignments'] = [{'work_state':'RUNNING','harness_job_id':'synthetic-job'}]
        self.store(c)
        output = Path(self.tmp.name)/'report'
        p.render(self.db,output)
        md = (output/'PROGRESS.md').read_text()
        self.assertIn('Active cases: 1 / case parallelism 10',md)
        self.assertIn('Recorded RUNNING case-worker jobs: 1',md)
        self.assertIn('total active agents: UNKNOWN (root/shared jobs not included)',md)
        self.assertIn('configured max_active_agents: 8',md)
        self.assertIn('Physical experiments last reported: UNKNOWN',md)


if __name__ == '__main__':
    unittest.main()
