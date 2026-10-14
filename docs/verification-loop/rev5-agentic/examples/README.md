# Synthetic local progress examples

Every record here has `synthetic: true`. All `synthetic://fake/` references, hashes, identities, targets, deployments, measurements, assertions, and review records are invented to exercise the local format. The labels `DEFENDED`, `CONFIRMED`, and `INDEPENDENTLY_VERIFIED` in these records describe fake inputs to the register; they are not Phorvex results. No customer or twin connection is used.

Run from the package root:

```sh
python3 examples/generate.py
python3 tools/check_package.py
python3 -m unittest discover -s tests -v
```

The generator builds a temporary SQLite store, exercises the same transactional update API as a coordinator, then writes [Markdown](report/PROGRESS.md), [JSON](report/cases.json), and [CSV](report/cases.csv). It removes the temporary store. Pass an output directory as the first argument to generate a separate demonstration. Generated report timestamps are local generation times; they do not replace evidence times.

| Case | Formatting behavior |
| --- | --- |
| DEMO-PENDING | Registered, parked, blocked on an adapter; 0/18 milestones |
| DEMO-NEGATIVE | Negative terminal disposition with partial defense progress; 7/18 |
| DEMO-ENGINEERING | Admitted engineering branch adds six requirements, making 24; records deployment and two retained failed/unresolved retests |
| DEMO-FULL | Fake complete FULL acceptance with 18/18; separate G2 components and twelve battery scenarios |
| DEMO-STALE | Historical fake DEFENDED remains visible; a changed epoch stales its dependent evidence, reopens the record, and reduces credit to 2/18 |

The battery includes six archetype families and six named invariant assertions. SLO and NaN negative scenarios are `EXPECTED_REJECTION` tests whose assertions pass when the intended rejection is observed; they are not failed defense gates. The local guards check statuses, references, dependency metadata, mandatory assertion identities, and battery-before-WIN timing. Independent review of original receipts must establish their actual correctness and approved manifest completeness.

`case_parallelism` limits admitted ACTIVE case slots. Parked and terminal cases do not consume that slot. Recorded RUNNING case-worker job IDs and the separate physical experiment bound appear beside case counts. Root and shared jobs are absent from the local case assignments, so total active agents stays UNKNOWN; the scheduler/harness must enforce the configured agent cap using its complete job inventory. Physical usage remains UNKNOWN unless an observed count is supplied; parking does not prove reconciliation or resource release. Changing pins on an ACTIVE case preserves its slot and sets `work_state` to `RECONCILE_REQUIRED`.

The tests cover local CAS races and case-capacity races, history retention, dependency staleness, guard failures, unknown metrics, and rendering. They do not test execution adapters, physical isolation, distributed scheduling, reviewer authentication, or harness integration.
