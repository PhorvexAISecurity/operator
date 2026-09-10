# Design: TRIAGED → AGREED

New fixes use `fix_loop: lead_worker`. Assign proposer, skeptic, coordinator and
live_verifier to the lead; implementer to the worker.

1. Lead: pin the baseline and trace the issue through real production inputs.
   Reproduce the failure with a legitimate control. Inspect the live cluster when
   useful and authorized; retain observations with source/environment pins.
2. Lead: write one fix plan in `03-decision.md`: cause, changes, expected behavior,
   compatibility consequences and discriminating tests. Declare class A/B, L0–L2,
   required L3/live and L4/soak. Start baseline RED for reuse at head.
3. Lead: sign `decision`, transition DESIGNING → AGREED, and send the worker the
   plan, pins and tests with an instruction to implement. No worker proposal,
   blind seal, critique round or worker approval is required.
4. Worker: implement and test. Lead: review the committed implementation and
   independently reproduce the incident. Return precise defects until revisions
   pass; then deliver the PR. See `verify.md` and `../operations/HANDOFFS.md`.
5. After merge/deployment, the lead verifies the running fix live before closure.

Use standing scope from `../operations/AUTONOMY.md` for routine in-scope decisions.
If evidence disproves the plan, preserve the old prediction and re-sign the smallest
amendment with that authorization reference. The revised code still needs review.
Scope expansion, weaker guarantees and waivers need their actual authority.

## Existing blind peer records

Absent `fix_loop` or `blind_peer` retains DESIGNING → CRITIQUED → AGREED: proposer
writes `01-proposal`; a separate skeptic seals `02A` before exposure, then writes
`02B` and signs critique/decision. Never manufacture historical blind evidence.

Before agreement or an implementation head, the coordinator can migrate using
revision-checked `configure`: set `fix_loop: lead_worker`, assign the roles above,
and reference the user's instruction with `--approval-ref`. Preserve historical
artifacts and signatures; re-sign decision for the changed contract.
