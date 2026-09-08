# Fix protocol

Load the stage you are working on, not this entire reference on every turn.

## Roles

Roles name responsibilities; participants are explicitly assigned in status.
One participant may own compatible roles. Two participants normally suffice:
proposer + implementer, and skeptic + live verifier + coordinator.

| Role | Owns | Must not do |
|---|---|---|
| human_owner | scope, explicit authorizations, deadlock/waiver/risk rulings | replace evidence with approval |
| proposer | root cause, proposal, predicted behavior and scope | approve their own design |
| implementer | patch, tests, RED/GREEN and raw evidence | sign P3, live, or final review |
| skeptic | sealed derivation, critique, agreed decision, P3 and final review | read proposal before sealing; silently edit implementation |
| live_verifier | approved scoped L3/L4, positive controls and cleanup | extrapolate beyond observed environment |
| coordinator | assignments, pins, revisions, dependencies and synchronization | fabricate another role's evidence or signature |

Intake uses an investigator; campaigns use a lead and independent reviewer.
Release synchronizer is the coordinator responsibility for a release. Roles
are capability-based, not permanently attached to a model or tool. A change of
participant is recorded; it does not transfer a previous review signature.

## Stages and artifacts

| State range | Read | Exit evidence |
|---|---|---|
| TRIAGED → AGREED | `stages/design.md` | intake, proposal, sealed blind derivation, critique, frozen decision |
| AGREED → PR_READY | `stages/verify.md` | exact patch, RED/GREEN, L0–L2, independent P3 |
| PR_READY → CLOSED | `stages/release.md` | reviewed PR/merge, observed deployment, L3/L4, final review and synchronization |

Side states: `HELD` (owner pause), `BLOCKED` (external condition), `DEFERRED`
(with owner/date), `REOPENED` (failed acceptance), `INVALIDATED` (model disproved),
`ACCEPTED_RISK` (explicit ruling). These are not successful code-fix closure.
`--force` may enter a recovery state with approval; it cannot skip a forward gate.

Profiles: `standard`; `light` for local/mechanical changes; `batch` for disjoint
files and separately tested invariants. All retain independent review and
pinned evidence. A no-code design/risk decision uses intake/issue disposition;
a measurement program uses a campaign. Neither needs a fake implementation.

## Evidence contract

Use `record-check <fix> <check> --by <participant> --artifact <relative-path>
--command '<reproduction command>' --expect-revision N`. The tool retains signer,
hash, timestamp and source pin and indexes the artifact. It does not execute the
command or judge whether prose proves the claim. The signer is responsible for
that substantive review. See `tools/workflow.py … --help` for exact options.

Input edits use `configure <fix> --file <partial.yaml> --by <coordinator>
--expect-revision N`; it cannot set state, signatures or seals. CLI commands
print the new revision. Re-read `brief` after another participant writes.

Checks: `critique`, `decision`, `implementation`, `red`, `l0`, `l1`, `l2`,
`positive_control`, `incident`, `p3`, `patch_equivalence`, `l3`, `l4`, `final`.

- Baseline pins critique/decision/RED; implementation head pins offline/P3;
  running source and digest pin live/final evidence.
- Changed artifacts/pins invalidate their attestations. Keep prior raw evidence
  immutable; new attempts use new paths. Rebase requires new evidence or an
  independent patch-equivalence review, never a bare `PASS` assertion.
- `NOT_REQUIRED` is a human-signed, explained ruling for an eligible layer.
  FAIL, UNAVAILABLE and NON_DISCRIMINATING never become PASS automatically.
- RED must fail the intended assertion, not compile/setup. A positive control
  traverses the same instrument as the claim.
- Before P3, the skeptic signs `evidence/incident.md`: realistic inputs through
  production-derived conditions, baseline/head outcomes, and a legitimate
  control. Assert fixture relevance; enumerate compound-predicate arms and
  relevant stale/missing inputs. P3 binds this evidence hash and requires renewed
  review if it changes. The tool checks presence, ownership and pins, not the
  truth of the trace; substantive verification remains the skeptic's job.
- Class A predicts exact behavior changes. Class B predicts falsifiable bands
  for objective/belief/cost/clock changes. Missed criteria reopen the fix;
  disproved models invalidate it. Amendments preserve the original prediction
  and reference human authorization.

## Ownership and consistency

Before changing state, reread `brief` and supply its revision. The tool locks
before reading or validating and rejects stale revisions. Keep one canonical
workflow checkout for coordination; product worktrees contain code, not competing
copies of live status. Cross-clone Git conflicts still require reconciliation.

Approvals are scoped references in `STATUS.yaml.approvals` (`pr_open`, `merge`,
`deploy`, `close`, `accepted_risk`); an explicit command reference overrides the
matching scope. Evidence requirements remain mandatory even when authorized.
Do all authorized work before requesting a new gate. Hand off references and
next action, not conversation transcripts.

## History and release truth

Migrated records keep their original evidence and declared gaps. Never invent
missing historical seals or tests. They are readable without replaying the loop;
new transitions require the current contracts and missing evidence is explicit.
Canonical anatomy follows deployed source; implementation follows reviewed main.
A tag, Helm value or successful rollout alone cannot close an issue.

Each closed code fix retains an offline `verify.sh` and regression tests.
Each release runs cheap verifiers, publishes anatomy once, and reconciles each
issue separately. Broad campaigns are optional and require an explicit request;
they never replace missing per-fix verification. Refresh baselines only after
acceptance so regressions cannot be absorbed into the new normal.
