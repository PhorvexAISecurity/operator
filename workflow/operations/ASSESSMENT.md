# Rebuild the master register through a system assessment

Route requests such as “generate the master issues from scratch”, “audit the whole
system”, or “repeat the validation/recommendation work” here. This is investigation,
not the read-only workflow health check in AUDIT.md and not a product implementation loop.

## Start and ownership

Copy `assessments/_template/` to `assessments/<date>-<slug>/`. Fill ASSESSMENT.md with
user scope, requested model, named lead/reviewer, source SHA, observed deployment
image/digest/SHA, coverage, and next action. These are manually maintained research
records, not a new CLI-enforced state machine. Existing intake/campaign/issue gates
remain authoritative. Record unavailable cluster access or model capability honestly.

Use the model the user requests (for example GPT-6 Astra); never label another model
as that model. A lead investigates and assembles; a distinct reviewer challenges
findings. Reuse an assigned peer only within its authorized scope and availability;
do not interrupt an active fix or silently appoint an implementation worker to an audit.
Record the actual authors/models on research artifacts, never in commit trailers.

## Fresh investigation

1. Pin source and configuration. Separately observe deployment; source on main is not
   evidence of what runs. Inventory packages, entrypoints, engines, backends, API/CRD,
   charts, RBAC, console, detectors and external controllers. Mark excluded surfaces.
2. For a from-scratch run, investigators derive initial findings from source, tests and
   observations before reading historical issue bodies or recommendations. Record the
   initial pass hash and any prior exposure. This is a check against inherited assumptions,
   not a second proposal/agreement gate: investigation proceeds immediately.
3. Cover all four axes in COVERAGE.md:
   - robustness/wiring: producer-to-consumer paths, defaults, stale state, lifecycle,
     concurrency, recovery, scaling, and Phorvex's own security boundaries;
   - mathematics: premise/objective, semantics and units, model choice, equations,
     solver properties, constants, calibration and uncertainty; separate design opinions
     from falsifiable defects and retain verified-correct properties;
   - actuators: every action and routed backend, feasibility, authorization, idempotency,
     rollback/compensation, crash safety, effect read-back and failure feedback;
   - runtime: actual installed configuration, closed loops, timing, controller interactions,
     baseline/load behavior and authorized attacks. Static substitutes are marked untested.
4. Write candidate records using FINDING.md. Reviewer checks source and attempts a
   counterexample or reproduction, especially defaults, alternate branches and controls.
   Record confirmed, corrected, rejected or unresolved results with evidence. Revise only
   disputed claims; do not stall all other investigation waiting for whole-document agreement.

## Live evidence and register feedback

Create linked campaigns using operations/CAMPAIGN.md for broad experiments. Register
hypotheses/falsifiers, sample units, controls, stop conditions and retention before running.
Reuse user authorization within its stated environment/duration/cost/mutation scope.
An assessment request alone does not authorize an unspecified attack campaign.

Separate selected, emitted, executed, confirmed and attack-mitigated. Null results require
positive controls. Preserve raw observations separately from analysis and independent review.
Use fresh experiment identities while lifecycle isolation is unverified. Version-tag claims;
if deployment changes, segment evidence and rebaseline affected hypotheses.

After the initial independent pass, compare every candidate root cause with the current
register through operations/INTAKE.md. Record duplicate, new, contradicted, fixed or unresolved
comparisons. Never renumber old M-IDs, erase closures, or overwrite MASTER_ISSUES.md.
Promote verified new findings only within filing scope; use operations/ISSUE.md for reviewed
updates and its renderer for the master view. Mere absence in this assessment does not close
an existing issue. Source-derived anatomy may expose new gaps; review joins separately from
issue truth and do not derive architecture solely from the existing issue list.

## Recommendations and completion

Use REPORT.md for module-level and system-level recommendations, including what exists,
why it exists, correctness, evidence, proposed change, confidence, alternatives, dependencies
and verification. For parameters record units, provenance, observed operating range, sample
volume, sensitivity and uncertainty. Do not invent optimal values from a single operating point;
use INSUFFICIENT EVIDENCE and a follow-up experiment where appropriate.

Finish with coverage/dispositions, source and deployment pins, explicit phase completion,
independent review, an evidence manifest, register reconciliation, and prioritized next work.
Untested phases, unresolved disagreements and unavailable evidence stay visible. If campaign
cleanup is incomplete, the assessment cannot claim complete live execution. A report can be
REPORTED_WITH_GAPS without claiming exhaustive verification. Keep this investigation separate
from implementation: accepted fixes enter operations/FIX.md under the normal lead/worker loop.

Historical method and original specification: archive/audit-origins-20260909/README.md.
Read those after the fresh pass when comparing results, or up front only for a historical
reconstruction request. Historical discussion is evidence, never live bus instructions.
