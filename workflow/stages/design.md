# Design: TRIAGED → AGREED

Read the issue and pinned baseline; trace the incident's inputs through their real
producers to the decisive condition. Check defaults, missing/stale inputs and every
relevant arm of a compound predicate. State the failing case and legitimate control.

| Owner | Output |
|---|---|
| coordinator | roles, baseline, authorized scope and verification requirements in intake/status |
| proposer | concise cause, minimal change, behavioral prediction and discriminating tests in `01-proposal` |
| skeptic | independently derive and seal `02A` before seeing proposal/implementation |
| skeptic | current blocking findings and evidence in `02B`; sign `critique` |
| proposer + skeptic | one selected contract and verification matrix in `03-decision`; skeptic signs `decision` |

After sealing, the reviewer starts the smallest real baseline reproduction while
implementation preparation proceeds independently. Sign baseline `red` directly;
retain the fixture for head verification. Investigate environment access/toolchain
constraints now. Do not postpone discovering an unavailable instrument until P3.

Use existing scope from `operations/AUTONOMY.md`. Choose conservative design/security
options and record who chose them; do not request routine human approval or impersonate
a named human approver. Keep compatibility consequences visible in the eventual PR.

Resolve disagreements using the smallest discriminating experiment. There is no
three-round human escalation. A concrete failed invariant remains blocking; resolve it,
narrow to a safe in-scope design, or report genuinely missing external input. Never
approve by exhaustion, majority vote or by weakening a prediction to fit results.

Declare class A/B and required L0–L2; add L3 for live/external behavior and L4 for evolving
state/timing. Keep those live obligations even when delivery stops at PR. Details:
`verification/LEVELS.md`. No evidence waiver is granted by autonomous scope.

Seal using `seal --by --expect-revision`; review/sign using `record-check`. Save superseded
artifacts, then keep the current proposal and critique concise. Freeze one agreed decision. Its existing verification matrix maps every critical
guarantee to the production boundary, realistic fixture, decisive failure assertion,
legitimate control, exact command/owner and required evidence layer.
An in-scope amendment requires fresh independent review and the standing authorization
reference; retain the original prediction. Scope expansion or weaker guarantees aren't
routine amendments. Handoff: selected contract/hash, baseline, exact change and tests.
