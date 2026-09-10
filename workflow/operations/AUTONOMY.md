# Standing authorization: named issue → reviewed PR

Mehrdad, 2026-09-08, explicitly requested removing routine human intervention:
“I want to say 'start issue X' and after some time come back and expect the PR link”.
He required a leaner workflow without reducing implementation quality.

Starting a named issue authorizes assigned agents to choose and independently review
in-scope design/security defaults, implement, test in isolated local fixtures, commit,
push the issue branch and open/update its PR. It authorizes necessary peer bus messages.
Named product/security approvers in older tickets do not block this proposed-code path.
Record actual agent decisions under this delegation; never invent a human signature.

Prefer conservative, reversible choices and preserved defaults. Record consequential
compatibility choices in the PR. Resolve disagreement with a concrete counterexample
and discriminating test, not a round-count approval request. Amend a design within
scope through a re-signed lead plan and review of the worker’s revised code, retaining
the superseded prediction and evidence. Legacy blind peer fixes retain independent
design review.

This scope does not authorize merging, shared-cluster changes, attacks, execution grants,
persisted injections, weakening security guarantees, accepting unresolved risk, or
waiving required evidence. Reuse separately recorded authorization when it covers those
actions. Missing access or genuinely unobtainable required evidence remains an honest
blocker; never produce a misleading “ready” PR to satisfy the delivery target.

Default delivery ends at an open independently reviewed PR with its URL and accurate
validation status. Issue closure still requires the release/live-verification contract.
Explicit narrower user instructions override this default; preserve any resulting hold.
