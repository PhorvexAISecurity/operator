# Independent lead review, first pass

Source: dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca. Original report and seal retained.
Lead reran the full TestFresh/TestFP overlay suite successfully, reproduced the
attack-results data race with `-race` (expected failing run), and ran auditguard
successfully with `/opt/phorvex-tools` on PATH. Helm exists on this host; its absence
from the worker PATH was a local environment limit, not a missing installation.
Logs live in the assessment evidence directory. No live mutation was performed.

## Corrections and grouping required

- F1/F2/F3/F14/F16 overlap the existing M-136 authentication/trust boundary.
  Missing OIDC must fail closed unless an explicit tightly scoped demo mode is
  enabled; the proposed `if oidc != nil` check alone preserves the reported hole.
  A loopback bind does not by itself make an ALB a valid trusted proxy path.
  Verify actual reachability/config separately; no executed in-cluster exploit
  has been recorded here. Enforce authenticated role and tenant, not lens headers.
- F4 tenant-blind approval and client ID collision are valid source defects;
  reproduce with signed identities as well as the demo fallback. Lead also found
  concurrent approval executes one pending request twice through the real routes
  and gate (lead-fresh-console.md). These share lifecycle/identity surfaces.
  The default nil applier makes cluster-write impact latent; preserve that limit.
- F5/F11 expose a real writable-data configuration mismatch, but a writable
  decision-audit mount would enable F7 destructive clearing. Separate console
  state from operator audit history, preserve retention/security, and make failed
  persistence visible. Do not fix by broadly making the operator audit writable.
- F6/F19 belong together as experiment execution/measurement/recovery defects.
  Never claim DEFENDED from a literal or a failed fire step. Crash recovery must
  avoid overwriting a user's subsequent policy edits; restoring old mode blindly
  is unsafe. Scope/lease/ownership and bounded recovery need explicit design.
- F8 is independently reproduced. Locking only writes is insufficient if readers
  marshal pointers after unlocking; publish immutable snapshots or lock/copy
  consistently, including persistence and every watcher update.
- F9 is plausible from the cluster-scoped CRD and unfiltered list but needs an
  actual producer/control test. Namespace filtering alone still cannot attribute
  a different pod/run's event or prove effect from a request. Require target UID,
  run correlation and observed effect for a defended claim.
- F10 is not demonstrated RCE. Preserve the admission-gate mitigation. Check the
  intended operator-vs-tenant policy contract before calling different allowlists
  contradictory; a stack discovery error must not silently broaden a capability.
- F12/F13/F17/F18/F22/F23/F24 require exact issue dedup and targeted validation.
  Split missing audience, key refresh and fetch deadline into explicit acceptance
  conditions. Demo claims matter for due diligence; record their evidence limits.
- F15 server budgets are a concrete hardening candidate; choose timeouts that
  preserve supported SSE streaming. F20 unauthenticated health/version is not
  automatically a defect: identify sensitive fields and intended access contract.
  F21 formatting is maintenance, not evidence of a runtime vulnerability or a
  reason to delay unrelated fixes.
- Correct broad verified-negative claims: a finite traversal test set proves its
  tested cases; passing package tests or no observed command injection do not
  prove exhaustive correctness.

Complete the explicit partially read dashboard/backend files and reconcile the
existing issue claims before a final coverage assertion. Preserve source and live
truth separately. Lead acceptance of a report is not closure of its defects.
