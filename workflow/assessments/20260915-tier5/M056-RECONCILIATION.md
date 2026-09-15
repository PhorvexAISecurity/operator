# M56 current-source reconciliation

Disposition: already fixed in source; live verification remains pending.
Lead: codex-lead, 2026-09-15. Reconciled against main
`c53b04cbf9019665e4c1b05f607f70df9690e598`. Executed checkout
`9490693cce9f5ad023f0e379194eb718db14698b` differs only in workflow records;
`git diff --exit-code c53b04cb 9490693c -- phorvex build deploy` passes.

The historical name-keyed collector is disabled in favor of protected operation
receipts. The quarantine producer records the complete Pod name and UID, a
short hashed public label for long names, and the exact NetworkPolicy UID.
Recovery reads the full recorded name; a matching live target retains protection.
Only authoritative NotFound permits orphan cleanup, followed by canonical
NetworkPolicy owner/spec/UID checks and UID/resourceVersion delete preconditions.
Same-name replacement and failed reads refuse cleanup. Public labels alone are
not deletion authority. This behavior arrived in the protected-receipt work
(`395c15e4`) and remains on current main.

Independent test: `TestLeadM056LongNameJournalLifecycle` through actual quarantine
producer -> protected receipt -> RecoverOperations -> API readback. The 253-byte
Pod name and normal UUID exercise the original hashed-label premise.

| Control | Observed result |
|---|---|
| Live original long-name Pod | Quarantine and receipt retained |
| Original Pod authoritatively absent | Exact canonical NP and receipt removed |
| Same name with new Pod UID | Refused; NP and receipt unchanged |
| Authoritative Pod lookup fails | Refused; NP and receipt unchanged |
| Copied public markers on a foreign NP | Foreign NP untouched in every case |

All controls PASS. Source overlay and exact command/output are retained in
[evidence](evidence/m056-lead-control.log), with the independent probe source
[m056-long-name-probe.go.txt](evidence/m056-long-name-probe.go.txt).
The execution uses Go1.26.3, isolated fake Kubernetes objects, and the existing
real production functions. It does not establish API-server admission/precondition
semantics, CNI enforcement, or current dev-cluster behavior.

No duplicate production patch or issue closure is warranted. After DevOps restores
the deployment, the lead must observe the actual running source and retain or run
the separately authorized live quarantine/GC identity controls. Earlier live
obligations remain open; this disposition grants no production GO.
