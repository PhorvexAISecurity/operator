# M6 kickoff — 2026-09-08

Authority: Mehrdad requested M6 next, assigned Codex cluster access in K3's place, and requested collaboration with Claude through the new workflow. Exact supplied requirements: TICKET.md. Baseline/read-only investigation and preparation are authorized. Mostafa owns SEC-1/SEC-2/PO-1 choices; installation, permission grants, admission rollout, and persisted test injections await their required contract/scope authorization. No blanket deployment authority is inferred.

## Assigned roles
- human_owner: human-owner (Mehrdad; task coordination).
- proposer + implementer: claude, including Go, CEL/manifests, chart/RBAC packaging, tests and rollout documentation.
- skeptic + live_verifier + coordinator: codex-m006, including read-only operational baseline, independent source/security and operational review, approved cluster operations and verification.
- security_decision_owner: mostafa; SEC-1/SEC-2/PO-1 remain open.

Codex must not author production code, CEL or chart changes it reviews. Claude must not sign independent review or live verification of its changes. Codex supplies both technical and operational review; these are two review responsibilities held by one independent participant, not two independent reviewer identities. K3 has no role in this cycle.

## Locations and source
- Canonical workflow: /home/mehrdad/operator-workflow/workflow.
- Fix: fixes/M-6/STATUS.yaml; bus: coordination/inbox/<agent-id>/.
- Product worktree: /home/mehrdad/operator-m006.
- Branch: parallel/contract-m006-code-exec-admission.
- Baseline: 79c0370dd460a1d6400bc62346638655f64ae709, origin/main v0.4.97.
- M79 is parked; it is not an M6 implementation dependency. Do not silently expand into MIG node-exec.

## Initial scope / completion
Inventory actual native and deployed request paths, effective permissions and relevant admission resources; then propose the versioned security contract and implementation. Prepare Mostafa's decisions before finalizing enforcement rules. Preserve default action enablement, handler semantics and scoring unless separately approved. Required layers L0–L3, plus L4 for runtime freshness, removal, queued work and restoration. Closure requires real API-server allow/deny attribution and independent verification; object presence or fake-client tests are insufficient.

## Bus protocol
Use only workflow/coordination for M6. Claude sends as claude to codex-m006; Codex sends as codex-m006 to claude; subject fix=M-6. List/read are non-destructive; ack only after handling. Messages link artifacts, pins and next action; STATUS.yaml remains authority. Monitors notify active sessions and must be re-armed after restart; the bus does not start an idle agent automatically.
