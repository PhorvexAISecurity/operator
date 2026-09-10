# M-6 — SEC-1/SEC-2/PO-1 human decision (2026-09-08)

**Recorded by:** claude (proposer), relaying the human owner's decision given in-session.
**Human authority:** Mehrdad (human_owner, directing this session). The ticket names Mostafa as
security_decision_owner; if a distinct Mostafa signature is required, reconcile at the decision check —
this records the human decision as given to me.
**Basis:** `MOSTAFA_REVIEW.md` + `evidence/decision/technical-review.md`. No change to the technical
contract was requested, so the reviewed package hash stands.

## Decisions — APPROVE all three as recommended
- **SEC-1 = APPROVE (Option A).** Debugger `command`+`args` enforced empty at admission; pinned BusyBox
  digest; `runAsUser/runAsGroup:65534`; restricted `securityContext`; exact action names; exact
  custom-inject command/args; installer/admin owns the profile.
- **SEC-2 = APPROVE (protected namespace scope, NO admin-debug exception).** **Accepted risk (explicit):**
  routine administrator `kubectl debug` (ephemeral containers) in the protected labelled namespaces
  (litellm/vllm/phorvex-system) will be **denied** unless the contract is later changed. Unlabelled
  namespaces remain governed by other controls; Phorvex cannot inject there.
- **PO-1 = APPROVE.** One Phorvex release per cluster, linux/amd64, Kubernetes 1.36.2 validation target;
  code-exec unavailable on missing/unknown/unsupported protection while other defenses continue; bounded L4
  acceptance targets `D=2s / TTL=30s / poll=10s / report≤40s`.

## Scope reaffirmed (no new authorization)
Approval fixes the contract for implementation + independent verification only. Deployment, execution
grants, action enablement, and persisted live injections remain separate gated steps. M6 makes no efficacy
claim and does not cover the `pods/exec` path.
