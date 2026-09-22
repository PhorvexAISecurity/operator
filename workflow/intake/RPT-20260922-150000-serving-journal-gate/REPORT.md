# Report

## Claim

An exact-target protected serving operation retained in a nonterminal or unreadable journal slot is still offered to ranking as capability-feasible. Repeated ticks can select the same high-gain action, after which the dispatch-time safety guard refuses to repeat the ambiguous write. Other safe effect domains remain unselected even though the protected action cannot currently execute.

## Expected behavior

Before scoring, the selected native backend must read the exact target UID/effect-domain journal slot. An absent or terminal valid slot may proceed to ordinary dispatch validation. A nonterminal, malformed, unreadable, or authority-unavailable slot must produce the existing `capability-unsupported` exclusion. The dispatch guard remains authoritative for a record created after the capability read.

## Observed behavior

The boss console evidence retained a KV-domain ConfigMap in phase `dispatching` with unchanged Kubernetes resourceVersion and an old managed-field timestamp. Current manager decisions repeatedly selected KV reset and then returned `dispatch-error`, `outcome-unknown`, and `actuated=false` because the protected operation remained unresolved. The original write outcome is absent; it must not be replayed, deleted, or inferred.

The deployed serving route through port 8000 is intentional: the guardrail proxy forwards `/reset_prefix_cache` to stock vLLM on port 8001. The installed vLLM handler returns empty HTTP 200 and explicitly does not confirm whether reset succeeded, while the native client requires JSON `success:true`. This is a separate unresolved effect-confirmation contract, not a port mismatch and not grounds to mark the old operation successful.

## Reproduction and scope

Source baseline: deployed `9409389467504720b5f0eaa19b91bed7a4793e51`; implementation rebased onto current main `30a1cea4e954830c815ceaba2b47bbaae0a16088`. The source reproduction is read-only. No cluster call, replay, receipt mutation, or serving request is part of this fix.

## Initial evidence

- Incident: `/home/mehrdad/operator/.git/phorvex-workflow/post25-live-20260920/review/BOSS-CONSOLE-LANDINGS-20260922T1401Z`
- Lead verdict: `LEAD-LATEST-VERDICT.json`
- Port/contract correction: `PORT-AND-CONTRACT-CORRECTION.md`
- Source repair receipt: `KV-PROTECTED-JOURNAL-GATE-IMPLEMENTATION.json`
