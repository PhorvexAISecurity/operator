# T1-M020 — L3 live verification verdict

**Date:** 2026-09-07 · **Verifier:** K3 (live_verifier) · **Result: PASS**
**Observed deployment:** `phorvex:0.4.95` (digest `sha256:e69abb52…`, embedded
gitSHA `743a9d46b840` per decisionTrace pins; M-20 merge `835e682` is an ancestor).
Rollout chain in audit corpus: 0.4.93 (M-23) 15:52–16:28Z → 0.4.94 (M-20) 16:28–16:53Z
→ 0.4.95 (both) 16:54Z–.

## Checks performed (all live, cluster EKS via jump host)

1. **REQ-1 zero-diff green** — `crm-prod/crm-prod-defense` and
   `voice-prod/voice-prod-defense` show the legacy message byte-identical
   ("all enabled actions have matching capabilities in the selected fleet"),
   `lastTransitionTime` 2026-09-05 — untouched across three deploys. PASS.
2. **Honest-∃ flip** — 10 policies `status=False reason=UnsupportedActionsEnabled`,
   every flagged action at unsupported==total (1/1, 2/2, 3/3). PASS.
3. **Count accuracy vs ground truth** — every N/M in every message recomputed
   independently from pod labels/annotations/resources (GPU/model identity,
   route-service): 13/13 policies consistent, zero mismatches. PASS.
4. **Count-while-green (partial gap) — live probe** — annotated
   `litellm-prod/litellm-85884ddcbd-s9cbs` with `phorvex.ai/model-id=l3-probe` +
   `phorvex.ai/route-service=l3-probe` (both are *annotations* in the ingest path;
   an earlier label-only attempt was a no-op, itself confirming the witness reads
   the annotation). Within ≤1 tick (15s):
   `True | all enabled actions serviceable; endpoint-rotate unsupported on 1/2 assets (pod advertises no GPU or model identity)`
   — exact proposed grammar, condition stays True on partial gap. PASS.
5. **Recovery + debounce** — probe annotations removed: t+15s
   `Unknown | transient capability loss (1/3 consecutive ticks): endpoint-rotate unsupported on 2/2 …`,
   t+30s `False` with the 2/2 message, stable thereafter. Debounce transient and
   threshold behave as specified. PASS.
6. **Stability / no flap** — repeated samples byte-identical; post-cleanup full
   condition set byte-identical to pre-probe baseline (`diff` clean). PASS.

## Notes
- `model-shard-replace` has no independent ground-truth predicate in the
  cross-check (skipped); its message counts were still consistent with fleet size.
- Probe side effects: none observed (calm fleet; no selections during probe).
  Cluster fully restored.

## Verdict
**L3 PASS.** All six live checks green on the observed 0.4.95 deployment.
