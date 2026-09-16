# M34 independently reproduced incident

Lead codex-lead independently executed the baseline and head against the actual recon/capability/action-set/optimizer path. Baseline product is `38f1f18c6211e059217320af9168427a111de8b3`; final product is `4c14b6e243ddb6f4d81ea298b7cd8ba00b6b3f4b`. Exact integration commit at baseline execution and head are retained in `lead/pins.log`; `lead/reproduce.sh` and `lead/capability_test.go` retain the test-overlay recipe. Baseline Phorvex source equality was checked before execution.

| Control | Baseline | Final head |
| --- | --- | --- |
| Configured scalar pool, only warm-swap enabled | Actual recon produces no cover; action set reports `recon-cover: action invalidates no facts`; assertion fails | Three existing process-fact keys; candidate admitted and optimizer selects warm-swap |
| Same workload, rotate enabled | Real rotate candidate survives with three process facts | Positive remains PASS |
| Rotate and warm-swap compete on same cover | Not part of baseline incident | Both candidates exist; default costs select warm-swap and measured cheap rotate observations change the choice to rotate |
| Actual API + ReplicaSet controller + snapshot + optimizer + native runner | Not claimed as baseline execution | Real snapshot derives verified pool/owner evidence; partial dispatch stays uncredited; exact old UID removed, shadow promoted, controller creates clean replacement, bounded readiness/recovery confirms and journal clears |

Raw independent outputs: `lead/baseline.log`, `lead/head.log`, `lead/api-kcm.log`. Baseline low-level fixture seeds workload values to isolate the recon omission; the separate real-API/KCM control derives pool evidence through the actual snapshot producer and reaches the native handler. The local serving HTTP endpoint emulates the supported serving contract and the test explicitly supplies kubelet/model readiness. These substitutions do not establish real CNI convergence, actual model load, serving request availability, attack mitigation or live GPU isolation.

The final native lifecycle control is deterministic: replacement readiness is held until the first dispatch returns partial; only then it is released, recovery runs, and exact remaining identities/owner/role/readiness and zero journals are checked. No handler implementation was weakened. The pre-existing same-node pool is now eligible without a two-GPU-node requirement; model-shard's separate floor is preserved.

Independent incident verdict PASS for the source/selectability claim. Live L3 stays pending the deployed supported serving-pool controls.
