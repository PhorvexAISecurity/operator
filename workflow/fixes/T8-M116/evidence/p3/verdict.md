# Independent M116 review — PASS for interface scope

Reviewer codex-lead. Contract source `04cdeca79adbe047c695eb26e9e98785a596c7e1`; product content identical to `9c759e523b8755469591815b34e9d1dd1bda2600`. Reviewed complete product delta from `38f1f18c6211e059217320af9168427a111de8b3`, deployment transformation and permanent tests. Source pin differs only by intake whitespace repair. Submission commit `97c084437fc9b6cbd66359388673a41a470e82a3` adds evidence/workflow only.

Independent real HTTP baseline/head probe is retained under `evidence/lead/`: baseline ignored observe mode, blocked high score, and logged prompt canary; the low-score request reached upstream exactly once. Same unchanged probe at final product source passes default enforcement, high-score enforcement refusal, high-score observation forwarding, benign forwarding, and prompt omission. Only classifier output is injected; HTTP parsing, scoring conversion, configuration, decision, response and upstream server are real.

I also directly observed both real deployed model variants against the 16-case labelled corpus and independently evaluated the retained scores with the new evaluator. PGv1 calibration and held-out splits each TP3 FP1 TN3 FN1; PGv2 calibration TP4 FP0 TN4 FN0 and held-out TP4 FP1 TN3 FN0. The interface repair therefore does not solve classifier quality. No threshold change is approved by this small synthetic corpus. Deployed proxy behavior remains baseline; new interface L3 is pending.

Counterexample findings repaired and rechecked:
- Verdicts emitted before the upstream attempt now say admitted, not forwarded/completed.
- Unavailable upstream returns 502 and closes the HTTP client; drain still aborts in-flight streaming with subsequent requests working.
- Corpus canonical hash binds labels/text/splits and prevents same-ID relabelling from passing provenance checks. Incomplete class coverage refuses calibration claims.
- Invalid mode or nonfinite threshold is rejected before any deployment mutation; stale transformed output cannot be applied.

Permanent verifier independently rerun after whitespace repair: 19 tests PASS, byte compilation PASS, git diff check PASS; retained `evidence/lead/verify-final.log`. These include a real uvicorn proxy and HTTP upstream; actual model loading is excluded from offline tests and real classifier observations are separately retained. Preflight receipt is independently inspected as local diff/workflow PASS, not remote CI or deployment evidence.

No security-event emission or threshold promotion was added. Ordinary enforcement defaults remain unchanged. Residuals: representative calibration/held-out quality, deployed source/config provenance, serving-path real-model enforce/observe controls and telemetry retention. PASS authorizes integration and PR delivery only, not issue closure or production approval.
