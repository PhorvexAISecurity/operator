# M124 independently reproduced incident

Lead codex-lead independently exercised actual Namespace/Pod API annotations through the runner preparation/dispatch path to a counting HTTP upstream. Product baseline is `38f1f18c6211e059217320af9168427a111de8b3`; accepted product is `1ceec03e7dafc2ad75314bdc53edb29bcce46d96`. The retained overlay uses the real isolated API server and a recording actuator transport, with feasible selected views to isolate the boundary. Separate permanent tests derive selection from the actual snapshot producer and exercise actual native API mutation and Phoenix SecurityEvent creation.

| Control | Baseline | Final source |
| --- | --- | --- |
| Explicit Namespace false and Pod false | One HTTP POST, positive passes | One HTTP POST, positive passes |
| Namespace TRUE | One HTTP POST leaks; suppression assertion fails | No POST, not-attempted, namespace reason |
| Pod opt-out true | One HTTP POST leaks; suppression assertion fails | No POST, not-attempted, Pod reason |
| Pod changes to whitespace/uppercase TRUE during preparation | One HTTP POST leaks; suppression assertion fails | No POST, not-attempted, Pod reason |

Raw baseline evidence is `lead/baseline-http.log`, from the recorded baseline execution. `lead/head-http.log` retains the first passing implementation170e2c53 execution. `lead/final-head-http.log` reruns the same controls at final product1ceec03e; `lead/final-pins.log` records execution HEAD and confirms no product/tool delta from that pin. `lead/http_boundary_test.go` is the exact independent overlay. Only two fixture lines changed between170e2c53 and1ceec03e; no runtime logic changed. All final independent controls passed.

The overlay records actual API serialization and actual HTTP dispatch, not a mocked final success flag. It isolates boundary refusal and cannot establish production latency, admission policy, serving availability or the effect of an already accepted asynchronous operation. No shared cluster was changed. Live issue-specific acceptance remains pending deployment and the registered disposable-fixture controls.

The worker initially bound the older170e2c53 lead log to its final-source positive-control check; at revision9 it superseded that check with its own final-source preflight execution. This lead incident/P3 uses the independent final1ceec03e rerun and preserves the older evidence unchanged.
